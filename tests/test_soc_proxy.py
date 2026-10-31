"""Proxy routes behind the SOC views: agents, events, health, response audit."""
import json
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import ManagerProxyError  # noqa: E402
from tests.test_manager_proxy import MANAGER, SECRET_TOKEN, _ServerMixin  # noqa: E402


class SocProxyTests(_ServerMixin, unittest.TestCase):
    def test_routes_map_to_manager_paths(self):
        port = self._build()
        expected = {
            "/api/agents": "/api/v1/agents",
            "/api/events": "/api/v1/events",
            "/api/events?after_event=12&after_record=0&host_id=WS-1&category=process&limit=50":
                "/api/v1/events?after_event=12&after_record=0&host_id=WS-1&category=process&limit=50",
            "/api/response-audit?limit=100": "/api/v1/response-audit?limit=100",
        }
        for route, manager_path in expected.items():
            with unittest.mock.patch("app.manager_get", return_value=(200, b'{"ok":true}')) as mocked:
                status, _, body = self._request(port, route)
            self.assertEqual((status, body), (200, b'{"ok":true}'), route)
            mocked.assert_called_once_with(MANAGER, SECRET_TOKEN, manager_path)

    def test_event_query_validation(self):
        port = self._build()
        with unittest.mock.patch("app.manager_get") as mocked:
            for route in ("/api/events?after_event=-1", "/api/events?category=Proc%20ess",
                          "/api/events?limit=500", "/api/events?sql=1", "/api/agents?x=1"):
                status, _, _ = self._request(port, route)
                self.assertIn(status, (400, 404), route)
        mocked.assert_not_called()

    def test_503_when_not_configured(self):
        port = self._build(manager_url=None, manager_token=None)
        for route in ("/api/agents", "/api/events"):
            self.assertEqual(self._request(port, route)[0], 503, route)
        status, _, body = self._request(port, "/api/health")
        report = json.loads(body)
        self.assertEqual((status, report["console"]["mode"], report["manager"]), (200, "file", None))

    def test_health_reports_manager_and_recent_errors(self):
        port = self._build()
        responses = {"/healthz": (200, b'{"status":"ok"}'),
                     "/readyz": (503, b'{"status":"not_ready","reason":"schema"}')}
        with unittest.mock.patch("app.manager_get", side_effect=lambda u, t, p, **k: responses[p]):
            report = json.loads(self._request(port, "/api/health")[2])
        self.assertEqual(report["manager"]["healthz"]["status"], "ok")
        self.assertEqual(report["manager"]["readyz"]["http_status"], 503)
        self.assertNotIn(SECRET_TOKEN, json.dumps(report))

        with unittest.mock.patch("app.manager_get", side_effect=ManagerProxyError("refused")):
            self.assertEqual(self._request(port, "/api/agents")[0], 502)
            report = json.loads(self._request(port, "/api/health")[2])
        self.assertEqual(report["manager"]["healthz"]["status"], "unreachable")
        self.assertIn("/api/v1/agents", [e["path"] for e in report["recent_errors"]])


if __name__ == "__main__":
    unittest.main()
