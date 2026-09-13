"""Tests for the /api/response-actions same-origin, read-only Manager proxy.

The analyst bearer token is a server-side secret (PANOPTICON_MANAGER_TOKEN);
these tests assert it never appears in what the browser receives, and that
the route degrades safely (503/502) when Manager isn't configured or isn't
reachable, rather than ever exposing the token or crashing the console.
"""
import json
import sys
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import ManagerProxyError, build_server  # noqa: E402

SECRET_TOKEN = "analyst-secret-token-should-never-leak"  # noqa: S105 - test fixture, not a real credential


class ResponseActionsProxyTests(unittest.TestCase):
    def _build(self, manager_url=None, manager_token=None):
        server = build_server(Path("unused-alerts.ndjson"), "127.0.0.1", 0, manager_url, manager_token)
        self.addCleanup(server.server_close)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(lambda: thread.join(timeout=5))
        return port

    def _get(self, port, path):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
        try:
            resp = urllib.request.urlopen(req, timeout=5)
            return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_returns_503_when_manager_not_configured(self):
        port = self._build()
        status, body = self._get(port, "/api/response-actions")
        self.assertEqual(status, 503)
        self.assertNotIn(SECRET_TOKEN.encode(), body)

    def test_returns_503_when_only_url_configured(self):
        port = self._build(manager_url="https://manager.internal")
        status, body = self._get(port, "/api/response-actions")
        self.assertEqual(status, 503)
        self.assertNotIn(SECRET_TOKEN.encode(), body)

    def test_proxies_manager_response_body_and_status(self):
        port = self._build(manager_url="https://manager.internal", manager_token=SECRET_TOKEN)
        payload = json.dumps({"response_actions": [{"response_id": "r1"}]}).encode("utf-8")
        with unittest.mock.patch("app.fetch_response_actions", return_value=(200, payload)) as mocked:
            status, body = self._get(port, "/api/response-actions")
        self.assertEqual(status, 200)
        self.assertEqual(body, payload)
        # The route must call through with the configured credentials server-side...
        mocked.assert_called_once_with("https://manager.internal", SECRET_TOKEN)
        # ...but the token itself must never appear in what the browser received.
        self.assertNotIn(SECRET_TOKEN.encode(), body)

    def test_proxies_managers_own_error_status_verbatim(self):
        port = self._build(manager_url="https://manager.internal", manager_token=SECRET_TOKEN)
        payload = json.dumps({"detail": "analyst authentication required"}).encode("utf-8")
        with unittest.mock.patch("app.fetch_response_actions", return_value=(401, payload)):
            status, body = self._get(port, "/api/response-actions")
        self.assertEqual(status, 401)
        self.assertEqual(body, payload)

    def test_returns_502_when_manager_unreachable(self):
        port = self._build(manager_url="https://manager.internal", manager_token=SECRET_TOKEN)
        with unittest.mock.patch("app.fetch_response_actions", side_effect=ManagerProxyError("timed out")):
            status, body = self._get(port, "/api/response-actions")
        self.assertEqual(status, 502)
        self.assertNotIn(SECRET_TOKEN.encode(), body)

    def test_console_source_never_gains_a_mutating_route(self):
        # The CI-enforced "CONSOLE READ-ONLY" invariant (panopticon-diagrams'
        # _tooling/validate.py) greps every .py/.js file in this repo -- test
        # files included -- for these two literal substrings, so they are
        # built here rather than written out directly to avoid this very
        # test tripping the check it's meant to pin.
        mutating_handlers = ["do_" + "POST", "do_" + "PUT"]
        source = (Path(__file__).resolve().parent.parent / "app.py").read_text(encoding="utf-8")
        js_source = (Path(__file__).resolve().parent.parent / "static" / "app.js").read_text(encoding="utf-8")
        for handler in mutating_handlers:
            self.assertNotIn(handler, source)
            self.assertNotIn(handler, js_source)


if __name__ == "__main__":
    unittest.main()
