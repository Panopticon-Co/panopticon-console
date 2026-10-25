"""Tests for the Manager-backed routes: /api/alerts (manager mode),
/api/incidents, /api/incidents/{id}, /api/incidents/{id}/status and
/api/status.

Most tests patch ``app.manager_get`` / ``app.manager_post`` so they assert
exactly what this console would send to Manager. ``FakeManagerEndToEndTests``
runs a real loopback HTTP server standing in for Manager, to pin that the
bearer token is attached server-side and never reaches the browser.
"""
import json
import sys
import tempfile
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import ManagerProxyError, build_server, map_alert_row  # noqa: E402

SECRET_TOKEN = "analyst-secret-token-should-never-leak"  # noqa: S105 - test fixture
MANAGER = "http://manager.test"

STORED_ALERT = {
    "alert_id": "ALT-1",
    "rule_id": "DET-PROC-011",
    "title": "Obfuscated script",
    "severity": "high",
    "level": 11,
    "timestamp": "2026-10-25T08:00:00Z",
    "confidence": 0.8,
    "evidence": {"process.name": "powershell.exe"},
}
ROW = {
    "alert_id": "ALT-1",
    "rule_id": "DET-PROC-011",
    "level": 11,
    "severity": "high",
    "host_id": "WS-1",
    "agent_id": "agent-1",
    "event_id": "e1",
    "alert_timestamp": "2026-10-25T08:00:00Z",
    "created_at": "2026-10-25T08:00:02Z",
    "mitre_tactic": "Execution",
    "mitre_technique": "T1059",
    "detection_source": "rule",
    "incident_id": "INC-1",
    "alert": STORED_ALERT,
}


class _ServerMixin:
    def _build(self, manager_url=MANAGER, manager_token=SECRET_TOKEN, alerts_file=None):
        server = build_server(alerts_file, "127.0.0.1", 0, manager_url, manager_token)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        # One cleanup, shutdown first: addCleanup is LIFO, so a separate
        # join registered after shutdown would wait its full timeout.
        self.addCleanup(lambda: (server.shutdown(), thread.join(timeout=5)))
        return server.server_address[1]

    def _request(self, port, path, method="GET", body=None, headers=None):
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}", method=method, data=body, headers=headers or {}
        )
        try:
            resp = urllib.request.urlopen(req, timeout=5)
            return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()


class AlertRowMappingTests(unittest.TestCase):
    def test_row_alert_plus_authoritative_columns(self):
        alert = map_alert_row(ROW)
        self.assertEqual(alert["title"], "Obfuscated script")
        self.assertEqual(alert["confidence"], 0.8)
        self.assertEqual(alert["detection_source"], "rule")
        self.assertEqual(alert["incident_id"], "INC-1")
        self.assertEqual(alert["agent_id"], "agent-1")
        self.assertEqual(alert["host_id"], "WS-1")  # filled from the row
        self.assertEqual(alert["stored_at"], "2026-10-25T08:00:02Z")

    def test_row_columns_override_stored_source_but_not_other_fields(self):
        row = dict(ROW, detection_source="correlation", severity="low", alert=dict(STORED_ALERT, detection_source="rule"))
        alert = map_alert_row(row)
        self.assertEqual(alert["detection_source"], "correlation")
        self.assertEqual(alert["severity"], "high")  # stored alert wins for non-authoritative fields

    def test_row_without_alert_object_is_built_from_columns(self):
        row = {k: v for k, v in ROW.items() if k != "alert"}
        alert = map_alert_row(row)
        self.assertEqual(alert["alert_id"], "ALT-1")
        self.assertEqual(alert["timestamp"], "2026-10-25T08:00:00Z")
        self.assertEqual(alert["mitre_technique"], "T1059")

    def test_alert_stored_as_json_string(self):
        alert = map_alert_row(dict(ROW, alert=json.dumps(STORED_ALERT)))
        self.assertEqual(alert["title"], "Obfuscated script")

    def test_non_object_row_is_dropped(self):
        self.assertIsNone(map_alert_row("nope"))
        self.assertIsNone(map_alert_row(None))


class ManagerAlertsRouteTests(_ServerMixin, unittest.TestCase):
    def test_maps_rows_and_marks_source(self):
        port = self._build()
        payload = json.dumps({"alerts": [ROW, "junk"], "next_before": "2026-10-25T07:59:00Z"}).encode()
        with unittest.mock.patch("app.manager_get", return_value=(200, payload)) as mocked:
            status, headers, body = self._request(port, "/api/alerts")
        self.assertEqual(status, 200)
        mocked.assert_called_once_with(MANAGER, SECRET_TOKEN, "/api/v1/alerts")
        data = json.loads(body)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["alert_id"], "ALT-1")
        self.assertEqual(data[0]["detection_source"], "rule")
        self.assertEqual(headers["X-Panopticon-Alert-Source"], "manager")
        self.assertEqual(headers["X-Panopticon-Next-Before"], "2026-10-25T07:59:00Z")
        self.assertNotIn(SECRET_TOKEN.encode(), body)
        self.assertNotIn(SECRET_TOKEN, json.dumps(headers))

    def test_passes_whitelisted_filters_through(self):
        port = self._build()
        with unittest.mock.patch("app.manager_get", return_value=(200, b'{"alerts":[]}')) as mocked:
            status, _, _ = self._request(
                port,
                "/api/alerts?severity=critical&source=correlation&incident_id=INC-1&limit=50"
                "&before=2026-10-25T08:00:00%2B00:00",
            )
        self.assertEqual(status, 200)
        path = mocked.call_args.args[2]
        self.assertEqual(
            path,
            "/api/v1/alerts?severity=critical&source=correlation&incident_id=INC-1&limit=50"
            "&before=2026-10-25T08%3A00%3A00%2B00%3A00",
        )

    def test_empty_filter_values_are_dropped(self):
        port = self._build()
        with unittest.mock.patch("app.manager_get", return_value=(200, b'{"alerts":[]}')) as mocked:
            self._request(port, "/api/alerts?severity=&limit=5")
        self.assertEqual(mocked.call_args.args[2], "/api/v1/alerts?limit=5")

    def test_rejects_invalid_queries_without_calling_manager(self):
        port = self._build()
        bad = [
            "unknown=1",
            "severity=urgent",
            "source=ml",
            "limit=0",
            "limit=201",  # above Manager's own cap of 200
            "limit=abc",
            "incident_id=INC%2F..%2Fx",
            "before=2026-10-25%2008:00",  # a space is not a cursor character
            "severity=high&severity=low",
            "host_id=" + "a" * 200,
        ]
        with unittest.mock.patch("app.manager_get") as mocked:
            for query in bad:
                status, _, body = self._request(port, "/api/alerts?" + query)
                self.assertEqual(status, 400, query)
                self.assertIn(b"error", body)
        mocked.assert_not_called()

    def test_manager_error_status_passed_through(self):
        port = self._build()
        with unittest.mock.patch("app.manager_get", return_value=(401, b'{"detail":"analyst authentication required"}')):
            status, headers, body = self._request(port, "/api/alerts")
        self.assertEqual(status, 401)
        self.assertEqual(body, b'{"detail":"analyst authentication required"}')
        self.assertEqual(headers["X-Panopticon-Alert-Source"], "manager")

    def test_unexpected_payload_is_502(self):
        port = self._build()
        for payload in (b"not json", b'{"rows": []}', b'{"alerts": {}}', b"[]"):
            with unittest.mock.patch("app.manager_get", return_value=(200, payload)):
                status, _, _ = self._request(port, "/api/alerts")
            self.assertEqual(status, 502, payload)

    def test_unreachable_manager_is_502_not_file_fallback(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        alerts_file = Path(tmp.name) / "alerts.ndjson"
        alerts_file.write_text(json.dumps(STORED_ALERT) + "\n", encoding="utf-8")
        port = self._build(alerts_file=alerts_file)
        with unittest.mock.patch("app.manager_get", side_effect=ManagerProxyError("refused")):
            status, _, body = self._request(port, "/api/alerts")
        self.assertEqual(status, 502)
        self.assertNotIn(SECRET_TOKEN.encode(), body)


class FileModeAlertsTests(_ServerMixin, unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.alerts_file = Path(tmp.name) / "alerts.ndjson"
        lines = [
            dict(STORED_ALERT, alert_id="A", detection_source="rule", timestamp="2026-10-25T08:00:00Z"),
            dict(STORED_ALERT, alert_id="B", detection_source="correlation", incident_id="INC-1", severity="critical", timestamp="2026-10-25T08:01:00Z"),
            dict(STORED_ALERT, alert_id="C", timestamp="2026-10-25T08:02:00Z"),
        ]
        self.alerts_file.write_text("".join(json.dumps(a) + "\n" for a in lines), encoding="utf-8")

    def test_file_mode_marks_source_and_applies_filters(self):
        port = self._build(manager_url=None, manager_token=None, alerts_file=self.alerts_file)
        status, headers, body = self._request(port, "/api/alerts")
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Panopticon-Alert-Source"], "file")
        self.assertEqual([a["alert_id"] for a in json.loads(body)], ["A", "B", "C"])
        _, _, body = self._request(port, "/api/alerts?source=correlation")
        self.assertEqual([a["alert_id"] for a in json.loads(body)], ["B"])
        _, _, body = self._request(port, "/api/alerts?incident_id=INC-1&severity=critical")
        self.assertEqual([a["alert_id"] for a in json.loads(body)], ["B"])
        _, _, body = self._request(port, "/api/alerts?limit=2")
        self.assertEqual([a["alert_id"] for a in json.loads(body)], ["B", "C"])
        _, _, body = self._request(port, "/api/alerts?before=2026-10-25T08:01:00Z")
        self.assertEqual([a["alert_id"] for a in json.loads(body)], ["A"])
        status, _, _ = self._request(port, "/api/alerts?source=nope")
        self.assertEqual(status, 400)

    def test_url_without_token_stays_in_file_mode(self):
        port = self._build(manager_url=MANAGER, manager_token=None, alerts_file=self.alerts_file)
        with unittest.mock.patch("app.manager_get") as mocked:
            status, headers, _ = self._request(port, "/api/alerts")
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Panopticon-Alert-Source"], "file")
        mocked.assert_not_called()


class ManagerGetProxyTests(_ServerMixin, unittest.TestCase):
    ROUTES = ("/api/incidents", "/api/incidents/INC-1", "/api/status")

    def test_503_when_not_configured(self):
        for kwargs in ({"manager_url": None, "manager_token": None}, {"manager_url": MANAGER, "manager_token": None}):
            port = self._build(**kwargs)
            for route in self.ROUTES:
                status, _, body = self._request(port, route)
                self.assertEqual(status, 503, route)
                self.assertIn(b"not configured", body)

    def test_502_when_unreachable(self):
        port = self._build()
        with unittest.mock.patch("app.manager_get", side_effect=ManagerProxyError("timed out")):
            for route in self.ROUTES:
                status, _, body = self._request(port, route)
                self.assertEqual(status, 502, route)
                self.assertNotIn(SECRET_TOKEN.encode(), body)

    def test_passes_status_and_body_through_verbatim(self):
        port = self._build()
        expected = {
            "/api/incidents": "/api/v1/incidents",
            "/api/incidents?status=investigating&host_id=WS-1&limit=10": "/api/v1/incidents?status=investigating&host_id=WS-1&limit=10",
            "/api/incidents/INC-1": "/api/v1/incidents/INC-1",
            "/api/status": "/api/v1/status",
        }
        for route, manager_path in expected.items():
            for code, payload in ((200, b'{"ok":true}'), (404, b'{"detail":"incident not found"}')):
                with unittest.mock.patch("app.manager_get", return_value=(code, payload)) as mocked:
                    status, headers, body = self._request(port, route)
                self.assertEqual((status, body), (code, payload), route)
                self.assertIn("application/json", headers["Content-Type"])
                mocked.assert_called_once_with(MANAGER, SECRET_TOKEN, manager_path)

    def test_incident_query_and_id_validation(self):
        port = self._build()
        with unittest.mock.patch("app.manager_get") as mocked:
            for route in (
                "/api/incidents?status=closed",
                "/api/incidents?severity=high",
                "/api/incidents?limit=-1",
                "/api/incidents/INC%201",
                "/api/incidents/INC;rm",
                "/api/incidents/" + "I" * 129,
                "/api/incidents/INC-1?x=1",
            ):
                status, _, _ = self._request(port, route)
                self.assertEqual(status, 400, route)
            # Deeper paths are simply unknown routes.
            status, _, _ = self._request(port, "/api/incidents/INC-1/alerts")
            self.assertEqual(status, 404)
        mocked.assert_not_called()


class IncidentStatusProxyTests(_ServerMixin, unittest.TestCase):
    PATH = "/api/incidents/INC-1/status"

    def _post(self, port, body, path=None, headers=None):
        return self._request(port, path or self.PATH, "POST", body, headers or {"Content-Type": "application/json"})

    def test_503_when_not_configured(self):
        port = self._build(manager_url=None, manager_token=None)
        status, _, _ = self._post(port, b'{"status":"resolved"}')
        self.assertEqual(status, 503)

    def test_forwards_normalized_body(self):
        port = self._build()
        reply = b'{"incident_id":"INC-1","status":"resolved"}'
        with unittest.mock.patch("app.manager_post", return_value=(200, reply)) as mocked:
            status, _, body = self._post(port, b'{"status":"resolved","note":"  confirmed benign  "}')
        self.assertEqual((status, body), (200, reply))
        mocked.assert_called_once_with(
            MANAGER, SECRET_TOKEN, "/api/v1/incidents/INC-1/status",
            json.dumps({"status": "resolved", "note": "confirmed benign"}).encode(),
        )
        self.assertNotIn(SECRET_TOKEN.encode(), body)

    def test_every_contract_status_accepted_and_blank_note_dropped(self):
        port = self._build()
        for value in ("open", "investigating", "resolved", "false_positive"):
            with unittest.mock.patch("app.manager_post", return_value=(200, b"{}")) as mocked:
                status, _, _ = self._post(port, json.dumps({"status": value, "note": "   "}).encode())
            self.assertEqual(status, 200, value)
            self.assertEqual(json.loads(mocked.call_args.args[3]), {"status": value})

    def test_validation_errors(self):
        port = self._build()
        cases = [
            b"",
            b"not json",
            b"[]",
            b'{"note":"x"}',
            b'{"status":"closed"}',
            b'{"status":"RESOLVED"}',
            b'{"status":"resolved","note":5}',
            b'{"status":"resolved","analyst":"mallory"}',
            json.dumps({"status": "resolved", "note": "x" * 2001}).encode(),
        ]
        with unittest.mock.patch("app.manager_post") as mocked:
            for body in cases:
                status, _, _ = self._post(port, body)
                self.assertEqual(status, 400, body[:40])
            status, _, _ = self._post(port, b'{"status":"resolved"}', path="/api/incidents/INC;1/status")
            self.assertEqual(status, 400)
        mocked.assert_not_called()

    def test_body_over_16kb_is_413(self):
        port = self._build()
        big = json.dumps({"status": "resolved", "note": "x" * (17 * 1024)}).encode()
        with unittest.mock.patch("app.manager_post") as mocked:
            try:
                status, _, _ = self._post(port, big)
            except (ConnectionError, urllib.error.URLError):
                # The server may close before reading the whole oversized body.
                status = 413
        self.assertEqual(status, 413)
        mocked.assert_not_called()

    def test_manager_errors(self):
        port = self._build()
        with unittest.mock.patch("app.manager_post", return_value=(409, b'{"detail":"conflict"}')):
            status, _, body = self._post(port, b'{"status":"resolved"}')
        self.assertEqual((status, body), (409, b'{"detail":"conflict"}'))
        with unittest.mock.patch("app.manager_post", side_effect=ManagerProxyError("refused")):
            status, _, body = self._post(port, b'{"status":"resolved"}')
        self.assertEqual(status, 502)
        self.assertNotIn(SECRET_TOKEN.encode(), body)

    def test_unknown_post_routes_404(self):
        port = self._build()
        for path in ("/api/incidents/INC-1", "/api/incidents/INC-1/status/x", "/api/alerts", "/api/status"):
            status, _, _ = self._post(port, b"{}", path=path)
            self.assertEqual(status, 404, path)


class _FakeManager(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *args):
        pass

    def _reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        self.seen.append(("GET", self.path, self.headers.get("Authorization")))
        if self.headers.get("Authorization") != f"Bearer {SECRET_TOKEN}":
            self._reply(401, {"detail": "analyst authentication required"})
        elif self.path.startswith("/api/v1/alerts"):
            self._reply(200, {"alerts": [ROW], "next_before": None})
        elif self.path == "/api/v1/status":
            self._reply(200, {"events": {"pending": 0, "claimed": 0, "done": 3, "failed": 0}, "incidents_open": 1})
        else:
            self._reply(404, {"detail": "not found"})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        self.seen.append(("POST", self.path, self.headers.get("Authorization"), body))
        self._reply(200, {"incident_id": "INC-1", "status": body["status"]})


class FakeManagerEndToEndTests(_ServerMixin, unittest.TestCase):
    def setUp(self):
        _FakeManager.seen = []
        self.fake = ThreadingHTTPServer(("127.0.0.1", 0), _FakeManager)
        self.addCleanup(self.fake.server_close)
        thread = threading.Thread(target=self.fake.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.fake.shutdown)
        self.manager_url = f"http://127.0.0.1:{self.fake.server_address[1]}"

    def test_token_attached_server_side_only(self):
        port = self._build(manager_url=self.manager_url)
        status, headers, body = self._request(port, "/api/alerts?severity=high")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)[0]["incident_id"], "INC-1")
        self.assertNotIn("X-Panopticon-Next-Before", headers)
        status, _, body = self._request(port, "/api/status")
        self.assertEqual((status, json.loads(body)["incidents_open"]), (200, 1))
        status, _, _ = self._request(
            port, "/api/incidents/INC-1/status", "POST", b'{"status":"investigating"}', {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(_FakeManager.seen[0][:2], ("GET", "/api/v1/alerts?severity=high"))
        self.assertEqual(_FakeManager.seen[2][1], "/api/v1/incidents/INC-1/status")
        self.assertEqual(_FakeManager.seen[2][3], {"status": "investigating"})
        for entry in _FakeManager.seen:
            self.assertEqual(entry[2], f"Bearer {SECRET_TOKEN}")
        # The browser never supplies (or receives) the token.
        self.assertNotIn(SECRET_TOKEN.encode(), body)

    def test_wrong_token_surfaces_managers_401(self):
        port = self._build(manager_url=self.manager_url, manager_token="wrong")
        status, _, body = self._request(port, "/api/status")
        self.assertEqual(status, 401)
        self.assertNotIn(b"wrong", body)


if __name__ == "__main__":
    unittest.main()
