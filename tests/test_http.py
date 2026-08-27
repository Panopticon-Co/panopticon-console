"""HTTP-level tests for the console server.

Each test starts a real ``build_server`` on an ephemeral port in a background
thread and talks to it over a real socket with ``urllib``. Deterministic: no
sleeps, the server is up before the thread's ``serve_forever`` is even needed
because construction binds the socket.
"""
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import build_server  # noqa: E402

ALERT_A = {
    "alert_id": "ALT-A",
    "rule_id": "DET-PROC-011",
    "title": "High-Entropy Obfuscated Script Execution",
    "severity": "high",
    "level": 11,
    "timestamp": "2026-08-27T18:20:40.645Z",
    "mitre_tactic": "Defense Evasion",
    "mitre_technique": "T1027",
    "evidence": {"process.name": "powershell.exe", "process.command_line": "powershell.exe -enc VwB="},
}
ALERT_B = dict(ALERT_A, alert_id="ALT-B", rule_id="DET-PROC-099")

# An alert whose fields carry an HTML/JS injection attempt. The API passes it
# through verbatim (correct); app.js is responsible for escaping on render. This
# test just pins that the server itself adds no HTML-unsafe behaviour and keeps
# the payload intact for the client to neutralise.
ALERT_XSS = dict(
    ALERT_A,
    alert_id="ALT-XSS",
    title="<img src=x onerror=alert(1)>",
    evidence={"process.command_line": "<script>alert('xss')</script>"},
)


class ConsoleHTTPTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.alerts_file = self.tmp / "alerts.ndjson"

        self.server = build_server(self.alerts_file, "127.0.0.1", 0)
        self.addCleanup(self.server.server_close)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._shutdown)

    def _shutdown(self):
        self.server.shutdown()
        self.thread.join(timeout=5)

    def _write(self, *alerts):
        self.alerts_file.write_text(
            "".join(json.dumps(a) + "\n" for a in alerts), encoding="utf-8"
        )

    def _get(self, path, method="GET"):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=5)
            return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    # -- static -----------------------------------------------------------
    def test_index_served(self):
        status, headers, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"PANOPTICON CONSOLE", body)

    def test_appjs_served_with_js_content_type(self):
        status, headers, body = self._get("/app.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", headers["Content-Type"])
        self.assertIn(b"textContent", body)  # the XSS-safe render path is present

    def test_security_headers_present(self):
        _, headers, _ = self._get("/")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("Content-Security-Policy", headers)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])

    def test_unknown_path_is_404(self):
        # There is no filesystem mapping: only the exact static routes and
        # /api/alerts resolve. A percent-encoded traversal is not decoded into
        # a path, it is simply an unknown route.
        for path in ("/secrets", "/%2e%2e/app.py", "/static/index.html", "/api"):
            status, _, _ = self._get(path)
            self.assertEqual(status, 404, f"{path} should 404")

    def test_head_request_has_no_body(self):
        status, headers, body = self._get("/", method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertIn("Content-Length", headers)

    # -- /api/alerts ----------------------------------------------------------
    def test_api_empty_when_file_missing(self):
        status, headers, body = self._get("/api/alerts")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers["Content-Type"])
        self.assertEqual(json.loads(body), [])

    def test_api_returns_alerts_in_order_with_expected_fields(self):
        self._write(ALERT_A, ALERT_B)
        status, _, body = self._get("/api/alerts")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual([a["alert_id"] for a in data], ["ALT-A", "ALT-B"])
        first = data[0]
        for field in ("rule_id", "severity", "level", "title", "timestamp",
                      "mitre_technique", "evidence"):
            self.assertIn(field, first)
        self.assertEqual(first["evidence"]["process.name"], "powershell.exe")

    def test_api_reflects_file_updates_between_polls(self):
        status, _, body = self._get("/api/alerts")
        self.assertEqual(json.loads(body), [])
        self._write(ALERT_A)
        _, _, body = self._get("/api/alerts")
        self.assertEqual(len(json.loads(body)), 1)
        self._write(ALERT_A, ALERT_B)
        _, _, body = self._get("/api/alerts")
        self.assertEqual(len(json.loads(body)), 2)

    def test_api_passes_injection_payload_through_untransformed(self):
        self._write(ALERT_XSS)
        _, _, body = self._get("/api/alerts")
        data = json.loads(body)
        self.assertEqual(data[0]["title"], "<img src=x onerror=alert(1)>")
        self.assertEqual(
            data[0]["evidence"]["process.command_line"], "<script>alert('xss')</script>"
        )

    def test_api_skips_malformed_line(self):
        self.alerts_file.write_text(
            json.dumps(ALERT_A) + "\n" + "NOT JSON\n" + json.dumps(ALERT_B) + "\n",
            encoding="utf-8",
        )
        _, _, body = self._get("/api/alerts")
        self.assertEqual([a["alert_id"] for a in json.loads(body)], ["ALT-A", "ALT-B"])


class ConfigurableAlertPathTests(unittest.TestCase):
    """The alert source is whatever --alerts-file pointed at - no fixed path."""

    def test_two_servers_serve_their_own_distinct_files(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        file_one = root / "one" / "alerts.ndjson"
        file_two = root / "two" / "custom-name.ndjson"
        file_one.parent.mkdir()
        file_two.parent.mkdir()
        file_one.write_text(json.dumps(ALERT_A) + "\n", encoding="utf-8")
        file_two.write_text(json.dumps(ALERT_B) + "\n", encoding="utf-8")

        servers = []
        for path in (file_one, file_two):
            srv = build_server(path, "127.0.0.1", 0)
            self.addCleanup(srv.server_close)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self.addCleanup(lambda s=srv, th=t: (s.shutdown(), th.join(timeout=5)))
            servers.append(srv)

        got = []
        for srv in servers:
            port = srv.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/alerts", timeout=5) as r:
                got.append(json.loads(r.read()))

        self.assertEqual(got[0][0]["rule_id"], "DET-PROC-011")
        self.assertEqual(got[1][0]["rule_id"], "DET-PROC-099")


if __name__ == "__main__":
    unittest.main()
