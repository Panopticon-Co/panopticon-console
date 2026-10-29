"""Separate browser credentials; no shared-token fallback or browser bearer storage."""

import http.client
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from app import build_server
from evidence_sessions import COOKIE, EvidenceError, exchange

TOKEN_A = "individual_analyst_A_" + "a" * 24
TOKEN_B = "individual_analyst_B_" + "b" * 24
SHARED = "shared_console_credential"


class EvidenceSessionTests(unittest.TestCase):
    def setUp(self):
        self.server = build_server(None, "127.0.0.1", 0, "https://manager.test", SHARED)
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join, 5)
        self.addCleanup(self.server.shutdown)
        self.calls = []
        self.revoked = set()
        self.mock = patch("evidence_sessions.exchange", side_effect=self.backend)
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def backend(self, url, token, path):
        self.calls.append((url, token, path))
        if token in self.revoked:
            return 401, b'{"detail":"revoked"}'
        if path == "/api/v1/analysts/me":
            return 200, json.dumps({"analyst_id": "A" if token == TOKEN_A else "B",
                                    "role": "analyst", "permissions": ["artifact:read"],
                                    "access_token": "must_never_escape"}).encode()
        return 200, json.dumps({"artifact": "scoped", "caller": "A" if token == TOKEN_A else "B"}).encode()

    def request(self, path, *, method="GET", value=None, cookie=None, headers=None):
        combined = {"Origin": self.origin, "Content-Type": "application/json", **(headers or {})}
        if cookie:
            combined["Cookie"] = cookie
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=json.dumps(value).encode() if value is not None else None,
                               headers=combined)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def login(self, token=TOKEN_A, cookie=None):
        status, headers, body = self.request("/api/evidence/session", method="POST",
                                             value={"access_token": token}, cookie=cookie)
        self.assertEqual(status, 200, body)
        return headers["Set-Cookie"].split(";")[0], headers, json.loads(body)

    def test_two_browsers_use_their_own_credentials_and_cookie_contains_no_token(self):
        cookie_a, headers, identity = self.login()
        cookie_b, _, _ = self.login(TOKEN_B)
        self.assertNotEqual(cookie_a, cookie_b)
        self.assertNotIn(TOKEN_A, str(headers) + str(identity))
        self.assertNotIn("must_never_escape", str(identity))
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        self.assertIn("Path=/api/evidence", headers["Set-Cookie"])
        for cookie, actor in ((cookie_a, "A"), (cookie_b, "B")):
            status, _, body = self.request("/api/evidence/cases/case-1", cookie=cookie)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["caller"], actor)
        self.assertTrue(all(call[1] != SHARED for call in self.calls))

    def test_missing_or_forged_session_never_falls_back_to_global_identity(self):
        for cookie in (None, COOKIE + "=" + "a" * 43):
            self.assertEqual(self.request("/api/evidence/cases/r1", cookie=cookie)[0], 401)
        self.assertEqual(self.calls, [])

    def test_logout_and_credential_revocation_block_next_read(self):
        cookie, _, _ = self.login()
        self.assertEqual(self.request("/api/evidence/session/logout", method="POST", cookie=cookie)[0], 200)
        self.assertEqual(self.request("/api/evidence/cases/r1", cookie=cookie)[0], 401)
        cookie, _, _ = self.login()
        self.revoked.add(TOKEN_A)
        self.assertEqual(self.request("/api/evidence/cases/r1", cookie=cookie)[0], 401)
        calls = len(self.calls)
        self.assertEqual(self.request("/api/evidence/cases/r1", cookie=cookie)[0], 401)
        self.assertEqual(len(self.calls), calls)

    def test_origin_host_and_path_cannot_be_used_to_forward_arbitrary_requests(self):
        cookie, _, _ = self.login()
        for headers in ({"Origin": "https://attacker.test"}, {"Host": "attacker.test"},
                        {"Sec-Fetch-Site": "cross-site"}):
            self.assertEqual(self.request("/api/evidence/session", method="POST",
                                           value={"access_token": TOKEN_A}, headers=headers)[0], 403)
        calls = len(self.calls)
        for path in ("/api/evidence/../../admin", "/api/evidence/cases/r1?token=bad",
                     "/api/evidence/artifacts/art_" + "a" * 64 + "/content?url=https://bad"):
            self.assertIn(self.request(path, cookie=cookie)[0], (400, 404))
        self.assertEqual(len(self.calls), calls)

    def test_retry_login_is_idempotent_and_switching_identity_invalidates_old_session(self):
        cookie_a, _, _ = self.login()
        repeated, _, _ = self.login(cookie=cookie_a)
        self.assertEqual(cookie_a, repeated)
        cookie_b, _, identity = self.login(TOKEN_B, cookie_a)
        self.assertNotEqual(cookie_a, cookie_b)
        self.assertEqual(identity["analyst_id"], "B")
        self.assertEqual(self.request("/api/evidence/cases/r1", cookie=cookie_a)[0], 401)

    def test_expired_session_and_viewer_identity_refused(self):
        cookie, _, _ = self.login()
        with patch("evidence_sessions.time.monotonic", return_value=10**20):
            self.assertEqual(self.request("/api/evidence/cases/r1", cookie=cookie)[0], 401)
        with patch("evidence_sessions.exchange", return_value=(200, b'{"analyst_id":"viewer","role":"viewer","permissions":[]}')):
            self.assertEqual(self.request("/api/evidence/session", method="POST",
                                           value={"access_token": TOKEN_A})[0], 403)

    def test_session_capacity_is_bounded_and_never_discards_other_sessions(self):
        cookie, _, _ = self.login()
        with patch("evidence_sessions.MAX_SESSIONS", 1):
            self.assertEqual(self.request("/api/evidence/session", method="POST",
                                           value={"access_token": TOKEN_B})[0], 429)
        self.assertEqual(self.request("/api/evidence/session", cookie=cookie)[0], 200)

    def test_evidence_transport_requires_tls_outside_loopback(self):
        with self.assertRaises(EvidenceError) as error:
            exchange("http://manager.internal", TOKEN_A, "/api/v1/analysts/me")
        self.assertEqual(error.exception.status, 503)

    def test_real_transport_refuses_redirect_before_forwarding_the_credential(self):
        requests = []

        class Upstream(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                requests.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/credential-trap")
                self.send_header("Content-Length", "0")
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(EvidenceError) as error:
                exchange(f"http://127.0.0.1:{server.server_address[1]}", TOKEN_A,
                         "/api/v1/analysts/me")
            self.assertEqual(error.exception.status, 502)
            self.assertEqual(requests, ["/api/v1/analysts/me"])
        finally:
            server.shutdown()
            thread.join(5)
            server.server_close()
