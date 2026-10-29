"""Per-browser evidence identity. Manager remains the authorization authority."""

import hmac
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import CookieError, SimpleCookie

COOKIE = "panopticon_evidence_session"
TTL = 3600
MAX_SESSIONS = 256
MAX_REPLY = 2 * 1024 * 1024
ID = r"[A-Za-z0-9._:-]{1,128}"
ARTIFACT = r"art_[0-9a-f]{64}"


class EvidenceError(Exception):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def exchange(manager_url, token, path):
    """Bounded authenticated GET with redirects refused, even to another trusted host."""
    parsed = urllib.parse.urlsplit(manager_url)
    if (parsed.scheme != "https" and not
            (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"})):
        raise EvidenceError(503, "Evidence identity requires HTTPS Manager or a loopback lab Manager")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise EvidenceError(503, "Invalid evidence Manager address")
    request = urllib.request.Request(manager_url.rstrip("/") + path,
                                    headers={"Authorization": "Bearer " + token,
                                             "Accept": "application/json"})
    try:
        response = urllib.request.build_opener(NoRedirect()).open(request, timeout=5)
    except urllib.error.HTTPError as exc:
        response = exc
    except (OSError, ValueError) as exc:
        raise EvidenceError(502, "Could not reach evidence Manager") from exc
    with response:
        data = response.read(MAX_REPLY + 1)
        if len(data) > MAX_REPLY:
            raise EvidenceError(502, "Evidence Manager response exceeds size limit")
        if 300 <= response.code < 400:
            raise EvidenceError(502, "Evidence Manager redirect refused")
        return response.code, data


class EvidenceSessions:
    def __init__(self, manager_url, public_origin=None):
        self.manager_url = manager_url
        self.public_origin = public_origin
        self.sessions = {}
        self.lock = threading.Lock()

    def origin(self, handler, *, write=False):
        host, port = handler.server.server_address[:2]
        if self.public_origin:
            parsed = urllib.parse.urlsplit(self.public_origin)
            if (parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password
                    or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
                raise EvidenceError(503, "Public evidence origin must be an HTTPS origin")
            origins = {"https://" + parsed.netloc}
        elif host in {"127.0.0.1", "::1", "localhost"}:
            origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}", f"http://[::1]:{port}"}
        else:
            raise EvidenceError(503, "Configure an HTTPS public origin for browser evidence access")
        authority = handler.headers.get("Host", "")
        expected = next((o for o in origins if urllib.parse.urlsplit(o).netloc == authority), None)
        if expected is None:
            raise EvidenceError(403, "Evidence request host is not allowed")
        origin = handler.headers.get("Origin")
        if (write and origin != expected) or (origin is not None and origin != expected):
            raise EvidenceError(403, "Evidence request must come from this Console origin")
        if handler.headers.get("Sec-Fetch-Site") == "cross-site":
            raise EvidenceError(403, "Cross-site evidence request refused")
        return expected

    @staticmethod
    def cookie_id(handler):
        raw = handler.headers.get("Cookie", "")
        if len(raw) > 8192 or sum(p.strip().startswith(COOKIE + "=") for p in raw.split(";")) != 1:
            return None
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except CookieError:
            return None
        item = jar.get(COOKIE)
        return item.value if item and re.fullmatch(r"[A-Za-z0-9_-]{43}", item.value) else None

    @staticmethod
    def cookie(value, origin, *, clear=False):
        return (f"{COOKIE}={value}; Path=/api/evidence; HttpOnly; SameSite=Strict; "
                f"Max-Age={0 if clear else TTL}" + ("; Secure" if origin.startswith("https:") else ""))

    def live(self, handler):
        self.origin(handler)
        sid = self.cookie_id(handler)
        with self.lock:
            entry = self.sessions.get(sid)
            if entry is None or entry["expires"] <= time.monotonic():
                self.sessions.pop(sid, None)
                raise EvidenceError(401, "Sign in with your individual evidence identity")
            return sid, entry.copy()

    def identity(self, token):
        if not self.manager_url:
            raise EvidenceError(503, "Evidence Manager is not configured")
        status, body = exchange(self.manager_url, token, "/api/v1/analysts/me")
        if status != 200:
            raise EvidenceError(status if status in {401, 403} else 502, "Evidence identity refused")
        try:
            value = json.loads(body)
            if (not isinstance(value, dict) or not isinstance(value.get("analyst_id"), str)
                    or not 1 <= len(value["analyst_id"]) <= 128
                    or not isinstance(value.get("role"), str)
                    or not isinstance(value.get("permissions"), list)
                    or "artifact:read" not in value["permissions"]):
                raise ValueError("not an artifact reader")
            return {"analyst_id": value["analyst_id"], "role": value["role"],
                    "permissions": ["artifact:read"], "access_policy_version": 2}
        except (ValueError, TypeError) as exc:
            raise EvidenceError(403, "Identity is not eligible to read artifacts") from exc

    def handle_get(self, handler, route, query):
        if not route.startswith("/api/evidence/"):
            return False
        try:
            sid, entry = self.live(handler)
            if route == "/api/evidence/session" and not query:
                identity = self.identity(entry["token"])
                handler._send_bytes(200, json.dumps({"signed_in": True, **identity}).encode(),
                                    "application/json")
                return True
            path = None
            match = re.fullmatch(r"/api/evidence/cases/(" + ID + r")", route)
            if match and not query:
                path = "/api/v1/response-actions/" + match.group(1) + "/export"
            match = re.fullmatch(r"/api/evidence/artifacts/(" + ARTIFACT + r")/(content|custody|context|chunks)", route)
            if match:
                operation = match.group(2)
                allowed = {"after", "limit"} if operation == "custody" else (
                    {"offset", "manifest_sha256"} if operation == "chunks" else set())
                pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=bool(query))
                if len(pairs) != len(dict(pairs)) or any(k not in allowed for k, _ in pairs):
                    raise EvidenceError(400, "Invalid evidence query")
                for key, value in pairs:
                    if key == "manifest_sha256":
                        valid = re.fullmatch(r"[0-9a-f]{64}", value)
                    else:
                        valid = re.fullmatch(r"[0-9]{1,19}", value)
                    if not valid:
                        raise EvidenceError(400, "Invalid evidence query value")
                path = "/api/v1/response-artifacts/" + match.group(1) + "/" + operation
                if pairs:
                    path += "?" + urllib.parse.urlencode(pairs)
            if path is None:
                raise EvidenceError(404, "Evidence route unavailable")
            status, body = exchange(self.manager_url, entry["token"], path)
            with self.lock:
                if sid not in self.sessions or self.sessions[sid]["expires"] <= time.monotonic():
                    raise EvidenceError(401, "Evidence session ended")
                if status == 401:
                    self.sessions.pop(sid, None)
            handler._send_bytes(status, body, "application/json")
        except (ValueError, EvidenceError) as exc:
            handler._send_json_error(getattr(exc, "status", 400), str(exc))
        return True

    def handle_post(self, handler):
        if not handler.path.startswith("/api/evidence/"):
            return False
        try:
            # Consume the bounded frame before an early refusal. Closing a Windows
            # socket with unread POST bytes can reset it before the 403 reaches
            # the browser. A deadline prevents a slow sender holding this worker.
            handler.connection.settimeout(5)
            body = handler._read_body()
            if body is None:
                return True
            origin = self.origin(handler, write=True)
            if handler.path == "/api/evidence/session/logout":
                with self.lock:
                    self.sessions.pop(self.cookie_id(handler), None)
                handler._send_bytes(200, b'{"signed_in":false}', "application/json",
                                    {"Set-Cookie": self.cookie("", origin, clear=True)})
                return True
            if handler.path != "/api/evidence/session":
                raise EvidenceError(404, "Evidence route unavailable")
            if handler.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise EvidenceError(415, "Evidence sign-in requires application/json")
            value = json.loads(body)
            if (not isinstance(value, dict) or set(value) != {"access_token"}
                    or not isinstance(value["access_token"], str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{20,512}", value["access_token"])):
                raise EvidenceError(400, "Provide an individual analyst access token")
            token = value["access_token"]
            identity = self.identity(token)
            with self.lock:
                now = time.monotonic()
                for key in [key for key, entry in self.sessions.items() if entry["expires"] <= now]:
                    del self.sessions[key]
                old = self.cookie_id(handler)
                current = self.sessions.get(old)
                if current and hmac.compare_digest(current["token"], token):
                    sid = old
                else:
                    self.sessions.pop(old, None)
                    if len(self.sessions) >= MAX_SESSIONS:
                        raise EvidenceError(429, "Evidence session capacity reached")
                    sid = secrets.token_urlsafe(32)
                self.sessions[sid] = {"token": token, "expires": now + TTL}
            handler._send_bytes(200, json.dumps({"signed_in": True, **identity}).encode(),
                                "application/json", {"Set-Cookie": self.cookie(sid, origin)})
        except (ValueError, EvidenceError) as exc:
            handler._send_json_error(getattr(exc, "status", 400), str(exc))
        except TimeoutError:
            handler._send_json_error(408, "Evidence request body timed out")
        return True
