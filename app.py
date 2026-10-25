"""Panopticon Console - alert, incident and response viewer.

Two alert sources, chosen at start-up:

* **Manager mode** (``--manager-url`` plus the ``PANOPTICON_MANAGER_TOKEN``
  environment variable): this server proxies Manager's analyst API
  (``/api/v1/alerts``, ``/api/v1/incidents``, ``/api/v1/status``,
  ``/api/v1/response-actions``) under same-origin ``/api/...`` routes. The
  analyst bearer token lives only in this server process, is attached to the
  outbound request here, and is never sent to or readable by browser
  JavaScript. The browser never makes a cross-origin request, so the
  restrictive CSP (``connect-src 'self'``) is unchanged.
* **File mode** (no Manager configured): ``/api/alerts`` reads the Alert NDJSON
  file that ``panopticon-detection-engine`` writes via its ``--output-file``
  option (one ``Alert.to_dict()`` object per line). Incident, status and
  response routes answer ``503`` in this mode.

Boundary: the detection engine owns detection and ``Alert`` creation; Manager
owns persistence, incident state and response authorization. This console only
presents what they return and relays an analyst's explicit decisions (approve /
reject a response action, set an incident's status). It never executes a
response.

Not in scope, by design: browser-facing authentication, a database, a message
queue, WebSockets, TLS. The server binds ``127.0.0.1`` by default; it is a local
development / demo tool.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional

STATIC_DIR = Path(__file__).resolve().parent / "static"

# Static assets this console will serve, mapped to their content type. Only these
# exact paths are reachable; there is no directory walking of STATIC_DIR, so a
# request path can never be turned into an arbitrary filesystem location.
_STATIC_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}

# Alert fields the UI relies on. Declared here so a test can pin the contract
# against the detection engine's Alert.to_dict() output; the API itself passes
# every field through untouched.
DISPLAY_FIELDS = (
    "alert_id",
    "rule_id",
    "title",
    "severity",
    "level",
    "timestamp",
    "mitre_tactic",
    "mitre_technique",
    "evidence",
)

JSON_TYPE = "application/json; charset=utf-8"
MAX_BODY_BYTES = 16 * 1024
NOT_CONFIGURED = "Manager connection not configured (--manager-url / PANOPTICON_MANAGER_TOKEN)"

# Identifiers that may appear in a proxied path segment. Anything else is
# refused before a request to Manager is built.
_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
# Pagination cursor / timestamp accepted for ``before``.
_CURSOR_RE = re.compile(r"[A-Za-z0-9:._+-]{1,64}")

SEVERITIES = ("low", "medium", "high", "critical")
DETECTION_SOURCES = ("rule", "stateful", "behavioral", "correlation")
INCIDENT_STATUSES = ("open", "investigating", "resolved", "false_positive")
MAX_NOTE_CHARS = 2000


def _enum(values: tuple[str, ...]) -> Callable[[str], Optional[str]]:
    def check(value: str) -> Optional[str]:
        return value if value in values else None

    return check


def _pattern(regex: re.Pattern) -> Callable[[str], Optional[str]]:
    def check(value: str) -> Optional[str]:
        return value if regex.fullmatch(value) else None

    return check


def _limit(value: str) -> Optional[str]:
    if value.isdigit() and 1 <= int(value) <= 1000:
        return str(int(value))
    return None


# Whitelisted query parameters per proxied list route (CONTRACT.md section 7).
ALERT_QUERY = {
    "severity": _enum(SEVERITIES),
    "source": _enum(DETECTION_SOURCES),
    "incident_id": _pattern(_ID_RE),
    "host_id": _pattern(_ID_RE),
    "rule_id": _pattern(_ID_RE),
    "limit": _limit,
    "before": _pattern(_CURSOR_RE),
}
INCIDENT_QUERY = {
    "status": _enum(INCIDENT_STATUSES),
    "host_id": _pattern(_ID_RE),
    "limit": _limit,
}


class QueryError(ValueError):
    """A browser query string that does not satisfy the route's whitelist."""


def validate_query(raw_query: str, allowed: dict[str, Callable[[str], Optional[str]]]) -> dict[str, str]:
    """Return the validated query as a dict, or raise QueryError.

    Unknown parameters, repeated parameters and values that fail their
    validator are all refused rather than silently dropped, so a typo in a
    filter is visible instead of quietly returning unfiltered data. Empty
    values are treated as "no filter".
    """
    try:
        pairs = urllib.parse.parse_qsl(raw_query, keep_blank_values=True, strict_parsing=bool(raw_query))
    except ValueError as exc:
        raise QueryError("malformed query string") from exc
    result: dict[str, str] = {}
    seen: set[str] = set()
    for key, value in pairs:
        if key not in allowed:
            raise QueryError(f"unsupported query parameter: {key[:40]}")
        if key in seen:
            raise QueryError(f"repeated query parameter: {key}")
        seen.add(key)
        if value == "":
            continue
        checked = allowed[key](value)
        if checked is None:
            raise QueryError(f"invalid value for {key}")
        result[key] = checked
    return result


def read_alerts(alerts_file: Path) -> list[dict[str, Any]]:
    """Parse the engine's Alert NDJSON file into a list of alert dicts.

    A missing file returns ``[]`` (the console is expected to start before the
    first detection run). Blank lines are ignored. A line that is not valid
    JSON, or is valid JSON but not an object, is skipped rather than aborting
    the whole read - so a half-written final line from a concurrent engine run
    never blanks the console.
    """
    try:
        raw = alerts_file.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError):
        return []

    alerts: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            alerts.append(obj)
    return alerts


def filter_file_alerts(alerts: list[dict[str, Any]], query: dict[str, str]) -> list[dict[str, Any]]:
    """Apply the validated /api/alerts filters to file-mode alerts.

    With no query this is the identity, so the file is passed through untouched.
    ``limit`` keeps the last N lines (the newest, in append order).
    """
    if not query:
        return alerts

    def keep(alert: dict[str, Any]) -> bool:
        if "severity" in query and str(alert.get("severity", "")).lower() != query["severity"]:
            return False
        if "source" in query and alert.get("detection_source") != query["source"]:
            return False
        for key in ("incident_id", "host_id", "rule_id"):
            if key in query and alert.get(key) != query[key]:
                return False
        if "before" in query and not str(alert.get("timestamp", "")) < query["before"]:
            return False
        return True

    out = [a for a in alerts if keep(a)]
    if "limit" in query:
        out = out[-int(query["limit"]):]
    return out


# Row-level columns copied onto the alert object when the stored alert lacks
# them. detection_source / incident_id / agent_id are Manager's authoritative
# columns and win whenever they are set.
_ROW_FALLBACK_FIELDS = (
    "alert_id", "rule_id", "level", "severity", "host_id", "event_id", "mitre_tactic", "mitre_technique",
)
_ROW_AUTHORITATIVE_FIELDS = ("detection_source", "incident_id", "agent_id")


def map_alert_row(row: Any) -> Optional[dict[str, Any]]:
    """Turn one Manager ``/api/v1/alerts`` row into the alert object the UI renders."""
    if not isinstance(row, dict):
        return None
    stored = row.get("alert")
    if isinstance(stored, str):
        try:
            stored = json.loads(stored)
        except json.JSONDecodeError:
            stored = None
    alert: dict[str, Any] = dict(stored) if isinstance(stored, dict) else {}
    for key in _ROW_FALLBACK_FIELDS:
        if alert.get(key) is None and row.get(key) is not None:
            alert[key] = row[key]
    for key in _ROW_AUTHORITATIVE_FIELDS:
        if row.get(key) is not None:
            alert[key] = row[key]
        else:
            alert.setdefault(key, None)
    if alert.get("timestamp") is None and row.get("alert_timestamp") is not None:
        alert["timestamp"] = row["alert_timestamp"]
    if row.get("created_at") is not None:
        alert["stored_at"] = row["created_at"]
    return alert


class ManagerProxyError(Exception):
    """Raised when the server-side Manager call itself fails (timeout,
    connection refused, malformed response) -- distinct from Manager
    returning a real HTTP error status, which is instead passed through
    verbatim so the browser sees the same status Manager gave."""


def _send_to_manager(request: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured URL
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ManagerProxyError(str(exc)) from exc


def manager_get(manager_url: str, manager_token: str, path: str, *, timeout: float = 5.0) -> tuple[int, bytes]:
    """Server-side GET of a Manager path (already validated, including any query)."""
    request = urllib.request.Request(
        manager_url.rstrip("/") + path,
        headers={"Authorization": f"Bearer {manager_token}", "Accept": "application/json"},
    )
    return _send_to_manager(request, timeout)


def manager_post(
    manager_url: str, manager_token: str, path: str, payload: bytes, *, timeout: float = 5.0
) -> tuple[int, bytes]:
    """Server-side JSON POST to a Manager path (already validated)."""
    request = urllib.request.Request(
        manager_url.rstrip("/") + path,
        data=payload,
        method="POST",
        headers={"Authorization": f"Bearer {manager_token}", "Content-Type": "application/json"},
    )
    return _send_to_manager(request, timeout)


def fetch_response_actions(manager_url: str, manager_token: str, *, timeout: float = 5.0) -> tuple[int, bytes]:
    """Server-side-only call to Manager's GET /api/v1/response-actions.

    Returns Manager's own (status_code, body) verbatim on any HTTP response (so
    a 401/403 from Manager surfaces as-is); raises ManagerProxyError only when
    the request itself could not be completed at all.
    """
    return manager_get(manager_url, manager_token, "/api/v1/response-actions", timeout=timeout)


def submit_response_action(
    manager_url: str,
    manager_token: str,
    response_id: str,
    operation: str,
    payload: bytes = b"",
    *,
    timeout: float = 5.0,
) -> tuple[int, bytes]:
    """Proxy one analyst decision to Manager without exposing credentials."""
    if operation not in {"authorize", "reject"} or not re.fullmatch(
        r"[A-Za-z0-9._:-]+", response_id
    ):
        raise ValueError("invalid response action route")
    request = urllib.request.Request(
        manager_url.rstrip("/")
        + "/api/v1/response-actions/"
        + urllib.parse.quote(response_id, safe="")
        + "/"
        + operation,
        data=payload if operation == "reject" else None,
        method="POST",
        headers={
            "Authorization": f"Bearer {manager_token}",
            "Content-Type": "application/json",
        },
    )
    return _send_to_manager(request, timeout)


def _error(message: str) -> bytes:
    return json.dumps({"error": message}).encode("utf-8")


def make_handler(
    alerts_file: Optional[Path], manager_url: str | None = None, manager_token: str | None = None
) -> type[BaseHTTPRequestHandler]:
    manager_configured = bool(manager_url and manager_token)

    class ConsoleHandler(BaseHTTPRequestHandler):
        server_version = "PanopticonConsole/1.0"
        sys_version = ""  # don't advertise the Python version in the Server header

        def log_message(self, fmt, *args):  # noqa: A003 - silence default stderr spam
            pass

        # -- helpers -------------------------------------------------------
        def _common_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            # The page renders attacker-influenced strings (process command
            # lines carried in alert evidence). app.js escapes them via
            # textContent; this CSP is the second layer and also blocks any
            # outbound request from the page.
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
                "connect-src 'self'; base-uri 'none'; form-action 'none'",
            )

        def _send_bytes(
            self, status: int, body: bytes, content_type: str, extra_headers: Optional[dict[str, str]] = None
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self._common_headers()
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _send_json_error(self, status: int, message: str) -> None:
            self._send_bytes(status, _error(message), JSON_TYPE)

        def _not_found(self) -> None:
            self._send_bytes(404, b"not found\n", "text/plain; charset=utf-8")

        def _require_manager(self) -> bool:
            if manager_configured:
                return True
            self._send_json_error(503, NOT_CONFIGURED)
            return False

        def _proxy_get(self, path: str) -> None:
            """GET a validated Manager path and pass its status/body through."""
            if not self._require_manager():
                return
            try:
                status, body = manager_get(manager_url, manager_token, path)
            except ManagerProxyError as exc:
                self._send_json_error(502, f"could not reach Manager: {exc}")
                return
            self._send_bytes(status, body, JSON_TYPE)

        def _read_body(self) -> Optional[bytes]:
            """Read a bounded request body; on failure send the error and return None."""
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json_error(400, "invalid Content-Length")
                return None
            if length < 0 or length > MAX_BODY_BYTES:
                self._send_json_error(413, "request body too large")
                return None
            return self.rfile.read(length) if length else b""

        # -- routing ----------------------------------------------------------
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            route, _, raw_query = self.path.partition("?")
            if route in _STATIC_ROUTES:
                filename, content_type = _STATIC_ROUTES[route]
                asset = STATIC_DIR / filename
                try:
                    body = asset.read_bytes()
                except OSError:
                    self._not_found()
                    return
                self._send_bytes(200, body, content_type)
                return
            if route == "/api/alerts":
                self._handle_alerts(raw_query)
                return
            if route == "/api/response-actions":
                self._handle_response_actions()
                return
            if route == "/api/status":
                self._proxy_get("/api/v1/status")
                return
            if route == "/api/incidents":
                try:
                    query = validate_query(raw_query, INCIDENT_QUERY)
                except QueryError as exc:
                    self._send_json_error(400, str(exc))
                    return
                suffix = "?" + urllib.parse.urlencode(query) if query else ""
                self._proxy_get("/api/v1/incidents" + suffix)
                return
            match = re.fullmatch(r"/api/incidents/([^/]+)", route)
            if match is not None:
                if raw_query or not _ID_RE.fullmatch(match.group(1)):
                    self._send_json_error(400, "invalid incident id")
                    return
                self._proxy_get("/api/v1/incidents/" + match.group(1))
                return
            self._not_found()

        def _handle_alerts(self, raw_query: str) -> None:
            try:
                query = validate_query(raw_query, ALERT_QUERY)
            except QueryError as exc:
                self._send_json_error(400, str(exc))
                return
            if not manager_configured:
                alerts = read_alerts(alerts_file) if alerts_file is not None else []
                body = json.dumps(filter_file_alerts(alerts, query)).encode("utf-8")
                self._send_bytes(200, body, JSON_TYPE, {"X-Panopticon-Alert-Source": "file"})
                return
            suffix = "?" + urllib.parse.urlencode(query) if query else ""
            try:
                status, body = manager_get(manager_url, manager_token, "/api/v1/alerts" + suffix)
            except ManagerProxyError as exc:
                self._send_json_error(502, f"could not reach Manager: {exc}")
                return
            headers = {"X-Panopticon-Alert-Source": "manager"}
            if status != 200:
                self._send_bytes(status, body, JSON_TYPE, headers)
                return
            try:
                payload = json.loads(body)
                rows = payload["alerts"]
                if not isinstance(rows, list):
                    raise TypeError("alerts is not a list")
            except (ValueError, KeyError, TypeError):
                self._send_json_error(502, "Manager returned an unexpected alerts payload")
                return
            alerts = [a for a in (map_alert_row(r) for r in rows) if a is not None]
            next_before = payload.get("next_before")
            if isinstance(next_before, str) and _CURSOR_RE.fullmatch(next_before):
                headers["X-Panopticon-Next-Before"] = next_before
            self._send_bytes(200, json.dumps(alerts).encode("utf-8"), JSON_TYPE, headers)

        def _handle_response_actions(self) -> None:
            if not self._require_manager():
                return
            try:
                status, body = fetch_response_actions(manager_url, manager_token)
            except ManagerProxyError as exc:
                self._send_json_error(502, f"could not reach Manager: {exc}")
                return
            self._send_bytes(status, body, JSON_TYPE)

        def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
            match = re.fullmatch(r"/api/response-actions/([^/]+)/(authorize|reject)", self.path)
            if match is not None:
                self._handle_response_action_decision(match.group(1), match.group(2))
                return
            match = re.fullmatch(r"/api/incidents/([^/]+)/status", self.path)
            if match is not None:
                self._handle_incident_status(match.group(1))
                return
            self._not_found()

        def _handle_incident_status(self, incident_id: str) -> None:
            if not _ID_RE.fullmatch(incident_id):
                self._send_json_error(400, "invalid incident id")
                return
            if not self._require_manager():
                return
            payload = self._read_body()
            if payload is None:
                return
            try:
                body_obj = json.loads(payload or b"null")
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json_error(400, "request body must be JSON")
                return
            if not isinstance(body_obj, dict) or set(body_obj) - {"status", "note"}:
                self._send_json_error(400, "body must be an object with only status and note")
                return
            status_value = body_obj.get("status")
            if status_value not in INCIDENT_STATUSES:
                self._send_json_error(400, "status must be one of: " + ", ".join(INCIDENT_STATUSES))
                return
            note = body_obj.get("note")
            if note is not None and not isinstance(note, str):
                self._send_json_error(400, "note must be a string")
                return
            if note is not None and len(note) > MAX_NOTE_CHARS:
                self._send_json_error(400, f"note must be at most {MAX_NOTE_CHARS} characters")
                return
            forward: dict[str, str] = {"status": status_value}
            if note and note.strip():
                forward["note"] = note.strip()
            try:
                status, body = manager_post(
                    manager_url,
                    manager_token,
                    "/api/v1/incidents/" + incident_id + "/status",
                    json.dumps(forward).encode("utf-8"),
                )
            except ManagerProxyError as exc:
                self._send_json_error(502, f"could not reach Manager: {exc}")
                return
            self._send_bytes(status, body, JSON_TYPE)

        def _handle_response_action_decision(self, response_id: str, operation: str) -> None:
            if not self._require_manager():
                return
            payload = self._read_body()
            if payload is None:
                return
            if operation == "authorize" and payload:
                self._send_json_error(400, "authorize does not accept a request body")
                return
            if operation == "reject":
                try:
                    body_obj = json.loads(payload or b"{}")
                except json.JSONDecodeError:
                    self._send_json_error(400, "request body must be JSON")
                    return
                if not isinstance(body_obj, dict) or not isinstance(body_obj.get("reason"), str) or not body_obj["reason"].strip():
                    self._send_json_error(400, "reject requires a non-empty reason")
                    return
                payload = json.dumps({"reason": body_obj["reason"]}).encode("utf-8")
            try:
                status, body = submit_response_action(manager_url, manager_token, response_id, operation, payload)
            except (ManagerProxyError, ValueError) as exc:
                self._send_json_error(502, f"could not reach Manager: {exc}")
                return
            self._send_bytes(status, body, JSON_TYPE)

        def do_HEAD(self):  # noqa: N802
            self.do_GET()

    return ConsoleHandler


def build_server(
    alerts_file: Optional[Path],
    host: str,
    port: int,
    manager_url: str | None = None,
    manager_token: str | None = None,
) -> ThreadingHTTPServer:
    """Construct (but do not start) the console HTTP server."""
    return ThreadingHTTPServer((host, port), make_handler(alerts_file, manager_url, manager_token))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Panopticon Console - alert, incident and response viewer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--alerts-file",
        default=None,
        help="Path to the detection engine's Alert NDJSON output file (the path passed to its "
        "--output-file). Used when no Manager is configured. May not exist yet.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address. Left at localhost for a local demo tool; only widen deliberately.",
    )
    parser.add_argument("--port", type=int, default=8787, help="Bind port")
    parser.add_argument(
        "--manager-url",
        default=None,
        help="Optional Manager base URL (e.g. http://127.0.0.1:8000). Together with the "
        "PANOPTICON_MANAGER_TOKEN environment variable, alerts, incidents, status and response "
        "actions come from Manager through same-origin Console routes; the browser never sees the token.",
    )
    args = parser.parse_args(argv)

    manager_token = os.environ.get("PANOPTICON_MANAGER_TOKEN")
    if not args.alerts_file and not (args.manager_url and manager_token):
        parser.error("give --alerts-file, or --manager-url with PANOPTICON_MANAGER_TOKEN set")
    alerts_file = Path(args.alerts_file).expanduser() if args.alerts_file else None
    server = build_server(alerts_file, args.host, args.port, args.manager_url, manager_token)
    if args.manager_url and manager_token:
        print(f"[*] Alert source: Manager {args.manager_url} (token held server-side)")
        if alerts_file is not None:
            print("[*] --alerts-file ignored while Manager is configured")
    else:
        if args.manager_url:
            print("[*] --manager-url set but PANOPTICON_MANAGER_TOKEN is not -- Manager views disabled")
        print(f"[*] Alert source: file {alerts_file}")
        if alerts_file is not None and not alerts_file.exists():
            print("[*] (alerts file does not exist yet - it will appear once the engine runs)")
    print(f"[*] Serving on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
