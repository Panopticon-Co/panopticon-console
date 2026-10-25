"""Panopticon Console - minimal V1 alert viewer.

Reads the Alert NDJSON file that ``panopticon-detection-engine`` writes via its
``--output-file`` option (one JSON object per line, the shape of
``src/alerting/alert.py::Alert.to_dict()`` in that repo) and serves it as a
single auto-polling web page.

Boundary: the detection engine owns detection, ``Alert`` creation and alert
serialization. This console only reads the file the engine already wrote and
presents it. It never imports the detection engine and never calls it over the
network - the integration surface is the NDJSON file on disk, nothing else.

Optionally, if ``--manager-url`` and a ``PANOPTICON_MANAGER_TOKEN`` analyst
bearer token are configured, this server proxies the Manager response-action
queue and its analyst decisions. The token lives only in this server process,
is attached to outbound requests, and is never sent to browser JavaScript. The
browser uses same-origin routes, so the existing restrictive CSP remains in
place.

Not in V1, by design: authentication, database, message queue, WebSockets, TLS.
The server binds ``127.0.0.1`` by default; it is a local development / demo tool.
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
from typing import Any

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


class ManagerProxyError(Exception):
    """Raised when the server-side Manager call itself fails (timeout,
    connection refused, malformed response) -- distinct from Manager
    returning a real HTTP error status, which is instead passed through
    verbatim so the browser sees the same status Manager gave."""


def fetch_response_actions(manager_url: str, manager_token: str, *, timeout: float = 5.0) -> tuple[int, bytes]:
    """Server-side-only call to Manager's GET /api/v1/response-actions.

    The analyst bearer token is attached here and never leaves this process;
    the browser only ever talks to this console, same-origin. Returns
    Manager's own (status_code, body) verbatim on any HTTP response (so a
    401/403 from Manager surfaces as-is); raises ManagerProxyError only when
    the request itself could not be completed at all.
    """
    request = urllib.request.Request(
        manager_url.rstrip("/") + "/api/v1/response-actions",
        headers={"Authorization": f"Bearer {manager_token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured URL
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ManagerProxyError(str(exc)) from exc


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
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ManagerProxyError(str(exc)) from exc


def make_handler(
    alerts_file: Path, manager_url: str | None = None, manager_token: str | None = None
) -> type[BaseHTTPRequestHandler]:
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

        def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self._common_headers()
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _not_found(self) -> None:
            self._send_bytes(404, b"not found\n", "text/plain; charset=utf-8")

        # -- routing ----------------------------------------------------------
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            route = self.path.split("?", 1)[0]
            if route in _STATIC_ROUTES:
                filename, content_type = _STATIC_ROUTES[route]
                asset = STATIC_DIR / filename
                try:
                    body = asset.read_bytes()
                except OSError:
                    self._not_found()
                    return
                self._send_bytes(200, body, content_type)
            elif route == "/api/alerts":
                body = json.dumps(read_alerts(alerts_file)).encode("utf-8")
                self._send_bytes(200, body, "application/json; charset=utf-8")
            elif route == "/api/response-actions":
                self._handle_response_actions()
            else:
                self._not_found()

        def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
            match = re.fullmatch(r"/api/response-actions/([^/]+)/(authorize|reject)", self.path)
            if match is None:
                self._not_found()
                return
            self._handle_response_action_decision(match.group(1), match.group(2))

        def _handle_response_actions(self) -> None:
            if not manager_url or not manager_token:
                body = json.dumps(
                    {"error": "Manager connection not configured (--manager-url / PANOPTICON_MANAGER_TOKEN)"}
                ).encode("utf-8")
                self._send_bytes(503, body, "application/json; charset=utf-8")
                return
            try:
                status, body = fetch_response_actions(manager_url, manager_token)
            except ManagerProxyError as exc:
                body = json.dumps({"error": f"could not reach Manager: {exc}"}).encode("utf-8")
                self._send_bytes(502, body, "application/json; charset=utf-8")
                return
            self._send_bytes(status, body, "application/json; charset=utf-8")

        def _handle_response_action_decision(self, response_id: str, operation: str) -> None:
            if not manager_url or not manager_token:
                body = json.dumps(
                    {"error": "Manager connection not configured (--manager-url / PANOPTICON_MANAGER_TOKEN)"}
                ).encode("utf-8")
                self._send_bytes(503, body, "application/json; charset=utf-8")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_bytes(400, b'{"error":"invalid Content-Length"}', "application/json; charset=utf-8")
                return
            if length < 0 or length > 16 * 1024:
                self._send_bytes(413, b'{"error":"request body too large"}', "application/json; charset=utf-8")
                return
            payload = self.rfile.read(length) if length else b""
            if operation == "authorize" and payload:
                self._send_bytes(400, b'{"error":"authorize does not accept a request body"}', "application/json; charset=utf-8")
                return
            if operation == "reject":
                try:
                    body_obj = json.loads(payload or b"{}")
                except json.JSONDecodeError:
                    self._send_bytes(400, b'{"error":"request body must be JSON"}', "application/json; charset=utf-8")
                    return
                if not isinstance(body_obj, dict) or not isinstance(body_obj.get("reason"), str) or not body_obj["reason"].strip():
                    self._send_bytes(400, b'{"error":"reject requires a non-empty reason"}', "application/json; charset=utf-8")
                    return
                payload = json.dumps({"reason": body_obj["reason"]}).encode("utf-8")
            try:
                status, body = submit_response_action(manager_url, manager_token, response_id, operation, payload)
            except (ManagerProxyError, ValueError) as exc:
                body = json.dumps({"error": f"could not reach Manager: {exc}"}).encode("utf-8")
                self._send_bytes(502, body, "application/json; charset=utf-8")
                return
            self._send_bytes(status, body, "application/json; charset=utf-8")

        def do_HEAD(self):  # noqa: N802
            self.do_GET()

    return ConsoleHandler


def build_server(
    alerts_file: Path, host: str, port: int, manager_url: str | None = None, manager_token: str | None = None
) -> ThreadingHTTPServer:
    """Construct (but do not start) the console HTTP server."""
    return ThreadingHTTPServer((host, port), make_handler(alerts_file, manager_url, manager_token))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Panopticon Console - minimal V1 alert viewer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--alerts-file",
        required=True,
        help="Path to the detection engine's Alert NDJSON output file "
        "(the path passed to its --output-file). May not exist yet.",
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
        help="Optional Manager base URL (e.g. https://manager.internal). When set together with "
        "the PANOPTICON_MANAGER_TOKEN environment variable, enables response-action decisions "
        "through same-origin Console routes; the browser never sees the token.",
    )
    args = parser.parse_args(argv)

    alerts_file = Path(args.alerts_file).expanduser()
    manager_token = os.environ.get("PANOPTICON_MANAGER_TOKEN")
    server = build_server(alerts_file, args.host, args.port, args.manager_url, manager_token)
    if args.manager_url and not manager_token:
        print("[*] --manager-url set but PANOPTICON_MANAGER_TOKEN is not -- response-actions panel disabled")
    print(f"[*] Panopticon Console watching: {alerts_file}")
    if not alerts_file.exists():
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
