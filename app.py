"""Panopticon Console - minimal V1 alert viewer.

Reads the Alert NDJSON file that ``panopticon-detection-engine`` writes via its
``--output-file`` option (one JSON object per line, the shape of
``src/alerting/alert.py::Alert.to_dict()`` in that repo) and serves it as a
single auto-polling web page.

Boundary: the detection engine owns detection, ``Alert`` creation and alert
serialization. This console only reads the file the engine already wrote and
presents it. It never imports the detection engine and never calls it over the
network - the integration surface is the NDJSON file on disk, nothing else.

Not in V1, by design: authentication, database, message queue, WebSockets, TLS.
The server binds ``127.0.0.1`` by default; it is a local development / demo tool.
"""
from __future__ import annotations

import argparse
import json
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


def make_handler(alerts_file: Path) -> type[BaseHTTPRequestHandler]:
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
            else:
                self._not_found()

        def do_HEAD(self):  # noqa: N802
            self.do_GET()

    return ConsoleHandler


def build_server(alerts_file: Path, host: str, port: int) -> ThreadingHTTPServer:
    """Construct (but do not start) the console HTTP server."""
    return ThreadingHTTPServer((host, port), make_handler(alerts_file))


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
    args = parser.parse_args(argv)

    alerts_file = Path(args.alerts_file).expanduser()
    server = build_server(alerts_file, args.host, args.port)
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
