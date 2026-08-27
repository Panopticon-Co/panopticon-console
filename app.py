"""Panopticon Console — minimal V1 alert viewer.

Reads the Alert NDJSON file produced by panopticon-detection-engine's
`--output-file` option (one JSON object per line, matching
src/alerting/alert.py::Alert.to_dict() in that repo) and serves it as a
single polling web page. No auth, no database, no external services —
the detection engine owns alert generation, this console only presents
what it already wrote to disk.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STATIC_DIR = Path(__file__).resolve().parent / "static"


def read_alerts(alerts_file: Path) -> list[dict]:
    if not alerts_file.exists():
        return []
    alerts = []
    with alerts_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


def make_handler(alerts_file: Path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # keep the console quiet; errors still raise

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._serve_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            elif self.path == "/api/alerts":
                alerts = read_alerts(alerts_file)
                body = json.dumps(alerts).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def _serve_file(self, path: Path, content_type: str):
            if not path.exists():
                self.send_response(404)
                self.end_headers()
                return
            body = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main():
    parser = argparse.ArgumentParser(description="Panopticon Console — minimal V1 alert viewer")
    parser.add_argument(
        "--alerts-file",
        type=str,
        required=True,
        help="Path to the detection engine's Alert NDJSON output file (its --output-file)",
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8787, help="Bind port (default 8787)")
    args = parser.parse_args()

    alerts_file = Path(args.alerts_file)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(alerts_file))
    print(f"[*] Panopticon Console watching: {alerts_file}")
    print(f"[*] Serving on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
