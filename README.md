# panopticon-console

Minimal V1 alert viewer for the **Panopticon&Co** EDR platform.

The console reads the Alert NDJSON file that
[`panopticon-detection-engine`](https://github.com/Panopticon-Co/panopticon-detection-engine)
writes via its `--output-file` option and serves it as a single auto-polling
web page, so a human can see that a detection fired.

## Scope (deliberately small)

| Owns | Does **not** own |
|---|---|
| Reading the engine's alert NDJSON | Detection logic |
| Presenting alerts to a human | `Alert` creation / serialization |
| Polling for new alerts | Telemetry collection |
| | Remediation / response |

The integration boundary is **the alert file on disk**. The console does not
import the detection engine and makes no network call to it. No database, no
message queue, no WebSockets, no authentication — none of that is a V1
requirement. It is a local development / demo tool and binds `127.0.0.1` by
default.

## Requirements

Python 3.9+ standard library only. No `pip install`.

## Run

```bash
python app.py --alerts-file /path/to/panopticon-detection-engine/alerts.ndjson
```

Then open <http://127.0.0.1:8787>.

| Flag | Default | Meaning |
|---|---|---|
| `--alerts-file` | *(required)* | Path to the engine's `--output-file`. May not exist yet — the console starts anyway and picks it up once it appears. |
| `--host` | `127.0.0.1` | Bind address. Only widen deliberately. |
| `--port` | `8787` | Bind port. |

### HTTP surface

| Route | Response |
|---|---|
| `GET /` | The viewer page (`static/index.html`). |
| `GET /app.js` | The client script. |
| `GET /api/alerts` | `application/json` array of alert objects, in file order. Missing / unreadable file → `[]`. Malformed lines are skipped. |

The page polls `/api/alerts` every 3 seconds and shows timestamp, rule ID,
severity + Wazuh level, MITRE tactic/technique, title, and the evidence
key/value pairs. Rows whose `alert_id` was not present on the previous poll
flash briefly.

### Live runs (detection-engine V2)

The detection engine's V2 `--reliable` pipeline appends each alert to its
`--output-file` the moment it is generated (`IncrementalAlertWriter`), instead
of one dump at stream end. No console change is required for this — `read_alerts`
already returns the file as it has grown so far and skips a half-written final
line, so every poll picks up new alerts while the engine is still running. Point
`--alerts-file` at the engine's `--output-file` and leave both running.

`static/app.js` de-duplicates by `alert_id` before rendering, so if the engine
ever re-appends an already-delivered alert (e.g. a restart racing its own
delivery ack) the browser shows it once. The `/api/alerts` API itself is
unchanged: it passes every line through untouched.

## Security notes

- Alert evidence carries attacker-influenced strings (process command lines).
  The client writes every value to the DOM via `textContent` — never
  `innerHTML` string-building — and the server sends
  `Content-Security-Policy: default-src 'none'; script-src 'self'; …` plus
  `X-Content-Type-Options: nosniff` as a second layer.
- Only the three routes above resolve. There is no filesystem path mapping, so
  request paths cannot be turned into arbitrary file reads.
- Default bind is localhost. There is no auth because there is nothing
  multi-user about a local demo; do not add one to paper over exposing it.

## Test

```bash
python -m unittest discover -s tests
```

Unit tests (`tests/test_read_alerts.py`) cover NDJSON parsing: missing/empty
file, blank lines, malformed and truncated lines, non-object JSON, ordering,
and the display-field contract with the engine's `Alert.to_dict()`.
HTTP tests (`tests/test_http.py`) start a real server on an ephemeral port and
check the static routes, security headers, 404s, `HEAD`, the `/api/alerts`
payload and field set, live reflection of file updates, injection-payload
pass-through, and that two servers serve their own distinct `--alerts-file`.

## The full V1 demonstration

See [`docs/PANOPTICON_V1.md`](docs/PANOPTICON_V1.md) for the end-to-end
walkthrough: real Windows process creation → Officer (ETW/Sysmon) →
Schema 0.2 → detection engine → `DET-PROC-011` → `alerts.ndjson` → this console.
