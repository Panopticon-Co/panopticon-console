# panopticon-console

Minimal V1 alert viewer for Panopticon&Co. Reads the Alert NDJSON file produced by
[`panopticon-detection-engine`](https://github.com/Panopticon-Co/panopticon-detection-engine)'s
`--output-file` option and displays it as a polling web page.

This is deliberately the smallest thing that can show a human "an alert happened": no
authentication, no database, no message queue, no WebSockets. The detection engine owns alert
generation and output; this console only owns presentation, and points at the engine's output
file via a CLI flag rather than a hardcoded path.

## Run

```bash
python app.py --alerts-file /path/to/panopticon-detection-engine/alerts.ndjson
```

Then open `http://127.0.0.1:8787`. Options:

- `--host` — bind host (default `127.0.0.1`)
- `--port` — bind port (default `8787`)

No dependencies beyond the Python standard library.
