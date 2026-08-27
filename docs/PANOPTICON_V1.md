# Panopticon&Co — V1 vertical slice

This document makes the V1 workflow reproducible on a real Windows machine
without any prior context.

```
real process creation
   -> Officer agent  (ETW + Sysmon)
   -> Panopticon Schema 0.2 NDJSON
   -> panopticon-detection-engine
   -> rule DET-PROC-011
   -> Alert  ->  alerts.ndjson
   -> panopticon-console
   -> browser (human-visible)
```

---

## 1. The repositories

| Repo | Internal name | Language | Responsibility |
|---|---|---|---|
| [`panopticon-agent`](https://github.com/Panopticon-Co/panopticon-agent) | **Officer** | C++20 / CMake / vcpkg | Collect Windows **process-creation** telemetry from ETW (`Microsoft-Windows-Kernel-Process`) and Sysmon (`EvtSubscribe`), normalize it, emit **Panopticon Schema 0.2** NDJSON on stdout. Nothing else — no detection logic. |
| [`panopticon-detection-engine`](https://github.com/Panopticon-Co/panopticon-detection-engine) | **eyedetect** | Python (stdlib + `pyyaml`/`pydantic`) | Ingest Schema 0.2 events, evaluate them against YAML rules, correlate, produce `Alert` objects, serialize them to NDJSON. Owns detection **and** alert creation/serialization. CLI batch/stream tool — no server, no DB. |
| [`panopticon-console`](https://github.com/Panopticon-Co/panopticon-console) | *(console)* | Python stdlib | Read the engine's alert NDJSON file and present it to a human as a polling web page. Presentation only. |

The boundaries are one-way and file/artifact based:

```
panopticon-agent --build--> officer-agent.exe --Schema 0.2 NDJSON--> detection-engine --alerts.ndjson--> console
```

No repo imports another's source. The console never imports the engine.

## 2. How Officer fits in

Officer is the only component that touches Windows. It runs elevated, opens an
ETW session named `Panopticon-Officer-Process` and a Sysmon event
subscription, and for every process-creation event writes **one NDJSON line**
of Panopticon Schema 0.2 to stdout. Warnings/errors go to stderr. It runs
until `Ctrl+C`.

Authoritative schema: `panopticon-agent/schema/event.schema.json`
(JSON Schema draft 2020-12, `additionalProperties: false`).

## 3. How the detection engine consumes Officer events

`src/ingestion/officer_adapter.py` (`OfficerIngestionAdapter`,
`SCHEMA_VERSION = "0.2"`) normalizes each Officer JSON object
(`event`/`process`/`parent`/`user`/`host`/`source`/`agent` blocks) into the
engine's internal event dict. `src/ingestion/live_stream.py`
(`LiveTelemetryStream`) provides two ways in:

- **File** — `--officer-ndjson <file>`: read a captured Schema 0.2 NDJSON file
  line by line (schema auto-detected).
- **Subprocess** — `--officer --officer-bin <path> [--officer-source all|etw|sysmon]`:
  spawn `officer-agent.exe` and read its stdout pipe live. The engine owns that
  subprocess for the run.

Field-level contract: `panopticon-detection-engine/docs/OFFICER_INTEGRATION.md`.

## 4. How alerts are produced

For each event the engine runs the rule evaluator. **`DET-PROC-011`**
(`rules/process/DET-PROC-011_obfuscated_high_entropy_script.yaml`) matches when:

- `process.name` ∈ {`powershell.exe`, `cmd.exe`, `mshta.exe`, `wscript.exe`,
  `cscript.exe`, `pwsh.exe`}, **and**
- `process.command_line` Shannon entropy `> 4.3`
  (computed by the engine's `ShannonEntropyCalculator`).

A match becomes an `Alert` (`src/alerting/alert.py::Alert.from_detection_result`):
`level 11`, `severity high`, `confidence 0.90`, MITRE `T1027`
(Defense Evasion — *Obfuscated Files or Information*). With `--output-file`,
each alert is appended to that file as one JSON line
(`AlertFormatter.to_ndjson` == `json.dumps(alert.to_dict())`).

Alert fields the console uses: `alert_id`, `rule_id`, `title`, `severity`,
`level`, `timestamp`, `mitre_tactic`, `mitre_technique`, `evidence`.

## 5. How the console consumes alerts

`panopticon-console/app.py --alerts-file <path>` serves:

- `GET /` + `GET /app.js` — the viewer.
- `GET /api/alerts` — the file parsed to a JSON array (missing/unreadable → `[]`,
  malformed lines skipped).

The page polls `/api/alerts` every 3 s and renders a row per alert. The
alert-file path is **configuration** (`--alerts-file`), never hardcoded.

## 6. Running the detection engine

```powershell
cd panopticon-detection-engine
py -m pip install -r requirements.txt        # first time only

# Batch over a captured Officer NDJSON file:
py src\main.py --rules rules --officer-ndjson <capture.ndjson> `
   --output-file alerts.ndjson --no-auto-remediate

# Or let the engine own a live Officer subprocess (elevated shell required):
py src\main.py --rules rules --officer --officer-bin <path\to\officer-agent.exe> `
   --officer-source all --output-file alerts.ndjson --no-auto-remediate
```

`--no-auto-remediate` keeps the run non-destructive. (Remediation in this repo
is simulated bookkeeping regardless, per its `CLAUDE.md`; the flag simply
suppresses even that.)

## 7. Running the console

```powershell
cd panopticon-console
py app.py --alerts-file ..\panopticon-detection-engine\alerts.ndjson
# open http://127.0.0.1:8787
```

No dependencies. Start it before or after the engine — an absent file just
shows "No alerts yet" until it appears.

## 8. The V1 demonstration

### Prerequisites

- Windows 10/11, **Administrator PowerShell** (ETW + Sysmon need elevation).
- **Sysmon** installed and running (`Get-Service Sysmon*`). If it is not, the
  Sysmon collector will not start; ETW alone still satisfies this demo — use
  `--officer-source etw` (engine) or `--source etw` (agent).
- A built agent: `panopticon-agent/build-officer-x64/officer-agent.exe`
  (see `panopticon-agent/CLAUDE.md` for the CMake/vcpkg build).
- Python 3.9+ for the engine and console.

### The verified DET-PROC-011 trigger (benign)

```powershell
powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAFAAYQBuAG8AcAB0AGkAYwBvAG4ALQBWADEALQBEAGUAbQBvAA==
```

The `-EncodedCommand` payload decodes (UTF-16LE base64) to exactly:

```
Write-Host Panopticon-V1-Demo
```

It prints one line and exits. Its command line scores Shannon entropy ≈ 4.66,
above the `DET-PROC-011` threshold of 4.3, so the rule fires on a completely
harmless action.

### Procedure A — engine owns the Officer subprocess (recommended)

Matches the intended V1 architecture; exactly one Officer instance.

1. **Window 1 (any shell)** — start the console:
   ```powershell
   cd panopticon-console
   py app.py --alerts-file ..\panopticon-detection-engine\alerts.ndjson
   ```
   Open <http://127.0.0.1:8787> — it shows "No alerts yet".

2. **Window 2 (Administrator PowerShell)** — start the engine; it spawns Officer:
   ```powershell
   cd panopticon-detection-engine
   Remove-Item alerts.ndjson -ErrorAction SilentlyContinue
   py src\main.py --rules rules --officer `
      --officer-bin ..\panopticon-agent\build-officer-x64\officer-agent.exe `
      --officer-source all --output-file alerts.ndjson --no-auto-remediate
   ```
   Wait for `[officer-agent] Started etw collector.` /
   `[officer-agent] Started sysmon collector.`

3. **Window 3 (Administrator PowerShell)** — fire the trigger once:
   ```powershell
   powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAFAAYQBuAG8AcAB0AGkAYwBvAG4ALQBWADEALQBEAGUAbQBvAA==
   ```

4. Back in **Window 2**, the engine prints the `DET-PROC-011` alert within a
   couple of seconds. Press **`Ctrl+C`** — the engine stops Officer, writes
   `alerts.ndjson`, and exits.

5. Within 3 s the console poll picks up `alerts.ndjson` and the browser shows
   the alert row.

### Procedure B — capture then batch (fully scriptable)

Still one Officer instance, and it never runs concurrently with the engine.

1. **Administrator PowerShell** — capture live telemetry:
   ```powershell
   cd panopticon-agent
   .\build-officer-x64\officer-agent.exe --source all > capture.ndjson
   ```
   In another Administrator window, fire the trigger (above). Give it a few
   seconds, then `Ctrl+C` the agent.

2. Run the engine over the capture (exits on its own):
   ```powershell
   cd ..\panopticon-detection-engine
   py src\main.py --rules rules --officer-ndjson ..\panopticon-agent\capture.ndjson `
      --output-file alerts.ndjson --no-auto-remediate
   ```

3. Start the console against `alerts.ndjson` and open the browser.

### Where things land

| Thing | Location |
|---|---|
| Live Schema 0.2 events | Officer stdout (Procedure B: `capture.ndjson`) |
| Alerts | `panopticon-detection-engine\alerts.ndjson` (your `--output-file`) |
| Console | <http://127.0.0.1:8787> |

### Expected alert

One (or more) row(s) with:

| Field | Value |
|---|---|
| `rule_id` | `DET-PROC-011` |
| `severity` / `level` | `high` / `11` |
| `mitre_tactic` / `mitre_technique` | `Defense Evasion` / `T1027` |
| `title` | High-Entropy Obfuscated Script Execution (Zero-Day Anomaly Detection) |
| `evidence` | `process.name` = `powershell.exe`, `process.command_line` = the `-EncodedCommand …` line, `process.entropy` > 4.3, `process.pid`, `process.user` |

More than one `DET-PROC-011` row is normal — any other high-entropy
`powershell.exe` launch on the box during the window (e.g. a shell wrapper)
is a genuine match, not a false positive.

### Cleanup

```powershell
# Stop the console (Ctrl+C in Window 1) and the engine (Ctrl+C, Procedure A).
# If the agent was hard-killed and left its ETW session behind:
logman stop Panopticon-Officer-Process -ets
Get-Process officer-agent -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item panopticon-detection-engine\alerts.ndjson, panopticon-agent\capture.ndjson -ErrorAction SilentlyContinue
```

## 9. Administrator requirement

Officer opens an ETW kernel-process session and a Sysmon subscription; both
require an elevated token. Unelevated, Officer prints
`Warning: Officer is not elevated…` and then
`Officer could not start any telemetry collectors.` and exits non-zero.
Always run Officer — and any engine invocation that spawns it via `--officer` —
from an **Administrator PowerShell**.

## 10. Verified DET-PROC-011 demonstration command

See §8. Base64 (`-EncodedCommand`) →
`VwByAGkAdABlAC0ASABvAHMAdAAgAFAAYQBuAG8AcAB0AGkAYwBvAG4ALQBWADEALQBEAGUAbQBvAA==`
→ `Write-Host Panopticon-V1-Demo`. Entropy ≈ 4.66 > 4.3.

## 11. Expected alert

Covered in §8 ("Expected alert"). The canonical shape is
`panopticon-detection-engine/src/alerting/alert.py::Alert.to_dict()`.

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Officer could not start any telemetry collectors` | Not elevated. Use an Administrator PowerShell. |
| `Could not start sysmon collector` but ETW works | Sysmon not installed/running. Install Sysmon, or run with `--officer-source etw` / `--source etw`. |
| Engine `--officer` run never returns | By design — it streams until `Ctrl+C`. Press it to end the run and flush `alerts.ndjson`. |
| Console shows "No alerts yet" though the engine printed an alert | In `--officer` mode `alerts.ndjson` is written only when the engine stops. `Ctrl+C` the engine. Also confirm `--alerts-file` == the engine's `--output-file`. |
| `/api/alerts` returns `[]` but the file has lines | Wrong path, or a stale console is already bound to the port — check `Get-NetTCPConnection -LocalPort 8787`. |
| Orphaned ETW session after a crash / hard kill | `logman stop Panopticon-Officer-Process -ets`. |
| `tests/test_officer_artifact_integration.py` hangs | Do not run it in an **elevated** shell: with real collectors active the agent runs until interrupted, so the subprocess-stream test never returns. It is written for unelevated CI and skips unless `OFFICER_AGENT_BIN` is set. |
| Windows shows as "Windows 10" in `host.os.name` | Cosmetic. Officer reads `ProductName` from the registry, which still says "Windows 10" on Windows 11. |

## Test taxonomy — what proves what

| Layer | What runs | What it proves | What it does **not** prove |
|---|---|---|---|
| **Unit** | `pytest` in detection-engine (55 pass, 2 skip); `python -m unittest discover -s tests` in console (22 pass) | Rule logic, entropy, alert shaping, NDJSON parsing, HTTP surface, header hardening. Deterministic, OS-independent. | Anything about real Windows telemetry. |
| **Integration** | detection-engine `test_officer_integration.py`, `test_officer_source_selection.py`, `test_officer_artifact_integration.py` (needs `OFFICER_AGENT_BIN`); console `test_http.py` | The adapter, the CLI flags, the subprocess-spawn + stdout-pipe boundary, and the console's file→HTTP boundary — using fixtures / a built binary. | That the events are *real* — fixtures are replayed, not observed. |
| **Live Windows E2E** | The §8 procedure, elevated, on real hardware. | The whole vertical slice: a real `powershell.exe` creation, observed by the live agent, carried as Schema 0.2, detected as `DET-PROC-011`, written to `alerts.ndjson`, shown in a browser. | — this is the one that counts. |

Only the live Windows E2E procedure is "real E2E". A test that replays sample
NDJSON is an integration test, not E2E.
