# Contributing to panopticon-console

Thank you for contributing to **panopticon-console**, the alert viewer for
the Panopticon&Co capstone EDR/XDR platform.

## Stack

This is a small, dependency-free project by design:

- **Server**: Python 3 standard library only (`app.py`, built on
  `http.server`). No framework, no `pip install` needed.
- **Client**: vanilla HTML/CSS/JavaScript (`static/index.html`,
  `static/app.js`). No build step, no bundler, no `package.json`.
- **Tests**: `unittest` for the Python server (`tests/test_*.py`) and plain
  Node.js scripts for the client (`tests/*.cjs`) — Node is used only to run
  these scripts directly, not as an npm project.

Please keep it that way unless a change genuinely requires a new dependency
— raise that as its own discussion before adding one, since "zero
dependencies" is a deliberate scope decision documented in `README.md`, not
an accident.

## Development setup

```bash
git clone https://github.com/Panopticon-Co/panopticon-console.git
cd panopticon-console
python app.py --alerts-file /path/to/alerts.ndjson
```

Then open <http://127.0.0.1:8787>.

## Running tests

```bash
python -m unittest discover -s tests -v
node --check static/app.js
node tests/test_dashboard.cjs
node tests/test_theme.cjs
node tests/test_response_panel.cjs
```

This matches `.github/workflows/ci.yml` exactly.

## Pull request guidelines

- Ensure new routes/behavior have test coverage under `tests/` (Python
  `unittest` for server behavior, `.cjs` for client behavior).
- Do not weaken an existing test to make it pass.
- The client must escape all attacker-influenced content (e.g. alert
  evidence) via `textContent`, never `innerHTML` string-building — this is a
  deliberate security invariant, not a style preference. See `SECURITY.md`.
- If your change adds a route, keep the "closed route set" property intact:
  `app.py`'s `do_GET` should still resolve only known, explicit paths, with
  no filesystem path mapping that could turn a request path into an
  arbitrary file read.
- Use the PR template (`.github/pull_request_template.md`).

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. Security
vulnerabilities should **not** be filed as public issues — see
`SECURITY.md`.
