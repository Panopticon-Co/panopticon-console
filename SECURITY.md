# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security vulnerability.** Report
privately via GitHub Security Advisories:

<https://github.com/Panopticon-Co/panopticon-console/security/advisories/new>

Please include:

- A description of the vulnerability and its impact.
- Reproduction steps.
- Affected route(s) or file(s) — see `app.py` for the full server-side
  routing surface (`/`, `/app.js`, `/api/alerts`, `/api/response-actions`).

Areas of particular interest given this console's design: XSS via alert
evidence fields (the client is expected to render all evidence via
`textContent`, never `innerHTML`), CSP bypasses, and any way for the
optional Manager analyst token (an environment-variable, server-side-only
secret used by `/api/response-actions`) to become reachable from browser
JavaScript or a response body.

## Response

This is a capstone/research project maintained on a best-effort basis —
there is no guaranteed response SLA. We will acknowledge reports as soon as
reasonably possible.

## Scope note

This console is a local development/demo tool by design (binds `127.0.0.1`
by default, no browser-facing authentication). That is a documented design
choice, not an oversight — see `README.md`'s "What this is not (yet)"
section. Reports about the *absence* of multi-user auth are welcome as
context for future work but are not itself a vulnerability in the current,
documented scope.

## Supported Versions

This project does not yet cut versioned releases; security fixes are applied
to `main`.
