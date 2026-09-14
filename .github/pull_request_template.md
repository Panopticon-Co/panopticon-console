## Summary

<!-- One or two sentences: what does this PR do and why? -->

## Changes

<!-- Bullet list of the concrete changes. -->

## Testing

<!-- Exact commands run and their results, e.g.
     `python -m unittest discover -s tests -v`,
     `node tests/test_dashboard.cjs`, `node tests/test_theme.cjs`,
     `node tests/test_response_panel.cjs`. -->

## Security Impact

<!-- Does this touch the CSP, the closed route set in app.py's do_GET,
     how alert evidence is rendered (textContent vs innerHTML), or the
     Manager analyst-token proxy? If yes, describe what was verified. If
     no, say "None." explicitly rather than leaving this blank. -->

## Documentation

<!-- Which docs were updated (README, SECURITY.md)? If none needed
     updating, say so. -->

## Cross-Repository Impact

<!-- Does this change what this console expects from the detection
     engine's alert NDJSON shape, or from panopticon-manager's
     response-actions API? If yes, link the corresponding PR(s) in those
     repos. -->

## Checklist

- [ ] Tests added/updated under `tests/` for the change
- [ ] `python -m unittest discover -s tests -v` passes locally
- [ ] `node --check static/app.js` and the `.cjs` test scripts pass locally
- [ ] No new dependency was added without discussing it first (this project
      is intentionally zero-dependency — stdlib Python + vanilla JS)
- [ ] Attacker-influenced content is rendered via `textContent`, never
      `innerHTML` string-building
- [ ] No existing test was weakened or deleted to make CI pass
