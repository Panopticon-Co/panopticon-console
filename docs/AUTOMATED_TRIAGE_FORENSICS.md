# Automated triage and forensic context

The Response page's Automated investigation triage section uses the existing
individual evidence identity. Sign in above it, then refresh triage. Manager
remains the authority for every operation; the shared configured token is never
used for these routes. HTTPS/public-origin and same-origin/identity-version
requirements match the existing evidence session.

A separately provisioned triage administrator can configure a detection rule's
standard-endpoint collection decisions, exact Windows/Linux file allowlists,
budgets and enable toggle, and classify actively enrolled hosts with a reason.
Saving creates a new immutable policy revision; stale editors receive conflict.
Critical/unclassified endpoints require approval or retain an explicit skip.
This role cannot approve responses, retrieve artifacts or grant evidence scope.

Analyst operators can inspect paginated runs, policy revision, endpoint, deadline,
skip reasons, live blockers and reserved bytes. Approvers can stop remaining
collections with a reason. Existing queued cancellation and pending rejection are
reused; delivered work may already have started, and late evidence is retained.
Links open the actual collection response case, not the original disruptive
recommendation's command. Existing Response controls retain the approval flow.

The evidence dialog displays scoped forensic collection context: source record,
original observation time, rule, asset class, native process identity or exact
file-metadata target, effective response tier and evidence/trust references.
Native start tokens use the server's decimal-string identity representation to
avoid uint64 precision loss in JavaScript. Missing historical provenance and
plan/audit disagreement are labelled rather than invented or silently displayed.

Forensic metadata is advisory; it cannot authorize execution or prove byte
integrity. Case/endpoint access grants still apply. Existing signature/hash
verification and mandatory custody receipts gate content viewing and signed
bundle download. Compromised-key flags stay visible and content stays blocked.
Anonymous/shared-token views strip all forensic context as well as artifacts.

Only the existing three collection actions are eligible for automation. File
collection remains metadata/hash JSON. No raw file acquisition, memory capture,
new action, script or shell is added. Merge does not restart running services:
deploy compatible Manager, Console and agent releases, provision identities and
case grants, then explicitly enable selected rules for operational use.
