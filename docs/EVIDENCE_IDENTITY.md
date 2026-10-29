# Individual browser evidence identity

The evidence routes use an individually issued analyst bearer credential, separate
from the shared Console response-view identity. POST `/api/evidence/session` with
`{"access_token":"..."}` to authenticate against Manager's `/api/v1/analysts/me`.
The server accepts only an eligible artifact reader. No username supplied by a
browser is trusted. The response contains a minimal public identity and an opaque
HttpOnly, SameSite=Strict cookie; the bearer token remains in server memory and
must never enter browser local storage. Login retries reuse an existing session
only after the same credential authenticates again.

Sessions expire after one hour, are capped at 256, and are lost on restart. POST
`/api/evidence/session/logout` clears the cookie and server session. Switching
identity invalidates the old session. No evidence route falls back to the shared
`PANOPTICON_MANAGER_TOKEN`. Manager rechecks the actual credential and case/endpoint
scope on every request; a Console cookie cannot grant access.

The session response also contains an opaque `identity_version`, distinct from
the HttpOnly authentication cookie. Each case/artifact request must echo it in
`X-Panopticon-Evidence-Identity`. Switching browser identity changes this version;
a stale tab receives 409 instead of using the new credential implicitly. It is
not a credential and cannot authorize a request without the actual session cookie.

Loopback HTTP is supported for local development. Public access requires an
explicit `PANOPTICON_CONSOLE_PUBLIC_ORIGIN=https://console.example` and HTTPS
termination. Public cookies are Secure; Origin and Host must match that exact
configured origin. Forwarded-protocol headers are not trusted. State-changing
evidence requests require a same-origin Origin header; cross-site requests are
refused. Non-loopback Manager connections require HTTPS. Evidence upstream calls
refuse redirects, have bounded responses and a five-second timeout.

Evidence proxy paths are closed: session, case export, artifact content, custody,
signed context and bounded chunks. Arbitrary URLs, route traversal and unknown or
duplicate query parameters are refused. The individual token is attached only by
the server and never returned with evidence.
