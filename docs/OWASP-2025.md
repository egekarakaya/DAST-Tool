# OWASP Top 10:2025 coverage

Reference: [OWASP/Top10, 2025 English sources](https://github.com/OWASP/Top10/tree/master/2025/docs/en).
This is our engineering coverage matrix, not an OWASP certification. Rule mappings
identify related risk areas; individual CWEs are narrower than the category.

| Category | Implemented analysis | Limits |
|---|---|---|
| A01 Broken Access Control | Operator-defined role/endpoint/marker comparisons; CORS observations | Requires a correct policy and valid role sessions; no automatic IDOR discovery. Wildcard CORS alone is informational. |
| A02 Security Misconfiguration | CSP, framing, nosniff, cookie attributes, directory-index signatures, error disclosure | Missing headers indicate hardening gaps. Directory/error patterns need context. |
| A03 Software Supply Chain Failures | Not tested | Needs SBOM/SCA, dependency advisories, provenance and pipeline review. |
| A04 Cryptographic Failures | HSTS on HTTPS responses; password forms served/submitted over HTTP or using GET | Does not audit cipher suites, at-rest encryption, key storage or password hashes. |
| A05 Injection | Opt-in single-quote SQL error differential and inert HTML tag reflection | SQL errors are indicators, not confirmed SQLi. HTML insertion does not establish executable XSS. No command injection/SSRF probes. |
| A06 Insecure Design | Not tested | Needs business rules, threat modelling and design review. |
| A07 Authentication Failures | Session identifier names in link query strings | No login, password strength, MFA, lockout, session fixation or logout validation. |
| A08 Software or Data Integrity Failures | Missing SRI on external script references | Hardening observation only; does not prove tampering or test deserialization/signatures. |
| A09 Security Logging and Alerting Failures | Not tested | Requires server-side logs, alert destinations and end-to-end verification. |
| A10 Mishandling of Exceptional Conditions | SQL/stack-trace disclosure signatures | No DoS, resource exhaustion, transaction rollback or fail-open testing. |

Each finding includes `owasp`, `cwe`, `confidence`, role, URL, evidence and remediation.
The report lists **all ten categories**. `partial-checks-enabled` means rules were
enabled, not that every endpoint in the category was tested. `not-tested` means
no applicable enabled implementation. No finding is not a pass.

## Probe semantics

With `--active --profile standard`, discovered/seeded query URLs receive a random
alphanumeric control, a single quote appended to the original value, and an inert
custom HTML element. At most the first two parameters are considered per URL.
Credential/session-looking parameter names are skipped. Existing unrelated
parameters stay unchanged. All requests go through the same scope, pacing,
budget, TLS and health controls. Probe responses are not crawled.

A new SQL signature must be absent from both baseline and control. An HTML probe
must become a parsed tag, rather than escaped text or script/comment content.
No JavaScript is executed and no data extraction payload is sent.
Reports omit query values and full bodies; only controlled markers, parameter
names, response statuses and error-family labels are retained.
The schema is version 2. Replaying a finding requires your original scan input.

## Access policy semantics

A policy contains a path, allowed role names and a marker that uniquely identifies
protected content. The scanner automatically adds policy paths as seeds, subject
to every role's path scope. First, an allowed role must return the marker with a
2xx response. A disallowed role returning the same marker with 2xx produces
`operator-policy-violation`. Truncated/missing responses or login pages are
inconclusive; 401/403 after a valid allowed baseline is `denied-as-expected`.
A generic page title or shared navigation text is an unsuitable marker.

## Sources and attribution

Category names and risk descriptions are based on OWASP Top 10:2025:
[official edition](https://top10.owasp.org/2025/) and
[source repository](https://github.com/OWASP/Top10/tree/master/2025/docs/en).
OWASP's material is licensed under CC BY 3.0. The scanner implementation, demo,
coverage decisions and mappings here are our own; OWASP has not endorsed them.
