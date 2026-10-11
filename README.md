# DAST Tool

A lightweight Python CLI with separate crawling, assessment and reporting components.
Version 0.1 is a **passive configuration assessment MVP**, not a complete vulnerability scanner.
Only scan applications you own or are explicitly authorized to test.

## Quick start

Python 3.11+:

```sh
python -m pip install .
dast scan https://staging.example.com --profile production --output reports
dast scan https://staging.example.com --no-crawl --seed /api/health
dast scan https://staging.example.com --openapi examples/openapi.json
python -m pip install ".[test]"
python -m unittest discover -s tests -v
```

Reports: `reports/report.json` and `reports/report.html`.
Exit codes: 0 completed within configured finding threshold; 1 threshold reached;
2 invalid configuration, transport/server-health error or incomplete scan (including budget exhaustion).
A clean report does **not** establish that an application has no vulnerabilities.

## Supported today

- Explicit HTTP/1.0 mode via \`--protocol 1.0\`, HTTP/1.1 and TLS-verified HTTPS; HTTP/2 negotiation using `--protocol auto` (default).
  `--protocol 2` requires negotiated HTTP/2; `--protocol 1.1` disables HTTP/2.
- Pooled keep-alive for HTTP/1.1–2; HTTP/1.0 closes each connection. Gzip/deflate decoding through HTTPX.
  Custom trust bundles use \`--ca-file path/to/ca.pem\`; certificate checks remain enabled.
- Breadth-first HTML link discovery, same-origin redirects, depth/request/body/time budgets.
- Automated crawling; manually supplied endpoint assessment with `--no-crawl --seed`.
  Manual mode is CLI seed selection, **not** an intercepting browser proxy.
- Local OpenAPI 3 **JSON** discovery: concrete GET paths only; no remote references,
  server URL traversal, parameter generation, POST/PUT/DELETE or GraphQL testing.
- Separate per-role clients, environment-based Authorization/Cookie headers,
  role-specific path allowlists. No automatic login or role inference.
- Passive CSP, framing, nosniff, HSTS, cookie-attribute and CORS observations.
- Evidence metadata, role attribution, remediation, protocol and coverage reporting.
  Findings prove only the observed configuration. Wildcard CORS is informational.
- Single concurrent request, configurable requests/second, shared request budget
  across roles, health circuit breaker and bounded retained response bodies.
- Commit-triggered tests and a local fixture assessment; optional scheduled/manual/
  main-branch assessment against a configured authorized deployment.

## Authentication and path scope

`examples/auth.json` stores environment variable **names**, never secrets.
Set `DAST_USER_AUTH` and `DAST_ADMIN_AUTH` to full header values (e.g. `Bearer ...`),
then run:

```sh
dast scan https://staging.example.com --auth-config examples/auth.json \
  --seed /account --seed /admin --seed /api/health
```

Each role has an isolated cookie jar. Headers are applied only to URLs allowed by
same-origin and role path policy; cross-origin redirects are not followed.
Path lists describe where a role may scan; they do not prove authorization enforcement.
Expired credentials and login success are not currently detected.
Use non-production test accounts with the intended permissions.

## Production profile

Defaults: 1 request/second, 50 requests, depth 3, 256 KiB retained decoded body,
10-second HTTP operation timeout and 120-second scan budget.
Production caps are 2 requests/second and 200 requests.
Both profiles send GET only. Production additionally rejects query strings and
common destructive path segments. Standard permits queries and those paths;
select it only for a suitable test environment.

No form submission, mutation payloads, automatic retry, JavaScript execution or
off-origin requests. A 429 immediately stops scanning; three consecutive 5xx or
transport errors stop scanning. TLS certificate validation remains enabled.

**GET can change state in poorly designed applications.** These controls reduce
risk; they do not guarantee production safety. Start on staging with explicit
path allowlists and application monitoring. An in-flight operation may exceed
the total duration budget by up to its HTTP timeout; decoded-body retention is
bounded, but HTTP library decompression buffers are not a hard process-memory cap.
There are no measured CPU/RAM benchmarks yet.
HTTP/1.0 uses CPython protocol selectors covered by local wire tests; HTTP/1.0
keep-alive is deliberately not attempted. Reports record requested mode separately
from the response version, since servers may reply with a newer version.

## CI and scheduled scans

`.github/workflows/ci.yml` validates Python 3.11–3.13, including live loopback HTTP/TLS/HTTP2 fixtures, and scans a local fixture
after pushes/PRs. It never accepts an external target from PR code.

`.github/workflows/target-scan.yml` runs manually, on main pushes and Mondays
at 03:00 UTC (06:00 Europe/Istanbul). It stays disabled until repository variables
`DAST_ENABLED=true` and `DAST_TARGET=https://your-authorized-deployment` are set.
Create the GitHub environment `dast`; configure deployment timing/environment
rules for your project. The workflow does not deploy an application or wait for
your external deployment automatically. Hosted runners need network access to
the target; use controlled self-hosted runners for private deployments.
Only main code runs against the configured target. Keep secrets out of target URLs.
Authenticated CI requires your own environment secret bindings to auth config.

Reports omit query strings and never persist request headers, cookies or body text.
Path segments, role names and URLs can still reveal private identifiers.
Review artifact access/retention before enabling scans of private applications.

## Extension architecture

`Policy -> Transport -> HTMLPlanner/API seeds -> Check -> Finding -> JSON/HTML`

- `Transport` owns pacing, TLS and budgets.
- `Policy` validates every discovery and redirect before credentials/network use.
- `Check` consumes observations; it has no direct network authority.
- `CrawlPlanner` proposes links; the engine revalidates proposals.

The planner/check interfaces prepare for smart crawling and LLM assistance.
No LLM calls, agent loop or model credential handling exist in this release.
Future agents must propose structured actions routed through the same policy and
budget controls; external page text must be treated as untrusted input.

See [the requirements and roadmap](docs/ROADMAP.md) for unimplemented requirements.

## References

Architecture is informed by [ZAP passive scanning](https://www.zaproxy.org/docs/desktop/addons/passive-scanner/)
and the [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/).
Transport uses [HTTPX](https://www.python-httpx.org/) rather than embedding a heavyweight scanner.
Acunetix and Tenable WAS are proprietary commercial products, not open-source dependencies.
No ZAP, Acunetix or Tenable source code is copied.
