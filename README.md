# DAST Tool

Lightweight Python web/API assessment CLI: **crawl -> assess -> report**.
Includes partial OWASP Top 10:2025 coverage, role comparisons and opt-in query
probes. This is an early scanner, not a complete vulnerability assessment or
OWASP certification.

**Start here:** [Turkish local demo guide](docs/DEMO-TR.md) ·
[OWASP 2025 coverage](docs/OWASP-2025.md) · [Roadmap](docs/ROADMAP.md)

## Install and scan

Python 3.11+:

```sh
python -m pip install .
dast scan https://staging.example.com --profile production --output reports
dast scan https://staging.example.com --no-crawl --seed /api/health
dast scan https://staging.example.com --openapi examples/openapi.json
```

Reports: `reports/report.json` and `reports/report.html`.
Exit codes: 0 completed within finding threshold; 1 threshold reached;
2 invalid configuration, transport/server-health error or incomplete scan
(including budget exhaustion). Default threshold is `--fail-on none`.

## Local lab

The bundled application uses only synthetic data and binds to loopback:

```sh
python examples/dummy_app.py --port 8080 --mode vulnerable
```

In another terminal:

```sh
dast scan http://127.0.0.1:8080 --profile standard --active --rps 5 --max-requests 150 --output reports/lab
```

Use `examples/demo-auth.json`, `examples/demo-access.json` and the
[step-by-step guide](docs/DEMO-TR.md) to compare anonymous/admin access and repeat
the scan with `--mode fixed`.

## Capabilities

- Explicit HTTP/1.0 GET adapter (connection closes after each request); pooled
  HTTP/1.1; negotiated HTTP/2 (`auto`) or strict `--protocol 2`.
- Verified TLS, optional `--ca-file path/to/ca.pem`, gzip/deflate decoding.
- Same-origin HTML breadth-first crawling, redirect validation, role path scope.
- Manual seeds via `--no-crawl --seed`; local OpenAPI 3 JSON concrete GET discovery.
- Isolated per-role cookie jars and env-based Authorization/Cookie headers.
- OWASP/CWE-tagged header, cookie, password-form, session-link, directory,
  external-script integrity and error-disclosure observations.
- `--access-policy`: allowed-role baseline plus protected-content marker
  comparison; HTTP 200 alone never proves broken access control.
- `--active --profile standard`: SQL error differential and inert HTML tag
  probes on existing query parameters. No JavaScript execution or data extraction.
- JSON/HTML evidence, confidence, partial/not-tested category matrix, access cases,
  response protocols, request kinds and scan stop reason.
- Commit CI and optional scheduled/manual/main-branch target assessment.

## Safety and resource controls

Use only against applications you own or are authorized to test.
The production profile is GET-only and passive: 1 rps, 50 requests, depth 3,
256 KiB retained decoded body, 10-second HTTP operation timeout, 120-second scan
budget. Production limits cannot exceed 2 rps/200 requests. It rejects query
strings and common destructive path segments; active probes are rejected.
Standard permits queries and active probes if explicitly selected.

One concurrent request, shared pacing/budget across roles and probes; no retries.
429 stops immediately; three consecutive 5xx/transport errors open the circuit.
No cross-origin redirect, automatic form submission or browser execution.

GET can still have side effects. These controls reduce risk; they do not guarantee
production safety. An in-flight operation may exceed the total duration budget
by up to its timeout. Retained decoded bytes are bounded, but library decompression
buffers do not have a hard process-memory cap. CPU/RAM benchmarks are pending.

## Authentication and authorization checks

`examples/auth.json` references environment variable names rather than credentials.
Set full header values, e.g. `DAST_USER_AUTH=Bearer ...`, outside source control.
Supply seeds inside each role's path scope. Sessions are isolated but login/session
refresh and credential validity are not automatically verified.

An access-policy JSON contains:

```json
{"rules":[{"path":"/admin","allowed_roles":["admin"],"marker":"unique protected-content marker"}]}
```

Rules seed the endpoint under each role's scope. A valid allowed-role baseline
and a restricted role both returning that protected marker with 2xx yield a
policy violation. Choose a marker unique to protected content, not shared
navigation. Missing baselines/truncated responses/login pages are inconclusive.

## Evidence and coverage

Findings have `owasp`, `cwe`, `confidence`, evidence and remediation.
SQL errors remain indicators; inert HTML insertion is not proof of executable XSS.
A03 supply chain, A06 design and A09 logging/alerting are explicitly not tested.
Other categories have limited checks; zero findings is not a category pass.
See the [coverage matrix](docs/OWASP-2025.md).

Queries, request headers, cookie values and raw response bodies are omitted from
reports. Paths, role names and parameter names may still contain private identifiers.
Review artifact access and retention for private applications.

## CI and scheduling

`ci.yml` validates Python 3.11–3.13 with unit and live loopback HTTP/TLS/HTTP2
fixtures, then runs the actual CLI against vulnerable/fixed demo apps and uploads
reports. To run tests locally:

```sh
python -m pip install ".[test]"
python -m unittest discover -s tests -v
```

TLS fixtures need OpenSSL; they skip if unavailable locally. CI installs the test
extra and uses Ubuntu's OpenSSL.

`target-scan.yml` runs manually, on main pushes and Mondays at 03:00 UTC
(06:00 Europe/Istanbul). It stays disabled until repository variables
`DAST_ENABLED=true` and `DAST_TARGET` are set. Configure the `dast` GitHub
environment and deployment timing before enabling. It does not deploy or wait
for your external deployment. Authenticated CI needs environment secret bindings.
Public PRs only scan local fixtures.

## Architecture and references

`Policy -> Transport -> HTMLPlanner/API seeds -> Checks/probes -> Findings -> Reports`

Checks consume observations; planners propose URLs; the engine controls network
scope and budgets. These interfaces prepare for smart crawling/LLM proposals.
No LLM or agent loop exists yet.

References: [OWASP Top 10:2025](https://top10.owasp.org/2025/),
[OWASP source](https://github.com/OWASP/Top10/tree/master/2025/docs/en),
[ZAP passive scanning](https://www.zaproxy.org/docs/desktop/addons/passive-scanner/),
[HTTPX](https://www.python-httpx.org/).
Acunetix and Tenable WAS are commercial products, not open-source dependencies.
