# Requirements and delivery plan

## Coverage matrix

| Requirement | 0.1 status | Next work |
|---|---|---|
| Crawl, assess, report | HTML BFS, OWASP-tagged rules/probes, JSON/HTML | Better coverage, form inventory, browser adapter |
| HTTP/1.1, HTTP/2, TLS | Implemented through HTTPX, live local TLS/HTTP2 tests | Broader server interoperability |
| HTTP/1.0 | GET adapter with verified TLS; live wire-version tests | Broader interoperability; no HTTP/1.0 keep-alive |
| Keep-alive/compression | HTTPX pooling, gzip/deflate; live tests | Decompression resource hardening |
| Authentication and permissions | Env headers, per-role sessions/path scope, explicit access matrix | Login flows and session validation |
| Automated/manual | Crawl and explicit seed CLI modes | Intercept/replay proxy and human-guided exploration |
| Every code change | Local fixture scan on push/PR | Project-specific deploy-then-scan integration |
| API security | OpenAPI concrete GET discovery + passive assessment | Auth matrix, parameter samples, REST/GraphQL checks |
| Proof-based scanning | Configuration evidence, SQL differential, inert HTML proof, operator-defined access expectations | Broader safe confirmation and browser-context verification |
| Speed adjustment | Global RPS and one concurrent request | Adaptive throttling with latency baselines |
| Scheduled | Opt-in GitHub workflow | External scheduler or CLI daemon if justified |
| Production safety | GET-only, origin/path gates, budgets, breakers | Operator dry-run inventory, explicit endpoint exclusions |
| AI/Agentic DAST | Planner/check interfaces only | Policy-bound structured actions, offline evals, prompt-injection defenses |
| Smart crawling | No JS/forms | URL prioritization, deduplication and optional browser worker |

## Milestones

1. Validate this passive MVP on owned fixtures, including TLS/HTTP2, compression,
   cookies and malicious redirects. Benchmark peak RAM and request throughput.
2. Authentication: expand the explicit access-policy matrix with credential providers,
   OAuth/browser login, logged-in assertions, session refresh and role-aware inventory. An HTTP 200 alone must never
   be interpreted as proof of an authorization bypass.
3. Proof engine: expand the implemented baseline/control query probes with typed
   reproducibility and browser-context confirmation. Add safe checks
   individually with vulnerable and non-vulnerable fixtures.
4. Broader API checks and extension of the opt-in active staging probes; no production escalation
   by an agent. Add reporting formats and incremental scan baselines.
5. Optional ZAP adapter: separately installed engine for deeper testing,
   explicit resource/process limits and no silent feature delegation.
6. Smart crawler and LLM planner: untrusted-content isolation, proposal schema,
   origin/method/budget approval by engine, deterministic fallback and audit trail.

## Current boundaries

The scanner offers SQL error differential and inert HTML reflection checks, but does
not confirm SQLi exploitation or execute XSS. SSRF, RCE, uploads, business logic
and automatic object-level authorization discovery remain unimplemented. Missing headers are hardening
observations, not evidence of successful exploitation. HTTP/1.0 transport supports
GET only and deliberately closes each connection.

A single worker keeps request concurrency low but is not a quantified resource
guarantee. Response body bytes, discovered URLs and total requests are bounded;
HTML parsing/decompression/library allocations require further benchmarking.
