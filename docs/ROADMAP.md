# Requirements and delivery plan

## Coverage matrix

| Requirement | 0.1 status | Next work |
|---|---|---|
| Crawl, assess, report | HTML BFS, passive rules, JSON/HTML | Better coverage, form inventory, browser adapter |
| HTTP/1.1, HTTP/2, TLS | Implemented through HTTPX, CI mock/HTTP fixture coverage | Live TLS/HTTP2 integration tests |
| HTTP/1.0 | Not implemented | Isolated HTTP/1.0 transport and protocol compliance tests |
| Keep-alive/compression | HTTPX pooling, gzip/deflate | Compression/pooling integration tests and decompression resource hardening |
| Authentication and permissions | Env headers, per-role sessions and path scope | Login flows, session validation, per-role authorization comparison |
| Automated/manual | Crawl and explicit seed CLI modes | Intercept/replay proxy and human-guided exploration |
| Every code change | Local fixture scan on push/PR | Project-specific deploy-then-scan integration |
| API security | OpenAPI concrete GET discovery + passive assessment | Auth matrix, parameter samples, REST/GraphQL checks |
| Proof-based scanning | Configuration evidence only | Baseline/control pairs and safe exploit reproduction |
| Speed adjustment | Global RPS and one concurrent request | Adaptive throttling with latency baselines |
| Scheduled | Opt-in GitHub workflow | External scheduler or CLI daemon if justified |
| Production safety | GET-only, origin/path gates, budgets, breakers | Operator dry-run inventory, explicit endpoint exclusions |
| AI/Agentic DAST | Planner/check interfaces only | Policy-bound structured actions, offline evals, prompt-injection defenses |
| Smart crawling | No JS/forms | URL prioritization, deduplication and optional browser worker |

## Milestones

1. Validate this passive MVP on owned fixtures, including TLS/HTTP2, compression,
   cookies and malicious redirects. Benchmark peak RAM and request throughput.
2. Authentication: credential providers, OAuth/browser login, logged-in assertions,
   session refresh and role-aware endpoint inventory. An HTTP 200 alone must never
   be interpreted as proof of an authorization bypass.
3. Proof engine: typed request/response evidence with secret redaction, baseline
   and control requests, reproducibility and confidence levels. Add safe checks
   individually with vulnerable and non-vulnerable fixtures.
4. API checks and optional active **staging-only** profile; no production escalation
   by an agent. Add reporting formats and incremental scan baselines.
5. Optional ZAP adapter: separately installed engine for deeper testing,
   explicit resource/process limits and no silent feature delegation.
6. Smart crawler and LLM planner: untrusted-content isolation, proposal schema,
   origin/method/budget approval by engine, deterministic fallback and audit trail.

## Current boundaries

The scanner does not test SQL injection, XSS exploitation, SSRF, RCE, uploads,
business logic or object-level authorization. Missing headers are hardening
observations, not evidence of successful exploitation. HTTP/1.0 is intentionally
rejected by the CLI until it has a tested transport.

A single worker keeps request concurrency low but is not a quantified resource
guarantee. Response body bytes, discovered URLs and total requests are bounded;
HTML parsing/decompression/library allocations require further benchmarking.
