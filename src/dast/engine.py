from collections import deque
from urllib.parse import urljoin
import httpx
from .access import AccessMatrix
from .checks import PassiveChecks
from .crawl import HTMLPlanner
from .models import Role
from .owasp import coverage
from .policy import canonical, public_url
from .probes import query_probes
from .transport import BudgetExceeded, Transport
from .webchecks import WebChecks


def scan(policy, roles=None, seeds=None, crawl=True, protocol="auto",
         checks=None, planner=None, transport=None, ca_file=None,
         active=False, access_policy=None) -> dict:
    if active and policy.profile != "standard":
        raise ValueError("Active probes require the standard profile")
    roles = roles or [Role()]
    access = AccessMatrix(access_policy, roles, policy) if access_policy is not None else None
    checks = checks if checks is not None else [PassiveChecks(), WebChecks()]
    planner = planner or HTMLPlanner()
    transport = transport or Transport(policy, protocol, ca_file=ca_file)
    findings, pages, errors = [], [], []
    seen_findings = set()
    stop = "completed"
    consecutive_errors = 0

    def add(finding):
        key = (finding.rule, finding.url, finding.role, str(finding.evidence))
        if key not in seen_findings:
            seen_findings.add(key)
            findings.append(finding.to_dict())

    for role in roles:
        queue = deque()
        queued = set()
        seen = set()
        def enqueue(url, depth):
            if len(queued) >= policy.max_requests + 1:
                return
            if policy.allows(url, role.paths):
                normalized = canonical(url)
                if normalized not in queued:
                    queued.add(normalized)
                    queue.append((normalized, depth))
        for seed in (seeds or [policy.target]) + (access.seeds if access else []):
            enqueue(seed, 0)
        with transport.client(role.headers) as client:
            def fetch(url, kind="baseline"):
                nonlocal stop, consecutive_errors
                if stop != "completed" or not policy.allows(url, role.paths):
                    return None
                try:
                    o = transport.get(client, url)
                except BudgetExceeded as exc:
                    stop = str(exc)
                    return None
                except (httpx.HTTPError, ValueError):
                    errors.append({"url": public_url(url), "role": role.name,
                                   "type": "transport-error", "request_kind": kind})
                    consecutive_errors += 1
                    if consecutive_errors >= policy.max_errors:
                        stop = "error-circuit-breaker"
                    return None
                pages.append({"url": public_url(url), "role": role.name,
                              "status": o.status, "protocol": o.protocol,
                              "truncated": o.truncated, "request_kind": kind})
                # Preserve evidence even on the response that opens the circuit.
                for check in checks:
                    for finding in check.assess(o, role.name):
                        add(finding)
                if kind == "baseline" and access:
                    access.observe(o, role.name)
                if o.status == 429 or o.status >= 500:
                    consecutive_errors += 1
                    if o.status == 429 or consecutive_errors >= policy.max_errors:
                        stop = "server-health-circuit-breaker"
                else:
                    consecutive_errors = 0
                return o

            while queue and stop == "completed":
                url, depth = queue.popleft()
                if url in seen:
                    continue
                seen.add(url)
                o = fetch(url)
                if o is None or stop != "completed":
                    continue
                if active:
                    try:
                        for finding in query_probes(o, role.name, fetch, lambda: stop != "completed"):
                            add(finding)
                    except ValueError:
                        errors.append({"url": public_url(url), "role": role.name, "type": "invalid-query"})
                if depth < policy.max_depth and stop == "completed":
                    if 300 <= o.status < 400 and "location" in o.headers:
                        enqueue(urljoin(url, o.headers["location"]), depth + 1)
                    elif crawl and 200 <= o.status < 300:
                        for link in planner.propose(o):
                            enqueue(link, depth + 1)
        if stop != "completed":
            break
    access_cases = []
    if access:
        access_findings, access_cases = access.results()
        for finding in access_findings:
            add(finding)
    if not pages and not errors and stop == "completed":
        stop = "no-in-scope-seeds"
    return {"schema_version": 2, "target": public_url(policy.target),
            "profile": policy.profile, "active": active,
            "requested_protocol": protocol, "stop_reason": stop,
            "requests": transport.requests, "pages": pages,
            "findings": findings, "errors": errors, "access_cases": access_cases,
            "owasp_version": "2025", "owasp_coverage": coverage(findings, active, bool(access)),
            "limitations": [
                "OWASP coverage is partial; zero findings is not a category pass.",
                "SQL errors are indicators; inert HTML reflection does not prove XSS execution.",
                "Access results depend on operator-defined roles and a protected-content marker.",
                "GET requests can still trigger application side effects.",
                "No JavaScript execution, form submission or automatic login.",
                "URLs omit queries; path segments may still contain sensitive identifiers.",
            ]}
