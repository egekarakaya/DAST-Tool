from collections import deque
from urllib.parse import urljoin
import httpx
from .checks import PassiveChecks
from .crawl import HTMLPlanner
from .models import Role
from .policy import canonical, public_url
from .transport import BudgetExceeded, Transport


def scan(policy, roles=None, seeds=None, crawl=True, protocol="auto",
         checks=None, planner=None, transport=None, ca_file=None) -> dict:
    roles = roles or [Role()]
    checks = checks if checks is not None else [PassiveChecks()]
    planner = planner or HTMLPlanner()
    transport = transport or Transport(policy, protocol, ca_file=ca_file)
    findings, pages, errors = [], [], []
    seen_findings = set()
    stop = "completed"
    consecutive_errors = 0
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
        for seed in seeds or [policy.target]:
            enqueue(seed, 0)
        with transport.client(role.headers) as client:
            while queue:
                url, depth = queue.popleft()
                if url in seen:
                    continue
                seen.add(url)
                try:
                    o = transport.get(client, url)
                except BudgetExceeded as exc:
                    stop = str(exc)
                    break
                except (httpx.HTTPError, ValueError):
                    # Do not record raw exception messages: they may contain credentials.
                    errors.append({"url": public_url(url), "role": role.name,
                                   "type": "transport-error"})
                    consecutive_errors += 1
                    if consecutive_errors >= policy.max_errors:
                        stop = "error-circuit-breaker"
                        break
                    continue
                pages.append({"url": public_url(url), "role": role.name,
                              "status": o.status, "protocol": o.protocol,
                              "truncated": o.truncated})
                if o.status == 429 or o.status >= 500:
                    consecutive_errors += 1
                    if o.status == 429 or consecutive_errors >= policy.max_errors:
                        stop = "server-health-circuit-breaker"
                        break
                else:
                    consecutive_errors = 0
                for check in checks:
                    for finding in check.assess(o, role.name):
                        key = (finding.rule, finding.url, finding.role, str(finding.evidence))
                        if key not in seen_findings:
                            seen_findings.add(key)
                            findings.append(finding.to_dict())
                if depth < policy.max_depth:
                    if 300 <= o.status < 400 and "location" in o.headers:
                        enqueue(urljoin(url, o.headers["location"]), depth + 1)
                    elif crawl and 200 <= o.status < 300:
                        for link in planner.propose(o):
                            enqueue(link, depth + 1)
        if stop != "completed":
            break
    if not pages and not errors and stop == "completed":
        stop = "no-in-scope-seeds"
    return {"schema_version": 1, "target": public_url(policy.target),
            "profile": policy.profile, "requested_protocol": protocol, "stop_reason": stop,
            "requests": transport.requests, "pages": pages,
            "findings": findings, "errors": errors,
            "limitations": [
                "Passive configuration assessment; no exploitation confirmed.",
                "GET requests can still trigger application side effects.",
                "No JavaScript execution, form submission or automatic login.",
                "URLs omit queries; path segments may still contain sensitive identifiers.",
            ]}
