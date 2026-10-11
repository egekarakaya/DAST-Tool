"""Compare operator-defined access expectations using a protected-content marker."""
import hashlib
from urllib.parse import urljoin
from .models import Finding
from .policy import canonical, public_url


class AccessMatrix:
    def __init__(self, config, roles, policy):
        if not isinstance(config, dict) or not isinstance(config.get("rules"), list):
            raise ValueError("Access policy needs a rules array")
        self.rules = []
        self.observed = {}
        names = {role.name for role in roles}
        for rule in config["rules"]:
            route, allowed, marker = rule["path"], rule["allowed_roles"], rule["marker"]
            if (not isinstance(route, str) or not route.startswith("/") or route.startswith("//") or
                not isinstance(allowed, list) or not allowed or not set(allowed) <= names or
                not isinstance(marker, str) or not 4 <= len(marker) <= 256):
                raise ValueError("Invalid access policy rule")
            url = canonical(urljoin(policy.target, route))
            if not policy.allows(url):
                raise ValueError("Access rule is outside scan policy")
            self.rules.append({"url": url, "allowed": allowed, "marker": marker})
        self.roles = names

    @property
    def seeds(self):
        return [r["url"] for r in self.rules]

    def observe(self, o, role):
        for index, rule in enumerate(self.rules):
            if canonical(o.url) == rule["url"]:
                self.observed[index, role] = {
                    "status": o.status, "marker": rule["marker"] in o.body,
                    "truncated": o.truncated,
                }

    def results(self):
        findings, cases = [], []
        for index, rule in enumerate(self.rules):
            baseline = next((role for role in rule["allowed"]
                if (sample := self.observed.get((index, role))) and
                200 <= sample["status"] < 300 and sample["marker"] and not sample["truncated"]), None)
            for role in sorted(self.roles - set(rule["allowed"])):
                sample = self.observed.get((index, role))
                verdict = "inconclusive"
                if baseline and sample and not sample["truncated"]:
                    if sample["status"] in {401, 403}:
                        verdict = "denied-as-expected"
                    elif 200 <= sample["status"] < 300 and sample["marker"]:
                        verdict = "policy-violation"
                        findings.append(Finding(
                            "access-policy-violation", "high", public_url(rule["url"]), role,
                            {"baseline_role": baseline, "baseline_status": str(self.observed[index, baseline]["status"]),
                             "restricted_role_status": str(sample["status"]),
                             "protected_marker": "present in both responses",
                             "marker_sha256": hashlib.sha256(rule["marker"].encode()).hexdigest()},
                            "Enforce authorization server-side for this resource. Validate the configured marker identifies protected content.",
                            "operator-policy-violation"))
                cases.append({"url": public_url(rule["url"]), "role": role, "verdict": verdict})
        return findings, cases
