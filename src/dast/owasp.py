"""Rule-to-risk mappings maintained against OWASP Top 10:2025.

Mappings describe related risk areas, not full category coverage or certification.
"""
CATEGORIES = {
    "A01:2025": ("Broken Access Control", "Policy-bound role comparison and CORS observations only."),
    "A02:2025": ("Security Misconfiguration", "Headers, cookie flags and directory-listing indicators."),
    "A03:2025": ("Software Supply Chain Failures", "Requires SBOM/SCA and build-pipeline review."),
    "A04:2025": ("Cryptographic Failures", "HTTP password forms and HTTPS transport configuration only."),
    "A05:2025": ("Injection", "Opt-in SQL error differential and inert HTML reflection probes; no XSS execution."),
    "A06:2025": ("Insecure Design", "Requires business rules, threat modelling and manual design review."),
    "A07:2025": ("Authentication Failures", "Session identifiers in links only; no login/MFA/brute-force validation."),
    "A08:2025": ("Software or Data Integrity Failures", "External script SRI hardening observations only."),
    "A09:2025": ("Security Logging and Alerting Failures", "Requires server logs and alert pipeline verification."),
    "A10:2025": ("Mishandling of Exceptional Conditions", "Error disclosure signatures only; no resilience/DoS testing."),
}
RULES = {
    "missing-csp": (["A02:2025"], ["CWE-693"]),
    "missing-frame-protection": (["A02:2025"], ["CWE-1021"]),
    "missing-nosniff": (["A02:2025"], ["CWE-693"]),
    "missing-hsts": (["A04:2025"], ["CWE-319"]),
    "cookie-flags": (["A02:2025"], ["CWE-614", "CWE-1004"]),
    "cors-wildcard": (["A01:2025", "A02:2025"], ["CWE-942"]),
    "directory-listing": (["A02:2025"], ["CWE-548"]),
    "password-over-http": (["A04:2025"], ["CWE-319"]),
    "password-in-get-form": (["A04:2025"], ["CWE-598"]),
    "session-in-link": (["A07:2025"], ["CWE-598"]),
    "external-script-no-sri": (["A08:2025"], ["CWE-353"]),
    "error-disclosure": (["A02:2025", "A10:2025"], ["CWE-209"]),
    "sql-error-differential": (["A05:2025"], ["CWE-89"]),
    "html-injection": (["A05:2025"], ["CWE-79"]),
    "access-policy-violation": (["A01:2025"], ["CWE-862"]),
}


def coverage(findings, active=False, access=False):
    rows = []
    for category, (name, limitation) in CATEGORIES.items():
        rules = [rule for rule, (categories, _) in RULES.items() if category in categories]
        enabled = [r for r in rules if
                   (r not in {"sql-error-differential", "html-injection"} or active) and
                   (r != "access-policy-violation" or access)]
        rows.append({"category": category, "name": name,
                     "status": "partial-checks-enabled" if enabled else "not-tested",
                     "enabled_rules": enabled, "limitation": limitation,
                     "findings": sum(category in f.get("owasp", []) for f in findings)})
    return rows
