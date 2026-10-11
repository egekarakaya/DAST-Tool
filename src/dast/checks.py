from http.cookies import SimpleCookie
from urllib.parse import urlsplit
from .models import Finding
from .policy import public_url


class PassiveChecks:
    def assess(self, o, role) -> list[Finding]:
        findings = []
        def add(rule, severity, evidence, remediation):
            findings.append(Finding(rule, severity, public_url(o.url), role,
                                    evidence, remediation))
        html = "text/html" in o.headers.get("content-type", "").lower()
        if 200 <= o.status < 300 and html:
            if "content-security-policy" not in o.headers:
                add("missing-csp", "low", {"content-security-policy": "absent"},
                    "Define a Content-Security-Policy appropriate to the application.")
            if ("x-frame-options" not in o.headers and
                    "frame-ancestors" not in o.headers.get("content-security-policy", "").lower()):
                add("missing-frame-protection", "low",
                    {"x-frame-options": "absent", "csp-frame-ancestors": "absent"},
                    "Set CSP frame-ancestors or a valid X-Frame-Options policy.")
            if o.headers.get("x-content-type-options", "").lower() != "nosniff":
                add("missing-nosniff", "low", {"x-content-type-options": "not nosniff"},
                    "Set X-Content-Type-Options: nosniff.")
        if urlsplit(o.url).scheme == "https" and "strict-transport-security" not in o.headers:
            add("missing-hsts", "low", {"strict-transport-security": "absent"},
                "Enable HSTS after confirming HTTPS readiness.")
        for index, raw in enumerate(o.cookies):
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except Exception:
                continue
            for morsel in cookie.values():
                missing = [flag for flag in ("httponly", "samesite") if not morsel[flag]]
                if urlsplit(o.url).scheme == "https" and not morsel["secure"]:
                    missing.append("secure")
                if missing:
                    add("cookie-flags", "low",
                        {"cookie-index": str(index), "missing-flags": ", ".join(missing)},
                        "Review cookie purpose; apply Secure, HttpOnly and SameSite as appropriate.")
        if o.headers.get("access-control-allow-origin") == "*":
            add("cors-wildcard", "info", {"access-control-allow-origin": "*"},
                "Confirm the endpoint is intended to be publicly readable; wildcard alone is not an exploit.")
        return findings
