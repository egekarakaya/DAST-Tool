"""Small opt-in probes for staging. No script execution or data extraction."""
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from .models import Finding
from .policy import public_url
from .webchecks import Document, sql_signatures


def query_probes(baseline, role, fetch, halted):
    if baseline.truncated or not 200 <= baseline.status < 300:
        return []
    parts = urlsplit(baseline.url)
    pairs = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=100)
    findings = []
    for index, (name, value) in enumerate(pairs[:2]):
        if halted():
            break
        if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) or
                re.search(r"token|session|password|secret|auth|csrf|key", name, re.I)):
            continue
        marker = "dastprobe" + secrets.token_hex(8)
        def url(payload):
            values = pairs.copy()
            values[index] = (name, payload)
            return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(values), ""))
        control = fetch(url(marker), "control")
        if control is None or halted() or control.truncated or not 200 <= control.status < 300:
            continue
        quoted = fetch(url(value + "'"), "sql-probe")
        if quoted is not None and not quoted.truncated:
            signatures = sql_signatures(quoted.body) - sql_signatures(baseline.body) - sql_signatures(control.body)
            if signatures:
                findings.append(Finding(
                    "sql-error-differential", "medium", public_url(baseline.url), role,
                    {"parameter": name, "probe": "single quote appended",
                     "baseline_status": str(baseline.status), "control_status": str(control.status),
                     "probe_status": str(quoted.status), "new_error_signatures": ", ".join(sorted(signatures))},
                    "Review query construction and use parameterized queries; this differential needs manual confirmation.",
                    "differential-indicator"))
        if halted():
            break
        injected = fetch(url("<" + marker + "></" + marker + ">"), "html-probe")
        if (injected is None or injected.truncated or not 200 <= injected.status < 300 or
                "text/html" not in injected.headers.get("content-type", "").lower()):
            continue
        doc = Document()
        doc.feed(injected.body)
        baseline_doc, control_doc = Document(), Document()
        baseline_doc.feed(baseline.body)
        control_doc.feed(control.body)
        if marker in doc.tags and marker not in baseline_doc.tags and marker not in control_doc.tags:
            findings.append(Finding(
                "html-injection", "medium", public_url(baseline.url), role,
                {"parameter": name, "probe": "inert custom HTML tag",
                 "parsed_tag": marker, "baseline_status": str(baseline.status),
                 "control_status": str(control.status), "probe_status": str(injected.status)},
                "Apply context-appropriate output encoding. A parsed inert tag confirms HTML injection, not JavaScript execution.",
                "inert-html-confirmed"))
    return findings
