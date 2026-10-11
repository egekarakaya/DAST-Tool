import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit
from .models import Finding
from .policy import origin, public_url


SQL_ERRORS = {
    "sqlite": re.compile(r"(?:sqlite3?\.(?:OperationalError|DatabaseError)|SQLite (?:error|Exception)|unrecognized token:)", re.I),
    "mysql": re.compile(r"You have an error in your SQL syntax", re.I),
    "postgresql": re.compile(r"(?:psycopg\w*\.errors\.|PG::SyntaxError)", re.I),
}
ERROR_PATTERNS = {
    **SQL_ERRORS,
    "python-traceback": re.compile(r"Traceback \(most recent call last\):"),
    "java-stacktrace": re.compile(r"(?m)^\s*at [\w.$]+\([\w]+\.java:\d+\)"),
    "dotnet-stacktrace": re.compile(r"System\.\w+Exception:"),
}


def sql_signatures(body):
    return {name for name, pattern in SQL_ERRORS.items() if pattern.search(body)}


class Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.links, self.scripts = [], [], []
        self.current = None
        self.tags = set()
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.add(tag)
        if tag == "form":
            self.current = {"action": attrs.get("action", ""), "method": attrs.get("method", "get").lower(),
                            "password": False}
            self.forms.append(self.current)
        if tag == "input" and self.current is not None and attrs.get("type", "").lower() == "password":
            self.current["password"] = True
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs)
    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class WebChecks:
    def assess(self, o, role):
        findings = []
        def add(rule, severity, evidence, remediation, confidence="observed-configuration"):
            findings.append(Finding(rule, severity, public_url(o.url), role, evidence,
                                    remediation, confidence))
        for signature, pattern in ERROR_PATTERNS.items():
            if pattern.search(o.body):
                add("error-disclosure", "medium", {"signature": signature, "status": str(o.status)},
                    "Return generic client errors; keep diagnostic details in protected server logs.",
                    "signature-indicator")
                break
        if "text/html" not in o.headers.get("content-type", "").lower():
            return findings
        doc = Document()
        doc.feed(o.body)
        if (re.search(r"<title>\s*Index of /", o.body, re.I) and
                re.search(r"<h1>\s*Index of /", o.body, re.I) and doc.links):
            add("directory-listing", "medium", {"signature": "index-title-heading-and-links"},
                "Disable automatic directory indexing and review file exposure.", "signature-indicator")
        for form in doc.forms:
            if not form["password"]:
                continue
            destination = urljoin(o.url, form["action"])
            if urlsplit(o.url).scheme == "http" or urlsplit(destination).scheme == "http":
                add("password-over-http", "medium", {"form": "password input on HTTP page or action"},
                    "Serve password pages and submission endpoints exclusively over HTTPS.")
            if form["method"] == "get":
                add("password-in-get-form", "medium", {"method": "GET", "field": "password"},
                    "Submit credentials with POST over HTTPS; avoid credentials in URLs.")
        for link in doc.links:
            keys = {k.lower() for k, _ in parse_qsl(urlsplit(urljoin(o.url, link)).query)}
            if keys & {"sessionid", "session_id", "jsessionid", "phpsessid"}:
                add("session-in-link", "medium", {"location": "link query", "value": "redacted"},
                    "Carry session identifiers in appropriately protected cookies.", "signature-indicator")
                break
        for script in doc.scripts:
            try:
                external = origin(urljoin(o.url, script["src"])) != origin(o.url)
            except ValueError:
                continue
            if external and not script.get("integrity", "").strip():
                add("external-script-no-sri", "low", {"script": "external", "integrity": "absent"},
                    "Review third-party script trust and apply SRI where compatible; absence alone does not prove tampering.")
                break
        return findings
