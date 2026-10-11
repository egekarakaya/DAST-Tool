import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import httpx
from dast.cli import load_roles, main
from dast.crawl import api_seeds
from dast.engine import scan
from dast.models import Role
from dast.policy import Policy
from dast.report import write_report
from dast.transport import Transport


class ScannerTests(unittest.TestCase):
    def run_scan(self, handler, **kwargs):
        policy = kwargs.pop("policy", Policy("https://example.test", rps=2))
        client_factory = lambda **opts: httpx.Client(
            transport=httpx.MockTransport(handler), **opts)
        transport = Transport(policy, client_factory=client_factory)
        with patch("dast.transport.time.sleep"):
            return scan(policy, transport=transport, **kwargs)

    def test_scope_and_production_guards(self):
        p = Policy("https://example.test")
        for url in ["https://evil.test/", "http://example.test/",
                    "https://example.test:444/", "https://example.test/logout",
                    "https://example.test/?delete=1",
                    "https://example.test/a/%2e%2e/admin",
                    "https://user:secret@example.test/"]:
            self.assertFalse(p.allows(url), url)
        self.assertTrue(p.allows("https://example.test/account/profile", ("/account",)))
        self.assertFalse(p.allows("https://example.test/accounting", ("/account",)))

    def test_redirect_never_sends_auth_to_other_origin(self):
        calls = []
        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(302, headers={"location": "https://evil.test/"})
        result = self.run_scan(handler, roles=[Role("user", {"Authorization": "Bearer secret"})])
        self.assertEqual(calls, ["https://example.test/"])
        self.assertNotIn("secret", json.dumps(result))

    def test_crawl_budget_and_unsafe_links(self):
        calls = []
        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(200, headers={"content-type": "text/html"},
                text='<a href="/a">a</a><a href="/b">b</a><a href="/logout">logout</a>')
        result = self.run_scan(handler, policy=Policy("https://example.test", rps=2, max_requests=2))
        self.assertEqual(result["requests"], 2)
        self.assertEqual(result["stop_reason"], "request-budget")
        self.assertFalse(any("logout" in url for url in calls))

    def test_roles_isolate_cookies_and_share_budget(self):
        seen = []
        def handler(request):
            seen.append((request.headers.get("authorization"), request.headers.get("cookie")))
            return httpx.Response(200, headers={"set-cookie": "session=SECRET; Path=/"})
        roles = [Role("anonymous"), Role("user", {"Authorization": "Bearer TOKEN"})]
        result = self.run_scan(handler, roles=roles)
        self.assertEqual(seen, [(None, None), ("Bearer TOKEN", None)])
        self.assertEqual(result["requests"], 2)
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("TOKEN", json.dumps(result))

    def test_manual_mode(self):
        result = self.run_scan(lambda _: httpx.Response(
            200, headers={"content-type": "text/html"}, text='<a href="/next">next</a>'),
            crawl=False)
        self.assertEqual(result["requests"], 1)

    def test_rate_limit_stops_scan(self):
        result = self.run_scan(lambda _: httpx.Response(429))
        self.assertEqual(result["stop_reason"], "server-health-circuit-breaker")

    def test_server_errors_break_circuit(self):
        result = self.run_scan(lambda _: httpx.Response(503),
            seeds=["https://example.test/a", "https://example.test/b",
                   "https://example.test/c", "https://example.test/d"])
        self.assertEqual(result["requests"], 3)
        self.assertEqual(result["stop_reason"], "server-health-circuit-breaker")

    def test_openapi_ignores_write_methods_and_remote_refs(self):
        doc = {"openapi": "3.0.3", "servers": [{"url": "https://evil.test"}],
               "paths": {"/api/health": {"get": {}}, "/api/write": {"post": {}},
                         "/api/{id}": {"get": {}}, "//evil.test": {"get": {}}}}
        self.assertEqual(api_seeds(doc, "https://example.test"), ["https://example.test/api/health"])

    def test_missing_headers_are_configuration_evidence(self):
        result = self.run_scan(lambda _: httpx.Response(200,
            headers={"content-type": "text/html", "set-cookie": "session=secret"},
            text="hello"))
        self.assertIn("missing-csp", [f["rule"] for f in result["findings"]])
        self.assertTrue(all(f["confidence"] == "observed-configuration"
                            for f in result["findings"]))
        self.assertNotIn("secret", json.dumps(result))

    def test_body_limit(self):
        result = self.run_scan(lambda _: httpx.Response(200, content=b"x" * 10000),
            policy=Policy("https://example.test", max_body=1024))
        self.assertTrue(result["pages"][0]["truncated"])

    def test_report_escapes_html(self):
        result = self.run_scan(lambda _: httpx.Response(200))
        result["findings"] = [{"severity": "low", "rule": "<script>bad()</script>",
            "role": "anonymous", "url": "https://example.test", "evidence": {},
            "remediation": "fix"}]
        with tempfile.TemporaryDirectory() as tmp:
            write_report(result, tmp)
            html = (Path(tmp) / "report.html").read_text()
            self.assertNotIn("<script>bad()", html)
            self.assertIn("&lt;script&gt;", html)
            self.assertEqual(json.loads((Path(tmp) / "report.json").read_text()), result)

    def test_auth_config_fails_closed_when_secret_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "auth.json"
            config.write_text(json.dumps({"roles": [
                {"name": "user", "headers_env": {"Authorization": "MISSING_TEST_SECRET"}}]}))
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(ValueError):
                    load_roles(config)

    def test_invalid_budgets(self):
        for args in [{"rps": float("nan")}, {"max_requests": 0},
                     {"rps": 3}, {"timeout": -1}, {"max_depth": -1}]:
            with self.assertRaises(ValueError):
                Policy("https://example.test", **args)

    def test_cli_incomplete_scan_is_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("dast.cli.scan", return_value={
                "target": "https://example.test", "requests": 0, "pages": [],
                "findings": [], "errors": [], "limitations": [],
                "stop_reason": "no-in-scope-seeds"}):
                self.assertEqual(main(["scan", "https://example.test", "--output", tmp]), 2)


if __name__ == "__main__":
    unittest.main()
