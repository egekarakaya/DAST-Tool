import threading
import unittest
from unittest.mock import patch
import httpx
from dast.access import AccessMatrix
from dast.engine import scan
from dast.models import Observation, Role
from dast.owasp import CATEGORIES
from dast.policy import Policy
from dast.transport import Transport
from dast.webchecks import WebChecks
from examples.dummy_app import make_server


class OWASPTests(unittest.TestCase):
    def test_coverage_includes_untested_categories(self):
        policy = Policy("https://example.test")
        transport = Transport(policy, client_factory=lambda **opts: httpx.Client(
            transport=httpx.MockTransport(lambda _: httpx.Response(200)), **opts))
        report = scan(policy, transport=transport)
        rows = {r["category"]: r for r in report["owasp_coverage"]}
        self.assertEqual(set(rows), set(CATEGORIES))
        for category in ("A03:2025", "A05:2025", "A06:2025", "A09:2025"):
            self.assertEqual(rows[category]["status"], "not-tested")
        self.assertTrue(all("owasp" in f and "cwe" in f for f in report["findings"]))

    def test_active_production_rejected_before_network(self):
        with patch("dast.engine.Transport") as transport:
            with self.assertRaises(ValueError):
                scan(Policy("https://example.test"), active=True)
            transport.assert_not_called()

    def test_access_needs_allowed_baseline_and_marker(self):
        roles = [Role("anonymous"), Role("admin")]
        matrix = AccessMatrix({"rules": [{"path": "/admin", "allowed_roles": ["admin"],
                                         "marker": "PRIVATE PANEL"}]}, roles, Policy("https://example.test"))
        def observe(role, body, status=200):
            matrix.observe(Observation("https://example.test/admin", status, {}, [], body, "HTTP/1.1"), role)
        observe("anonymous", "PRIVATE PANEL")
        self.assertEqual(matrix.results()[0], [])
        observe("admin", "Please log in")
        self.assertEqual(matrix.results()[0], [])
        observe("admin", "PRIVATE PANEL")
        self.assertEqual(matrix.results()[0][0].rule, "access-policy-violation")
        observe("anonymous", "Please log in")
        self.assertEqual(matrix.results()[0], [])
        observe("anonymous", "Denied", 403)
        self.assertEqual(matrix.results()[1][0]["verdict"], "denied-as-expected")

    def test_passive_evidence_omits_sensitive_values(self):
        o = Observation("https://example.test", 200, {"content-type": "text/html"}, [],
            '<a href="/?sessionid=TOPSECRET">account</a><script src="https://other.test/a.js"></script>',
            "HTTP/1.1")
        findings = [f.to_dict() for f in WebChecks().assess(o, "anonymous")]
        self.assertNotIn("TOPSECRET", str(findings))
        self.assertEqual({f["rule"] for f in findings}, {"session-in-link", "external-script-no-sri"})

    def test_generic_error_page_is_not_disclosure(self):
        o = Observation("https://example.test", 500, {}, [], "Something went wrong", "HTTP/1.1")
        self.assertEqual(WebChecks().assess(o, "anonymous"), [])


class DemoTests(unittest.TestCase):
    def demo_scan(self, mode, **kwargs):
        server = make_server(0, mode)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target = f"http://127.0.0.1:{server.server_port}"
        try:
            policy = Policy(target, "standard", rps=20, max_requests=150)
            roles = [Role("anonymous"), Role("admin", {"Authorization": "Bearer demo-admin"})]
            access = {"rules": [{"path": "/admin", "allowed_roles": ["admin"], "marker": "DEMO_ADMIN_PANEL"}]}
            with patch("dast.transport.time.sleep"):
                return scan(policy, roles=roles, access_policy=access, active=True, **kwargs)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_vulnerable_demo_detects_expected_risks(self):
        report = self.demo_scan("vulnerable")
        self.assertEqual(report["stop_reason"], "completed")
        self.assertEqual(report["errors"], [])
        rules = {f["rule"] for f in report["findings"]}
        expected = {"access-policy-violation", "sql-error-differential", "html-injection",
                    "error-disclosure", "directory-listing", "password-over-http",
                    "password-in-get-form", "session-in-link", "external-script-no-sri"}
        self.assertTrue(expected <= rules, expected - rules)
        self.assertNotIn("demo-session-value", str(report))
        self.assertNotIn("Bearer demo-admin", str(report))
        self.assertNotIn("DEMO_ADMIN_PANEL", str(report))

    def test_fixed_demo_removes_targeted_findings(self):
        report = self.demo_scan("fixed")
        self.assertEqual(report["stop_reason"], "completed")
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["access_cases"][0]["verdict"], "denied-as-expected")

    def test_probes_obey_global_budget(self):
        server = make_server(0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target = f"http://127.0.0.1:{server.server_port}/search?q=test"
        try:
            policy = Policy(target, "standard", max_requests=2, rps=20)
            with patch("dast.transport.time.sleep"):
                report = scan(policy, active=True)
            self.assertEqual(report["requests"], 2)
            self.assertEqual(report["stop_reason"], "request-budget")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
