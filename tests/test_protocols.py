"""Live local fixtures; no requests leave loopback interfaces."""
import contextlib
import gzip
import http.server
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib
import httpx
from dast.engine import scan
from dast.models import Role
from dast.policy import Policy
from dast.transport import Transport


@contextlib.contextmanager
def http_fixture():
    calls = []
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *args):
            pass
        def do_GET(self):
            calls.append({"version": self.request_version, "port": self.client_address[1],
                          "cookie": self.headers.get("Cookie"), "path": self.path})
            body = b"<html>local fixture</html>"
            encoding = None
            if self.path == "/gzip":
                body, encoding = gzip.compress(body), "gzip"
            elif self.path == "/deflate":
                body, encoding = zlib.compress(body), "deflate"
            elif self.path == "/large":
                body, encoding = gzip.compress(b"x" * 1000000), "gzip"
            elif self.path == "/invalid":
                body, encoding = b"invalid gzip", "gzip"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "session=local-secret; Path=/; HttpOnly")
            if encoding:
                self.send_header("Content-Encoding", encoding)
            self.end_headers()
            self.wfile.write(body)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class LiveHTTPTests(unittest.TestCase):
    def test_http10_wire_version_and_role_cookie_isolation(self):
        with http_fixture() as (target, calls):
            policy = Policy(target, rps=2)
            result = scan(policy, roles=[Role("a"), Role("b")],
                          seeds=[target + "/", target + "/next"], crawl=False, protocol="1.0")
            self.assertEqual(result["errors"], [])
            self.assertEqual([c["version"] for c in calls], ["HTTP/1.0"] * 4)
            self.assertEqual([c["cookie"] for c in calls],
                             [None, "session=local-secret", None, "session=local-secret"])
            self.assertEqual(result["requested_protocol"], "1.0")

    def test_http11_keeps_connection_alive(self):
        with http_fixture() as (target, calls):
            result = scan(Policy(target, rps=2), protocol="1.1", crawl=False,
                          seeds=[target + "/", target + "/next"])
            self.assertEqual(result["errors"], [])
            self.assertEqual([c["version"] for c in calls], ["HTTP/1.1"] * 2)
            self.assertEqual(calls[0]["port"], calls[1]["port"])

    def test_gzip_and_deflate_both_protocols(self):
        with http_fixture() as (target, calls):
            for protocol in ("1.0", "1.1"):
                transport = Transport(Policy(target, rps=2), protocol)
                with transport.client({}) as client:
                    for route in ("/gzip", "/deflate"):
                        observation = transport.get(client, target + route)
                        self.assertEqual(observation.body, "<html>local fixture</html>")

    def test_compressed_body_retention_limit(self):
        with http_fixture() as (target, _):
            for protocol in ("1.0", "1.1"):
                transport = Transport(Policy(target, max_body=1024), protocol)
                with transport.client({}) as client:
                    observation = transport.get(client, target + "/large")
                    self.assertTrue(observation.truncated)
                    self.assertEqual(len(observation.body), 1024)

    def test_malformed_compression_is_reported(self):
        with http_fixture() as (target, _):
            for protocol in ("1.0", "1.1"):
                result = scan(Policy(target + "/invalid"), protocol=protocol, crawl=False)
                self.assertEqual(result["errors"][0]["type"], "transport-error")

    def test_strict_http2_rejects_http11_server(self):
        with http_fixture() as (target, _):
            result = scan(Policy(target), protocol="2", crawl=False)
            self.assertEqual(result["errors"][0]["type"], "transport-error")


@unittest.skipUnless(shutil.which("openssl"), "openssl required for local TLS fixture")
class LiveTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import hypercorn  # noqa: F401
        except ImportError:
            raise unittest.SkipTest('Install test extras: pip install ".[test]"')
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        try:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(cls.root / "key.pem"), "-out", str(cls.root / "cert.pem"),
                "-days", "1", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (cls.root / "fixture.py").write_text(
                "async def app(scope, receive, send):\n"
                "    body = scope['http_version'].encode()\n"
                "    await send({'type': 'http.response.start', 'status': 200, "
                "'headers': [(b'content-type', b'text/plain')]})\n"
                "    await send({'type': 'http.response.body', 'body': body})\n")
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            cls.target = f"https://127.0.0.1:{port}"
            cls.process = subprocess.Popen(
                [sys.executable, "-m", "hypercorn", "fixture:app",
                 "--bind", f"127.0.0.1:{port}",
                 "--certfile", str(cls.root / "cert.pem"),
                 "--keyfile", str(cls.root / "key.pem")],
                cwd=cls.root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(100):
                if cls.process.poll() is not None:
                    raise RuntimeError("TLS fixture exited before startup")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("TLS fixture did not start")
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        process = getattr(cls, "process", None)
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        cls.tmp.cleanup()

    def test_untrusted_certificate_rejected_for_all_protocols(self):
        for protocol in ("1.0", "1.1", "2"):
            result = scan(Policy(self.target), protocol=protocol, crawl=False)
            self.assertTrue(result["errors"], protocol)
            self.assertEqual(result["pages"], [])

    def test_trusted_tls_and_negotiated_http2(self):
        for protocol in ("1.1", "2"):
            transport = Transport(Policy(self.target), protocol,
                                  ca_file=str(self.root / "cert.pem"))
            with transport.client({}) as client:
                o = transport.get(client, self.target)
            self.assertEqual(o.body, protocol)
            self.assertEqual(o.protocol, "HTTP/" + protocol)

    def test_auto_negotiates_http2(self):
        transport = Transport(Policy(self.target), "auto",
                              ca_file=str(self.root / "cert.pem"))
        with transport.client({}) as client:
            self.assertEqual(transport.get(client, self.target).protocol, "HTTP/2")

    def test_http10_over_tls_uses_verified_context(self):
        transport = Transport(Policy(self.target), "1.0",
                              ca_file=str(self.root / "cert.pem"))
        with transport.client({}) as client:
            o = transport.get(client, self.target)
        # Hypercorn may respond in HTTP/1.1; body proves request wire version.
        self.assertEqual(o.body, "1.0")


if __name__ == "__main__":
    unittest.main()
