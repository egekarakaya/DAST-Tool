"""Deliberately weak local training fixture. Synthetic data; loopback binding only."""
import argparse
import html
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def make_server(port=8080, mode="vulnerable"):
    if mode not in {"vulnerable", "fixed"}:
        raise ValueError("Unknown demo mode")
    fixed = mode == "fixed"
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *args):
            pass

        def do_GET(self):
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query, keep_blank_values=True)
            status, content_type = 200, "text/html; charset=utf-8"
            if parsed.path == "/":
                body = """<html><head><title>DAST local lab</title></head><body>
                <h1>DAST local lab</h1><p>Synthetic data only.</p>
                <a href="/search?q=hello">Search</a>
                <a href="/item?id=1">Item API</a>
                <a href="/admin">Admin page</a>
                <a href="/login">Login form</a>
                <a href="/errors">Error handling</a>
                <a href="/files/">Directory</a>
                <a href="/api/health">Health API</a>"""
                if not fixed:
                    body += '<a href="/?sessionid=demo-session-value">Session URL</a>'
                    body += '<script src="https://cdn.example.invalid/demo.js"></script>'
                body += "</body></html>"
            elif parsed.path == "/search":
                value = query.get("q", [""])[0]
                body = "<html><h1>Search</h1><p>" + (html.escape(value) if fixed else value) + "</p></html>"
            elif parsed.path == "/item":
                value = query.get("id", ["1"])[0]
                # Transient, read-only SELECT against hard-coded synthetic values.
                with sqlite3.connect(":memory:") as db:
                    try:
                        sql = "SELECT 'Demo item' WHERE '1' = ?"
                        rows = db.execute(sql, (value,)).fetchall() if fixed else db.execute(
                            "SELECT 'Demo item' WHERE '1' = '" + value + "'").fetchall()
                        body = json.dumps({"items": rows})
                        content_type = "application/json"
                    except sqlite3.Error:
                        body = "sqlite3.OperationalError: unrecognized token: demo"
            elif parsed.path == "/admin":
                if fixed and self.headers.get("Authorization") != "Bearer demo-admin":
                    status, body = 403, "Forbidden"
                else:
                    body = "<html><h1>DEMO_ADMIN_PANEL</h1><p>Synthetic admin data.</p></html>"
            elif parsed.path == "/login":
                body = ("<html>Demo fixed mode: use HTTPS before accepting credentials.</html>" if fixed else
                        '<html><form action="/login" method="get"><input name="password" type="password"></form></html>')
            elif parsed.path == "/errors":
                status = 400 if fixed else 500
                body = "Request could not be processed." if fixed else (
                    "Traceback (most recent call last):\n  File demo.py, line 1\nValueError: demo diagnostic")
            elif parsed.path == "/files/":
                body = "<html>Files are not listed.</html>" if fixed else (
                    '<html><title>Index of /files/</title><h1>Index of /files/</h1><a href="/">Parent</a></html>')
            elif parsed.path == "/api/health":
                content_type, body = "application/json", '{"status":"ok"}'
            else:
                status, body = 404, "Not found"
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            if fixed:
                self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
            else:
                self.send_header("Set-Cookie", "demo-session=synthetic; Path=/")
                self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(payload)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--mode", choices=["vulnerable", "fixed"], default="vulnerable")
    args = parser.parse_args()
    server = make_server(args.port, args.mode)
    print(f"DAST {args.mode} lab: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
