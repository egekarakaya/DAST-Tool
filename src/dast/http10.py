"""Explicit HTTP/1.0 adapter; one connection per request, no proxy/redirect handling."""
import http.client
import ssl
import httpx


class HTTP10Connection(http.client.HTTPConnection):
    # CPython's protocol selectors are covered by live wire-version tests.
    _http_vsn = 10
    _http_vsn_str = "HTTP/1.0"


class HTTPS10Connection(http.client.HTTPSConnection):
    _http_vsn = 10
    _http_vsn_str = "HTTP/1.0"


class ResponseStream(httpx.SyncByteStream):
    def __init__(self, response, connection):
        self.response = response
        self.connection = connection

    def __iter__(self):
        try:
            while chunk := self.response.read(8192):
                yield chunk
        except (OSError, http.client.HTTPException) as exc:
            raise httpx.ReadError("HTTP/1.0 response read failed") from exc

    def close(self):
        self.response.close()
        self.connection.close()


class HTTP10Adapter(httpx.BaseTransport):
    def __init__(self, context: ssl.SSLContext, timeout: float):
        self.context = context
        self.timeout = timeout

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            raise ValueError("HTTP/1.0 adapter supports GET only")
        url = request.url
        if url.scheme not in {"http", "https"}:
            raise ValueError("Unsupported scheme")
        connection = (
            HTTPS10Connection(url.host, url.port, timeout=self.timeout, context=self.context)
            if url.scheme == "https" else
            HTTP10Connection(url.host, url.port, timeout=self.timeout))
        try:
            headers = {k.decode("ascii"): v.decode("latin-1") for k, v in request.headers.raw
                       if k.lower() != b"connection"}
            # HTTP/1.0 persistence requires server-specific negotiation.
            headers["Connection"] = "close"
            connection.request("GET", url.raw_path.decode("ascii"), headers=headers)
            response = connection.getresponse()
            if response.version not in {10, 11}:
                raise ValueError("Unsupported HTTP response version")
            return httpx.Response(
                response.status, headers=response.getheaders(),
                stream=ResponseStream(response, connection),
                extensions={"http_version": b"HTTP/1.0" if response.version == 10 else b"HTTP/1.1"},
            )
        except (OSError, http.client.HTTPException) as exc:
            connection.close()
            raise httpx.ConnectError("HTTP/1.0 request failed", request=request) from exc
        except Exception:
            connection.close()
            raise
