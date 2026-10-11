import time
import ssl
import httpx
from .models import Observation
from .policy import Policy


class BudgetExceeded(RuntimeError):
    pass


class Transport:
    """One pooled client per role; shared scan budget and pacing across roles."""
    def __init__(self, policy: Policy, protocol: str = "auto", client_factory=httpx.Client, ca_file=None):
        if protocol not in {"auto", "1.0", "1.1", "2"}:
            raise ValueError("Supported protocol modes: auto, 1.0, 1.1, 2")
        self.policy = policy
        self.protocol = protocol
        self.client_factory = client_factory
        self.context = ssl.create_default_context(cafile=ca_file)
        self.requests = 0
        self.next_request = 0.0
        self.started = time.monotonic()

    def client(self, headers: dict[str, str]):
        forbidden = {"host", "content-length", "transfer-encoding", "connection"}
        if any(k.lower() in forbidden for k in headers):
            raise ValueError("Transport routing/framing headers cannot be overridden")
        options = {}
        if self.protocol == "1.0":
            from .http10 import HTTP10Adapter
            options["transport"] = HTTP10Adapter(self.context, self.policy.timeout)
        return self.client_factory(
            **options,
            http2=self.protocol in {"auto", "2"}, verify=self.context, follow_redirects=False,
            trust_env=False, timeout=httpx.Timeout(self.policy.timeout),
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
            headers={"User-Agent": "DAST-Tool/0.1", **headers},
        )

    def get(self, client, url: str) -> Observation:
        now = time.monotonic()
        delay = max(0.0, self.next_request - now)
        if self.requests >= self.policy.max_requests:
            raise BudgetExceeded("request-budget")
        if now + delay - self.started >= self.policy.max_seconds:
            raise BudgetExceeded("duration-budget")
        time.sleep(delay)
        self.next_request = time.monotonic() + 1.0 / self.policy.rps
        self.requests += 1
        body = bytearray()
        truncated = False
        with client.stream("GET", url) as response:
            if self.protocol == "2" and response.http_version != "HTTP/2":
                raise ValueError("Server did not negotiate HTTP/2")
            for chunk in response.iter_bytes(chunk_size=8192):
                remaining = self.policy.max_body - len(body)
                body.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break
                if time.monotonic() - self.started >= self.policy.max_seconds:
                    raise BudgetExceeded("duration-budget")
            return Observation(
                url=url, status=response.status_code,
                headers=dict(response.headers),
                cookies=response.headers.get_list("set-cookie"),
                body=bytes(body).decode("utf-8", errors="replace"),
                protocol=response.http_version, truncated=truncated,
            )
