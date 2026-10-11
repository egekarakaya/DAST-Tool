import math
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, urlunsplit


def origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise ValueError("Target must be an HTTP(S) URL without embedded credentials")
    return p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == "https" else 80)


def canonical(url: str) -> str:
    p = urlsplit(url)
    origin(url)
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


def public_url(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


@dataclass(frozen=True)
class Policy:
    target: str
    profile: str = "production"
    rps: float = 1.0
    max_requests: int = 50
    max_depth: int = 3
    max_body: int = 262144
    timeout: float = 10.0
    max_seconds: float = 120.0
    max_errors: int = 3

    def __post_init__(self):
        origin(self.target)
        if self.profile not in {"production", "standard"}:
            raise ValueError("Unknown profile")
        if not math.isfinite(self.rps) or not 0 < self.rps <= 20:
            raise ValueError("rps must be in (0, 20]")
        if not 1 <= self.max_requests <= 10000 or not 0 <= self.max_depth <= 20:
            raise ValueError("Invalid request/depth budget")
        if not 1024 <= self.max_body <= 4194304:
            raise ValueError("max_body must be between 1 KiB and 4 MiB")
        if any(not math.isfinite(v) or v <= 0 for v in (self.timeout, self.max_seconds)):
            raise ValueError("Timeout and duration must be finite positive values")
        if self.max_errors < 1:
            raise ValueError("max_errors must be positive")
        if self.profile == "production" and (self.rps > 2 or self.max_requests > 200):
            raise ValueError("Production profile caps speed at 2 rps and budget at 200")

    def allows(self, url: str, paths: tuple[str, ...] = ("/",)) -> bool:
        try:
            if origin(url) != origin(self.target):
                return False
            p = urlsplit(url)
            decoded = unquote(unquote(p.path or "/"))
            # Fail closed on ambiguous path normalization.
            if "\\" in decoded or any(s in {".", ".."} for s in decoded.split("/")):
                return False
            if not any(decoded == prefix.rstrip("/") or
                       decoded.startswith(prefix.rstrip("/") + "/") for prefix in paths):
                return False
            if self.profile == "production":
                if p.query:
                    return False
                segments = re.split(r"[/._-]+", decoded.lower())
                if any(s in {"logout", "delete", "remove", "destroy", "reset",
                             "unsubscribe", "purchase", "checkout", "signout"} for s in segments):
                    return False
            return True
        except (ValueError, TypeError):
            return False
