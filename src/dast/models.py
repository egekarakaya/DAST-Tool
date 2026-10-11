from dataclasses import asdict, dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    url: str
    role: str
    evidence: dict[str, str]
    remediation: str
    confidence: str = "observed-configuration"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Observation:
    url: str
    status: int
    headers: dict[str, str]
    cookies: list[str]
    body: str
    protocol: str
    truncated: bool = False


@dataclass
class Role:
    name: str = "anonymous"
    headers: dict[str, str] = field(default_factory=dict)
    paths: tuple[str, ...] = ("/",)


class Check(Protocol):
    """Future checks consume observations; they do not own network access."""
    def assess(self, observation: Observation, role: str) -> list[Finding]: ...


class CrawlPlanner(Protocol):
    """Future smart/LLM planners propose URLs; the engine always applies policy."""
    def propose(self, observation: Observation) -> list[str]: ...
