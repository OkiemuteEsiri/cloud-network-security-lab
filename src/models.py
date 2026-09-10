from __future__ import annotations
from dataclasses import dataclass
from ipaddress import ip_network

ALLOWED_PROVIDERS = {"aws", "azure", "gcp"}
ALLOWED_DIRECTIONS = {"ingress", "egress"}

@dataclass(frozen=True)
class NetworkRule:
    provider: str
    account: str
    resource: str
    direction: str
    protocol: str
    port_start: int
    port_end: int
    source: str
    destination: str
    internet_exposed: bool
    owner: str = ""
    criticality: str = "medium"

    def __post_init__(self) -> None:
        if self.provider not in ALLOWED_PROVIDERS:
            raise ValueError(f"unsupported provider: {self.provider}")
        if self.direction not in ALLOWED_DIRECTIONS:
            raise ValueError(f"unsupported direction: {self.direction}")
        if not 0 <= self.port_start <= self.port_end <= 65535:
            raise ValueError("invalid port range")
        if self.criticality not in {"low", "medium", "high", "critical"}:
            raise ValueError("invalid criticality")
        # Fail closed on malformed CIDRs when values are CIDR-like.
        for value in (self.source, self.destination):
            if "/" in value:
                ip_network(value, strict=False)

@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    score: int
    resource: str
    provider: str
    rationale: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    remediation: str
    validation: str
