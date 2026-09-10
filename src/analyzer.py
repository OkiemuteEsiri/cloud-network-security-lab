from __future__ import annotations
from hashlib import sha256
from ipaddress import ip_network
from .models import Finding, NetworkRule

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 445: "SMB", 5432: "PostgreSQL", 3306: "MySQL", 1433: "MSSQL"}
CRITICALITY_WEIGHT = {"low": 0, "medium": 6, "high": 12, "critical": 18}


def _public_cidr(value: str) -> bool:
    try:
        net = ip_network(value, strict=False)
    except ValueError:
        return False
    return net.prefixlen == 0


def _id(rule: NetworkRule, title: str) -> str:
    raw = f"{rule.provider}|{rule.account}|{rule.resource}|{rule.direction}|{rule.protocol}|{rule.port_start}-{rule.port_end}|{rule.source}|{rule.destination}|{title}"
    return "CNS-" + sha256(raw.encode()).hexdigest()[:12].upper()


def assess_rule(rule: NetworkRule) -> list[Finding]:
    findings: list[Finding] = []
    exposed = rule.internet_exposed or _public_cidr(rule.source)
    criticality = CRITICALITY_WEIGHT[rule.criticality]

    def add(title: str, base: int, why: list[str], techniques: tuple[str, ...], remediation: str, validation: str) -> None:
        score = min(100, base + criticality + (12 if exposed else 0) + (6 if not rule.owner else 0))
        severity = "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 45 else "low"
        findings.append(Finding(_id(rule, title), title, severity, score, rule.resource, rule.provider, tuple(why), techniques, remediation, validation))

    if rule.direction == "ingress" and exposed:
        sensitive = [p for p in SENSITIVE_PORTS if rule.port_start <= p <= rule.port_end]
        if sensitive:
            names = ", ".join(f"{SENSITIVE_PORTS[p]}:{p}" for p in sensitive)
            add(
                "Internet-exposed administrative or data service",
                58,
                [f"Public ingress reaches {names}", f"Asset criticality is {rule.criticality}"],
                ("T1133", "T1021", "T1190"),
                "Remove direct internet exposure; use private connectivity, approved bastion/ZTNA patterns, and source restrictions.",
                "Re-evaluate the effective rule set and confirm the service is unreachable from public address space.",
            )

    if rule.direction == "ingress" and _public_cidr(rule.source) and rule.port_start == 0 and rule.port_end == 65535:
        add(
            "Any-protocol public ingress",
            64,
            ["Source is 0.0.0.0/0", "All ports are permitted"],
            ("T1190", "T1133"),
            "Replace broad ingress with least-privilege protocol, port and source controls.",
            "Confirm no equivalent all-port public rule remains after remediation.",
        )

    if rule.direction == "egress" and _public_cidr(rule.destination) and rule.port_start == 0 and rule.port_end == 65535:
        add(
            "Unrestricted internet egress",
            42,
            ["Destination is 0.0.0.0/0", "All ports are permitted"],
            ("T1071", "T1041"),
            "Constrain egress to required destinations/protocols and route through monitored control points where appropriate.",
            "Review effective egress policy and verify only approved destinations and ports remain.",
        )

    if not rule.owner:
        add(
            "Network rule lacks accountable owner",
            28,
            ["No owner is recorded for the network control"],
            (),
            "Assign a technical/business owner and document rule purpose and review cadence.",
            "Verify ownership metadata and next review date are present in the authoritative inventory.",
        )

    return findings


def assess(rules: list[NetworkRule]) -> list[Finding]:
    results = [finding for rule in rules for finding in assess_rule(rule)]
    return sorted(results, key=lambda f: (-f.score, f.finding_id))
