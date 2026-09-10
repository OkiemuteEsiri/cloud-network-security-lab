from __future__ import annotations
from collections import Counter
from .models import Finding


def metrics(findings: list[Finding]) -> dict[str, object]:
    by_severity = Counter(f.severity for f in findings)
    by_provider = Counter(f.provider for f in findings)
    return {
        "total": len(findings),
        "by_severity": dict(sorted(by_severity.items())),
        "by_provider": dict(sorted(by_provider.items())),
        "highest_score": max((f.score for f in findings), default=0),
        "critical_or_high": sum(f.severity in {"critical", "high"} for f in findings),
    }


def markdown(findings: list[Finding]) -> str:
    m = metrics(findings)
    lines = [
        "# Cloud Network Security Assessment",
        "",
        "> Synthetic multi-cloud assessment output. This is not production telemetry.",
        "",
        f"- Total findings: **{m['total']}**",
        f"- Critical/High: **{m['critical_or_high']}**",
        f"- Highest score: **{m['highest_score']}/100**",
        "",
        "| ID | Provider | Resource | Severity | Score | Finding |",
        "|---|---|---|---|---:|---|",
    ]
    for f in findings:
        lines.append(f"| {f.finding_id} | {f.provider.upper()} | {f.resource} | {f.severity.title()} | {f.score} | {f.title} |")
    for f in findings:
        lines.extend([
            "",
            f"## {f.finding_id} — {f.title}",
            f"**Rationale:** {'; '.join(f.rationale)}",
            f"**ATT&CK:** {', '.join(f.attack_techniques) if f.attack_techniques else 'Governance control'}",
            f"**Remediation:** {f.remediation}",
            f"**Validation:** {f.validation}",
        ])
    return "\n".join(lines) + "\n"
