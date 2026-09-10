# Cloud Network Security Lab

A recruiter-facing defensive security engineering project for reviewing cloud network controls across AWS, Azure and GCP. The lab turns synthetic security-group, NSG and firewall-rule data into explainable findings, remediation priorities and revalidation steps.

## Problem statement

Cloud environments accumulate network rules quickly. Public administrative exposure, broad ingress, unrestricted egress and missing rule ownership can increase attack surface and make remediation difficult. This project demonstrates how to normalize provider-neutral rule data, validate configuration, identify meaningful exposure, score findings and communicate remediation clearly.

## Architecture

```text
Synthetic AWS/Azure/GCP rule inventory
                |
                v
        Schema validation
                |
                v
       Exposure analysis
                |
                v
 Contextual risk scoring (0-100)
                |
                v
 ATT&CK mapping + reporting
                |
                v
 Remediation + revalidation
```

## Implemented capabilities

- provider-neutral AWS, Azure and GCP rule model
- CIDR and port-range validation
- public-ingress identification
- sensitive service exposure detection for SSH, RDP, SMB and common database ports
- all-port public ingress detection
- unrestricted internet egress detection
- missing-rule-owner governance checks
- deterministic finding IDs
- bounded 0-100 contextual risk scoring
- Critical/High/Medium/Low classification
- ATT&CK contextual mappings
- synthetic multi-cloud rule inventory
- Markdown assessment reporting
- unit tests
- least-privilege GitHub Actions CI

## Repository structure

```text
src/models.py                    validated network rule/finding models
src/analyzer.py                  exposure and governance analysis
src/reporting.py                 metrics and Markdown reporting
data/synthetic_rules.json        realistic synthetic multi-cloud rules
tests/test_analyzer.py           unit tests
docs/architecture-methodology.md methodology and remediation workflow
.github/workflows/ci.yml         compile and test gate
README.md                        recruiter-facing overview
```

## Risk model

Findings receive a base risk score that is adjusted by workload criticality, public exposure and missing ownership. Scores are capped at 100 and mapped to severity tiers. The model is intentionally explainable: each finding contains rationale, ATT&CK context, remediation guidance and validation criteria.

This score is a prioritization mechanism, not proof that exploitation occurred.

## MITRE ATT&CK context

Relevant mappings include:

- **T1190** — Exploit Public-Facing Application
- **T1133** — External Remote Services
- **T1021** — Remote Services
- **T1071** — Application Layer Protocol
- **T1041** — Exfiltration Over C2 Channel

ATT&CK mappings are threat-context annotations only and are not compromise evidence.

## Testing

The current unit suite covers invalid providers, invalid port ranges, public RDP exposure, internal HTTPS behavior, all-port public ingress, unrestricted egress, missing ownership, bounded scores and deterministic result ordering.

Run locally with:

```bash
python -m unittest discover -s tests -v
```

## Remediation and validation workflow

1. Confirm the effective rule and its business purpose.
2. Identify the accountable workload owner.
3. Remove unnecessary public exposure.
4. Narrow source, destination, protocol and port scope.
5. Prefer private connectivity, approved bastion or ZTNA patterns where appropriate.
6. Re-evaluate the effective rule set after remediation.
7. Confirm intended application connectivity still works.
8. Record closure evidence and maintain periodic rule review.

## Skills demonstrated

Cloud security engineering, attack-surface reduction, network segmentation, security control validation, risk-based prioritization, AWS/Azure/GCP security concepts, ATT&CK mapping, Python defensive tooling, unit testing, CI/CD security controls, remediation governance and executive-style reporting.

## Limitations

This lab intentionally uses synthetic data and simplified provider-neutral models. It does not connect to live AWS, Azure or GCP tenants, change security controls, scan services, ingest confidential telemetry, or claim production posture coverage. Route tables, service tags, peering, transit constructs and identity-aware network controls are simplified.

## Roadmap

- add provider-specific adapters for exported AWS/Azure/GCP configuration
- model route tables and peering paths
- add exception governance and expiry tracking
- add flow-log correlation for exposure validation
- add JSON/CSV report export
- add policy-as-code examples for preventive controls

## Safety

All data is synthetic. No credentials, employer/client data, production targets, exploit payloads or live cloud changes are included.
