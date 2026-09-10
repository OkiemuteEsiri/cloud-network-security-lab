# Architecture and Methodology

## Objective

This lab models defensive cloud-network security review across AWS, Azure and GCP using synthetic rule inventories. It focuses on exposure reduction, least privilege, ownership, explainable prioritization and revalidation.

## Processing flow

`synthetic inventory -> schema validation -> exposure analysis -> risk scoring -> ATT&CK context -> remediation -> revalidation`

The analyzer evaluates each network rule independently and produces deterministic findings. Public exposure, asset criticality and missing ownership influence priority. The score is bounded at 100 and supports triage rather than automatic enforcement.

## Controls

The current control set detects:

- public exposure of administrative or data services such as SSH, RDP, SMB and common database ports;
- any-protocol/all-port ingress from `0.0.0.0/0`;
- unrestricted all-port internet egress;
- missing accountable ownership for network rules.

## MITRE ATT&CK context

Relevant mappings include T1190 (Exploit Public-Facing Application), T1133 (External Remote Services), T1021 (Remote Services), T1071 (Application Layer Protocol) and T1041 (Exfiltration Over C2 Channel). These mappings describe plausible threat context only and do not prove compromise.

## Risk interpretation

Risk is contextual. A publicly reachable database on a critical workload should receive a higher remediation priority than an internal HTTPS rule on a lower-risk service. Missing ownership increases governance risk because stale or unnecessary rules are less likely to be reviewed and removed.

## Remediation workflow

1. Confirm the effective cloud control and its business purpose.
2. Identify the accountable workload owner.
3. Remove direct public exposure where it is not explicitly required.
4. Reduce source, destination, protocol and port scope to least privilege.
5. Prefer private connectivity, approved bastion patterns, ZTNA or managed service endpoints where appropriate.
6. Re-evaluate effective controls after the change.
7. Validate that intended application connectivity still works without recreating the original exposure.

## Limitations

The lab does not connect to live cloud tenants, alter security groups/NSGs/firewall rules, scan public services, or claim production posture coverage. Provider-specific inheritance, route tables, service tags, peering and identity-aware controls are simplified for portfolio clarity.
