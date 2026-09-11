# Credential Access Detection Lab

Defensive security-engineering project for identifying credential-access risk from synthetic endpoint and identity telemetry. The project contains no credential dumping, extraction, password recovery, exploitation, or live-host targeting logic.

## Problem statement

Credential-access activity is high impact because stolen authentication material can enable account takeover, lateral movement and persistence. A useful defensive workflow must correlate endpoint behavior with identity context, distinguish normal administration from suspicious access, prioritize findings transparently, and require validation evidence before closure.

## Architecture

```text
Synthetic telemetry + identity context
              |
              v
        strict ingestion
              |
              v
      detection rules engine
              |
              v
   contextual risk enrichment
              |
              v
   prioritized findings/report
              |
              v
 remediation evidence validation
```

## What the project detects

The engine analyzes synthetic telemetry for:

- unexpected access to LSASS by non-approved processes;
- browser credential-store access from unusual processes;
- suspicious Security Account Manager / SYSTEM hive access indicators;
- excessive credential-manager enumeration;
- privileged identity context combined with endpoint credential-access signals.

All detections are based on pre-generated fictional telemetry. Nothing in this repository performs credential extraction.

## MITRE ATT&CK context

| Technique | Purpose in this project |
|---|---|
| T1003 - OS Credential Dumping | Detection context for suspicious credential-process and protected-store access |
| T1003.001 - LSASS Memory | Detection context for abnormal LSASS access |
| T1003.002 - Security Account Manager | Detection context for SAM-related telemetry |
| T1555 - Credentials from Password Stores | Detection context for browser/password-store access |
| T1555.004 - Windows Credential Manager | Detection context for abnormal credential-manager enumeration |
| T1078 - Valid Accounts | Downstream identity-risk context only |

ATT&CK mappings are threat-model references, not claims that compromise occurred.

## Repository structure

```text
.
├── .github/workflows/security-quality.yml
├── data/
│   ├── synthetic_events.json
│   └── identity_context.json
├── docs/
│   └── methodology.md
├── reports/
│   └── example-assessment.md
├── src/
│   ├── __init__.py
│   ├── models.py
│   ├── ingestion.py
│   ├── detector.py
│   ├── remediation.py
│   ├── reporting.py
│   └── cli.py
└── tests/
    └── test_credential_access.py
```

## Risk model

Each finding receives a bounded 0-100 contextual score. The score is intentionally explainable rather than ML-based.

- base detection confidence: up to 45 points;
- privileged identity context: +20;
- critical asset: +15;
- successful/confirmed protected-store access: +10;
- missing endpoint protection: +10;
- approved administrative tooling: -25;
- disabled identity: -10.

Severity thresholds: Critical >= 85, High >= 70, Medium >= 45, Low < 45.

## Usage

```bash
python -m src.cli \
  --events data/synthetic_events.json \
  --identity-context data/identity_context.json \
  --output reports/generated-assessment.md
```

No third-party Python packages are required.

## Testing

```bash
python -m unittest discover -s tests -v
```

The tests cover ingestion validation, detection logic, scoring boundaries, deterministic IDs, prioritization, ATT&CK mappings, reporting, and remediation-evidence closure.

## Remediation workflow

A finding is not considered validated merely because a ticket says "fixed". Closure requires evidence of an accountable owner, a change reference, containment/remediation action, endpoint validation, identity/session review where relevant, detection retest and a passing validation result.

## Design decisions

- **Offline by design:** no endpoint, AD, EDR, browser, registry or memory access.
- **Synthetic data only:** avoids confidential or employer/client telemetry.
- **Fail closed:** malformed or duplicate evidence is rejected rather than silently normalized.
- **Deterministic findings:** stable SHA-derived IDs support repeatable tests and workflow tracking.
- **Explainable scoring:** each score includes human-readable rationale.
- **Separation of detection and validation:** technical exposure and remediation governance remain distinct.

## Limitations

This is a portfolio lab, not a replacement for EDR, SIEM or identity-provider analytics. Synthetic events simplify real-world process ancestry, signer reputation, token state, memory telemetry, baseline learning and enterprise allow-list governance. ATT&CK mappings describe defensive coverage, not confirmed attacker behavior.

## Skills demonstrated

Detection engineering, Windows credential-access threat modeling, Python security automation, defensive ATT&CK mapping, data validation, contextual risk prioritization, remediation validation, unit testing, technical documentation and CI/CD quality controls.

## Roadmap

- add synthetic Sysmon/EDR adapter schemas;
- add process-tree and signer-reputation enrichment;
- add time-window correlation and host baselining;
- export JSON alongside Markdown;
- add Sigma-style rule translation examples;
- add trend comparison across assessment snapshots.

## Safety

This repository intentionally excludes passwords, hashes, tokens, credential-dumping utilities, memory-reading code, registry-hive extraction, offensive payloads and live-target interaction.

## License

MIT
