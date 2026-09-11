# Methodology

## Objective

Model a safe, repeatable credential-access detection workflow using synthetic evidence. The repository demonstrates defensive engineering rather than credential acquisition.

## Trust boundaries

1. **Input boundary** - JSON is untrusted until schema, types, uniqueness and controlled enumerations pass validation.
2. **Correlation boundary** - endpoint events are correlated only with supplied synthetic identity context.
3. **Decision boundary** - deterministic rules generate findings; no finding is automatically treated as compromise.
4. **Closure boundary** - remediation is separate from detection and requires explicit validation evidence.

## Detection methodology

The rules focus on telemetry patterns defenders commonly investigate: LSASS access, protected registry-hive access indicators, browser credential-store access and Credential Manager enumeration. Each rule maps to ATT&CK context and produces a base confidence score.

The implementation never opens protected processes, reads memory, accesses browser databases, exports registry hives, requests credentials or authenticates to external systems.

## Contextual prioritization

Technical signal is enriched with:

- privileged identity status;
- asset criticality;
- whether access succeeded;
- endpoint protection health;
- approved-tool context;
- disabled identity state.

Scores are bounded to 0-100 and converted into explicit severity bands. Approved administrative tooling reduces urgency but does not remove the event from visibility.

## Validation workflow

Recommended operational lifecycle:

1. triage and determine whether activity is expected;
2. contain endpoint/account only when supported by evidence and organizational procedures;
3. remediate root cause and reduce unnecessary privileges;
4. validate endpoint controls and identity/session state;
5. rerun or retest the detection;
6. record accountable owner and change reference;
7. close only if validation passes.

## Limitations

Real enterprise detections require richer process lineage, code-signing state, EDR sensor fidelity, baseline learning, identity-provider telemetry, service-account governance and tuning against approved administrative software. This lab deliberately stays offline and synthetic.
