from .detector import metrics

def render(findings):
    m=metrics(findings)
    lines=["# Credential Access Assessment","","## Executive summary",f"- Total findings: **{m['total']}**",f"- Critical: **{m['severity']['critical']}**",f"- High: **{m['severity']['high']}**",f"- Highest contextual score: **{m['highest_score']}**",f"- ATT&CK context: {', '.join(m['techniques']) or 'None'}","","## Prioritized findings",""]
    for f in findings:
        lines += [f"### {f.finding_id} - {f.title}",f"- Severity: **{f.severity.upper()}** ({f.score}/100)",f"- Host: `{f.host}`",f"- Identity: `{f.user}`",f"- MITRE ATT&CK: `{f.technique}`","- Rationale:"] + [f"  - {r}" for r in f.rationale] + [""]
    lines += ["## Remediation and validation","1. Confirm whether activity is authorized and isolate affected endpoint if warranted.","2. Review identity privilege, active sessions and authentication telemetry.","3. Restore/verify endpoint protection and reduce unnecessary privileged access.","4. Retest the detection after remediation.","5. Close only with accountable ownership, change evidence and a passing validation result.","","> Synthetic portfolio assessment. ATT&CK mappings are defensive context, not evidence of compromise."]
    return "\n".join(lines)+"\n"
