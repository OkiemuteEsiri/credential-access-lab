import hashlib
from .models import Finding

RULES = {
    ("process_access", "lsass.exe"): ("Unexpected LSASS access", "T1003.001", 45),
    ("credential_store_access", "browser_store"): ("Unusual browser credential-store access", "T1555", 38),
    ("registry_access", "sam_system"): ("Suspicious SAM/SYSTEM access telemetry", "T1003.002", 42),
    ("credential_manager_enum", "windows_credential_manager"): ("Excessive Credential Manager enumeration", "T1555.004", 35),
}
CRIT = {"low":0,"medium":5,"high":10,"critical":15}

def _severity(score):
    return "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 45 else "low"

def _id(event, technique):
    raw=f"{event.event_id}|{event.host}|{event.user}|{technique}".encode()
    return "CA-" + hashlib.sha256(raw).hexdigest()[:12].upper()

def assess(events, identities):
    findings=[]
    for e in events:
        rule=RULES.get((e.action,e.target))
        if not rule: continue
        title, technique, score = rule; why=[f"rule base={score}"]
        ident=identities.get(e.user)
        if ident and ident.privileged: score += 20; why.append("privileged identity +20")
        if e.asset_criticality in CRIT and CRIT[e.asset_criticality]: score += CRIT[e.asset_criticality]; why.append(f"asset criticality +{CRIT[e.asset_criticality]}")
        if e.access_succeeded: score += 10; why.append("access succeeded +10")
        if not e.edr_healthy: score += 10; why.append("EDR unhealthy +10")
        if e.approved_admin_tool: score -= 25; why.append("approved admin tool -25")
        if ident and not ident.enabled: score -= 10; why.append("disabled identity -10")
        score=max(0,min(100,score))
        findings.append(Finding(_id(e,technique),e.event_id,e.host,e.user,title,technique,score,_severity(score),tuple(why)))
    return sorted(findings,key=lambda f:(-f.score,f.finding_id))

def metrics(findings):
    sev={s:0 for s in ("critical","high","medium","low")}
    for f in findings: sev[f.severity]+=1
    return {"total":len(findings),"severity":sev,"techniques":sorted({f.technique for f in findings}),"highest_score":max((f.score for f in findings),default=0)}
