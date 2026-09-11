REQUIRED = {"finding_id","owner","change_reference","remediation_action","endpoint_validated","identity_reviewed","detection_retested","validation_passed"}

def validate_closure(record):
    if not isinstance(record, dict) or set(record) != REQUIRED:
        return "invalid_closure", ["schema mismatch"]
    missing=[]
    for key in ("finding_id","owner","change_reference","remediation_action"):
        if not isinstance(record[key],str) or not record[key].strip(): missing.append(key)
    for key in ("endpoint_validated","identity_reviewed","detection_retested","validation_passed"):
        if type(record[key]) is not bool: return "invalid_closure", [f"{key} must be boolean"]
        if not record[key]: missing.append(key)
    return ("validated", []) if not missing else ("needs_evidence", missing)
