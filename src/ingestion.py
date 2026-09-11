import json
from pathlib import Path
from .models import Event, Identity

CRITICALITY = {"low", "medium", "high", "critical"}
EVENT_FIELDS = {"event_id","host","user","process","action","target","approved_admin_tool","access_succeeded","edr_healthy","asset_criticality"}
IDENTITY_FIELDS = {"user","privileged","enabled"}

def _load(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("top-level JSON must be a list")
    return data

def load_events(path):
    rows = _load(path); seen=set(); out=[]
    for row in rows:
        if not isinstance(row, dict) or set(row) != EVENT_FIELDS:
            raise ValueError("event schema mismatch")
        if row["event_id"] in seen: raise ValueError("duplicate event_id")
        seen.add(row["event_id"])
        for key in ("approved_admin_tool","access_succeeded","edr_healthy"):
            if type(row[key]) is not bool: raise ValueError(f"{key} must be boolean")
        if row["asset_criticality"] not in CRITICALITY: raise ValueError("invalid criticality")
        for key in ("event_id","host","user","process","action","target"):
            if not isinstance(row[key], str) or not row[key].strip(): raise ValueError(f"invalid {key}")
        out.append(Event(**row))
    return out

def load_identities(path):
    rows=_load(path); seen=set(); out={}
    for row in rows:
        if not isinstance(row, dict) or set(row) != IDENTITY_FIELDS: raise ValueError("identity schema mismatch")
        if row["user"] in seen: raise ValueError("duplicate identity")
        seen.add(row["user"])
        if type(row["privileged"]) is not bool or type(row["enabled"]) is not bool: raise ValueError("identity flags must be boolean")
        out[row["user"]] = Identity(**row)
    return out
