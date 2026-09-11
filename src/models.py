from dataclasses import dataclass
from typing import Tuple

@dataclass(frozen=True)
class Event:
    event_id: str
    host: str
    user: str
    process: str
    action: str
    target: str
    approved_admin_tool: bool
    access_succeeded: bool
    edr_healthy: bool
    asset_criticality: str

@dataclass(frozen=True)
class Identity:
    user: str
    privileged: bool
    enabled: bool

@dataclass(frozen=True)
class Finding:
    finding_id: str
    event_id: str
    host: str
    user: str
    title: str
    technique: str
    score: int
    severity: str
    rationale: Tuple[str, ...]
