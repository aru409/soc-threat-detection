from dataclasses import dataclass


@dataclass
class Alert:
    alert_id: str
    timestamp: str
    rule_name: str
    event_type: str
    source_ip: str
    username: str
    severity: str
    confidence: float
    description: str
    mitre_technique: str
    status: str = "Open"
