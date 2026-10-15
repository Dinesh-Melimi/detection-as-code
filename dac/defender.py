"""Package rules as Microsoft Defender XDR custom detection rules (advanced hunting).

Defender XDR custom detection rules run a KQL query on the advanced-hunting schema on a schedule
and raise an alert with response actions. Only rules whose logsource maps to a Defender XDR
advanced-hunting table are exportable (endpoint, identity, email, cloud); SIEM-only sources are
skipped. Output is the JSON body for the Defender XDR custom detection API / portal import.
"""
from __future__ import annotations

from .convert import convert_rule
from .mappings import logsource_key
from .sentinel import SEVERITY, attack_tags, iso_duration

# Defender XDR advanced-hunting tables that custom detection rules can query.
AH_TABLES = {
    "windows/process_creation": "DeviceProcessEvents",
    "windows/process_access": "DeviceEvents",
    "windows/security": "IdentityLogonEvents",
    "azure/signinlogs": "AADSignInEventsBeta",
}
# Entity columns Defender uses to attribute and group alerts, per table.
IMPACTED = {
    "DeviceProcessEvents": [{"identifier": "DeviceId"}, {"identifier": "AccountSid"}],
    "DeviceEvents": [{"identifier": "DeviceId"}],
    "IdentityLogonEvents": [{"identifier": "AccountSid"}],
    "AADSignInEventsBeta": [{"identifier": "AccountObjectId"}],
}


def exportable(rule: dict) -> bool:
    return logsource_key(rule["logsource"]) in AH_TABLES


def _frequency(rule: dict) -> str:
    tf = (rule.get("correlation") or {}).get("timeframe")
    iso = iso_duration(tf)  # e.g. PT10M, PT1H, P1D
    return {"PT10M": "0", "PT1H": "1", "PT3H": "3", "PT12H": "12", "P1D": "24"}.get(iso, "1")


def custom_detection(rule: dict) -> dict:
    table = AH_TABLES[logsource_key(rule["logsource"])]
    tactics, techniques = attack_tags(rule)
    query = convert_rule(rule, "kql")
    return {
        "displayName": rule["title"][:120],
        "description": " ".join(rule.get("description", "").split())[:1000],
        "severity": SEVERITY[rule.get("level", "medium")],
        "enabled": True,
        "queryCondition": {"queryText": query},
        "schedule": {"period": _frequency(rule)},
        "detectionAction": {
            "alertTemplate": {
                "title": rule["title"][:120],
                "severity": SEVERITY[rule.get("level", "medium")],
                "category": "SuspiciousActivity",
                "mitreTechniques": techniques,
                "recommendedActions": "Investigate the impacted asset and isolate if confirmed.",
            },
            "organizationalScope": None,
            "responseActions": [],
            "impactedAssets": IMPACTED.get(table, []),
        },
        "_table": table,
        "_tactics": tactics,
    }


def export(rules: list[dict]) -> dict:
    out, skipped = [], []
    for r in rules:
        (out.append(custom_detection(r)) if exportable(r) else skipped.append(r["id"]))
    return {"rules": out, "skipped": skipped}
