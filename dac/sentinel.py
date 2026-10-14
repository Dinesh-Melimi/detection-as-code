"""Package rules as Microsoft Sentinel scheduled analytics rules (ARM template).

Each rule becomes a `Microsoft.SecurityInsights/alertRules` resource with its KQL, severity,
schedule, ATT&CK tactics and techniques, entity mappings (for UEBA and investigation graphs),
and incident grouping. Deploy with:

    az deployment group create -g <rg> --template-file build/sentinel/analytics-rules.json \
        --parameters workspace=<log-analytics-workspace-name>
"""

from __future__ import annotations

import re
import uuid

from . import attack
from .convert import convert_rule
from .mappings import logsource_key

SEVERITY = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low",
            "informational": "Informational"}

# logsource -> [(entityType, identifier, KQL column)]; only columns that survive the query are used.
ENTITIES = {
    "windows/process_creation": [("Host", "HostName", "DeviceName"), ("Account", "Name", "AccountName"),
                                 ("Process", "CommandLine", "ProcessCommandLine")],
    "windows/process_access": [("Host", "HostName", "Computer")],
    "windows/security": [("Host", "HostName", "Computer"), ("Account", "Name", "TargetUserName"),
                         ("IP", "Address", "IpAddress")],
    "aws/cloudtrail": [("Account", "FullName", "UserIdentityArn"), ("IP", "Address", "SourceIpAddress")],
    "azure/signinlogs": [("Account", "FullName", "UserPrincipalName"), ("IP", "Address", "IPAddress")],
}

_UNITS = {"m": "M", "h": "H", "d": "D"}


def iso_duration(timeframe: str | None, default: str = "PT1H") -> str:
    if not timeframe:
        return default
    m = re.fullmatch(r"(\d+)([mhd])", timeframe.strip())
    if not m:
        raise ValueError(f"unsupported timeframe {timeframe!r}")
    n, unit = m.groups()
    return f"P{n}D" if unit == "d" else f"PT{n}{_UNITS[unit]}"


def tactic_name(tactic: str) -> str:
    return "".join(part.capitalize() for part in tactic.split("-"))


def attack_tags(rule: dict) -> tuple[list[str], list[str]]:
    tactics, techniques = [], []
    for tag in rule.get("tags", []):
        value = tag.removeprefix("attack.")
        if re.fullmatch(r"t\d{4}(\.\d{3})?", value):
            tid = value.upper()
            base = tid.split(".")[0]
            if base not in techniques:
                techniques.append(base)
            for t in attack.TECHNIQUES.get(tid, ("", []))[1]:
                if tactic_name(t) not in tactics:
                    tactics.append(tactic_name(t))
        elif value in attack.TACTICS and tactic_name(value) not in tactics:
            tactics.append(tactic_name(value))
    return tactics, techniques


def output_columns(query: str) -> set[str] | None:
    """Columns left after a summarize (None means the query keeps every column)."""
    m = re.search(r"\|\s*summarize\b.*?\bby\s+([^\n]+)", query)
    if not m:
        return None
    by = re.sub(r"\w+\([^)]*\)", "", m.group(1))  # drop bin(TimeGenerated, 1h) and similar
    return {c.strip() for c in by.split(",") if c.strip()}


def entity_mappings(rule: dict, query: str) -> list[dict]:
    cols = output_columns(query)
    out = []
    for etype, ident, column in ENTITIES.get(logsource_key(rule["logsource"]), []):
        if cols is None or column in cols:
            out.append({"entityType": etype, "fieldMappings": [{"identifier": ident, "columnName": column}]})
    return out


def analytic_rule(rule: dict) -> dict:
    query = convert_rule(rule, "kql")
    timeframe = (rule.get("correlation") or {}).get("timeframe")
    tactics, techniques = attack_tags(rule)
    rule_id = str(uuid.UUID(rule["id"]))
    props = {
        "displayName": rule["title"],
        "description": " ".join(rule.get("description", "").split()),
        "severity": SEVERITY[rule.get("level", "medium")],
        "enabled": True,
        "query": query,
        "queryFrequency": iso_duration(timeframe),
        "queryPeriod": iso_duration(timeframe),
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionEnabled": False,
        "suppressionDuration": "PT5H",
        "tactics": tactics,
        "techniques": techniques,
        "entityMappings": entity_mappings(rule, query),
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": True, "reopenClosedIncident": False, "lookbackDuration": "PT5H",
                "matchingMethod": "AllEntities", "groupByEntities": [], "groupByAlertDetails": [],
                "groupByCustomDetails": [],
            },
        },
        "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
    }
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": "2023-02-01",
        "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', '{rule_id}')]",
        "kind": "Scheduled",
        "properties": props,
    }


def arm_template(rules: list[dict]) -> dict:
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {"workspace": {
            "type": "string",
            "metadata": {"description": "Log Analytics workspace with Sentinel enabled"},
        }},
        "resources": [analytic_rule(r) for r in rules],
    }
