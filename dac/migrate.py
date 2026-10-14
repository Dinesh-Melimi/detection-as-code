"""Legacy SIEM -> Microsoft Sentinel migration planning.

Input: an export of legacy saved searches (e.g. Splunk savedsearches.conf flattened to CSV)
with columns name, datasource, techniques ("T1105;T1059.001"). Output: which legacy detections
are already covered by a tested rule in this repo, which are partial or gaps, and which data
sources still need a Sentinel connector or log forwarder before rules can be moved.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .rules import LoadedRule

UNKNOWN_SOURCE = ("unknown", "custom connector + parser (Logs Ingestion API / DCR)")

# legacy sourcetype -> (Sentinel table, how to onboard it)
DATASOURCES = {
    "xmlwineventlog:microsoft-windows-sysmon/operational": ("Event / DeviceProcessEvents",
                                                            "AMA + DCR, or Defender for Endpoint"),
    "wineventlog:security": ("SecurityEvent", "Windows Security Events via AMA"),
    "aws:cloudtrail": ("AWSCloudTrail", "Amazon Web Services S3 connector"),
    "azure:aad:signin": ("SigninLogs", "Microsoft Entra ID connector"),
    "o365:management:activity": ("OfficeActivity", "Microsoft 365 connector"),
    "pan:traffic": ("CommonSecurityLog", "CEF via AMA on a Linux log forwarder"),
    "pan:threat": ("CommonSecurityLog", "CEF via AMA on a Linux log forwarder"),
    "cisco:asa": ("CommonSecurityLog", "CEF/Syslog via AMA on a Linux log forwarder"),
    "linux_secure": ("Syslog", "Syslog via AMA"),
    "crowdstrike:events:sensor": ("CrowdStrike_*_CL",
                                  "CrowdStrike Falcon Data Replicator connector (custom table)"),
    "okta:im2": ("Okta_CL", "Okta SSO connector (custom table + parser)"),
}


def _techniques(cell: str) -> list[str]:
    return [t.strip().upper() for t in (cell or "").replace(",", ";").split(";") if t.strip()]


def covered_techniques(rules: list[LoadedRule]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for r in rules:
        for tag in r.data.get("tags", []):
            t = tag.removeprefix("attack.").upper()
            if t.startswith("T") and t[1:5].isdigit():
                out.setdefault(t, []).append(r.name)
                out.setdefault(t.split(".")[0], []).append(r.name)
    return out


def plan(legacy_csv: str | Path, rules: list[LoadedRule]) -> dict:
    cov = covered_techniques(rules)
    items, sources = [], {}
    with open(legacy_csv, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            techs = _techniques(row.get("techniques", ""))
            hits = {t: sorted(set(cov.get(t, []))) for t in techs}
            covered = [t for t, h in hits.items() if h]
            if not techs:
                status = "needs review (no ATT&CK mapping)"
            elif len(covered) == len(techs):
                status = "migrated"
            elif covered:
                status = "partial"
            else:
                status = "gap"
            ds = (row.get("datasource") or "").strip().lower()
            table, how = DATASOURCES.get(ds, UNKNOWN_SOURCE)
            sources.setdefault(ds, {"table": table, "onboarding": how, "detections": 0})["detections"] += 1
            items.append({"name": row["name"], "datasource": ds, "techniques": techs, "status": status,
                          "rules": sorted({r for h in hits.values() for r in h}), "table": table})
    counts: dict[str, int] = {}
    for i in items:
        counts[i["status"]] = counts.get(i["status"], 0) + 1
    done = counts.get("migrated", 0)
    return {"total": len(items), "counts": counts,
            "migrated_pct": round(100 * done / len(items), 1) if items else 0.0,
            "items": items, "datasources": sources}


def render(p: dict) -> str:
    lines = ["# Sentinel Migration Plan", "",
             f"{p['total']} legacy detections; {p['migrated_pct']}% already covered by tested rules.", "",
             "| Status | Count |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in sorted(p["counts"].items())]
    lines += ["", "## Data sources to onboard", "",
              "| Legacy source | Sentinel table | Onboarding | Detections |", "|---|---|---|---|"]
    lines += [f"| {k} | {v['table']} | {v['onboarding']} | {v['detections']} |"
              for k, v in sorted(p["datasources"].items(), key=lambda kv: -kv[1]["detections"])]
    lines += ["", "## Detections", "",
              "| Legacy detection | Techniques | Status | Repo rule(s) |", "|---|---|---|---|"]
    order = {"gap": 0, "partial": 1, "needs review (no ATT&CK mapping)": 2, "migrated": 3}
    for i in sorted(p["items"], key=lambda x: (order[x["status"]], x["name"])):
        lines.append(f"| {i['name']} | {', '.join(i['techniques']) or '-'} | {i['status']} | "
                     f"{', '.join(i['rules']) or '-'} |")
    return "\n".join(lines) + "\n"
