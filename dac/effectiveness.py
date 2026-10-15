"""Measure detection effectiveness: fidelity, analyst workload, and ATT&CK coverage gaps.

Detection engineering is a feedback loop. This reads per-rule alert outcomes (from the SIEM/case
system) and scores each detection on fidelity (true-positive rate) and workload (alerts per week),
flags noisy or stale rules for tuning, and compares technique coverage against a priority list to
surface the gaps worth building next.
"""
from __future__ import annotations

import csv
from datetime import date

from . import attack
from .rules import LoadedRule


def _tech_of(rule: LoadedRule) -> set[str]:
    out = set()
    for tag in rule.data.get("tags", []):
        t = tag.removeprefix("attack.").upper()
        if t.startswith("T") and t[1:5].isdigit():
            out.add(t.split(".")[0])
    return out


def load_outcomes(path):
    """CSV: rule,alerts,true_positives,benign_positives,last_alert (YYYY-MM-DD),weeks."""
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def rule_scorecard(outcomes, today, stale_weeks=26, noisy_per_week=10, low_fidelity=0.25):
    cards = []
    for o in outcomes:
        alerts = int(o["alerts"])
        tp = int(o["true_positives"])
        weeks = max(int(o.get("weeks", 1)), 1)
        fidelity = round(tp / alerts, 2) if alerts else None
        per_week = round(alerts / weeks, 1)
        flags = []
        if fidelity is not None and alerts >= 5 and fidelity < low_fidelity:
            flags.append("low fidelity: tune or add filters")
        if per_week > noisy_per_week:
            flags.append(f"high volume ({per_week}/wk): raising analyst workload")
        if o.get("last_alert"):
            weeks_since = (today - date.fromisoformat(o["last_alert"])).days / 7
            if weeks_since > stale_weeks:
                flags.append(f"stale: no alert in {weeks_since:.0f} weeks; validate it still fires")
        if alerts == 0:
            flags.append("never fired: validate with an attack sample")
        cards.append({"rule": o["rule"], "alerts": alerts, "fidelity": fidelity, "per_week": per_week,
                      "flags": flags})
    return sorted(cards, key=lambda c: (c["fidelity"] is None,
                                        c["fidelity"] if c["fidelity"] is not None else 1))


def coverage_gaps(rules, priority_techniques):
    covered = set()
    for r in rules:
        covered |= _tech_of(r)
    gaps = []
    for tid in priority_techniques:
        base = tid.split(".")[0]
        if base not in covered:
            name = attack.TECHNIQUES.get(tid, attack.TECHNIQUES.get(base, (tid, [])))[0]
            gaps.append({"technique": base, "name": name or tid})
    return {"covered": sorted(covered), "gaps": gaps,
            "coverage_pct": round(100 * (len(priority_techniques) - len(gaps)) / len(priority_techniques), 1)
            if priority_techniques else 100.0}


def portfolio_health(cards):
    scored = [c for c in cards if c["fidelity"] is not None]
    total_alerts = sum(c["alerts"] for c in cards)
    return {"rules": len(cards), "flagged": sum(1 for c in cards if c["flags"]),
            "avg_fidelity": round(sum(c["fidelity"] for c in scored) / len(scored), 2) if scored else None,
            "alerts_per_week": round(sum(c["per_week"] for c in cards), 1), "total_alerts": total_alerts}


def render(cards, gaps, health):
    L = ["# Detection Effectiveness Report", "",
         f"{health['rules']} detections, {health['flagged']} flagged for tuning. "
         f"Average fidelity {health['avg_fidelity']}, {health['alerts_per_week']} alerts/week total. "
         f"Priority ATT&CK coverage {gaps['coverage_pct']}%.", "",
         "## Rules to tune (lowest fidelity first)", "", "| Rule | Alerts | Fidelity | /week | Action |",
         "|---|---|---|---|---|"]
    for c in cards:
        if c["flags"]:
            L.append(f"| {c['rule']} | {c['alerts']} | "
                     f"{c['fidelity'] if c['fidelity'] is not None else '-'} | {c['per_week']} | "
                     f"{'; '.join(c['flags'])} |")
    L += ["", "## Coverage gaps (priority techniques with no detection)", ""]
    L += [f"- **{g['technique']}** {g['name']}" for g in gaps["gaps"]] or ["- none"]
    return "\n".join(L) + "\n"
