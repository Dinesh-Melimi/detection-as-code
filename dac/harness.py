"""Run each rule against its labelled sample datasets.

Layout: ``samples/<rule file stem>/malicious.json`` and ``benign.json``.
Each file is ``{"description": str, "expected_alerts": int, "events": [...]}``.
A malicious dataset must produce exactly ``expected_alerts`` (>= 1) alerts;
a benign dataset must produce exactly ``expected_alerts`` (normally 0).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .engine import evaluate
from .rules import SAMPLES_DIR, LoadedRule

SAMPLE_KINDS = ("malicious", "benign")


@dataclass
class SampleResult:
    rule: str
    kind: str
    expected: int
    actual: int

    @property
    def passed(self) -> bool:
        return self.expected == self.actual


def load_sample(rule_name: str, kind: str, samples_dir: Path = SAMPLES_DIR) -> dict:
    with open(samples_dir / rule_name / f"{kind}.json", encoding="utf-8") as fh:
        return json.load(fh)


def run_rule(rule: LoadedRule, samples_dir: Path = SAMPLES_DIR) -> list[SampleResult]:
    results = []
    for kind in SAMPLE_KINDS:
        sample = load_sample(rule.name, kind, samples_dir)
        alerts = evaluate(rule.data, sample["events"])
        results.append(SampleResult(rule.name, kind, sample["expected_alerts"], len(alerts)))
    return results
