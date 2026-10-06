"""The core CI guarantee: each rule fires on its attack samples and stays
quiet on its benign samples."""

import pytest

from dac.harness import load_sample, run_rule
from dac.rules import load_rules

RULES = load_rules()


@pytest.mark.parametrize("rule", RULES, ids=[r.name for r in RULES])
def test_rule_samples(rule):
    for result in run_rule(rule):
        assert result.passed, (
            f"{result.rule} on {result.kind} samples: expected {result.expected} alerts, got {result.actual}")


@pytest.mark.parametrize("rule", RULES, ids=[r.name for r in RULES])
def test_sample_expectations_are_meaningful(rule):
    assert load_sample(rule.name, "malicious")["expected_alerts"] >= 1
    benign = load_sample(rule.name, "benign")
    assert benign["expected_alerts"] == 0
    assert len(benign["events"]) >= 2, "benign samples should include realistic near-misses"
