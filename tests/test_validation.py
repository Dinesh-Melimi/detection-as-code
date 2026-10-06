"""Every shipped rule must validate; broken rules must be rejected."""

import copy

import pytest

from dac.rules import validate_all, validate_rule


def test_all_rules_valid(rules):
    assert len(rules) >= 10
    report = validate_all(rules)
    assert {path: errs for path, errs in report.items() if errs} == {}


@pytest.fixture
def good_rule(rules):
    return copy.deepcopy(next(r for r in rules if r.name == "aws_cloudtrail_logging_disabled").data)


@pytest.mark.parametrize("mutate,fragment", [
    (lambda r: r.pop("level"), "'level' is a required property"),
    (lambda r: r.update(id="not-a-uuid"), "does not match"),
    (lambda r: r.update(level="urgent"), "is not one of"),
    (lambda r: r.update(tags=["attack.defense-evasion", "attack.t9999"]), "unknown technique T9999"),
    (lambda r: r.update(tags=["attack.t1562.008", "attack.made-up"]), "unknown tactic"),
    (lambda r: r.update(tags=["attack.t1562.008", "attack.execution"]), "does not belong"),
    (lambda r: r["detection"].update(condition="selection and missing"), "undefined selection 'missing'"),
    (lambda r: r["detection"].update(extra={"eventName": "x"}), "defined but not used"),
    (lambda r: r["detection"].update(condition="selection and"), "condition:"),
    (lambda r: r["detection"]["selection"].update({"eventName|wildcard": "x"}), "unsupported modifier"),
    (lambda r: r["detection"]["selection"].update({"eventName|re": "(unclosed"}), "invalid regex"),
    (lambda r: r["logsource"].update(product="gcp"), "no backend mapping"),
    (lambda r: r.update(correlation={"type": "event_count", "group_by": ["x"], "timeframe": "5m"}),
     "'threshold' is a required property"),
])
def test_invalid_rules_rejected(good_rule, mutate, fragment):
    mutate(good_rule)
    errors = validate_rule(good_rule)
    assert any(fragment in e for e in errors), errors
