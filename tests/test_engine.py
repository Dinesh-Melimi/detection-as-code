"""Unit tests for field matching, condition parsing and correlation."""

import pytest

from dac.engine import (
    ConditionError,
    evaluate,
    match_field,
    match_selection,
    parse_condition,
    parse_timeframe,
)

EVENT = {
    "Image": r"C:\Windows\System32\cmd.exe",
    "CommandLine": "cmd.exe /c whoami /all",
    "EventID": 4688,
    "userIdentity": {"type": "Root"},
}


@pytest.mark.parametrize("spec,value,expected", [
    ("Image", r"c:\windows\system32\CMD.EXE", True),          # equality is case-insensitive
    ("Image|endswith", r"\cmd.exe", True),
    ("Image|startswith", r"C:\Windows", True),
    ("CommandLine|contains", "WHOAMI", True),
    ("CommandLine|contains", ["nope", "whoami"], True),       # list = OR
    ("CommandLine|contains|all", ["whoami", "/all"], True),   # |all = AND
    ("CommandLine|contains|all", ["whoami", "/priv"], False),
    ("CommandLine|re", r"whoami\s+/(all|priv)", True),
    ("EventID", 4688, True),
    ("EventID", "4688", True),                                # numbers compare as strings
    ("userIdentity.type", "Root", True),                      # dotted path into nested object
    ("Missing", "x", False),
    ("Missing", None, True),                                  # null = field absent
])
def test_match_field(spec, value, expected):
    assert match_field(EVENT, spec, value) is expected


def test_selection_dict_is_and_list_is_or():
    assert match_selection(EVENT, {"EventID": 4688, "Image|endswith": "cmd.exe"})
    assert not match_selection(EVENT, {"EventID": 4688, "Image|endswith": "powershell.exe"})
    assert match_selection(EVENT, [{"EventID": 1}, {"Image|endswith": "cmd.exe"}])


def test_condition_precedence():
    # and binds tighter than or: a or (b and c)
    assert parse_condition("a or b and c") == ("or", ("sel", "a"), ("and", ("sel", "b"), ("sel", "c")))
    assert parse_condition("(a or b) and not c") == (
        "and", ("or", ("sel", "a"), ("sel", "b")), ("not", ("sel", "c")))


@pytest.mark.parametrize("bad", ["", "a and", "(a or b", "a b", "a & b", "and a"])
def test_condition_errors(bad):
    with pytest.raises(ConditionError):
        parse_condition(bad)


def test_timeframe():
    assert parse_timeframe("10m").total_seconds() == 600
    assert parse_timeframe("1h").total_seconds() == 3600
    with pytest.raises(ValueError):
        parse_timeframe("10 minutes")


def _rule(**extra):
    rule = {"id": "x", "title": "t", "detection": {"sel": {"EventID": 1}, "condition": "sel"}}
    rule.update(extra)
    return rule


def _ev(sec, **fields):
    return {"@timestamp": f"2026-01-01T00:{sec // 60:02d}:{sec % 60:02d}Z", "EventID": 1, **fields}


def test_event_count_respects_window():
    rule = _rule(correlation={"type": "event_count", "group_by": ["u"], "timeframe": "1m", "threshold": 3})
    spread = [_ev(0, u="a"), _ev(50, u="a"), _ev(100, u="a")]      # never 3 within 60s
    burst = [_ev(0, u="b"), _ev(10, u="b"), _ev(20, u="b")]
    assert evaluate(rule, spread) == []
    alerts = evaluate(rule, spread + burst)
    assert len(alerts) == 1 and alerts[0].group == {"u": "b"}


def test_value_count():
    rule = _rule(correlation={"type": "value_count", "field": "c", "group_by": ["u"],
                              "timeframe": "1h", "threshold": 2})
    assert evaluate(rule, [_ev(0, u="a", c="US"), _ev(60, u="a", c="US")]) == []
    assert len(evaluate(rule, [_ev(0, u="a", c="US"), _ev(60, u="a", c="RU")])) == 1


def test_sequence_requires_order():
    rule = {
        "id": "x", "title": "t",
        "detection": {"fail": {"r": "fail"}, "ok": {"r": "ok"}, "condition": "fail or ok"},
        "correlation": {"type": "sequence", "group_by": ["u"], "timeframe": "5m",
                        "steps": [{"selection": "fail", "min_count": 2}, {"selection": "ok"}]},
    }
    success_first = [_ev(0, u="a", r="ok"), _ev(10, u="a", r="fail"), _ev(20, u="a", r="fail")]
    assert evaluate(rule, success_first) == []
    in_order = [_ev(0, u="a", r="fail"), _ev(10, u="a", r="fail"), _ev(20, u="a", r="ok")]
    assert len(evaluate(rule, in_order)) == 1


def test_events_missing_group_field_are_ignored():
    rule = _rule(correlation={"type": "event_count", "group_by": ["u"], "timeframe": "1m", "threshold": 1})
    assert evaluate(rule, [_ev(0)]) == []
