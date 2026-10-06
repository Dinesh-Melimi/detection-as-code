"""Converter tests: every rule converts, plus exact output for key cases."""

import pytest

from dac.convert import KqlBackend, SplBackend, convert_rule
from dac.rules import load_rules

RULES = load_rules()


@pytest.mark.parametrize("target", ["kql", "spl"])
@pytest.mark.parametrize("rule", RULES, ids=[r.name for r in RULES])
def test_every_rule_converts(rule, target):
    query = convert_rule(rule.data, target)
    assert rule.data["id"] in query
    assert "| where " in query


def test_kql_field_mapping_and_operators():
    rule = next(r for r in RULES if r.name == "proc_creation_win_certutil_download").data
    q = convert_rule(rule, "kql")
    assert q.splitlines()[1] == "DeviceProcessEvents"
    assert 'FolderPath endswith @"\\certutil.exe"' in q        # Image -> FolderPath, verbatim string
    assert 'ProcessCommandLine contains "-urlcache"' in q


def test_spl_field_mapping_and_escaping():
    rule = next(r for r in RULES if r.name == "win_security_member_added_to_local_admins").data
    q = convert_rule(rule, "spl")
    assert 'source="WinEventLog:Security"' in q
    assert 'EventCode=4732 AND lower(TargetSid)="s-1-5-32-544"' in q


def test_not_condition_rendering():
    rule = next(r for r in RULES if r.name == "proc_access_win_lsass_memory_access").data
    assert "and not((SourceImage endswith" in convert_rule(rule, "kql")
    assert "AND NOT (like(lower(SourceImage)" in convert_rule(rule, "spl")


def test_sequence_correlation_rendering():
    rule = next(r for r in RULES if r.name == "win_security_bruteforce_then_success").data
    kql = convert_rule(rule, "kql")
    assert "countif(EventID == 4625)" in kql
    assert "bin(TimeGenerated, 10m)" in kql
    assert "Step1Count >= 5 and Step2Last > Step1First" in kql
    spl = convert_rule(rule, "spl")
    assert "| bin _time span=10m" in spl
    assert "Step1Count >= 5 AND Step2Last > Step1First" in spl


def test_literal_escaping():
    assert KqlBackend({}).literal('a"b') == '@"a""b"'
    assert KqlBackend({}).literal("plain") == '"plain"'
    assert SplBackend({}).literal('C:\\x"y') == '"C:\\\\x\\"y"'
    assert SplBackend({}).quote_field("userIdentity.type") == "'userIdentity.type'"


def test_null_check():
    rule = {"id": "i", "title": "t", "level": "low", "logsource": {"product": "aws", "service": "cloudtrail"},
            "detection": {"sel": {"eventName": "X", "errorCode": None}, "condition": "sel"}}
    assert "isempty(ErrorCode)" in convert_rule(rule, "kql")
    assert "isnull(errorCode)" in convert_rule(rule, "spl")
