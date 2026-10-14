import json
import uuid
from pathlib import Path

from dac.cli import main
from dac.migrate import plan, render
from dac.rules import RULES_DIR, load_rules
from dac.sentinel import arm_template, attack_tags, entity_mappings, iso_duration, output_columns

LEGACY = Path(__file__).resolve().parent.parent / "examples" / "legacy_splunk_searches.csv"


def _rules():
    return load_rules(RULES_DIR)


def test_iso_duration():
    assert iso_duration("10m") == "PT10M"
    assert iso_duration("1h") == "PT1H"
    assert iso_duration("1d") == "P1D"
    assert iso_duration(None) == "PT1H"


def test_every_rule_becomes_a_valid_scheduled_rule():
    rules = _rules()
    t = arm_template([r.data for r in rules])
    assert len(t["resources"]) == len(rules)
    names = set()
    for res, rule in zip(t["resources"], rules, strict=True):
        p = res["properties"]
        assert res["kind"] == "Scheduled"
        assert p["query"] and p["severity"] in {"High", "Medium", "Low", "Informational"}
        assert p["tactics"] and all(" " not in x and "-" not in x for x in p["tactics"])
        assert all(x.startswith("T") and "." not in x for x in p["techniques"])
        uuid.UUID(res["name"].split("'")[-2])  # rule GUID is stable
        names.add(res["name"])
        assert p["entityMappings"], f"{rule.name} has no entity mappings"
    assert len(names) == len(rules)


def test_certutil_tactics_and_entities():
    rule = next(r.data for r in _rules() if r.name == "proc_creation_win_certutil_download")
    tactics, techniques = attack_tags(rule)
    assert "CommandAndControl" in tactics and "DefenseEvasion" in tactics
    assert techniques == ["T1105", "T1140"]


def test_entities_only_use_columns_left_after_summarize():
    rule = next(r.data for r in _rules() if r.name == "win_security_bruteforce_then_success")
    t = arm_template([rule])["resources"][0]["properties"]
    assert output_columns(t["query"]) == {"TargetUserName"}
    assert [m["fieldMappings"][0]["columnName"] for m in t["entityMappings"]] == ["TargetUserName"]
    assert t["queryPeriod"] == "PT10M"
    assert entity_mappings({"logsource": {"product": "x", "category": "y"}}, "T") == []


def test_migration_plan():
    p = plan(LEGACY, _rules())
    by = {i["name"]: i for i in p["items"]}
    assert by["Certutil download"]["status"] == "migrated"
    assert by["Palo Alto C2 beacon"]["status"] == "gap"
    assert by["Office macro spawning shell"]["status"] == "partial"
    assert by["Legacy admin report"]["status"].startswith("needs review")
    assert p["datasources"]["pan:threat"]["table"] == "CommonSecurityLog"
    assert "log forwarder" in p["datasources"]["pan:threat"]["onboarding"]
    md = render(p)
    assert md.startswith("# Sentinel Migration Plan") and "| gap |" in md


def test_cli_sentinel_and_migrate(tmp_path, capsys):
    out = tmp_path / "rules.json"
    assert main(["sentinel", "--out", str(out)]) == 0
    assert json.loads(out.read_text())["contentVersion"] == "1.0.0.0"
    assert main(["migrate", "--legacy", str(LEGACY)]) == 0
    assert "Data sources to onboard" in capsys.readouterr().out
