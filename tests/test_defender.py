from dac.cli import main
from dac.defender import custom_detection, export, exportable
from dac.rules import RULES_DIR, load_rules


def _rules():
    return [r.data for r in load_rules(RULES_DIR)]


def test_only_advanced_hunting_sources_export():
    res = export(_rules())
    # some endpoint rules export; the AWS CloudTrail rule is skipped
    assert res["rules"] and res["skipped"]
    for cd in res["rules"]:
        assert cd["queryCondition"]["queryText"]
        assert cd["severity"] in {"High", "Medium", "Low", "Informational"}
        assert cd["schedule"]["period"] in {"0", "1", "3", "12", "24"}


def test_certutil_rule_maps_to_device_table_and_techniques():
    cid = "4e9a1c7b-3f6d-4b28-9c51-b8e2d4a6f010"
    rule = next(r for r in _rules() if r["id"] == cid)
    cd = custom_detection(rule)
    assert cd["_table"] == "DeviceProcessEvents"
    assert "T1105" in cd["detectionAction"]["alertTemplate"]["mitreTechniques"]
    assert cd["detectionAction"]["impactedAssets"] == [{"identifier": "DeviceId"},
                                                       {"identifier": "AccountSid"}]


def test_cloudtrail_rule_not_exportable():
    rule = next(r for r in _rules() if r["logsource"].get("product") == "aws")
    assert not exportable(rule)


def test_cli_defender(tmp_path):
    out = tmp_path / "cd.json"
    assert main(["defender", "--out", str(out)]) == 0
    import json
    data = json.loads(out.read_text())
    assert isinstance(data, list) and data
