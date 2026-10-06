from dac import attack
from dac.coverage import build_index, render_markdown


def test_coverage_is_deterministic(rules):
    assert render_markdown(rules) == render_markdown(list(reversed(rules)))


def test_coverage_contents(rules):
    md = render_markdown(rules)
    index = build_index(rules)
    assert f"Rules: **{len(rules)}**" in md
    for tech in index:
        assert tech in md
    assert "| credential-access |" in md
    assert "_no coverage_" in md  # gaps are shown, not hidden


def test_all_tagged_techniques_known(rules):
    for rule in rules:
        for tech in attack.techniques_from_tags(rule.data["tags"]):
            assert tech in attack.TECHNIQUES


def test_committed_report_is_up_to_date(rules):
    from pathlib import Path
    committed = Path(__file__).resolve().parent.parent / "docs" / "COVERAGE.md"
    assert committed.read_text() == render_markdown(rules), "run `make coverage` and commit docs/COVERAGE.md"
