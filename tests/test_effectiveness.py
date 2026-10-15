from datetime import date

from dac.effectiveness import coverage_gaps, load_outcomes, portfolio_health, rule_scorecard
from dac.rules import RULES_DIR, load_rules

TODAY = date(2026, 10, 15)


def _cards():
    return rule_scorecard(load_outcomes("samples/outcomes.csv"), TODAY)


def test_low_fidelity_and_noisy_flagged():
    c = {x["rule"]: x for x in _cards()}
    ps = c["proc_creation_win_powershell_encoded_command"]
    assert ps["fidelity"] == 0.06
    assert any("low fidelity" in f for f in ps["flags"]) and any("high volume" in f for f in ps["flags"])
    assert c["proc_creation_win_certutil_download"]["flags"] == []     # 20/22 TP, fine


def test_never_fired_flagged():
    c = {x["rule"]: x for x in _cards()}
    assert "never fired: validate with an attack sample" in c["proc_access_win_lsass_memory_access"]["flags"]


def test_cards_sorted_lowest_fidelity_first():
    cards = _cards()
    scored = [c["fidelity"] for c in cards if c["fidelity"] is not None]
    assert scored == sorted(scored)


def test_coverage_gaps():
    pri = [ln.strip() for ln in open("samples/priority_techniques.txt") if ln.strip()]
    g = coverage_gaps(load_rules(RULES_DIR), pri)
    gap_ids = {x["technique"] for x in g["gaps"]}
    assert "T1486" in gap_ids and "T1105" not in gap_ids           # T1105 (certutil) is covered
    assert g["coverage_pct"] == 75.0
    assert next(x for x in g["gaps"] if x["technique"] == "T1486")["name"] == "Data Encrypted for Impact"


def test_portfolio_health():
    h = portfolio_health(_cards())
    assert h["rules"] == 6 and h["flagged"] >= 2 and 0 <= h["avg_fidelity"] <= 1
