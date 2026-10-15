"""Command line interface: ``python -m dac <command>``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .convert import BACKENDS, convert_rule
from .coverage import render_markdown
from .defender import export as defender_export
from .effectiveness import coverage_gaps, load_outcomes, portfolio_health, rule_scorecard
from .effectiveness import render as eff_render
from .harness import run_rule
from .migrate import plan, render
from .rules import RULES_DIR, load_rules, validate_all
from .sentinel import arm_template


def cmd_validate(args) -> int:
    rules = load_rules(Path(args.rules))
    report = validate_all(rules)
    failed = 0
    for path, errors in report.items():
        if errors:
            failed += 1
            print(f"FAIL {path}")
            for err in errors:
                print(f"     - {err}")
        else:
            print(f"ok   {path}")
    print(f"\n{len(rules) - failed}/{len(rules)} rules valid")
    return 1 if failed else 0


def cmd_test(args) -> int:
    rules = load_rules(Path(args.rules))
    failures = 0
    print(f"{'rule':<50} {'dataset':<10} {'expected':>8} {'actual':>6}  result")
    for rule in rules:
        for res in run_rule(rule):
            failures += not res.passed
            status = "PASS" if res.passed else "FAIL"
            print(f"{res.rule:<50} {res.kind:<10} {res.expected:>8} {res.actual:>6}  {status}")
    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


def cmd_convert(args) -> int:
    targets = list(BACKENDS) if args.target == "all" else [args.target]
    out = Path(args.out)
    for rule in load_rules(Path(args.rules)):
        for target in targets:
            query = convert_rule(rule.data, target)
            if args.out == "-":
                print(query)
                continue
            dest = out / target / f"{rule.name}.{target}"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(query, encoding="utf-8")
            print(f"wrote {dest}")
    return 0


def cmd_coverage(args) -> int:
    md = render_markdown(load_rules(Path(args.rules)))
    if args.out == "-":
        print(md)
    else:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


def cmd_sentinel(args) -> int:
    rules = load_rules(Path(args.rules))
    template = arm_template([r.data for r in rules])
    text = json.dumps(template, indent=2)
    if args.out == "-":
        print(text)
    else:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({len(template['resources'])} analytics rules)")
    return 0


def cmd_effectiveness(args) -> int:
    from datetime import date
    cards = rule_scorecard(load_outcomes(args.outcomes), date.fromisoformat(args.today))
    pri = [ln.strip() for ln in open(args.priority) if ln.strip()] if args.priority else []
    gaps = coverage_gaps(load_rules(Path(args.rules)), pri)
    health = portfolio_health(cards)
    text = eff_render(cards, gaps, health)
    if args.out == "-":
        print(text)
    else:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}: {health['flagged']} rules flagged, "
              f"{gaps['coverage_pct']}% priority coverage")
    return 0


def cmd_defender(args) -> int:
    rules = load_rules(Path(args.rules))
    result = defender_export([r.data for r in rules])
    text = json.dumps(result["rules"], indent=2)
    if args.out == "-":
        print(text)
    else:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}: {len(result['rules'])} Defender XDR custom detection rules "
              f"({len(result['skipped'])} SIEM-only rules skipped)")
    return 0


def cmd_migrate(args) -> int:
    p = plan(args.legacy, load_rules(Path(args.rules)))
    md = render(p)
    if args.out == "-":
        print(md)
    else:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"wrote {args.out}: {p['migrated_pct']}% migrated, {p['counts']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dac", description="Detection-as-Code toolkit")
    parser.add_argument("--rules", default=str(RULES_DIR), help="rules directory")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="schema + semantic validation").set_defaults(func=cmd_validate)
    sub.add_parser("test", help="evaluate rules against sample logs").set_defaults(func=cmd_test)

    p = sub.add_parser("convert", help="convert rules to KQL / SPL")
    p.add_argument("--target", choices=[*BACKENDS, "all"], default="all")
    p.add_argument("--out", default="build", help="output dir, or - for stdout")
    p.set_defaults(func=cmd_convert)

    p = sub.add_parser("coverage", help="generate ATT&CK coverage markdown")
    p.add_argument("--out", default="docs/COVERAGE.md", help="output file, or - for stdout")
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("sentinel", help="export rules as a Sentinel analytics-rule ARM template")
    p.add_argument("--out", default="build/sentinel/analytics-rules.json",
                   help="output file, or - for stdout")
    p.set_defaults(func=cmd_sentinel)

    p = sub.add_parser("effectiveness",
                       help="score detection fidelity/workload and find ATT&CK coverage gaps")
    p.add_argument("--outcomes", required=True,
                   help="CSV: rule,alerts,true_positives,benign_positives,last_alert,weeks")
    p.add_argument("--priority", help="file of priority ATT&CK technique IDs, one per line")
    p.add_argument("--today", default=__import__("datetime").date.today().isoformat())
    p.add_argument("--out", default="-", help="output markdown file, or - for stdout")
    p.set_defaults(func=cmd_effectiveness)

    p = sub.add_parser("defender", help="export rules as Microsoft Defender XDR custom detection rules")
    p.add_argument("--out", default="build/defender/custom-detections.json",
                   help="output file, or - for stdout")
    p.set_defaults(func=cmd_defender)

    p = sub.add_parser("migrate", help="plan a legacy SIEM to Sentinel migration")
    p.add_argument("--legacy", required=True, help="CSV of legacy searches: name,datasource,techniques")
    p.add_argument("--out", default="-", help="output markdown file, or - for stdout")
    p.set_defaults(func=cmd_migrate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
