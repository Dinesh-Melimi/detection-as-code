"""Command line interface: ``python -m dac <command>``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .convert import BACKENDS, convert_rule
from .coverage import render_markdown
from .harness import run_rule
from .rules import RULES_DIR, load_rules, validate_all


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

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
