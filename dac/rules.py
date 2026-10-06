"""Loading and validating rules.

Validation runs in two layers:
  1. JSON Schema (structure, types, required metadata).
  2. Semantic checks the schema cannot express (condition references,
     modifiers, regex compilation, ATT&CK tags, backend mappings).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from . import attack
from .engine import (
    SUPPORTED_MODIFIERS,
    ConditionError,
    operator_for,
    parse_condition,
    parse_field_spec,
    parse_timeframe,
    selections_in,
    selections_of,
)
from .mappings import MAPPINGS, logsource_key

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
SAMPLES_DIR = ROOT / "samples"
SCHEMA = json.loads((Path(__file__).parent / "rule.schema.json").read_text())
_VALIDATOR = Draft202012Validator(SCHEMA)


@dataclass
class LoadedRule:
    path: Path
    data: dict

    @property
    def name(self) -> str:
        return self.path.stem


class _StringDateLoader(yaml.SafeLoader):
    """SafeLoader that keeps dates as plain strings (so they validate as JSON)."""


_StringDateLoader.yaml_implicit_resolvers = {
    ch: [(tag, rx) for tag, rx in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for ch, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def load_yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.load(fh, Loader=_StringDateLoader)  # noqa: S506 - SafeLoader subclass


def discover_rules(rules_dir: Path = RULES_DIR) -> list[Path]:
    return sorted(rules_dir.rglob("*.yml"))


def load_rules(rules_dir: Path = RULES_DIR) -> list[LoadedRule]:
    return [LoadedRule(p, load_yaml(p)) for p in discover_rules(rules_dir)]


def schema_errors(rule: dict) -> list[str]:
    errors = sorted(_VALIDATOR.iter_errors(rule), key=lambda e: list(e.path))
    return [f"schema: {'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors]


def _check_selection(name: str, selection, errors: list[str]) -> None:
    items = selection if isinstance(selection, list) else [selection]
    for item in items:
        for spec, value in item.items():
            _, modifiers = parse_field_spec(spec)
            unknown = set(modifiers) - SUPPORTED_MODIFIERS
            if unknown:
                errors.append(f"{name}: unsupported modifier(s) {sorted(unknown)} in {spec!r}")
            ops = [m for m in modifiers if m != "all"]
            if len(ops) > 1:
                errors.append(f"{name}: more than one operator modifier in {spec!r}")
            if operator_for(modifiers) == "re":
                for v in value if isinstance(value, list) else [value]:
                    try:
                        re.compile(str(v))
                    except re.error as exc:
                        errors.append(f"{name}: invalid regex {v!r}: {exc}")


def semantic_errors(rule: dict) -> list[str]:
    errors: list[str] = []
    sels = selections_of(rule)

    try:
        referenced = selections_in(parse_condition(rule["detection"]["condition"]))
    except ConditionError as exc:
        return [f"condition: {exc}"]
    for missing in sorted(referenced - sels.keys()):
        errors.append(f"condition references undefined selection {missing!r}")
    for unused in sorted(sels.keys() - referenced):
        errors.append(f"selection {unused!r} is defined but not used in condition")
    for name, sel in sels.items():
        _check_selection(name, sel, errors)

    corr = rule.get("correlation")
    if corr:
        try:
            parse_timeframe(corr["timeframe"])
        except ValueError as exc:
            errors.append(f"correlation: {exc}")
        for step in corr.get("steps", []):
            if step["selection"] not in sels:
                errors.append(f"correlation step references undefined selection {step['selection']!r}")

    techniques = attack.techniques_from_tags(rule["tags"])
    if not techniques:
        errors.append("tags: at least one ATT&CK technique tag (attack.tXXXX) is required")
    for tech in techniques:
        if tech not in attack.TECHNIQUES:
            errors.append(f"tags: unknown technique {tech} (add it to dac/attack.py)")
    tactics = attack.tactics_from_tags(rule["tags"])
    if not tactics:
        errors.append("tags: at least one ATT&CK tactic tag (e.g. attack.execution) is required")
    for tactic in tactics:
        if tactic not in attack.TACTICS:
            errors.append(f"tags: unknown tactic {tactic!r}")
        elif not any(tactic in attack.TECHNIQUES.get(t, ("", []))[1] for t in techniques):
            errors.append(f"tags: tactic {tactic!r} does not belong to any tagged technique")

    if logsource_key(rule["logsource"]) not in MAPPINGS:
        errors.append(f"logsource {logsource_key(rule['logsource'])!r} has no backend mapping")
    return errors


def validate_rule(rule: dict) -> list[str]:
    errors = schema_errors(rule)
    if errors:  # semantic checks assume a structurally valid rule
        return errors
    return semantic_errors(rule)


def validate_all(rules: list[LoadedRule]) -> dict[str, list[str]]:
    """Return {rule path: [errors]} including cross-rule checks."""
    report = {str(r.path): validate_rule(r.data) for r in rules}
    seen: dict[str, str] = {}
    for r in rules:
        rid = r.data.get("id")
        if rid in seen:
            report[str(r.path)].append(f"duplicate id {rid} (also in {seen[rid]})")
        seen[rid] = str(r.path)
        if not (SAMPLES_DIR / r.name).is_dir():
            report[str(r.path)].append(f"missing sample directory samples/{r.name}/")
    return report
