"""Rule evaluation engine.

Evaluates a parsed rule against a list of JSON events. Two stages:

1. Per-event matching: each named selection is a set of field matchers, and
   the ``condition`` string combines selections with and / or / not.
2. Optional correlation across matched events (event_count, value_count,
   sequence) grouped by one or more fields inside a sliding time window.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}
TIMESTAMP_FIELD = "@timestamp"

_MISSING = object()


class ConditionError(ValueError):
    """Raised when a condition string cannot be parsed."""


# --------------------------------------------------------------------------
# Field matching
# --------------------------------------------------------------------------

def get_field(event: dict, path: str) -> Any:
    """Return a field value; supports dotted paths into nested objects."""
    if path in event:
        return event[path]
    current: Any = event
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def parse_field_spec(spec: str) -> tuple[str, list[str]]:
    """Split ``CommandLine|contains|all`` into ("CommandLine", ["contains", "all"])."""
    name, *modifiers = spec.split("|")
    return name, modifiers


def operator_for(modifiers: list[str]) -> str:
    """Return the comparison operator implied by modifiers (default: eq)."""
    return next((m for m in modifiers if m != "all"), "eq")


def _match_value(actual: Any, expected: Any, op: str) -> bool:
    if actual is _MISSING or actual is None:
        return False
    if op == "re":
        return re.search(str(expected), str(actual), re.IGNORECASE) is not None
    a, e = str(actual).lower(), str(expected).lower()
    if op == "eq":
        return a == e
    if op == "contains":
        return e in a
    if op == "startswith":
        return a.startswith(e)
    if op == "endswith":
        return a.endswith(e)
    raise ValueError(f"unsupported operator {op!r}")


def match_field(event: dict, spec: str, expected: Any) -> bool:
    name, modifiers = parse_field_spec(spec)
    actual = get_field(event, name)
    if expected is None:  # `Field: null` means "field absent or null"
        return actual is _MISSING or actual is None
    op = operator_for(modifiers)
    values = expected if isinstance(expected, list) else [expected]
    results = [_match_value(actual, v, op) for v in values]
    return all(results) if "all" in modifiers else any(results)


def match_selection(event: dict, selection: dict | list) -> bool:
    """A dict ANDs its fields; a list of dicts ORs them."""
    if isinstance(selection, list):
        return any(match_selection(event, s) for s in selection)
    return all(match_field(event, k, v) for k, v in selection.items())


# --------------------------------------------------------------------------
# Condition parsing (tiny recursive-descent parser)
# --------------------------------------------------------------------------
# Grammar:
#   expr   := term ("or" term)*
#   term   := factor ("and" factor)*
#   factor := "not" factor | "(" expr ")" | IDENT
# AST nodes are tuples: ("sel", name) | ("and", a, b) | ("or", a, b) | ("not", a)

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*)")
_KEYWORDS = {"and", "or", "not"}


def _tokenize(text: str) -> list[str]:
    text = text.strip()
    tokens, pos = [], 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ConditionError(f"unexpected character at position {pos} in {text!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


def parse_condition(text: str) -> tuple:
    tokens = _tokenize(text)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise ConditionError(f"unexpected end of condition {text!r}")
        tok = tokens[pos]
        pos += 1
        return tok

    def expr() -> tuple:
        node = term()
        while peek() == "or":
            take()
            node = ("or", node, term())
        return node

    def term() -> tuple:
        node = factor()
        while peek() == "and":
            take()
            node = ("and", node, factor())
        return node

    def factor() -> tuple:
        tok = take()
        if tok == "not":
            return ("not", factor())
        if tok == "(":
            node = expr()
            if take() != ")":
                raise ConditionError(f"missing ')' in {text!r}")
            return node
        if tok in _KEYWORDS or tok == ")":
            raise ConditionError(f"unexpected {tok!r} in {text!r}")
        return ("sel", tok)

    if not tokens:
        raise ConditionError("empty condition")
    ast = expr()
    if pos != len(tokens):
        raise ConditionError(f"unexpected trailing token {tokens[pos]!r} in {text!r}")
    return ast


def selections_in(ast: tuple) -> set[str]:
    if ast[0] == "sel":
        return {ast[1]}
    return set().union(*(selections_in(child) for child in ast[1:]))


def eval_condition(ast: tuple, is_match: Callable[[str], bool]) -> bool:
    kind = ast[0]
    if kind == "sel":
        return is_match(ast[1])
    if kind == "not":
        return not eval_condition(ast[1], is_match)
    if kind == "and":
        return eval_condition(ast[1], is_match) and eval_condition(ast[2], is_match)
    return eval_condition(ast[1], is_match) or eval_condition(ast[2], is_match)


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------

_TIMEFRAME = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_timeframe(value: str) -> timedelta:
    m = _TIMEFRAME.match(value)
    if not m:
        raise ValueError(f"invalid timeframe {value!r} (expected e.g. 30s, 10m, 1h)")
    return timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class Alert:
    rule_id: str
    title: str
    events: list[dict]
    group: dict = field(default_factory=dict)


def selections_of(rule: dict) -> dict:
    return {k: v for k, v in rule["detection"].items() if k != "condition"}


def _group_events(events: list[dict], group_by: list[str]) -> dict[tuple, list[dict]]:
    groups: dict[tuple, list[dict]] = {}
    for ev in events:
        key = tuple(get_field(ev, f) for f in group_by)
        if any(k is _MISSING or k is None for k in key):
            continue
        groups.setdefault(key, []).append(ev)
    for evs in groups.values():
        evs.sort(key=lambda e: parse_timestamp(e[TIMESTAMP_FIELD]))
    return groups


def _correlate(rule: dict, matched: list[dict]) -> list[Alert]:
    corr = rule["correlation"]
    group_by = corr["group_by"]
    window = parse_timeframe(corr["timeframe"])
    sels = selections_of(rule)
    alerts: list[Alert] = []

    for key, evs in _group_events(matched, group_by).items():
        times = [parse_timestamp(e[TIMESTAMP_FIELD]) for e in evs]
        group = dict(zip(group_by, key, strict=True))
        hit: list[dict] | None = None

        if corr["type"] in ("event_count", "value_count"):
            start = 0
            for end in range(len(evs)):
                while times[end] - times[start] > window:
                    start += 1
                in_window = evs[start:end + 1]
                if corr["type"] == "event_count":
                    score = len(in_window)
                else:
                    score = len({str(get_field(e, corr["field"])) for e in in_window})
                if score >= corr["threshold"]:
                    hit = in_window
                    break

        elif corr["type"] == "sequence":
            first, second = corr["steps"]
            min_first = first.get("min_count", 1)
            for i, ev in enumerate(evs):
                if not match_selection(ev, sels[second["selection"]]):
                    continue
                prior = [
                    evs[j] for j in range(i)
                    if times[i] - times[j] <= window
                    and match_selection(evs[j], sels[first["selection"]])
                ]
                if len(prior) >= min_first:
                    hit = prior + [ev]
                    break

        if hit:
            alerts.append(Alert(rule["id"], rule["title"], hit, group))
    return alerts


def evaluate(rule: dict, events: list[dict]) -> list[Alert]:
    """Run a rule over events and return alerts.

    Without correlation, each matching event is one alert. With correlation,
    at most one alert is produced per group (the first window that qualifies).
    """
    ast = parse_condition(rule["detection"]["condition"])
    sels = selections_of(rule)
    matched = [
        ev for ev in events
        if eval_condition(ast, lambda name, ev=ev: match_selection(ev, sels[name]))
    ]
    if "correlation" not in rule:
        return [Alert(rule["id"], rule["title"], [ev]) for ev in matched]
    return _correlate(rule, matched)
