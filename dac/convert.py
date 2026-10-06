"""Convert rules to Microsoft Sentinel KQL and Splunk SPL.

Both backends share the same traversal (selections -> condition AST ->
correlation) and only differ in how they render a single comparison,
boolean operators, literals, and the aggregation tail.
"""

from __future__ import annotations

import re

from .engine import operator_for, parse_condition, parse_field_spec, selections_of
from .mappings import MAPPINGS, TIMESTAMP, logsource_key


class Backend:
    name = ""
    and_op = " and "
    or_op = " or "

    def __init__(self, fieldmap: dict[str, str]):
        self.fieldmap = fieldmap

    # --- hooks implemented per backend -----------------------------------
    def quote_field(self, name: str) -> str:
        return name

    def literal(self, value: str) -> str:
        raise NotImplementedError

    def compare(self, field: str, op: str, value) -> str:
        raise NotImplementedError

    def is_null(self, field: str) -> str:
        raise NotImplementedError

    def negate(self, expr: str) -> str:
        raise NotImplementedError

    def comment(self, rule: dict) -> str:
        raise NotImplementedError

    def correlation(self, rule: dict, corr: dict) -> list[str]:
        raise NotImplementedError

    # --- shared traversal --------------------------------------------------
    def field(self, name: str) -> str:
        return self.quote_field(self.fieldmap.get(name, name))

    @staticmethod
    def group(parts: list[str], joiner: str) -> str:
        return parts[0] if len(parts) == 1 else "(" + joiner.join(parts) + ")"

    def render_field(self, spec: str, expected) -> str:
        name, modifiers = parse_field_spec(spec)
        field = self.field(name)
        if expected is None:
            return self.is_null(field)
        values = expected if isinstance(expected, list) else [expected]
        op = operator_for(modifiers)
        parts = [self.compare(field, op, v) for v in values]
        return self.group(parts, self.and_op if "all" in modifiers else self.or_op)

    def render_selection(self, selection) -> str:
        if isinstance(selection, list):
            return self.group([self.render_selection(s) for s in selection], self.or_op)
        return self.group([self.render_field(k, v) for k, v in selection.items()], self.and_op)

    def render_condition(self, ast: tuple, sels: dict) -> str:
        kind = ast[0]
        if kind == "sel":
            return self.render_selection(sels[ast[1]])
        if kind == "not":
            return self.negate(self.render_condition(ast[1], sels))
        joiner = self.and_op if kind == "and" else self.or_op
        return "(" + joiner.join(self.render_condition(c, sels) for c in ast[1:]) + ")"

    def convert(self, rule: dict, source: str) -> str:
        sels = selections_of(rule)
        cond = self.render_condition(parse_condition(rule["detection"]["condition"]), sels)
        if cond.startswith("(") and cond.endswith(")") and _balanced(cond[1:-1]):
            cond = cond[1:-1]
        lines = [self.comment(rule), source, f"| where {cond}"]
        if "correlation" in rule:
            lines += self.correlation(rule, rule["correlation"])
        return "\n".join(lines) + "\n"


def _balanced(text: str) -> bool:
    depth = 0
    for ch in text:
        depth += ch == "("
        depth -= ch == ")"
        if depth < 0:
            return False
    return depth == 0


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


class KqlBackend(Backend):
    name = "kql"

    def literal(self, value: str) -> str:
        value = str(value)
        if "\\" in value or '"' in value:
            return '@"' + value.replace('"', '""') + '"'  # verbatim string
        return f'"{value}"'

    def compare(self, field, op, value):
        if op == "eq" and _is_number(value):
            return f"{field} == {value}"
        if op == "eq":
            return f"{field} =~ {self.literal(value)}"
        if op == "re":
            return f"{field} matches regex {self.literal('(?i)' + str(value))}"
        return f"{field} {op} {self.literal(value)}"  # contains/startswith/endswith

    def is_null(self, field):
        return f"isempty({field})"

    def negate(self, expr):
        return f"not({expr})"

    def comment(self, rule):
        return f"// {rule['title']} ({rule['id']}) - level: {rule['level']}"

    def correlation(self, rule, corr):
        ts = TIMESTAMP["kql"]
        by = ", ".join(self.field(f) for f in corr["group_by"]) + f", bin({ts}, {corr['timeframe']})"
        if corr["type"] == "event_count":
            return [f"| summarize EventCount = count() by {by}",
                    f"| where EventCount >= {corr['threshold']}"]
        if corr["type"] == "value_count":
            f = self.field(corr["field"])
            return [f"| summarize ValueCount = dcount({f}), Values = make_set({f}) by {by}",
                    f"| where ValueCount >= {corr['threshold']}"]
        sels = selections_of(rule)
        s1, s2 = (self.render_selection(sels[s["selection"]]) for s in corr["steps"])
        n = corr["steps"][0].get("min_count", 1)
        return [f"| summarize Step1Count = countif({s1}), Step1First = minif({ts}, {s1}), "
                f"Step2Last = maxif({ts}, {s2}) by {by}",
                f"| where Step1Count >= {n} and Step2Last > Step1First"]


class SplBackend(Backend):
    name = "spl"
    and_op = " AND "
    or_op = " OR "

    def quote_field(self, name):
        return name if re.fullmatch(r"\w+", name) else f"'{name}'"

    def literal(self, value: str) -> str:
        return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

    def compare(self, field, op, value):
        if op == "eq" and _is_number(value):
            return f"{field}={value}"
        if op == "re":
            return f"match({field}, {self.literal('(?i)' + str(value))})"
        v = str(value).lower()
        pattern = {"eq": v, "contains": f"%{v}%", "startswith": f"{v}%", "endswith": f"%{v}"}[op]
        if op == "eq":
            return f"lower({field})={self.literal(pattern)}"
        return f"like(lower({field}), {self.literal(pattern)})"

    def is_null(self, field):
        return f"isnull({field})"

    def negate(self, expr):
        return f"NOT {expr}" if expr.startswith("(") else f"NOT ({expr})"

    def comment(self, rule):
        return f"``` {rule['title']} ({rule['id']}) - level: {rule['level']} ```"

    def correlation(self, rule, corr):
        by = " ".join(self.field(f) for f in corr["group_by"])
        span = [f"| bin _time span={corr['timeframe']}"]
        if corr["type"] == "event_count":
            return span + [f"| stats count AS EventCount BY _time {by}",
                           f"| where EventCount >= {corr['threshold']}"]
        if corr["type"] == "value_count":
            f = self.field(corr["field"])
            return span + [f"| stats dc({f}) AS ValueCount values({f}) AS Values BY _time {by}",
                           f"| where ValueCount >= {corr['threshold']}"]
        sels = selections_of(rule)
        s1, s2 = (self.render_selection(sels[s["selection"]]) for s in corr["steps"])
        n = corr["steps"][0].get("min_count", 1)
        return [f"| eval step1_time=if({s1}, _time, null()), step2_time=if({s2}, _time, null())",
                *span,
                f"| stats count(step1_time) AS Step1Count min(step1_time) AS Step1First "
                f"max(step2_time) AS Step2Last BY _time {by}",
                f"| where Step1Count >= {n} AND Step2Last > Step1First"]


BACKENDS = {"kql": KqlBackend, "spl": SplBackend}


def convert_rule(rule: dict, target: str) -> str:
    mapping = MAPPINGS[logsource_key(rule["logsource"])][target]
    return BACKENDS[target](mapping["fields"]).convert(rule, mapping["source"])
