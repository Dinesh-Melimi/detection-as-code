# Interview Walkthrough

A plain-English guide to every part of this project, plus questions an interviewer is likely to ask and how to answer them honestly.

## The 30-second pitch

> "Detection-as-Code means treating detection rules like software: they live in Git, they're reviewed, validated and tested in CI before they reach the SIEM. I built a small version of that pipeline. Rules are written in a Sigma-style YAML format and mapped to MITRE ATT&CK. A Python engine validates them, converts them to Sentinel KQL and Splunk SPL, and runs each one against labelled attack and benign log samples. CI fails if a rule misses its attack or fires on benign data, and it publishes the queries and an ATT&CK coverage report as build artifacts."

## The 2-minute version (walk the diagram)

1. An analyst writes a rule in `rules/` and adds two sample files in `samples/<rule>/`: one with attack events, one with benign look-alikes.
2. `dac validate` checks the rule's structure with JSON Schema, then checks its logic (does the condition reference real selections? is the regex valid? are the ATT&CK tags real?).
3. `pytest` runs the rule through my engine against both sample files and checks the exact number of alerts.
4. The converters translate the same rule into KQL and SPL, renaming fields for each platform.
5. The coverage script reads the ATT&CK tags of all rules and produces a matrix showing which tactics and techniques are covered and which aren't.
6. GitHub Actions runs all of this on every push and uploads the queries and report.

## Component by component

### Rules (`rules/**/*.yml`)
Each rule is a YAML file. The important parts:
- **logsource** says what kind of log the rule reads (e.g. Windows process creation, AWS CloudTrail). It's how the converter picks the right table.
- **detection** holds named *selections* (sets of field conditions) and a *condition* string that combines them with and / or / not.
- **correlation** (optional) is for rules that need more than one event, like "5 failed logons then a success".
- **tags** link the rule to ATT&CK tactics (the "why", e.g. credential-access) and techniques (the "how", e.g. T1003.001 LSASS Memory).
- **falsepositives** and **level** help the SOC triage alerts.

### Schema (`dac/rule.schema.json`)
A JSON Schema that every rule must satisfy: required fields, allowed `level` and `status` values, UUID-formatted `id`, tag format, and correlation-type-specific required keys (e.g. `value_count` needs `field`).

### Validation (`dac/rules.py`)
Two layers:
1. Schema validation (structure).
2. Semantic checks the schema can't express: condition parses; every selection referenced exists and every defined selection is used; modifiers are supported; regexes compile; technique IDs exist in our ATT&CK table; each tactic tag belongs to at least one tagged technique; the log source has a KQL and SPL mapping; IDs are unique; a samples folder exists.

A small detail: PyYAML turns `date: 2026-10-06` into a Python date object, which fails a "string" schema. I use a SafeLoader subclass that keeps dates as strings.

### Engine (`dac/engine.py`)
The reference implementation of what a rule means.
- **Field matching**: looks up a field (including nested `a.b.c` paths), applies the modifier (`contains`, `startswith`, `endswith`, `re`, or equality), case-insensitively. A list of values is OR; the `|all` modifier makes it AND.
- **Condition parser**: a ~40-line recursive-descent parser that turns `"selection and not filter"` into a tree. `and` binds tighter than `or`, parentheses override. Same tree is reused by the converters.
- **Correlation**: groups matched events by fields (e.g. user), sorts by time, and slides a time window:
  - `event_count`: N events in the window.
  - `value_count`: N distinct values of a field (e.g. countries) in the window.
  - `sequence`: at least N "step 1" events before a "step 2" event, within the window.

### Converters (`dac/convert.py`, `dac/mappings.py`)
A base `Backend` class walks the condition tree; `KqlBackend` and `SplBackend` only define how to write one comparison, a string literal, `not`, a null check, and the aggregation at the end.
- KQL: `=~` for case-insensitive equality, `contains`/`startswith`/`endswith`, `matches regex "(?i)..."`, verbatim strings `@"C:\..."` so backslashes don't need escaping. Correlations become `summarize ... by user, bin(TimeGenerated, 10m)`.
- SPL: a base search (`index=... source=...`) followed by `| where` using `lower()`, `like()` and `match()`. Correlations become `bin _time` + `stats`.
- `mappings.py` maps each logsource to a table/search and renames fields. Example: rules say `Image` (Sysmon name); in Defender's `DeviceProcessEvents` that's `FolderPath`.

### Sample logs and harness (`samples/`, `dac/harness.py`)
Each rule has `malicious.json` and `benign.json` with an `expected_alerts` number. The harness runs the engine and compares. Benign sets are deliberately close to the attack (e.g. certutil `-hashfile` vs `-urlcache`; 5 failed logons with success 30 minutes later vs within 10 minutes). That's what proves the rule is precise, not just that it fires.

### Coverage report (`dac/coverage.py`, `docs/COVERAGE.md`)
Reads technique tags from all rules, looks up each technique's tactics, and writes a table per tactic plus per-technique and per-rule tables. It shows gaps explicitly ("_no coverage_"). Output is deterministic and a test fails if the committed file is stale.

### Tests (`tests/`)
- `test_engine.py`: modifiers, AND/OR semantics, null checks, parser precedence and errors, window logic for all three correlation types.
- `test_validation.py`: all shipped rules are valid; 13 deliberately broken variants are each rejected with the right error.
- `test_rules_against_samples.py`: the core guarantee, one test per rule.
- `test_convert.py`: every rule converts to both targets; exact checks on field mapping, escaping, `not`, and correlation output.
- `test_coverage.py`: deterministic output, gaps shown, committed report up to date.

### CI (`.github/workflows/ci.yml`) and Makefile
Lint and validate run in parallel; tests run on Python 3.10 and 3.12 after both pass; then a job converts rules, builds the coverage report, and uploads them as an artifact. `make ci` runs the same steps locally.

## Rule-by-rule talking points

| Rule | What it catches | Why it matters | Main false positive |
|---|---|---|---|
| Encoded PowerShell | `powershell -enc <base64>` | Hides script content | Management agents (SCCM/RMM) |
| LSASS access | Process opening lsass with dump-style access masks | Credential theft (Mimikatz, comsvcs MiniDump) | EDR/AV/backup agents |
| Local admin added | Event 4732 to SID S-1-5-32-544 | Persistence with privileges | Normal admin work |
| Suspicious schtask | `/create /tr` to AppData/Temp/Public or LOLBin | Common malware persistence | Per-user updaters (Teams, Zoom) |
| Brute force then success | ≥5 failures then success in 10 min | Password guessing that worked | User fumbling a new password |
| AWS root login | ConsoleLogin by Root | Root should almost never be used | Break-glass procedures |
| CloudTrail disabled | StopLogging / DeleteTrail | Attacker blinding the defenders | Planned trail migration |
| Impossible travel lite | 2+ countries in 1 hour | Stolen credentials used abroad | VPNs |
| Office spawns shell | Word/Excel → cmd/powershell/mshta | Macro phishing execution | Legacy business macros |
| Certutil download/decode | `-urlcache`, `-decode` | LOLBin payload fetch | Admin cert troubleshooting |

Why the LSASS access masks? `0x1010` = `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`, which is what Mimikatz requests; `0x1fffff` is `PROCESS_ALL_ACCESS`. Reading memory (`VM_READ`) is the key right for dumping credentials.

## Likely interview questions

**Q: What is Detection-as-Code and why does it matter?**
Managing detections like software: version control, peer review, automated validation and testing, and automated deployment. It stops the "someone edited the rule in the SIEM console and broke it" problem, gives you history of why a rule changed, and lets you prove a rule still works after a change.

**Q: Why Sigma-style instead of writing KQL directly?**
Sigma is vendor-neutral. You write the logic once and convert it to whatever SIEM you run. It also makes rules shareable with the community. In a real job I'd use Sigma with pySigma backends; I wrote my own small engine here to understand and show how conversion works.

**Q: How do you know a rule actually works?**
Each rule has attack samples and benign samples with an exact expected alert count. CI fails if either is wrong. Benign samples are near-misses, which tests precision. Honest caveat: samples are synthetic. In production I'd also replay real attack telemetry (e.g. from Atomic Red Team runs in a lab) and check the generated query against the live SIEM.

**Q: How do you handle false positives?**
Filters in the rule (`not filter_known` in the LSASS rule), documenting expected false positives in each rule, choosing a sensible `level`, and adding the false-positive pattern to the benign samples so it can't regress. In production I'd also look at alert volume per rule over time and tune.

**Q: Walk me through the brute-force rule.**
The condition keeps only 4625 (failed) and 4624 (successful, network or RDP) events. Correlation groups by target user, and for each success looks back 10 minutes for at least 5 failures. The benign set has a user with 2 typos (too few), a password spray with no success, and 5 failures followed by success 30 minutes later (outside the window). Only the true attack alerts.

**Q: Your engine uses sliding windows but KQL uses `bin()`. Isn't that a mismatch?**
Yes, and I document it. `bin()` makes fixed buckets, so a burst crossing a bucket boundary can be missed. In KQL you could fix it with `row_window_session()` or a self-join on time ranges; in Splunk with `streamstats time_window=`. I chose `bin()` for readability and noted the limitation.

**Q: How do you map rules to different SIEM schemas?**
Rules use source-native field names (Sysmon, CloudTrail). `mappings.py` holds the table/search per logsource and per-backend field renames. Rules don't change when a backend schema changes; only the mapping does. Those mappings must be verified against the actual connector or TA in your environment.

**Q: Why validate ATT&CK tags against a local table?**
Typos in technique IDs silently break coverage reporting. Rejecting unknown IDs forces a reviewer to add the technique deliberately. It's a subset, not the full ATT&CK dataset; the next step would be loading the official STIX bundle.

**Q: What does the coverage report tell you, and what doesn't it?**
It shows which tactics and techniques have at least one tested rule and, more usefully, where there are none. It does not mean a technique is fully detected; one rule covers one or a few procedures of a technique.

**Q: What would you add next?**
- Run generated queries against real Sentinel/Splunk test instances in CI.
- Replace the hand-built engine with pySigma and keep the test harness.
- Load full ATT&CK from STIX; map log sources to ATT&CK data components.
- Deploy approved rules to Sentinel via API/Bicep or Splunk via `savedsearches.conf`.
- More log sources (Okta, GCP, Linux auditd) and Sigma features (`1 of`, `|cidr`, `|windash`).

**Q: How would this run in a team?**
Branch, PR, CI must be green, peer review of the logic and false positives, merge to main, automated deploy to a staging workspace, then production. Rules move from `experimental` to `test` to `stable` based on observed alert quality.

**Q: Anything you'd do differently?**
Point out the honest limitations: no live SIEM execution in CI, tumbling vs sliding windows, SPL `like()` treats `_` as wildcard, and synthetic samples. Knowing these is part of understanding the tool.

## Commands to demo live

```bash
make validate
make test-samples
python -m dac convert --target kql --out - | head -20
python -m dac coverage --out - | head -30
```

To show a test catching a regression: change `min_count: 5` to `min_count: 2` in the brute-force rule and run `make test-samples`; the benign set (user with 2 typos) now alerts and the test fails.
