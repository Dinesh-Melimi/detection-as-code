"""Minimal MITRE ATT&CK (Enterprise) reference data.

This is intentionally a small, hand-maintained subset covering the techniques
referenced by rules in this repo, not the full ATT&CK dataset. Validation
rejects any technique tag that is not listed here, which forces a reviewer to
consciously add (and double-check) new technique metadata.
"""

TACTICS = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# technique id -> (name, tactics)
TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1003.001": ("OS Credential Dumping: LSASS Memory", ["credential-access"]),
    "T1027": ("Obfuscated Files or Information", ["defense-evasion"]),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task",
                  ["execution", "persistence", "privilege-escalation"]),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ["execution"]),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", ["execution"]),
    "T1078": ("Valid Accounts",
              ["defense-evasion", "persistence", "privilege-escalation", "initial-access"]),
    "T1078.004": ("Valid Accounts: Cloud Accounts",
                  ["defense-evasion", "persistence", "privilege-escalation", "initial-access"]),
    "T1098": ("Account Manipulation", ["persistence", "privilege-escalation"]),
    "T1105": ("Ingress Tool Transfer", ["command-and-control"]),
    "T1110": ("Brute Force", ["credential-access"]),
    "T1110.001": ("Brute Force: Password Guessing", ["credential-access"]),
    "T1136.001": ("Create Account: Local Account", ["persistence"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["defense-evasion"]),
    "T1204.002": ("User Execution: Malicious File", ["execution"]),
    "T1562.008": ("Impair Defenses: Disable or Modify Cloud Logs", ["defense-evasion"]),
    "T1566.001": ("Phishing: Spearphishing Attachment", ["initial-access"]),
}


def techniques_from_tags(tags: list[str]) -> list[str]:
    """Extract technique IDs from tags like ``attack.t1059.001``."""
    return [t.split(".", 1)[1].upper() for t in tags if t.lower().startswith("attack.t")]


def tactics_from_tags(tags: list[str]) -> list[str]:
    return [
        t.split(".", 1)[1] for t in tags
        if t.startswith("attack.") and not t.lower().startswith("attack.t")
    ]
