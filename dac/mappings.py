"""Log source -> backend mappings.

Each rule declares a ``logsource`` (product + category or service). Here we
map that to the backend-specific table / search prefix and rename fields where
the backend schema differs from the rule's field names.

These mappings are reasonable defaults, not a guarantee: field names depend on
the connector, Splunk TA, or parser your environment uses. Review them before
deploying generated queries.
"""

SYSMON_SPL = 'index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"'

MAPPINGS: dict[str, dict[str, dict]] = {
    # Sysmon Event ID 1 style fields in rules.
    "windows/process_creation": {
        "kql": {
            # Defender for Endpoint table as surfaced in Sentinel.
            "source": "DeviceProcessEvents",
            "fields": {
                "Image": "FolderPath",
                "CommandLine": "ProcessCommandLine",
                "ParentImage": "InitiatingProcessFolderPath",
                "User": "AccountName",
            },
        },
        "spl": {
            "source": SYSMON_SPL + " EventCode=1",
            "fields": {},
        },
    },
    # Sysmon Event ID 10 (ProcessAccess).
    "windows/process_access": {
        "kql": {
            # Assumes Sysmon is collected into the Event table and EventData is
            # parsed into columns (e.g. by a Sysmon parser function).
            "source": 'Event\n| where Source == "Microsoft-Windows-Sysmon" and EventID == 10',
            "fields": {},
        },
        "spl": {
            "source": SYSMON_SPL + " EventCode=10",
            "fields": {},
        },
    },
    # Windows Security event log.
    "windows/security": {
        "kql": {"source": "SecurityEvent", "fields": {}},
        "spl": {
            "source": 'index=windows source="WinEventLog:Security"',
            "fields": {"EventID": "EventCode"},
        },
    },
    "aws/cloudtrail": {
        "kql": {
            "source": "AWSCloudTrail",
            "fields": {
                "eventSource": "EventSource",
                "eventName": "EventName",
                "userIdentity.type": "UserIdentityType",
                "userIdentity.arn": "UserIdentityArn",
                "sourceIPAddress": "SourceIpAddress",
                "errorCode": "ErrorCode",
            },
        },
        "spl": {"source": 'index=aws sourcetype="aws:cloudtrail"', "fields": {}},
    },
    "azure/signinlogs": {
        "kql": {"source": "SigninLogs", "fields": {}},
        "spl": {
            "source": 'index=azure sourcetype="azure:aad:signin"',
            "fields": {
                "UserPrincipalName": "userPrincipalName",
                "Location": "location",
                "ResultType": "status.errorCode",
            },
        },
    },
}

TIMESTAMP = {"kql": "TimeGenerated", "spl": "_time"}


def logsource_key(logsource: dict) -> str:
    return f"{logsource['product']}/{logsource.get('category') or logsource.get('service')}"
