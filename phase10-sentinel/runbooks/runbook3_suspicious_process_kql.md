# Runbook: SOC-Alert-T1059-SuspiciousProcess (Sentinel/KQL)

## MITRE ATT&CK
T1059 - Command and Scripting Interpreter

## Severity
Medium

## Trigger Condition
A process is created (Sysmon EventID 1) with a command line matching
known suspicious patterns: encoded PowerShell, reconnaissance commands
(`whoami`, `net user`), or known attacker tooling (`mimikatz`).

## Detection Query (KQL)
```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| extend ParsedXml = parse_xml(EventData)
| mv-expand DataItem = ParsedXml.DataItem.EventData.Data
| where DataItem["@Name"] == "CommandLine"
| extend CommandLine = tostring(DataItem["#text"])
| where CommandLine matches regex @"(?i)(powershell.*-enc|whoami|net\s+user|mimikatz)"
```

**Engineering note:** this query resolves the `CommandLine` field by
name via `mv-expand` rather than a fixed array index (e.g. `Data[10]`).
Sysmon's XML field order can shift between config/schema versions, so
matching by `@Name` is more resilient than a positional index and
avoids silent breakage if the field order changes upstream.

## Investigation Steps
1. Identify the host, parent process, and the exact command line that matched.
2. Determine whether the process was launched by a legitimate admin/scripted task or an interactive user session.
3. Check the parent process chain for anomalies (e.g., Office app spawning PowerShell).
4. Review what the command actually attempted to do (download, execute, enumerate).

## Pivot Searches
```kql
// All process creation events on the host around the same time
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| where Computer == "<computer>"
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
```
```kql
// Network connections from the same host shortly after
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 3
| where Computer == "<computer>"
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
```

## True/False Positive Indicators
- **True Positive:** Encoded PowerShell with no legitimate business reason, execution by an unexpected parent process, followed by network activity or account enumeration.
- **False Positive:** Known admin script or scheduled task using `whoami`/`net user` for legitimate inventory/auditing purposes, documented automation.

## Response Actions
- If true positive: isolate the host, capture the full process tree, review for persistence mechanisms and lateral movement, escalate per IR plan.
- If false positive: document the legitimate script/tool and consider a detection exclusion for that specific parent process or scheduled task.

## SPL vs KQL Comparison
| Splunk (SPL) | Sentinel (KQL) |
|---|---|
| `rex field=CommandLine "..."` | `extend CommandLine = tostring(DataItem["#text"])` + `matches regex` |
| Flattened Sysmon fields (native) | `parse_xml()` + `mv-expand` to unpack embedded XML |

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1059/
