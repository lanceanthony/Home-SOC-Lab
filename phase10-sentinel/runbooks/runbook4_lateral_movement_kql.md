# Runbook: SOC-Alert-T1021-LateralMovement (Sentinel/KQL)

## MITRE ATT&CK
T1021 - Remote Services

## Severity
High (Sentinel's severity ceiling; equivalent to "Critical" in Splunk version)

## Trigger Condition
A network connection is observed to destination port 445 (SMB),
consistent with PsExec-style remote service execution or SMB-based
lateral movement.

## Detection Query (KQL)
```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 3
| extend ParsedXml = parse_xml(EventData)
| mv-expand DataItem = ParsedXml.DataItem.EventData.Data
| where DataItem["@Name"] == "DestinationPort"
| extend DestPort = toint(DataItem["#text"])
| where DestPort == 445
```

**Engineering note:** Sysmon does not log loopback (127.0.0.1) network
connections by default — this rule was validated against traffic to a
real network interface, not localhost, since loopback traffic is
excluded as noise in the standard SwiftOnSecurity config.

## Investigation Steps
1. Identify the source host, destination host, and account context of the connection.
2. Determine whether SMB/445 traffic between these two hosts is expected (e.g., domain file share, backup job).
3. Check for a corresponding successful logon (4624, logon type 3) on the destination host around the same time.
4. Look for PsExec-specific artifacts: `PSEXESVC` service creation, named pipes, or Sysmon EventID 1 process creation for `psexec.exe`/`psexesvc.exe`.

## Pivot Searches
```kql
// Logons on the destination host around the same time
SecurityEvent
| where Computer == "<destination_host>"
| where EventID == 4624 and LogonType == 3
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
```
```kql
// Check for PsExec service artifacts
SecurityEvent
| where EventID == 7045
| where ServiceName has "PSEXESVC"
```

## True/False Positive Indicators
- **True Positive:** Connection between hosts with no documented business reason, unfamiliar source account, followed by process creation or file activity on the target.
- **False Positive:** Known backup/patch management tool using SMB, IT admin performing documented remote administration, expected domain file share traffic.

## Response Actions
- If true positive: isolate both source and destination hosts, review for additional lateral movement across the environment, reset credentials for any account involved, escalate per IR plan.
- If false positive: document the legitimate tool/process and consider excluding its known source/destination pair from future alerts.

## SPL vs KQL Comparison
| Splunk (SPL) | Sentinel (KQL) |
|---|---|
| Real-time per-result alerting | 5-minute scheduled query (closest practical equivalent; NRT rule type is an option if available on your Sentinel tier) |
| Native `DestinationPort` field | `parse_xml()` + `mv-expand` to extract `DestinationPort` by name from embedded XML |

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1021/
