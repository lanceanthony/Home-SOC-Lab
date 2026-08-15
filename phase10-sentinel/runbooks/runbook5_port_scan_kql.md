# Runbook: SOC-Alert-T1046-PortScan (Sentinel/KQL)

## MITRE ATT&CK
T1046 - Network Service Discovery

## Severity
High

## Trigger Condition
A single source host contacts an unusually high number of distinct
destination ports within a 5-minute window, consistent with
reconnaissance/port scanning activity.

## Detection Query (KQL)
```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 3
| extend ParsedXml = parse_xml(EventData)
| mv-expand DataItem = ParsedXml.DataItem.EventData.Data
| where DataItem["@Name"] == "DestinationPort"
| extend DestPort = toint(DataItem["#text"])
| summarize DistinctPorts = dcount(DestPort) by Computer, bin(TimeGenerated, 5m)
| where DistinctPorts >= 1
```

**Tuning note:** the original Splunk version used a `>= 1` threshold
(essentially "any distinct port"), which is a low bar kept here to
match the original exactly. In a production environment, raise this
to something like `>= 5` distinct ports within the window for a
cleaner, less noisy signal.

## Investigation Steps
1. Identify the source host and the list of distinct ports contacted.
2. Determine whether this matches known vulnerability scanning tools/schedules (e.g., a documented internal scanner).
3. Check whether any of the scanned ports returned a successful connection, which would indicate the scan found an open service.
4. Review what process on the source host initiated the connections (Sysmon EventID 1 around the same timestamps).

## Pivot Searches
```kql
// Full list of ports contacted by the source host in the window
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 3
| where Computer == "<computer>"
| extend ParsedXml = parse_xml(EventData)
| mv-expand DataItem = ParsedXml.DataItem.EventData.Data
| where DataItem["@Name"] == "DestinationPort"
| extend DestPort = toint(DataItem["#text"])
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| distinct DestPort
```
```kql
// Process creation on the source host around the same time
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| where Computer == "<computer>"
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
```

## True/False Positive Indicators
- **True Positive:** Unfamiliar source host, no documented scanning schedule, followed by successful connections or further attacker activity on discovered open ports.
- **False Positive:** Known internal vulnerability scanner (e.g., Nessus, Qualys) running on schedule, IT asset discovery tool, monitoring/observability agent probing multiple services.

## Response Actions
- If true positive: isolate the source host, identify what (if anything) it discovered, escalate if this precedes exploitation attempts on the discovered ports.
- If false positive: document the known scanner and add it to an allowlist/exclusion for future rule tuning.

## SPL vs KQL Comparison
| Splunk (SPL) | Sentinel (KQL) |
|---|---|
| `dc(DestinationPort)` | `dcount(DestPort)` |
| `stats ... by _time, SourceIp, ComputerName` | `summarize ... by Computer, bin(TimeGenerated, 5m)` |

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1046/
