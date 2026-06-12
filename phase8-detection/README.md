# Phase 8 — Detection Engineering

**Duration:** Week 10 | **Status:** ✅ Complete

Built 5 production-quality MITRE ATT&CK mapped Splunk detection alerts against real lab-generated event data. Each alert has a corresponding detection runbook written in SOC SOP format.

## Alerts Built

| # | Alert Name | MITRE ID | Severity | Type |
|---|-----------|----------|----------|------|
| 1 | Brute Force Login | T1110 | High | Scheduled |
| 2 | New Admin Account | T1136.001 | Critical | Scheduled |
| 3 | Suspicious Process | T1059 | Medium | Scheduled |
| 4 | Lateral Movement (PsExec) | T1021 | Critical | Real-Time |
| 5 | Port Scan Recon | T1046 | High | Scheduled |

## Alert Details

### Alert 1 — Brute Force Login Detection (T1110)
```spl
index=windows_logs sourcetype="WinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats count by _time, Account_Name, Source_Network_Address
| where count >= 1
| sort -count
```
**Schedule:** Every 5 minutes | **Trigger:** Results > 0 | **Severity:** High

### Alert 2 — New Local Admin Account Created (T1136.001)
```spl
index=windows_logs sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| eval event_type=case(EventCode=4720, "Account Created", EventCode=4732, "Added to Privileged Group", true(), "Other")
| table _time, EventCode, event_type, Account_Name, Sam_Account_Name
| sort _time
```
**Schedule:** Every 15 minutes | **Trigger:** Results > 0 | **Severity:** Critical

### Alert 3 — Suspicious Process Creation (T1059)
```spl
index=windows_logs sourcetype="WinEventLog:Sysmon" EventCode=1
| rex field=CommandLine "(?i)(?P<suspicious_cmd>whoami|net user|net group|systeminfo|ipconfig)"
| where isnotnull(suspicious_cmd)
| table _time, Computer, ParentImage, Image, CommandLine, suspicious_cmd
| sort _time
```
**Schedule:** Every 5 minutes | **Trigger:** Results > 0 | **Severity:** Medium

### Alert 4 — Lateral Movement via PsExec/SMB (T1021)
```spl
index=windows_logs sourcetype="WinEventLog:Sysmon" (EventCode=1 OR EventCode=3)
| where match(Image, "(?i)psexec") OR match(CommandLine, "(?i)psexec") OR (EventCode=3 AND DestinationPort=445)
| table _time, EventCode, Computer, Image, CommandLine, DestinationIp, DestinationPort
| sort _time
```
**Type:** Real-time, Per-Result | **Trigger:** For each result | **Severity:** Critical

### Alert 5 — Reconnaissance Port Scan (T1046)
```spl
index=windows_logs sourcetype="WinEventLog:Sysmon" EventCode=3
| bucket _time span=1m
| stats dc(DestinationPort) as unique_ports, values(DestinationPort) as ports, values(DestinationIp) as targets by _time, SourceIp, ComputerName
| where unique_ports >= 1
| sort -unique_ports
```
**Schedule:** Every 5 minutes | **Trigger:** Results > 0 | **Severity:** High

## MITRE ATT&CK Coverage

| Technique ID | Name | Simulated | Detected |
|-------------|------|-----------|----------|
| T1110 | Brute Force | ✅ | ✅ |
| T1136.001 | Create Account: Local Account | ✅ | ✅ |
| T1059 | Command and Scripting Interpreter | ✅ | ✅ |
| T1021 | Remote Services | ✅ | ✅ |
| T1046 | Network Service Discovery | ✅ | ✅ |

## Key SPL Techniques Used

- `bucket _time span=5m` — time-window based threshold detection
- `dc(DestinationPort)` — unique port counting for scan detection
- `rex` — named capture groups for CommandLine parsing
- `eval case()` — multi-condition field classification
- `stats count by` — aggregation for threshold alerting
- Real-time per-result alerting for high-severity lateral movement detection

## Detection Runbooks

All runbooks follow SOC SOP format: alert metadata, what it detects, why it matters, trigger condition, investigation steps, pivot searches, true/false positive indicators, and response actions.

- [Runbook 1 — Brute Force Login Detection](runbooks/runbook1_brute_force.md)
- [Runbook 2 — New Local Admin Account](runbooks/runbook2_new_admin.md)
- [Runbook 3 — Suspicious Process Creation](runbooks/runbook3_suspicious_process.md)
- [Runbook 4 — Lateral Movement via PsExec/SMB](runbooks/runbook4_lateral_movement.md)
- [Runbook 5 — Reconnaissance Port Scan](runbooks/runbook5_port_scan.md)

## Validation

23 triggered alerts observed during testing across T1110, T1136.001, and T1059 — confirming all scheduled alerts fire correctly against live lab data.

## Tools

- Splunk Enterprise 9.3.2
- Sysmon v15.20 (SwiftOnSecurity config)
- Windows Server 2022
- PowerShell (test data generation)

## Screenshots

| Screenshot | Description |
|------------|-------------|
| `phase8_data_verification.png` | Master verification search across all event types |
| `alert1_brute_force_search.png` / `_saved.png` | Alert 1 search and saved confirmation |
| `alert2_new_admin_search.png` / `_saved.png` | Alert 2 search and saved confirmation |
| `alert3_suspicious_process_search.png` / `_saved.png` | Alert 3 search and saved confirmation |
| `alert4_lateral_movement_search.png` / `_saved.png` | Alert 4 search and saved confirmation |
| `alert5_port_scan_search.png` / `_saved.png` | Alert 5 search and saved confirmation |
| `phase8_all_alerts.png` | All 5 alerts on Settings → Alerts page |
| `phase8_triggered_alerts.png` | Activity → Triggered Alerts showing 23 fired alerts |
