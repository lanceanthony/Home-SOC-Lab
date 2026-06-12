# Runbook: Reconnaissance Port Scan Detection

## Alert Metadata
- **Alert ID:** SOC-RB-005
- **MITRE ATT&CK:** T1046 — Network Service Discovery
- **Severity:** High
- **Splunk Alert Name:** SOC-Alert-T1046-PortScan
- **Created:** June 2026
- **Author:** Lance Vidaure

## What This Alert Detects
Sysmon EventCode 3 (network connection) events bucketed into 1-minute windows, grouped by source IP and destination host, where the count of distinct destination ports reaches the alert threshold. This identifies a single source rapidly connecting to multiple ports — the signature of a port scan.

## Why It Matters
Port scanning is almost always one of the earliest steps in an attack (MITRE Discovery tactic, T1046). An internal host scanning multiple ports against another host indicates either an attacker performing reconnaissance after initial access, or a compromised host being used to map the internal network for further lateral movement targets.

## Trigger Condition
Sysmon EID 3 bucketed into 1-minute windows, grouped by `_time`, `SourceIp`, and `ComputerName`, where `dc(DestinationPort)` meets or exceeds the threshold. Alert fires when results > 0.

## Investigation Steps
1. Identify the source IP — is this a known admin workstation, a server, or an unexpected host?
2. Review the full list of destination ports and targets in the `ports` and `targets` fields — does the pattern match a known scanning tool signature (sequential ports, common service ports like 22/80/443/445/3389)?
3. Check what process initiated the connections — pivot to Sysmon EID 1 on the source host around the same timestamp to identify the responsible executable.
4. Determine if this source host showed any suspicious process activity (Alert 3) or brute force activity (Alert 1) immediately before the scan.
5. Check whether any of the scanned ports were followed by a successful connection and subsequent lateral movement (Alert 4).

## Key SPL Pivot Searches
```spl
index=windows_logs sourcetype="WinEventLog:Sysmon" EventCode=1
  ComputerName=[SOURCE_HOST_FROM_ALERT]
| table _time, User, ParentImage, Image, CommandLine
| sort _time
```

## True Positive Indicators
- Source host has no administrative reason to be scanning other hosts on the network.
- Scan covers a wide range of ports or targets multiple hosts in succession.
- Scan is preceded by suspicious process activity or a brute force alert on the same source host.

## False Positive Indicators
- Source is a known vulnerability scanner or monitoring tool with a documented schedule.
- Source is an admin workstation performing legitimate network troubleshooting (verify with the user/ticket).

## Response Actions
- **Contain:** If source host is unexpected, isolate it from the network pending investigation.
- **Investigate:** Correlate with Alerts 1, 3, and 4 for the same source host to build a full attack timeline.
- **Escalate if:** Scan activity is followed by any successful lateral movement (Alert 4) or new account creation (Alert 2) on a scanned target.
- **Document:** Log source IP, scanned ports/targets, responsible process, and timeline in incident ticket.

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1046/
