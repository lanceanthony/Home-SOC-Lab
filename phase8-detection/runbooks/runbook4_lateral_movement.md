# Runbook: Lateral Movement via PsExec / SMB

## Alert Metadata
- **Alert ID:** SOC-RB-004
- **MITRE ATT&CK:** T1021 — Remote Services
- **Severity:** Critical
- **Splunk Alert Name:** SOC-Alert-T1021-LateralMovement
- **Created:** June 2026
- **Author:** Lance Vidaure

## What This Alert Detects
Sysmon EventCode 1 (process creation) where the process image or command line references PsExec, OR Sysmon EventCode 3 (network connection) where the destination port is 445 (SMB). This is a real-time, per-result alert — it fires immediately on each matching event.

## Why It Matters
PsExec and direct SMB connections (port 445) are the most common tools and protocols used for lateral movement once an attacker has valid credentials. An attacker moving from a compromised host to a domain controller or another workstation typically uses these mechanisms. Because this represents an active intrusion in progress, it is alerted on in real time rather than on a schedule.

## Trigger Condition
(Sysmon EID 1 AND Image/CommandLine matches "psexec") OR (Sysmon EID 3 AND DestinationPort = 445). Real-time, per-result — fires on every matching event individually.

## Investigation Steps
1. Identify source host, destination host, and the account context (`User` field) for the triggering event.
2. If PsExec-related: check `ParentImage` and `CommandLine` for the exact command run on the remote host.
3. If SMB (port 445): confirm whether this is expected traffic (file shares, domain controller communication) vs. an unexpected workstation-to-workstation connection.
4. Pivot to the destination host's logs — check for 4624 logon events (Logon_Type 3, network logon) around the same timestamp.
5. Check for any suspicious process creation (Alert 3) on the destination host immediately following the connection.
6. Build a timeline: source recon (Alert 3) → lateral movement (this alert) → new account on destination (Alert 2)? This chain indicates a full intrusion lifecycle.

## Key SPL Pivot Searches
```spl
index=windows_logs sourcetype="WinEventLog:Security" EventCode=4624
  Logon_Type=3
  Source_Network_Address=[SOURCE_IP_FROM_ALERT]
| table _time, Account_Name, Logon_Type, Source_Network_Address, ComputerName
| sort _time
```

## True Positive Indicators
- PsExec executed from a host that does not normally perform remote administration.
- SMB connection (445) between two workstations that have no business relationship (not domain controller traffic).
- Connection followed by a Type 3 (network) logon with an account that does not normally access that host.

## False Positive Indicators
- Connection to/from the domain controller (192.168.10.10) — expected SMB/AD traffic baseline.
- PsExec used by IT/SOC analyst for legitimate remote administration (verify against change record).

## Response Actions
- **Contain:** Immediately isolate both source and destination hosts from the network.
- **Investigate:** Full timeline correlation across Alerts 1, 2, 3, and 5 for the same hosts/accounts.
- **Escalate if:** Any true positive indicator is present — this alert represents active lateral movement and should be treated as a confirmed incident pending investigation.
- **Document:** Log source host, destination host, account, process/command, and full timeline in incident ticket. This alert alone justifies opening IR-2026-002.

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1021/
