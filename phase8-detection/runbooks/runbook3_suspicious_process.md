# Runbook: Suspicious Process Creation

## Alert Metadata
- **Alert ID:** SOC-RB-003
- **MITRE ATT&CK:** T1059 — Command and Scripting Interpreter
- **Severity:** Medium
- **Splunk Alert Name:** SOC-Alert-T1059-SuspiciousProcess
- **Created:** June 2026
- **Author:** Lance Vidaure

## What This Alert Detects
Sysmon EventCode 1 (process creation) events where the command line contains common reconnaissance or enumeration commands: `whoami`, `net user`, `net group`, `systeminfo`, or `ipconfig`. Checked every 5 minutes.

## Why It Matters
These commands are textbook post-exploitation discovery actions (MITRE Discovery tactic). An attacker who has landed on a host typically runs these within the first minutes to understand their privilege level, the local user base, group memberships, and network configuration before deciding their next move.

## Trigger Condition
Sysmon EID 1 where `CommandLine` matches `whoami`, `net user`, `net group`, `systeminfo`, or `ipconfig` (case-insensitive). Alert fires when results > 0.

## Investigation Steps
1. Identify the parent process (`ParentImage`) — is it a normal shell (explorer → cmd/powershell) or something unusual (Office app, browser, scheduled task)?
2. Check the `User` field — is this an interactive admin session or a service account?
3. Look at the sequence of commands — a single `whoami` from an admin doing routine work is normal; a rapid sequence of all five commands in seconds is reconnaissance behavior.
4. Pivot to Sysmon EID 3 (network connections) from the same `ProcessGuid`/host around the same time — did recon precede a connection attempt?
5. Check for any 4625/4624 events on this host shortly before the recon commands ran.

## Key SPL Pivot Searches
```spl
index=windows_logs sourcetype="WinEventLog:Sysmon" EventCode=1
  ComputerName=[HOST_FROM_ALERT]
| table _time, User, ParentImage, Image, CommandLine
| sort _time
```

## True Positive Indicators
- Commands run via PowerShell spawned from an unusual parent (not an interactive logon shell).
- Multiple recon commands executed in rapid succession (seconds apart).
- Activity follows a successful logon from an unfamiliar source IP.

## False Positive Indicators
- Admin or analyst running these commands manually for legitimate troubleshooting.
- Commands originate from a known monitoring/inventory script (consistent schedule, consistent account).

## Response Actions
- **Contain:** If parent process or user account is unfamiliar, isolate the host from the network.
- **Investigate:** Build a full process tree (parent/child) around the triggering event.
- **Escalate if:** Recon commands are followed by lateral movement indicators (Alert 4) or new account creation (Alert 2).
- **Document:** Log host, user, full command sequence, and timestamps in incident ticket.

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1059/
