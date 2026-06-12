# Runbook: Brute Force Login Detection

## Alert Metadata
- **Alert ID:** SOC-RB-001
- **MITRE ATT&CK:** T1110 — Brute Force
- **Severity:** High
- **Splunk Alert Name:** SOC-Alert-T1110-BruteForce
- **Created:** June 2026
- **Author:** Lance Vidaure

## What This Alert Detects
One or more failed logon attempts (EventCode 4625) against any account, bucketed in 5-minute windows and grouped by source IP and account name.

## Why It Matters
Password spraying and credential stuffing attacks rely on repeated failed logons to guess valid credentials. Left undetected, a successful logon (4624) often follows, giving the attacker initial access.

## Trigger Condition
EventCode 4625 events bucketed into 5-minute windows, grouped by `_time`, `Account_Name`, and `Source_Network_Address`. Alert fires when results > 0.

## Investigation Steps
1. Identify the source IP — is it internal (lab) or external?
2. Check if any 4624 (successful logon) followed the 4625 events from the same source.
3. Identify which accounts were targeted — admin accounts escalate priority immediately.
4. Determine if this is a single-account brute force or a password spray across multiple accounts.
5. Pivot to Sysmon EID 1 on the source host for any post-logon process activity.

## Key SPL Pivot Searches
```spl
index=windows_logs sourcetype="WinEventLog:Security"
  (EventCode=4624 OR EventCode=4625)
  Source_Network_Address=[SOURCE_IP_FROM_ALERT]
| table _time, EventCode, Account_Name, Logon_Type
| sort _time
```

## True Positive Indicators
- Source IP is external or an unexpected internal host.
- Multiple different accounts targeted from the same source (spray pattern).
- A successful 4624 logon follows a burst of 4625 events.

## False Positive Indicators
- Source IP is a known service account host or scheduled task runner.
- Single account, consistent with an IT admin password reset operation.
- Source is the local host (::1) during testing/lab activity.

## Response Actions
- **Contain:** Block source IP at pfSense firewall.
- **Investigate:** Check for any 4624 success following the burst.
- **Escalate if:** Any 4624 success follows the brute force pattern.
- **Document:** Log account names, source IP, and timestamps in incident ticket.

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1110/
