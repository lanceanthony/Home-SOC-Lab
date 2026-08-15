# Runbook: SOC-Alert-T1110-BruteForce (Sentinel/KQL)

## MITRE ATT&CK
T1110 - Brute Force

## Severity
High

## Trigger Condition
5 or more failed logon attempts (EventID 4625) from the same account,
computer, and source IP within a 5-minute window.

## Detection Query (KQL)
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedCount = count() by Account, Computer, IpAddress, bin(TimeGenerated, 5m)
| where FailedCount >= 5
```

## Investigation Steps
1. Identify the source account and IP address from the alert entities.
2. Confirm whether the account is a real user or service account expected to authenticate from that source.
3. Check for any successful logon (EventID 4624) immediately following the failed attempts — this would indicate a successful brute force.
4. Review the account's recent authentication history for a baseline of normal behavior.

## Pivot Searches
```kql
// Check for a successful logon shortly after the failed attempts
SecurityEvent
| where EventID == 4624
| where Account == "<account>"
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
```
```kql
// Full authentication history for the account
SecurityEvent
| where Account == "<account>"
| where EventID in (4624, 4625)
| sort by TimeGenerated desc
```

## True/False Positive Indicators
- **True Positive:** Unfamiliar source IP, account not expected to authenticate from that location, followed by a successful logon.
- **False Positive:** Known service account with a misconfigured credential, user who mistyped their password repeatedly, expected automation/script retry behavior.

## Response Actions
- If true positive: disable the account, reset credentials, isolate the source host if internal, review for lateral movement.
- If false positive: document and consider adjusting the account's expected behavior baseline or excluding known automation sources.

## SPL vs KQL Comparison
| Splunk (SPL) | Sentinel (KQL) |
|---|---|
| `bucket _time span=5m` | `bin(TimeGenerated, 5m)` |
| `stats count by _time, Account_Name, Source_Network_Address` | `summarize FailedCount = count() by Account, Computer, IpAddress, bin(TimeGenerated, 5m)` |
| `where count >= 5` | `where FailedCount >= 5` |

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1110/
