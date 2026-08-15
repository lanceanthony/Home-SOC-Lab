# Runbook: SOC-Alert-T1136-NewAdmin (Sentinel/KQL)

## MITRE ATT&CK
T1136.001 - Create Account: Local Account

## Severity
High (Sentinel's severity ceiling; equivalent to "Critical" in Splunk version)

## Trigger Condition
A new local account is created (EventID 4720) or added to a privileged
group such as local Administrators (EventID 4732).

## Detection Query (KQL)
```kql
SecurityEvent
| where EventID in (4720, 4732)
| project TimeGenerated, EventID, Account = TargetAccount, Computer, SubjectAccount
```

## Investigation Steps
1. Identify the account that was created or promoted, and the account that performed the action (`SubjectAccount`).
2. Confirm whether this account creation/privilege change was part of an approved change request or expected admin activity.
3. Check the subject account's recent activity for other unusual actions around the same time window.
4. Verify the new account's group memberships and logon activity since creation.

## Pivot Searches
```kql
// All activity by the account that performed the creation
SecurityEvent
| where Account == "<SubjectAccount>"
| sort by TimeGenerated desc
| take 50
```
```kql
// Logon activity by the newly created/promoted account
SecurityEvent
| where Account == "<TargetAccount>"
| where EventID in (4624, 4625)
| sort by TimeGenerated desc
```

## True/False Positive Indicators
- **True Positive:** Account created outside of change management, unexpected subject account performing the action, off-hours creation, unfamiliar naming convention (e.g., not matching org's standard user ID format).
- **False Positive:** IT/helpdesk performing routine onboarding, documented change ticket exists, subject account is a known admin performing expected work.

## Response Actions
- If true positive: disable the newly created/promoted account immediately, investigate the subject account for compromise, review all actions taken by the new account since creation.
- If false positive: document the change ticket reference and close.

## SPL vs KQL Comparison
| Splunk (SPL) | Sentinel (KQL) |
|---|---|
| `EventCode=4720 OR EventCode=4732` | `EventID in (4720, 4732)` |
| `table _time, EventCode, ...` | `project TimeGenerated, EventID, ...` |

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1136/001/
