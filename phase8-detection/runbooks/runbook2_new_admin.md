# Runbook: New Local Admin Account Created

## Alert Metadata
- **Alert ID:** SOC-RB-002
- **MITRE ATT&CK:** T1136.001 — Create Account: Local Account
- **Severity:** Critical
- **Splunk Alert Name:** SOC-Alert-T1136-NewAdmin
- **Created:** June 2026
- **Author:** Lance Vidaure

## What This Alert Detects
Creation of a new local account (EventCode 4720) and/or addition of an account to a privileged group such as Administrators (EventCode 4732), checked every 15 minutes.

## Why It Matters
Creating a new local administrator account is one of the most common persistence techniques. An attacker who has gained initial access often creates a backup account so they retain privileged access even if the original compromised credentials are reset or disabled.

## Trigger Condition
EventCode 4720 (account created) OR EventCode 4732 (member added to privileged group) on WinServer-DC. Alert fires when results > 0.

## Investigation Steps
1. Identify which account was created and which account performed the action (`Account_Name` vs the actor in `Sam_Account_Name`/Subject fields).
2. Confirm whether this matches a known, scheduled change request (IT ticket, GPO automation).
3. Check the actor's recent activity — pivot to 4624 logons and Sysmon EID 1 for that user around the same timestamp.
4. Check if the new account was immediately used to log on (4624 shortly after 4720).
5. Review whether the action occurred outside business hours.

## Key SPL Pivot Searches
```spl
index=windows_logs sourcetype="WinEventLog:Security"
  (EventCode=4624 OR EventCode=4672)
  Account_Name=[NEW_ACCOUNT_NAME]
| table _time, EventCode, Account_Name, Logon_Type, Source_Network_Address
| sort _time
```

## True Positive Indicators
- Account creation has no corresponding change ticket or GPO automation.
- New account is immediately added to Administrators and logs on shortly after.
- Actor account that created the new user has no history of performing user management.

## False Positive Indicators
- Action performed by a known domain admin during a documented onboarding/change window.
- Account creation tied to a scheduled provisioning script (consistent naming convention, consistent timing).

## Response Actions
- **Contain:** Disable the new account immediately pending verification.
- **Investigate:** Review actor's full session — what else did they touch before/after this action?
- **Escalate if:** No change ticket exists, or the account was used to log on within minutes of creation.
- **Document:** Log new account name, actor, timestamp, and group membership change in incident ticket.

## References
- MITRE ATT&CK: https://attack.mitre.org/techniques/T1136/001/
