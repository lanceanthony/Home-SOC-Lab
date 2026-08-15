# Phase 10 — Microsoft Sentinel Integration

**Duration:** Weeks 12–13 | **Status:** ✅ Complete

Integrated Microsoft Sentinel as a second cloud-native SIEM alongside
the existing Splunk deployment, giving the lab true dual-SIEM
capability. Onboarded WinServer-DC to Azure via Azure Arc, deployed
the Azure Monitor Agent, and rebuilt all 5 Phase 8 MITRE ATT&CK-mapped
detections as KQL Analytics Rules — each validated end-to-end against
live, self-generated test data and walked through the full Sentinel
incident investigation workflow.

## Architecture

```
Azure Subscription
└── rg-homesoclab (East US)
    ├── law-homesoclab            (Log Analytics Workspace)
    ├── Microsoft Sentinel        (enabled on law-homesoclab)
    ├── WIN-QL3E6D8BOAK           (Azure Arc-enabled server, = WinServer-DC)
    │   └── AzureMonitorWindowsAgent (extension)
    ├── dcr-winserver-dc-security (DCR — Windows Security Events)
    └── dcr-winserver-dc-sysmon  (DCR — Sysmon Operational log)
```

WinServer-DC connects to Azure via a secondary NAT-mode network
adapter in VirtualBox (added alongside the existing host-only lab
adapter), giving it outbound internet access for Arc/AMA without
disrupting the internal 192.168.10.0/24 lab network used by Splunk.

## Key Tasks
- Created Log Analytics workspace `law-homesoclab` and enabled Microsoft Sentinel
- Onboarded WinServer-DC to Azure via Azure Arc (`azcmagent connect`, device-code authentication)
- Deployed the Azure Monitor Agent (AMA) extension and two Data Collection Rules (Windows Security Events, Sysmon Operational)
- Validated ingestion of both `SecurityEvent` and Sysmon `Event` tables in Log Analytics
- Rebuilt all 5 Phase 8 Splunk detections as KQL Scheduled Query Rules with MITRE ATT&CK tagging and entity mapping
- Generated live test data and confirmed all 5 rules fired and produced incidents
- Investigated incidents through the Sentinel/Defender Incidents workflow (timeline, investigation graph, classification, closure)

## Detections Built

| Alert | MITRE Technique | Severity | Schedule |
|---|---|---|---|
| SOC-Alert-T1110-BruteForce | T1110 | High | Every 5 min |
| SOC-Alert-T1136-NewAdmin | T1136.001 | High* | Every 15 min |
| SOC-Alert-T1059-SuspiciousProcess | T1059 | Medium | Every 5 min |
| SOC-Alert-T1021-LateralMovement | T1021 | High* | Every 5 min |
| SOC-Alert-T1046-PortScan | T1046 | High | Every 5 min |

*Sentinel's severity scale tops out at High; these map to the
"Critical" severity used in the original Splunk versions.

**Detection Runbooks:** [phase10-sentinel/runbooks/](runbooks/)

## Validation

All 5 rules were tested against real, intentionally generated activity
on WinServer-DC (failed logons, local admin account creation,
encoded PowerShell/recon commands, SMB connection attempts, and a
multi-port connection sweep) and confirmed to produce incidents in the
Sentinel Incidents queue. At least one incident
(`SOC-Alert-T1021-LateralMovement`) was fully investigated end-to-end:
timeline review, investigation graph, investigation comment, and
closure with a True Positive classification.

## Notable Engineering Problems Solved

Sysmon logs its event data as embedded XML inside a single `EventData`
column rather than as flattened native fields (unlike Splunk's UF,
which flattens Sysmon fields automatically). Two approaches were
evaluated for extracting fields like `CommandLine` and
`DestinationPort`:

- **Fixed array index** (e.g. `Data[10]["#text"]`) — works, but is
  fragile: the field's position can shift if Sysmon's schema/config
  changes, silently breaking the rule.
- **Name-based lookup via `mv-expand`** — expands every `Data` element
  and filters by its `@Name` attribute, so the query keeps working
  regardless of field order. This is the approach used in the final
  rules (see runbooks 3–5).

Separately, WinServer-DC's Azure Arc extension install repeatedly
failed with a TLS/certificate handshake error
(`certificate verify failed`) when downloading the AMA extension. Root
cause: the VM's Windows Update state was over 4 years stale (last
patch: March 2022), leaving its root certificate trust store out of
date. Resolved by forcing a Windows root-cert refresh
(`certutil -generateSSTFromWU`), enforcing TLS 1.2 via the .NET
`SchUseStrongCrypto` registry keys, and running a full Windows Update
pass.

## SPL → KQL Cheat Sheet

| Splunk (SPL) | Sentinel (KQL) |
|---|---|
| `stats count by field` | `summarize count() by field` |
| `stats dc(field)` | `summarize dcount(field)` |
| `where field=value` | `where field == "value"` |
| `eval x=y` | `extend x = y` |
| `rex field=x "pattern"` | `extend x = extract("pattern", 1, field)` or `parse` |
| `bucket _time span=5m` | `bin(TimeGenerated, 5m)` |
| `table field1 field2` | `project field1, field2` |

## Tools
- Microsoft Sentinel / Log Analytics
- Azure Arc (Connected Machine Agent)
- Azure Monitor Agent (AMA)
- KQL (Kusto Query Language)
- Windows Server 2022, Sysmon v15.20
- PowerShell (test data generation), Azure CLI / Cloud Shell

## Screenshots

See [Screenshot Index](#screenshot-index) below for full file list and folder placement.
