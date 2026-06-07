# Phase 7 — Splunk Integration

**Duration:** Week 9 | **Status:** ✅ Complete

Integrated Splunk Enterprise into the existing SOC lab alongside Wazuh, creating a dual-SIEM environment. Deployed the Splunk Universal Forwarder on WinServer-DC, installed Sysmon with the SwiftOnSecurity configuration, and configured real-time log ingestion from Windows event channels and pfSense syslog into dedicated Splunk indexes.

---

## Architecture

![Phase 7 Architecture](screenshots/Phase7_Architecture_Diagram.svg)

| Component | Role | IP Address |
|-----------|------|------------|
| pfSense CE 2.7.2 | Firewall / Router | 192.168.10.1 (LAN) |
| WinServer-DC (Win Server 2022) | Domain Controller / Log Source | 192.168.10.10 |
| Ubuntu 22.04 — Splunk Enterprise 9.3.2 | SIEM / Indexer | 192.168.10.20 (Lab) / 192.168.56.102 (Host-Only) |
| Kali Linux | Attacker VM | 192.168.10.30 |
| Windows Host | Analyst Workstation (Splunk UI) | Physical Host |

---

## Key Tasks

- Installed Splunk Enterprise 9.3.2 on Ubuntu 22.04 (headless, terminal-only)
- Created custom indexes: `windows_logs` and `network_logs`
- Configured Splunk listeners: TCP 9997 (Universal Forwarder), UDP 514 (syslog), TCP 8000 (Web UI)
- Installed Splunk Universal Forwarder 10.4.0 on WinServer-DC
- Installed Sysmon v15.20 with SwiftOnSecurity configuration on WinServer-DC
- Configured forwarder to monitor Security, System, Application, and Sysmon event channels
- Accessed Splunk Web UI from physical Windows host via Host-Only adapter (192.168.56.102:8000)
- Validated data ingestion across all four sourcetypes (1,090+ events)
- Confirmed failed logon detection (EventCode 4625) end-to-end

---

## Data Sources

| Sourcetype | Index | Source | Event Volume |
|------------|-------|--------|-------------|
| WinEventLog:Security | windows_logs | WinServer-DC | 362+ events |
| WinEventLog:Sysmon | windows_logs | WinServer-DC | 710+ events |
| WinEventLog:System | windows_logs | WinServer-DC | 16+ events |
| WinEventLog:Application | windows_logs | WinServer-DC | 2+ events |
| syslog | network_logs | pfSense (UDP 514) | Configured |

---

## Sysmon EventCodes Observed

| EventCode | Description | Count |
|-----------|-------------|-------|
| 1 | Process Creation | 504 |
| 22 | DNS Query | 150 |
| 8 | CreateRemoteThread | 63 |
| 16 | Sysmon Config Change | 1 |
| 4 | Sysmon Service State Change | 1 |

---

## Security EventCodes Observed

| EventCode | Description |
|-----------|-------------|
| 5156 | Windows Filtering Platform — connection allowed |
| 5158 | Windows Filtering Platform — bind permitted |
| 4658 | Handle to object closed |
| 4656 | Handle to object requested |
| 4624 | Successful logon |
| 4625 | **Failed logon (detected in test)** |
| 4627 | Group membership enumeration |
| 4672 | Special privileges assigned to logon |

---

## Validation Searches

```spl
-- All sourcetypes overview
index=windows_logs | stats count by sourcetype

-- Security event breakdown
index=windows_logs sourcetype="WinEventLog:Security" | stats count by EventCode | sort -count

-- Sysmon event breakdown
index=windows_logs sourcetype="WinEventLog:Sysmon" | stats count by EventCode | sort -count

-- Failed logon detection
index=windows_logs EventCode=4625 | table _time, Account_Name, Logon_Type, Source_Network_Address
```

---

## Tools

- Splunk Enterprise 9.3.2
- Splunk Universal Forwarder 10.4.0
- Sysmon v15.20 (SwiftOnSecurity config)
- Ubuntu 22.04
- Windows Server 2022
- VirtualBox 7.x

---

## Screenshots

| Screenshot | Description |
|------------|-------------|
| `splunk_home.png` | Splunk Web UI — logged in as admin |
| `splunk_indexes.png` | Settings → Indexes showing windows_logs and network_logs |
| `splunk_udp514.png` | Settings → Data Inputs → UDP 514 active |
| `splunk_port9997.png` | Settings → Forwarding and Receiving → 9997 active |
| `splunk_sourcetypes.png` | All four sourcetypes with event counts |
| `splunk_security_eventcodes.png` | Security EventCode breakdown |
| `splunk_sysmon_eventcodes.png` | Sysmon EventCode breakdown |
| `splunk_4625_detection.png` | Failed logon EventCode 4625 detected |
| `Phase7_Architecture_Diagram.svg` | Full network architecture diagram |
