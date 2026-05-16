# MITRE ATT&CK Mapping — Home SOC Lab Phase 4

**Date:** May 16, 2026  
**Analyst:** Lance Vidaure  
**Environment:** SOC-Lab-Network (192.168.10.0/24)  
**Attacker VM:** Kali Linux 2026.1 (192.168.10.30)  
**Target VMs:** Ubuntu-Target (192.168.10.20), WinServer-DC (192.168.10.10)

---

## Techniques Simulated

| Technique ID | Technique Name | Tactic | Tool | Detected |
|-------------|----------------|--------|------|----------|
| T1046 | Network Service Discovery | Discovery | nmap -sV | ❌ No |
| T1592 | Gather Victim Host Information | Reconnaissance | Metasploit ssh_version | ❌ No |
| T1110 | Brute Force | Credential Access | Hydra v9.6 | ✅ Yes |
| T1110.001 | Password Guessing | Credential Access | Hydra wordlist | ✅ Yes |
| T1110 | Brute Force | Credential Access | Metasploit ssh_login | ✅ Yes |
| T1136.001 | Create Account: Local Account | Persistence | net user /add | ✅ Yes |
| T1078 | Valid Accounts | Defense Evasion | net localgroup administrators | ✅ Yes |

---

## Attack Chain

```
[Reconnaissance]         T1046  → nmap -sV 192.168.10.20
                         T1592  → Metasploit ssh_version
         ↓
[Credential Access]      T1110  → Hydra SSH brute-force (6 attempts)
                         T1110  → Metasploit ssh_login (6 attempts)
         ↓
[Persistence]            T1136.001 → net user testadmin /add
                         T1078     → net localgroup administrators testadmin /add
```

---

## Detection Coverage

### Detected ✅
- **T1110 (Brute Force):** Wazuh Rule 5760 — `sshd: authentication failed` (level 5)
- **T1110 (Brute Force):** Wazuh Rule 5503 — `PAM: User login failed` (level 5)
- **T1136.001 (Create Account):** Windows Event ID 4720 — new user created
- **T1078 (Valid Accounts):** Windows Event ID 4732 — member added to Administrators group
- **T1078 (Valid Accounts):** Windows Event ID 4738 — user account changed

### Not Detected ❌
- **T1046 (Network Service Discovery):** nmap scan generated zero Wazuh alerts
- **T1592 (Gather Victim Host Info):** Metasploit SSH fingerprint generated zero Wazuh alerts

---

## IOCs

| Type | Value | Associated Technique |
|------|-------|---------------------|
| IP Address | 192.168.10.30 | All attacker traffic |
| Port | 22/tcp | T1110 SSH brute-force |
| Port | 443/tcp | T1046 discovered service |
| Username | root | T1110 brute-force target |
| Username | testadmin | T1136.001 created account |
| Tool | nmap 7.x | T1046 |
| Tool | Hydra v9.6 | T1110 |
| Tool | Metasploit ssh_version | T1592 |
| Tool | Metasploit ssh_login | T1110 |

---

## Remediation Recommendations

| Technique | Recommendation |
|-----------|---------------|
| T1046 | Deploy Suricata IDS for network-layer port scan detection |
| T1592 | Suppress SSH version banner in sshd_config |
| T1110 | Install Fail2Ban — block after 3 failed SSH attempts |
| T1136.001 | GPO restricting local account creation; alert on Event ID 4720 |
| T1078 | Review Administrators group membership weekly; alert on Event ID 4732 |

---

*Full incident report: [IR-2026-001_Incident_Report.pdf](IR-2026-001_Incident_Report.pdf)*
