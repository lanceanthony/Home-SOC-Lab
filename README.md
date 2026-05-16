# 🔐 Home SOC Lab — Attack, Detection & Response Environment
 
> A fully functional Security Operations Center (SOC) lab built from scratch using free and open-source tools. Designed to demonstrate hands-on skills in network security, SIEM deployment, threat detection, attack simulation, and cloud security monitoring.
 
**Author:** Lance Vidaure | **GitHub:** [github.com/lanceanthony](https://github.com/lanceanthony) | **Completed:** May 2026
 
---
 
## 📋 Project Overview
 
This project simulates a real-world enterprise security environment inside VirtualBox. It covers the full SOC workflow: building the network, deploying a SIEM, enrolling endpoints, simulating attacks, detecting threats, writing incident reports, and documenting findings — all mapped to industry frameworks.
 
### Key Highlights
- ✅ Wazuh SIEM deployed with active Windows Server agent
- ✅ Custom detection rules written and validated
- ✅ Real attack simulation using Kali Linux, nmap, Hydra, and Metasploit
- ✅ Brute-force and privilege escalation attacks detected in real time
- ✅ AWS CloudTrail configured for cloud security monitoring
- ✅ Full incident report with MITRE ATT&CK mapping
- ✅ GRC documentation: security policy and risk assessment
---
 
## 🏗️ Lab Architecture
 
```
SOC-Lab-Network (192.168.10.0/24) — VirtualBox Internal Network
│
├── 192.168.10.1   pfSense CE 2.7.2        → Network Gateway / Firewall
├── 192.168.10.10  Windows Server 2022     → Domain Controller (SOCLAB.local)
├── 192.168.10.20  Ubuntu 22.04 LTS        → Wazuh SIEM (Manager + Indexer + Dashboard)
└── 192.168.10.30  Kali Linux 2026.1       → Attacker / Red Team VM
```
 
**Host Machine:** Windows 11, 8GB RAM, VirtualBox 7.x  
**Cloud:** AWS Free Tier — CloudTrail + S3 + IAM
 
---
 
## 📁 Repository Structure
 
```
Home-SOC-Lab/
├── README.md
├── phase1-network/
│   ├── README.md
│   └── screenshots/
├── phase2-windows/
│   ├── README.md
│   └── screenshots/
├── phase3-wazuh/
│   ├── README.md
│   ├── local_rules.xml
│   └── screenshots/
├── phase4-attack/
│   ├── README.md
│   ├── IR-2026-001_Incident_Report.pdf
│   ├── mitre-attack-mapping.md
│   └── screenshots/
├── phase5-aws/
│   ├── README.md
│   └── screenshots/
├── phase6-grc/
│   ├── README.md
│   ├── SOCLab_Security_Policy.pdf
│   └── SOCLab_Risk_Assessment.pdf
└── docs/
    └── SOCLab_Build_Guide.pdf
```
 
---
 
## 🔬 Phase Breakdown
 
### Phase 1 — Network Foundation
**Duration:** Week 1 | **Status:** ✅ Complete
 
Built the core network infrastructure using pfSense CE as the perimeter firewall and gateway. Configured internal-only network isolation to ensure all lab traffic stays contained within VirtualBox.
 
**Key tasks:**
- Installed and configured pfSense CE 2.7.2 at 192.168.10.1
- Configured LAN interface with DHCP server for SOC-Lab-Network
- Set firewall rules to isolate lab from host network
- Verified inter-VM connectivity
**Tools:** pfSense CE 2.7.2, VirtualBox 7.x
 
---
 
### Phase 2 — Windows Active Directory
**Duration:** Week 2–3 | **Status:** ✅ Complete
 
Deployed Windows Server 2022 as a domain controller with Active Directory, Group Policy, and user/OU structure simulating a small enterprise environment.
 
**Key tasks:**
- Promoted Windows Server 2022 to Domain Controller (SOCLAB.local)
- Created OUs: IT, HR, Finance, Contractors
- Created users: jsmith, hradmin, contractor01
- Configured GPOs: password policy, account lockout, audit logging
- Tested privilege escalation (Event IDs 4625, 4648)
**Tools:** Windows Server 2022, Active Directory, Group Policy Management
 
---
 
### Phase 3 — Wazuh SIEM Deployment
**Duration:** Week 4 | **Status:** ✅ Complete
 
Deployed the full Wazuh stack (indexer, manager, dashboard) on Ubuntu 22.04 and enrolled Windows Server as a monitored agent. Wrote and validated two custom detection rules.
 
**Key tasks:**
- Installed Wazuh 4.7.x (all-in-one) on Ubuntu 22.04
- Enrolled WinServer-DC as Agent ID 001 (Active)
- Confirmed agent connectivity: port 1514/tcp (communication), 1515/tcp (enrollment)
- Wrote custom detection rules:
  - Rule 100002: 5+ failed logons in 2 minutes (brute-force threshold)
  - Rule 100003: New privileged account created
- Verified rules loaded successfully via wazuh-analysisd
**Tools:** Wazuh 4.7.x, Ubuntu 22.04, OpenSearch 7.10.2
 
**Custom Rules (local_rules.xml):**
```xml
<group name="local,">
  <rule id="100002" level="10" frequency="5" timeframe="120">
    <if_matched_sid>60122</if_matched_sid>
    <description>5+ failed logons in 2 minutes</description>
  </rule>
  <rule id="100003" level="12">
    <if_sid>60144</if_sid>
    <description>New privileged account created</description>
  </rule>
</group>
```
 
---
 
### Phase 4 — Attack Simulation & Incident Response
**Duration:** Weeks 5–6 | **Status:** ✅ Complete
 
Deployed Kali Linux as an attacker VM and executed three attack phases against the lab environment. All attacks were monitored in Wazuh in real time. A full incident report was produced.
 
**Attacks Executed:**
 
| Attack | Tool | Target | MITRE ATT&CK | Detected |
|--------|------|---------|--------------|----------|
| Network recon | nmap -sV | 192.168.10.20 | T1046 | ❌ No |
| SSH brute-force | Hydra v9.6 | 192.168.10.20:22 | T1110 | ✅ Yes |
| SSH fingerprint | Metasploit ssh_version | 192.168.10.20:22 | T1592 | ❌ No |
| SSH brute-force | Metasploit ssh_login | 192.168.10.20:22 | T1110 | ✅ Yes |
| Privilege escalation | net user /add | 192.168.10.10 | T1136.001 | ✅ Yes |
 
**Detection Gap Identified:** nmap reconnaissance not detected — Wazuh requires network-layer IDS (Suricata) to catch port scans.
 
**Wazuh Rules Fired:**
- Rule 5760 (level 5) — sshd: authentication failed
- Rule 5503 (level 5) — PAM: User login failed
- Event ID 4738 — User account changed
- Event ID 4732 — Member added to privileged group
📄 **[Full Incident Report → IR-2026-001](phase4-attack/IR-2026-001_Incident_Report.pdf)**
 
**Tools:** Kali Linux 2026.1, nmap, Hydra, Metasploit Framework
 
---
 
### Phase 5 — AWS Cloud Security
**Duration:** Week 7 | **Status:** ✅ Complete
 
Integrated AWS cloud security monitoring into the SOC lab using CloudTrail for API activity logging and IAM least-privilege configuration.
 
**Key tasks:**
- Created AWS Free Tier account and configured region (us-east-2)
- Enabled CloudTrail trail (soclab-trail) with S3 log storage
- Created least-privilege IAM user (soclab-analyst) with ReadOnlyAccess
- Simulated cloud activity: EC2 describe, key pair creation
- Queried CloudTrail logs via AWS CLI (CloudShell)
- Identified security finding: MFA not enabled on IAM user (remediated)
- Enabled MFA on soclab-analyst account
**Security Finding:** `mfaAuthenticated: false` in CloudTrail event — IAM user accessed console without MFA.  
**Remediation:** MFA enabled using Authenticator app.
 
**Tools:** AWS CloudTrail, AWS S3, AWS IAM, AWS CloudShell
 
---
 
### Phase 6 — GRC Documentation
**Duration:** Week 8 | **Status:** ✅ Complete
 
Produced governance, risk, and compliance documentation for the lab environment including a security policy and risk assessment — simulating real-world GRC analyst deliverables.
 
📄 **[Security Policy PDF](phase6-grc/SOCLab_Security_Policy.pdf)**  
📄 **[Risk Assessment PDF](phase6-grc/SOCLab_Risk_Assessment.pdf)**
 
---
 
## 🛡️ Skills Demonstrated
 
| Domain | Skills |
|--------|--------|
| Network Security | Firewall config, network segmentation, VLAN isolation |
| SIEM | Wazuh deployment, agent enrollment, custom rule writing |
| Threat Detection | Real-time alert monitoring, log analysis, event correlation |
| Attack Simulation | nmap, Hydra, Metasploit — mapped to MITRE ATT&CK |
| Incident Response | IR report writing, Five Ws, IOC documentation, timeline analysis |
| Cloud Security | AWS CloudTrail, IAM least-privilege, MFA enforcement |
| GRC | Security policy writing, risk assessment, compliance mapping |
| Linux | Ubuntu Server administration, systemctl, bash scripting |
| Windows | Active Directory, GPO, Windows Event Log analysis |
 
---
 
## 📊 MITRE ATT&CK Coverage
 
| Technique ID | Name | Simulated | Detected |
|-------------|------|-----------|----------|
| T1046 | Network Service Discovery | ✅ | ❌ |
| T1110 | Brute Force | ✅ | ✅ |
| T1110.001 | Password Guessing | ✅ | ✅ |
| T1592 | Gather Victim Host Information | ✅ | ❌ |
| T1136.001 | Create Account: Local Account | ✅ | ✅ |
| T1078 | Valid Accounts | ✅ | ✅ |
 
---
 
## 📜 Certifications & Context
 
This project was built alongside:
- **CompTIA Security+** (active)
- **TryHackMe SOC Level 1** (completed)
- **Splunk Core Certified Power User** (in progress)
- **Queens College CUNY** — B.S. Computer Science (Dec 2026)
- **U.S. Army National Guard** — CBRN Specialist NCO (active)
---
 
## 📬 Contact
 
**Lance Vidaure**  
[github.com/lanceanthony](https://github.com/lanceanthony) | [LinkedIn](https://linkedin.com/in/lancevidaure)
