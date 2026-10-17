# Phase 11 — Endpoint Detection & Response (EDR)

Home SOC Lab · Detection Engineering & Threat Validation

This phase extends the lab beyond SIEM (Splunk + Microsoft Sentinel, Phases 7–10)
into the **endpoint detection and response** layer. I deployed two EDR platforms,
authored custom detection-as-code rules, executed a set of MITRE ATT&CK techniques
with Atomic Red Team, and measured detection coverage across the stack, including
the gaps.

---

## Objective

Simulate an attacker on a Windows Server 2022 domain controller and prove that each
stage is **detected** (real-time) and **investigable** (DFIR triage) using
open-source / free-tier EDR tooling, then document where coverage held and where it
did not.

---

## Environment

| Component | Detail |
|---|---|
| Target host | Windows Server 2022 Standard (domain controller, `WIN-QL3E6D8BOAK`) |
| Hypervisor | Oracle VirtualBox |
| EDR (detection) | **LimaCharlie** (free tier) — real-time telemetry + Detection & Response rules |
| Rule pack | **ext-sigma** (open-source Sigma ruleset, managed) |
| EDR (DFIR) | **Velociraptor** 0.77.3 — artifact collection & hunting (single-host GUI mode) |
| Adversary emulation | **Atomic Red Team** (345 techniques installed) |
| SIEM (prior phases) | Splunk Enterprise + Microsoft Sentinel |

---

## Tools deployed

### LimaCharlie (real-time detection)
- Windows sensor deployed to the DC; live telemetry confirmed (`NEW_PROCESS`,
  `DNS_REQUEST`, `SENSITIVE_PROCESS_ACCESS`, `CODE_IDENTITY`, autoruns).
- Subscribed to the **ext-sigma** managed ruleset (hundreds of MITRE-mapped rules).
- Authored **4 custom Detection & Response (D&R) rules** in YAML (detection-as-code),
  each MITRE-mapped and attributed.

### Velociraptor (DFIR triage & hunting)
- Deployed single-host (server + self-enrolled client in one process) to respect lab
  RAM constraints.
- Collected forensic artifacts on demand (e.g. `Windows.System.Pslist` — full running
  process table with paths and hashes).

---

## Custom detection rules authored

All rules are MITRE ATT&CK-mapped and written as LimaCharlie D&R YAML.

| Rule | Technique | Tactic | Detect logic (summary) |
|---|---|---|---|
| `cred-access-lsass-access` | T1003.001 | Credential Access | `SENSITIVE_PROCESS_ACCESS` targeting `lsass.exe` |
| `persistence-run-key` | T1547.001 | Persistence | `reg.exe` writing `CurrentVersion\Run` (tuned to available telemetry) |
| `defense-evasion-clear-logs` | T1070 | Defense Evasion | `fsutil.exe` / `wevtutil.exe` execution |
| `defense-evasion-rundll32-lolbin` | T1218.011 | Defense Evasion | `rundll32.exe` with `javascript` / `GetObject` / `RunHTMLApplication` |

Rule definitions are in [`/rules`](./rules).

---

## Adversary emulation

Executed six ATT&CK techniques with Atomic Red Team, each timestamped (UTC) for
cross-tool correlation:

| Technique | Test | Tactic |
|---|---|---|
| T1003.001 | Dump LSASS via ProcDump | Credential Access |
| T1547.001 | Registry Run key (`reg add`) | Persistence |
| T1053.005 | Scheduled task (`schtasks`) | Persistence |
| T1070 | Indicator removal (`fsutil`) | Defense Evasion |
| T1218.011 | Rundll32 remote JS payload (LOLBin) | Defense Evasion |
| T1059.001 | PowerShell command execution | Execution |

---

## Detection coverage matrix

Result of the emulation run. ✅ detected · ⚠️ rule authored but did not fire ·
❌ not detected · ◐ partial / investigable only.

| Technique | LimaCharlie (custom) | LimaCharlie (Sigma) | Velociraptor (DFIR) |
|---|---|---|---|
| **T1003.001** LSASS dump | ✅ `cred-access-lsass-access` | ✅ | ✅ process hunt |
| **T1547.001** Run key | ✅ `persistence-run-key` (tuned) | ✅ (2 rules) | ✅ RunKeys artifact |
| **T1053.005** Scheduled task | — | ✅ (2 rules) | ✅ scheduled-tasks artifact |
| **T1070** Indicator removal | ✅ `defense-evasion-clear-logs` | ✅ Fsutil | ✅ event-log hunt |
| **T1218.011** Rundll32 LOLBin | ⚠️ rule authored, no event emitted | ❌ | ◐ process hunt |
| **T1059.001** PowerShell | — | ✅ (2 rules) | ✅ process hunt |

**Score: 5 / 6 techniques detected · 4 custom rules firing · 1 documented gap.**

---

## Key findings

1. **Credential dumping was caught by my own rule, not just the vendor pack.**
   The `cred-access-lsass-access` D&R rule fired on the ProcDump LSASS handle access
   even though Windows Defender blocked the dump payload itself — the handle-open is
   the detection signal, independent of whether the dump completed.

2. **Defense-in-depth validated.** Where a custom rule initially missed (T1547.001
   before tuning), the Sigma pack caught it. Where the Sigma pack missed (T1218.011),
   the gap was isolated. Layered detection covered more than either layer alone.

3. **Documented visibility gap — T1218.011 (rundll32 LOLBin).** The remote-JS-payload
   variant did not surface a `NEW_PROCESS` event the sensor could match, so neither
   Sigma nor my authored rule fired. Root cause is a **telemetry/sensor-configuration
   limitation**, not rule-logic error — the rule is correct but had no event to match.
   This is the kind of blind spot detection engineering exists to find.

4. **Detection tuning to available telemetry.** The T1547.001 rule was first written
   against `REGISTRY_WRITE` events, which the sensor does not emit by default. I
   re-authored it against the `reg.exe` process + command-line telemetry that *is*
   collected, and confirmed it then fired. Demonstrates adapting detection logic to
   the data actually available.

---

## Skills demonstrated

- EDR deployment and sensor management (LimaCharlie, Velociraptor)
- Detection-as-code authoring (LimaCharlie D&R YAML, MITRE-mapped)
- Open-source ruleset integration and tuning (Sigma)
- Adversary emulation / purple-teaming (Atomic Red Team, MITRE ATT&CK)
- DFIR artifact collection and host triage (Velociraptor)
- Detection coverage analysis and gap identification

---

## Repository layout

```
phase11-edr/
├── README.md
├── rules/                       # custom LimaCharlie D&R rules (YAML)
│   ├── cred-access-lsass-access.yaml
│   ├── persistence-run-key.yaml
│   ├── defense-evasion-clear-logs.yaml
│   └── defense-evasion-rundll32-lolbin.yaml
└── screenshots/                 # evidence (sensor online, detections, DFIR)
```

---

*Part of an ongoing home SOC lab. Prior phases: Splunk integration & detection
engineering (Phases 7–9), Microsoft Sentinel dual-SIEM build via Azure Arc
(Phase 10).*
