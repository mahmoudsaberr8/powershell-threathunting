# PowerShell Threat Hunting & Hardening Lab

> ⚠️ **Educational & Lab Use Only.** All commands and techniques in this repository are sourced from MITRE ATT&CK, Atomic Red Team, and public security research. Everything was tested exclusively inside an isolated, offline Windows 10 VM. Nothing here should be run on a production system or a machine you do not own.

## Overview

This project documents **6 real-world PowerShell attack techniques** used by adversaries for execution, evasion, and credential access — and pairs each one with:

- The exact **Windows Event IDs** it generates
- A **detection strategy** a SOC/threat hunter would use to catch it
- A working **mitigation**, implemented via registry, `auditpol`, and Windows Firewall

The hardening portion was built entirely on **Windows 10 Home**, which has no `gpedit.msc`, no AppLocker, and no Credential Guard. That constraint forced a "how does this actually work under the hood" approach — every Group Policy setting is really just a registry write, and this lab proves it by replicating enterprise-grade hardening using only tools available on every Windows edition (`reg.exe`, `auditpol.exe`, PowerShell, `icacls`, Windows Firewall).

## Techniques Covered

| # | Technique | MITRE ATT&CK ID | Detection Event ID(s) | Mitigation |
|---|---|---|---|---|
| 01 | Execution Policy Bypass | T1059.001 | 4688 | Machine-level `ExecutionPolicy` registry key (overrides CLI flag) |
| 02 | Base64 Encoded Command | T1027 | 4104 | Script Block Logging + Module Logging + Transcription |
| 03 | Download Cradle (fileless execution) | T1059.001 / T1105 | 4104, 5156/5157 | Constrained Language Mode (`__PSLockdownPolicy`) + outbound firewall block |
| 04 | AMSI Bypass | T1562.001 | 4104 | CLM blocks .NET reflection; Defender policy locked via registry |
| 05 | Reverse Shell | T1059.001 / T1571 | 4688, 5156/5157 | CLM blocks `TCPClient`; firewall rules; process/connection auditing |
| 06 | Credential Dumping (Invoke-Mimikatz / LSASS) | T1003.001 | 4656, 4663, 4776 | LSASS Protected Process Light (`RunAsPPL`) |

## Repository Structure

```
ps-threat-hunting-lab/
├── README.md
├── LICENSE
└── evidence/
    ├── T01-execution-policy-bypass/
    │   ├── T01-execution-policy-bypass.md   # Attack description, mitigation, before/after, event log
    │   └── (screenshots referenced in the md file)
    ├── T02-base64-encoded-command/
    │   ├── T02-base64-encoded-command.md
    │   └── (screenshots)
    ├── T03-download-cradle/
    │   ├── T03-download-cradle.md
    │   └── (screenshots)
    ├── T04-amsi-bypass/
    │   ├── T04-amsi-bypass.md
    │   └── (screenshots)
    ├── T05-reverse-shell/
    │   ├── T05-reverse-shell.md
    │   └── (screenshots)
    └── T06-credential-dumping/
        ├── T06-credential-dumping.md
        └── (screenshots)
```

Each technique folder is self-contained: the `.md` file documents the attack, the mitigation, and the verification steps, with its screenshots (before/after/event log) sitting alongside it in the same folder and linked inline.

## Why Windows 10 Home

Most GPO/AppLocker hardening guides assume Windows 10/11 Pro or Enterprise. Home edition is missing `gpedit.msc`, AppLocker, and Credential Guard — but every one of those tools is just a friendly interface over the registry, `auditpol`, and the Windows Firewall API. This project maps each missing enterprise control to its Home-compatible equivalent:

| Enterprise Tool | Home Edition Equivalent |
|---|---|
| `gpedit.msc` → PowerShell logging policies | Direct registry keys under `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell` |
| AppLocker → Constrained Language Mode | `__PSLockdownPolicy` machine environment variable |
| AppLocker → block specific binaries | `icacls` execute-deny at the file system level |
| `gpedit.msc` → Audit Policy | `auditpol.exe` |
| `gpedit.msc` → Firewall rules | `New-NetFirewallRule` / `netsh advfirewall` |
| Credential Guard | LSASS Protected Process Light (`RunAsPPL`) — partial equivalent |

## Key Skills Demonstrated

- Detection engineering (Windows Event Log analysis, Sysmon-relevant IOCs)
- Threat hunting methodology mapped to MITRE ATT&CK
- Windows internals: registry policy enforcement, PowerShell language modes, LSASS protection
- Blue team hardening without enterprise tooling (registry, auditpol, icacls, Windows Firewall)
- Technical documentation for SOC/detection engineering workflows

## Usage

1. Open any `evidence/T0X-.../T0X-....md` file to read the full walkthrough for that technique: what the attack does, the exact commands, the registry/auditpol-based mitigation, and why it works.
2. Screenshots in each folder show the attack succeeding before hardening, the fix command being applied, the attack failing after hardening, and the corresponding Event Viewer entry.
3. To reproduce: apply the mitigation commands in an isolated lab VM (as Administrator), reboot where noted (required for LSASS PPL and Constrained Language Mode), then re-run the attack command to confirm it fails.

## References

- [MITRE ATT&CK — PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/)
- [Windows Event ID Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

## License

MIT — see [LICENSE](LICENSE).

---
*Built as part of a Blue Team / Detection Engineering self-study project. Lab environment: isolated VMware VM, Windows 10 Home.*
