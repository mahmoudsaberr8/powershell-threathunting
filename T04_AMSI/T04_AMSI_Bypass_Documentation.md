# Technique 04 — AMSI Bypass (Disable Malware Scanning)
## Lab Documentation | Windows 10 Pro
**MITRE:** T1562.001 | **Severity:** Critical | **Status:** Fully Mitigated

---

## What This Attack Does

AMSI (Antimalware Scan Interface) is a Windows feature that lets antivirus
scan PowerShell script content at runtime **before it executes**. This stops
many attacks even when no file is written to disk — including download cradles,
Mimikatz, and reverse shells.

The bypass uses .NET reflection to reach inside PowerShell's internals and
flip a single private field called `amsiInitFailed`:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
  .GetField('amsiInitFailed','NonPublic,Static')
  .SetValue($null,$true)
```

When `amsiInitFailed` is set to `True`, Windows thinks AMSI failed to
initialise and skips all scanning for that session. Every subsequent command
runs completely invisible to antivirus — download cradles, Mimikatz, reverse
shells all become undetectable.

**Why this matters:** A successful AMSI bypass is usually step two in an
attack chain. Step one is execution policy bypass (T01), step two is AMSI
bypass, and then everything else follows freely.

---

## Why T03 Already Solved This

Constrained Language Mode (applied in T03) removes .NET reflection from
PowerShell entirely. The bypass depends on three reflection method calls:

```
.GetType()   → removed by CLM
.GetField()  → removed by CLM
.SetValue()  → removed by CLM
```

Without these, the bypass cannot be constructed at all. CLM makes the
entire attack surface disappear before the attacker can reach it.

---

## Attack Demonstration — Two Layers Blocking

Run in a normal PowerShell (not admin):

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Layer 1 result — Defender AMSI signature fires first:

```
This script contains malicious content and has been blocked by your antivirus software.
+ CategoryInfo: ParserError: (:) [], ParentContainsErrorRecordException
+ FullyQualifiedErrorId: ScriptContainedMaliciousContent
```

Windows Defender has a specific signature for the `AmsiUtils` +
`amsiInitFailed` string combination. It recognises the bypass attempt
at the parser level and blocks it before any code runs.

![Layer 1 — Defender AMSI signature blocks the bypass](screenshots/T04/01_defender_amsi_signature_blocks.png)

### Layer 2 result — CLM blocks .NET reflection independently:

Run the read version of the same command:
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').GetValue($null)
```

```
Cannot invoke method. Method invocation is supported only on core types in this language mode.
+ CategoryInfo: InvalidOperation: (:) [], RuntimeException
+ FullyQualifiedErrorId: MethodInvocationNotSupportedInConstrainedLanguage
```

CLM explicitly identifies itself as the reason the reflection failed.
Even if Defender missed the signature, CLM would catch this independently.

![Layer 2 — CLM blocks .NET reflection](screenshots/T04/02_clm_blocks_reflection.png)

---

## Defence Architecture — Two Independent Layers

```
Attacker runs AMSI bypass command
         │
         ▼
┌─────────────────────────────────────┐
│  Layer 1 — AMSI / Defender          │
│  Signature match: AmsiUtils +        │
│  amsiInitFailed = known attack       │
│  Result: ScriptContainedMalicious   │
│          Content → BLOCKED           │
└─────────────────────────────────────┘
         │ (if Defender somehow missed it)
         ▼
┌─────────────────────────────────────┐
│  Layer 2 — Constrained Language Mode│
│  .GetType() / .GetField() are        │
│  .NET reflection = not a core type  │
│  Result: MethodInvocationNot        │
│          SupportedInConstrainedLang │
│          uage → BLOCKED              │
└─────────────────────────────────────┘
         │ (both must fail for attack to succeed)
         ▼
              AMSI stays active
         antivirus keeps scanning everything
```

The attacker is in a race they cannot win. AMSI scans before CLM runs,
and CLM runs before the code executes.

---

## Additional Fix — Lock Windows Defender ON via Registry

CLM blocks the bypass mechanism. This registry fix locks Defender itself
ON at machine policy level — preventing an attacker from disabling it
through Settings or other means even if they find a CLM bypass.

Run as Administrator in PowerShell ISE (F5):

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force

Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
  -Name "DisableAntiSpyware" `
  -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force

Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
  -Name "DisableRealtimeMonitoring" `
  -Value 0 -Type DWord

Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
  -Name "DisableBehaviorMonitoring" `
  -Value 0 -Type DWord

Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
  -Name "DisableScriptScanning" `
  -Value 0 -Type DWord

gpupdate /force
```

**Why value 0 keeps Defender ON:** These are "Disable" flags. Value `0`
means the disable is OFF — Defender stays running. Value `1` would disable
it. Setting them to `0` via machine-level registry prevents anyone from
toggling Defender off through the Settings app or any other user-level method.

---

## Verification — Registry Values Confirmed

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" |
  Select-Object DisableAntiSpyware

Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" |
  Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableScriptScanning
```

Results:

```
DisableAntiSpyware
------------------
0

DisableRealtimeMonitoring  DisableBehaviorMonitoring  DisableScriptScanning
-------------------------  -------------------------  ---------------------
0                          0                          0
```

All four protection flags confirmed at `0` — Defender locked ON.

![Verification — all Defender registry values confirmed at 0](screenshots/T04/03_defender_registry_verified.png)

---

## Key Learning — AMSI Defends Itself

The most significant finding from this technique was that Defender's AMSI
caught its own bypass attempt **before CLM even ran**. This is a race
condition Microsoft has partially closed by adding signatures for known
bypass strings directly into the AMSI scanner.

This means:
- Known bypass strings are recognised and blocked even in Full Language Mode
- Attackers must obfuscate the bypass itself to avoid the signature
- Obfuscated bypasses are then caught by Script Block Logging (T02) which
  decodes and logs them regardless of how they were encoded
- CLM provides a final catch-all even if both of the above fail

The defence layers reinforce each other. Defeating one layer makes the
attacker more visible to the others.

---

## Registry Values Written

| Path | Name | Type | Value |
|------|------|------|-------|
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender` | DisableAntiSpyware | REG_DWORD | 0 |
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection` | DisableRealtimeMonitoring | REG_DWORD | 0 |
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection` | DisableBehaviorMonitoring | REG_DWORD | 0 |
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection` | DisableScriptScanning | REG_DWORD | 0 |

---

## SOC Threat Hunting Notes

Event 4104 (Script Block Logging) may capture the bypass attempt itself
before AMSI or CLM block it — the log records the content at decode time,
which happens before the execution attempt that triggers the block.

**Splunk detection query (future implementation):**
```
source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
(ScriptBlockText="*AmsiUtils*" OR ScriptBlockText="*amsiInitFailed*"
OR ScriptBlockText="*amsiContext*" OR ScriptBlockText="*AmsiScanBuffer*")
```

Any hit means an attacker attempted an AMSI bypass — even if it was blocked.

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Technique | T1562.001 — Impair Defenses: Disable or Modify Tools |
| Tactic | Defense Evasion |
| Detection | Event ID 4104 (AmsiUtils / amsiInitFailed in script block) |
| Detection | Event ID 4688 (powershell.exe process creation) |
| Defender | ScriptContainedMaliciousContent signature match |
| Reference | https://attack.mitre.org/techniques/T1562/001/ |

---

## Screenshot Folder Structure

```
evidence/
└── T04/
    ├── 01_defender_amsi_signature_blocks.png
    ├── 02_clm_blocks_reflection.png
    └── 03_defender_registry_verified.png
```

---

*Lab environment: Windows 10 Pro · VMware · Standalone VM · No Domain*
*Date: [date of lab session]*
