# Technique 02 — Base64 Encoded Command (Obfuscation)
## Lab Documentation | Windows 10 Pro
**MITRE:** T1027 | **Severity:** High | **Status:** Fully Detected

---

## What This Attack Does

Attackers convert their real PowerShell commands into Base64 text and pass
them using the `-EncodedCommand` flag. The actual command becomes completely
unreadable to a human and bypasses simple keyword-based security filters that
scan for strings like `IEX`, `DownloadString`, or `Invoke-Expression`.

Without logging, Event 4688 only shows the Base64 blob — a threat hunter
cannot tell what the command actually did.

**Why UTF-16LE matters:** PowerShell's `-EncodedCommand` flag specifically
requires UTF-16LE encoding (Unicode), not standard UTF-8. This is why the
encoding step uses `[System.Text.Encoding]::Unicode.GetBytes()` and not
`[System.Text.Encoding]::UTF8.GetBytes()`. Using the wrong encoding produces
a blob that PowerShell rejects at runtime.

---

## Before — Attack Works (Baseline)

### Step 1 — Encode a real command

Command run (normal PowerShell, no admin):
```powershell
$cmd = "Write-Host 'malware'; Start-Process calc.exe"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
Write-Host $encoded
```

Output (the encoded blob — looks like random characters):
```
VwByAGkAdABlAC0ASABvAHMAdAAgACcAbQBhAGwAdwBhAHIAZQAnADsAIABTAHQAYQByAHQA
LQBQAHIAbwBjAGUAcwBzACAAYwBhAGwAYwAuAGUAeABlAA==
```

A security tool scanning for suspicious keywords sees only this blob.
The real intent — launching calc.exe as a payload — is completely hidden.

### Step 2 — Execute the hidden command

Command run:
```powershell
powershell.exe -EncodedCommand $encoded
```

Result: `malware` printed to console + Calculator opened.

The command executed successfully with the real payload completely hidden
behind Base64. Without Script Block Logging, logs only show the encoded
string — a threat hunter is blind to what actually ran.

![Before — encoded command executes successfully, calc opens](screenshots/T02/01_before_attack_calc_opens.png)

---

## The Fix — Script Block Logging via Registry

Script Block Logging forces PowerShell to write the **decoded** content of
every script block to Event ID 4104 **before execution**. Since PowerShell
must always decode the Base64 internally to run it, the decoded content is
always captured — regardless of what obfuscation was used to hide it.

**Important:** This is a **detection** control, not a blocking control.
The command still executes. The purpose is to make obfuscation useless
by permanently recording the attacker's real intent in the event log.

### Registry Fix — Enable Script Block Logging

Run as Administrator in PowerShell ISE (F5 to execute):

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force

Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" `
  -Value 1 -Type DWord

Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockInvocationLogging" `
  -Value 1 -Type DWord
```

**What each value does:**
- `EnableScriptBlockLogging = 1` — captures decoded script block content in Event 4104
- `EnableScriptBlockInvocationLogging = 1` — also logs invocation start/stop events,
  giving timestamps for when each block began and ended execution

Expected output after running:
```
Hive: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell

Name                 Property
----                 --------
ScriptBlockLogging
```

![Registry fix applied — ScriptBlockLogging key created](screenshots/T02/02_registry_fix_applied.png)

### Apply policy:

```powershell
gpupdate /force
```

Expected:
```
Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

---

## After — Detection Verification

### Step 1 — Run the encoded command again

Open a fresh normal PowerShell (not admin) and run:
```powershell
$cmd = "Write-Host 'malware'; Start-Process calc.exe"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded
```

The command still executes and calc still opens — this is expected.
Script Block Logging is a detection control, not a blocker.

### Step 2 — Hunt Event ID 4104 in Event Viewer

```
eventvwr.msc
→ Applications and Services Logs
→ Microsoft
→ Windows
→ PowerShell
→ Operational
→ Filter Current Log → Event ID: 4104
```

Open the newest 4104 event. The event description shows:

```
Creating Scriptblock text (1 of 1):
Write-Host 'malware'; Start-Process calc.exe
```

The attacker's real command is sitting in the log in plain text —
completely decoded and exposed despite the Base64 obfuscation.

![Event 4104 showing decoded command in plain text](screenshots/T02/03_event_4104_decoded_command.png)

---

## Key Learning — Why Obfuscation Fails Against Script Block Logging

```
Attacker's assumption:
  Base64 encoding hides the command → security tools see only gibberish

Reality with Script Block Logging enabled:
  PowerShell must decode the Base64 internally before it can run it
  Script Block Logging captures the content at that exact decode moment
  Event 4104 records the real command regardless of how it was encoded
```

There is no way to run a Base64 encoded command in PowerShell without
PowerShell first decoding it. Script Block Logging sits at that decode
point — it is architecturally impossible to bypass without disabling
logging entirely first (which is itself a detectable action).

---

## Registry Values Written

| Path | Name | Type | Value |
|------|------|------|-------|
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` | EnableScriptBlockLogging | REG_DWORD | 1 |
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` | EnableScriptBlockInvocationLogging | REG_DWORD | 1 |

Verified with:
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```

---

## SOC Threat Hunting Query (Future Splunk Implementation)

When this lab moves to Splunk, the detection query for this technique:

```
source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
(ScriptBlockText="*IEX*" OR ScriptBlockText="*EncodedCommand*"
OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*FromBase64String*"
OR ScriptBlockText="*Invoke-Expression*")
```

Any hit on this query means an attacker tried to hide a command — and failed.
Event 4104 exposes the real payload every time.

---

## Lab Notes — Issues Encountered

### Issue — clipboard not working between host and VM

**What happened:** Copy/paste between the host machine and VM was not
functional despite VMware Tools being installed and clipboard sharing
enabled in VM settings. A reboot did not resolve the issue.

**Workaround:** Used PowerShell ISE as the script editor. All multi-line
commands were typed into the ISE editor pane and executed with F5 instead
of pasting from the host. This bypasses the clipboard dependency entirely
and is now the standard method for the rest of this lab.

**Lesson:** ISE is actually preferable to the plain PowerShell console for
running multi-line scripts — it eliminates variable scoping issues that
occur when running commands line by line in the console.

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Technique | T1027 — Obfuscated Files or Information |
| Tactic | Defense Evasion |
| Sub-technique | Base64 encoding via -EncodedCommand flag |
| Detection | Event ID 4104 (Script Block Logging — decoded content) |
| Detection | Event ID 4688 (Process Creation — -EncodedCommand flag in args) |
| Reference | https://attack.mitre.org/techniques/T1027/ |

---

## Screenshot Folder Structure

```
evidence/
└── T02/
    ├── 01_before_attack_calc_opens.png
    ├── 02_registry_fix_applied.png
    └── 03_event_4104_decoded_command.png
```

---

*Lab environment: Windows 10 Pro · VMware · Standalone VM · No Domain*
*Date: [date of lab session]*
