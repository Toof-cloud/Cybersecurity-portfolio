# Boogeyman 1 Incident Investigation

## Overview

This project documents a comprehensive, SOC-style investigation of the Boogeyman 1 incident (Case `INC-2023-0113-BGM1`). The report analyzes suspicious spear-phishing activity, reconstructs the post-exploitation timeline, decrypts in-memory C2 traffic, carves exfiltrated DNS payloads, and documents enterprise detection and response strategies.

## Objectives

- Reconstruct the end-to-end attack timeline from phishing delivery to DNS exfiltration.
- Analyze email headers, DKIM/SPF routing, and weaponized `.lnk` payload delivery.
- Inspect Windows PowerShell Script Block logs (Event ID 4104) and C2 in-memory loops.
- Analyze network packet captures (`capture.pcapng`) for payload staging and C2 decimal-encoded POST streams.
- Carve and reconstruct exfiltrated binary KeePass databases from DNS query streams.
- Decrypt stolen vaults to determine exact compromised corporate assets.
- Extract high-confidence Indicators of Compromise (IOCs).
- Map all adversary tactics to the MITRE ATT&CK framework.
- Develop actionable SIEM/EDR detection rules and remediation playbooks.

## Skills Demonstrated

- SOC & DFIR Investigation
- Email & Phishing Forensics (`dump.eml`, DKIM/SPF, MIME decoding)
- Endpoint Log Analysis (`powershell.json`, Event ID 4104, `jq`)
- Network Protocol & Packet Forensics (`Wireshark`, `tshark`, TCP stream reassembly)
- Binary Data Carving & Deduplication (Python, `binascii`)
- Password Safe Decryption (`keepassxc-cli`, CyberChef)
- Timeline Reconstruction & IOC Cataloging
- MITRE ATT&CK Mapping
- Executive & Technical SOC Report Authoring

## Project Files

- [`report.md`](report.md) — Comprehensive master investigation report
- [`timeline.md`](timeline.md) — Chronological event sequence from email delivery to database decryption
- [`iocs.md`](iocs.md) — Structured catalog of verified Indicators of Compromise
- [`evidences.md`](evidences.md) — Detailed raw evidence excerpts, carving scripts, and hash verifications
- [`screenshots/`](screenshots/) — Directory of verified forensic screenshots annotated with red bounding boxes

## Status

**Completed** (100% Solved & Forensically Documented).
