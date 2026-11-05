# Cybersecurity Portfolio — Tyrone Gabriel Pascual

Aspiring **SOC Analyst**. Hands-on incident response, detection engineering, digital forensics, and network traffic analysis, documented as professional investigation reports and tested detection packs.

![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?logo=wireshark&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-EF3B2D?logo=suricata&logoColor=white)
![Sigma](https://img.shields.io/badge/Sigma_Rules-00B4D8?logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?logo=powershell&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?logo=kalilinux&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red)

## Projects

| Project | Type | Skills & Tools | Key Result |
|---|---|---|---|
| [Boogeyman 1 Investigation](incident-response/boogeyman-1/) | Incident Response / DFIR | Email header forensics, PowerShell 4104 logs (`jq`), PCAP analysis (`Wireshark`, `tshark`), Python carving, `keepassxc-cli` | Traced a phishing compromise end to end and reconstructed a KeePass vault exfiltrated over DNS |
| [Boogeyman 1 Detection Pack](detection-engineering/boogeyman-1-detections/) | Detection Engineering | **Suricata** NIDS rules (`pcre`, `threshold`, sticky buffers), **Sigma** YAML rules (EID 4104), Python rule validator, evasion & false-positive analysis | Engineered and tested 5 Suricata + 4 Sigma behavioral rules against 48,858 packets and 987 PowerShell logs with 0 false positives |

## Repository Layout

| Folder | Contents |
|---|---|
| [`incident-response/`](incident-response/) | End-to-end investigation reports (timeline, IOCs, evidence, MITRE mapping) |
| [`detection-engineering/`](detection-engineering/) | Custom Sigma & Suricata detection rules validated against attack PCAPs and logs |
| [`vulnerability-research/`](vulnerability-research/) | CVE exploit-and-detect case studies *(coming soon)* |
| [`ai-security/`](ai-security/) | LLM security and AI-assisted SOC tooling *(coming soon)* |

## Report Format

Each project includes an executive summary, technical analysis, MITRE ATT&CK mapping, tested detection logic, false-positive/evasion analysis, and remediation playbooks.

---
*All investigations and detection validations are performed in legal training environments (e.g., TryHackMe). Any credentials or personal data shown are simulated.*
