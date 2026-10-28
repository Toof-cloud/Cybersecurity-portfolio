# Cybersecurity Portfolio — Tyrone Gabriel Pascual

Aspiring **SOC Analyst**. Hands-on incident response, digital forensics and network traffic analysis, documented as professional investigation reports.

![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?logo=wireshark&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?logo=powershell&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?logo=kalilinux&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red)

## Projects

| Project | Type | Skills & Tools | Key Result |
|---|---|---|---|
| [Boogeyman 1](incident-response/boogeyman-1/) | Incident Response / DFIR | Email header forensics, PowerShell 4104 logs (`jq`), PCAP analysis (`Wireshark`, `tshark`), Python carving, `keepassxc-cli` | Traced a phishing compromise end to end and reconstructed a KeePass vault exfiltrated over DNS |

## Repository Layout

| Folder | Contents |
|---|---|
| [`incident-response/`](incident-response/) | End-to-end investigation reports (timeline, IOCs, evidence, MITRE mapping) |
| [`detection-engineering/`](detection-engineering/) | Sigma / Suricata detection rules *(coming soon)* |
| [`vulnerability-research/`](vulnerability-research/) | CVE exploit-and-detect case studies *(coming soon)* |
| [`ai-security/`](ai-security/) | LLM security and AI-assisted SOC tooling *(coming soon)* |

## Report Format

Each investigation includes an executive summary, attack timeline, IOC catalog, MITRE ATT&CK mapping, detection opportunities, remediation, and a "challenges & fixes" section.

---
*All investigations are performed in legal training environments (e.g., TryHackMe). Any credentials or personal data shown are simulated.*
