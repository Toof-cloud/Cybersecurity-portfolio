# Cybersecurity Portfolio — Tyrone Gabriel Pascual

Aspiring **SOC Analyst**. Hands-on incident response, detection engineering, cloud honeypot threat intelligence, digital forensics, and network traffic analysis, documented as professional investigation reports and tested detection packs.

![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?logo=wireshark&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-EF3B2D?logo=suricata&logoColor=white)
![Sigma](https://img.shields.io/badge/Sigma_Rules-00B4D8?logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk_SPL-000000?logo=splunk&logoColor=white)
![Azure](https://img.shields.io/badge/Azure_Cloud-0078D4?logo=microsoftazure&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?logo=powershell&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?logo=kalilinux&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red)

## Projects

| Project | Type | Skills & Tools | Key Result |
|---|---|---|---|
| [Cloud SSH Honeypot (Cowrie) & Threat Intel SOC](homelab/cowrie-honeypot-soc/) | Cloud SOC Homelab / Threat Intel & Detection Engineering | **Azure Cloud** (`Ubuntu 24.04`, NSG JIT hardening), **Docker** (`Cowrie v3.1.5`), **Sigma** (5 rules), **Splunk SPL** (6 queries), static ELF malware analysis | Captured **10,301 live attack events**, validated 5 Sigma rules (**2,375 hits**), and reverse-engineered a live 3.37 MB `.16` (`Mexals`) Linux rootkit & XMRig cryptominer |
| [Boogeyman 1 Detection Pack](detection-engineering/boogeyman-1-detections/) | Detection Engineering | **Suricata** NIDS rules (`pcre`, `threshold`, sticky buffers), **Sigma** YAML rules (EID 4104), Python rule validator, evasion & false-positive analysis | Engineered and tested 5 Suricata + 4 Sigma behavioral rules against 48,858 packets and 987 PowerShell logs with 0 false positives |
| [Boogeyman 1 Investigation](incident-response/boogeyman-1/) | Incident Response / DFIR | Email header forensics, PowerShell 4104 logs (`jq`), PCAP analysis (`Wireshark`, `tshark`), Python carving, `keepassxc-cli` | Traced a phishing compromise end to end and reconstructed a KeePass vault exfiltrated over DNS |

## Repository Layout

| Folder | Contents |
|---|---|
| [`homelab/`](homelab/cowrie-honeypot-soc/) | Live cloud honeypot deployment, SIEM/SPL correlation, Sigma detections, and static malware analysis |
| [`detection-engineering/`](detection-engineering/) | Custom Sigma & Suricata detection rules validated against attack PCAPs and logs |
| [`incident-response/`](incident-response/) | End-to-end investigation reports (timeline, IOCs, evidence, MITRE mapping) |
| [`vulnerability-research/`](vulnerability-research/) | CVE exploit-and-detect case studies *(coming soon)* |
| [`ai-security/`](ai-security/) | LLM security and AI-assisted SOC tooling *(coming soon)* |

## Report Format

Each project includes an executive summary, technical analysis, MITRE ATT&CK mapping, tested detection logic, false-positive/evasion analysis, and remediation playbooks.

---
*All investigations and detection validations are performed in isolated cloud homelab environments or authorized training ranges. Any credentials or personal data shown are simulated or sanitized.*
