# Detection Engineering

Custom Network IDS (**Suricata**) and Endpoint/SIEM (**Sigma**) detection packs tested against real attack packet captures and Windows event logs.

| Detection Pack | Rules Included | Validated Against | Companion DFIR Report |
|---|---|---|---|
| [Boogeyman 1 Detections](boogeyman-1-detections/) | **5 Suricata rules** + **4 Sigma rules** + Python validator | `capture.pcapng` (48,858 packets) & `powershell.json` (987 EID 4104 logs) | [Boogeyman 1 Incident Report](../incident-response/boogeyman-1/report.md) |
