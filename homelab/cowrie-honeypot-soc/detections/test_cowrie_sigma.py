#!/usr/bin/env python3
"""
Multi-Field Sigma Rule Validation Engine for Cowrie SSH Honeypot JSON Telemetry
Author: Tyrone Gabriel R. Pascual
"""
import json
import glob
import os
import yaml

LOG_PATHS = sorted(glob.glob(os.path.expanduser("~/homelab/cowrie-logs/cowrie.json*")))
RULE_PATHS = sorted(glob.glob(os.path.expanduser("~/homelab/detections/sigma/*.yml")))


def match_selection(event, sel_dict):
    for key, expected in sel_dict.items():
        parts = key.split("|")
        field = parts[0]
        mods = parts[1:]
        val = str(event.get(field, ""))
        if not val:
            return False

        exp_list = expected if isinstance(expected, list) else [expected]
        exp_list = [str(x) for x in exp_list]

        if "contains" in mods and "all" in mods:
            if not all(e.lower() in val.lower() for e in exp_list):
                return False
        elif "contains" in mods:
            if not any(e.lower() in val.lower() for e in exp_list):
                return False
        elif "startswith" in mods:
            if not any(val.lower().startswith(e.lower()) for e in exp_list):
                return False
        else:
            if not any(val.lower() == e.lower() for e in exp_list):
                return False
    return True


def evaluate_rule(event, rule):
    det = rule.get("detection", {})
    selections = {k: v for k, v in det.items() if k != "condition"}
    return any(match_selection(event, sel) for sel in selections.values())


def main():
    events = []
    for p in LOG_PATHS:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.strip():
                    try:
                        ev = json.loads(line)
                        if ev.get("src_ip") != "172.17.0.1":
                            events.append(ev)
                    except Exception:
                        pass

    print(f"[*] Loaded {len(events)} live Cowrie Honeypot telemetry events from ~/homelab/cowrie-logs/\n")

    for rp in RULE_PATHS:
        with open(rp, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        hits = [ev for ev in events if evaluate_rule(ev, rule)]
        ips = sorted({h.get("src_ip", "unknown") for h in hits})
        print(f"=== {os.path.basename(rp)} | Level: {rule.get('level','').upper()} | Hits: {len(hits)} | Unique Attacker IPs: {len(ips)} ===")
        print(f"Title: {rule.get('title')}")
        print(f"Attacker IPs: {', '.join(ips[:8])}")
        for h in hits[:4]:
            detail = (
                h.get("input")
                or h.get("filename")
                or h.get("version")
                or h.get("hassh")
                or f"{h.get('dst_ip')}:{h.get('dst_port')}"
                or h.get("eventid")
            )
            print(f"  -> [{h.get('timestamp')}] IP:{h.get('src_ip')} | Event:{h.get('eventid')} | Match: {str(detail)[:95]}")
        print()


if __name__ == "__main__":
    main()
