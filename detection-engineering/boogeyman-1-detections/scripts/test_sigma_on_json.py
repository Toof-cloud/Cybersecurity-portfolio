#!/usr/bin/env python3
"""Validate custom Sigma rules against Windows PowerShell Event ID 4104 JSON logs."""
import json, yaml, glob, os, sys

log_path = sys.argv[1] if len(sys.argv) > 1 else "/home/poopi/thm/boogeyman1/powershell.json"
sigma_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sigma")
if not os.path.exists(sigma_dir):
    sigma_dir = "/home/poopi/thm/boogeyman1/detections/sigma"

with open(log_path) as f:
    events = [json.loads(line) for line in f if line.strip()]

def match_block(text, block):
    t = text.lower()
    for key, vals in block.items():
        if isinstance(vals, str):
            vals = [vals]
        if "|all" in key:
            if not all(v.lower() in t for v in vals):
                return False
        else:
            if not any(v.lower() in t for v in vals):
                return False
    return True

def evaluate_rule(rule, text):
    det = rule["detection"]
    cond = det["condition"]
    blocks = {k: match_block(text, v) for k, v in det.items() if k != "condition"}
    if " and " in cond:
        return all(blocks[k.strip()] for k in cond.split(" and "))
    if " or " in cond:
        return any(blocks[k.strip()] for k in cond.split(" or "))
    return blocks[cond.strip()]

print(f"[*] Loaded {len(events)} PowerShell Event ID 4104 logs from {os.path.basename(log_path)}\n")
for rpath in sorted(glob.glob(os.path.join(sigma_dir, "*.yml"))):
    rule = yaml.safe_load(open(rpath))
    hits = [e for e in events if e.get("ScriptBlockText") and evaluate_rule(rule, e["ScriptBlockText"])]
    print(f"=== {os.path.basename(rpath)} | Level: {rule['level'].upper()} | Hits: {len(hits)} ===")
    print(f"Title: {rule['title']}")
    for h in hits:
        cmd = h["ScriptBlockText"].strip().replace("\n", " ")[:115]
        print(f"  -> [{h.get('Timestamp')}] {cmd}")
    print()
