#!/usr/bin/env python3
"""Attack success and utility per screening arm, plus spend."""
import glob
import json
import os
from collections import Counter

rows = []
for d in sorted(glob.glob(os.path.expanduser("~/bench/failclosed/f0/runs/screen-*"))):
    g = os.path.join(d, "gateway.jsonl")
    if not os.path.exists(g):
        continue
    recs = {}
    for line in open(g):
        r = json.loads(line)
        recs[r["id"]] = r
    ok = [r for r in recs.values() if r.get("status") == "ok"]
    p = os.path.join(d, "proxy.jsonl")
    cost = sum(json.loads(l).get("cost", 0) for l in open(p)) if os.path.exists(p) else 0
    st = Counter(r.get("status") for r in recs.values())
    asr = sum(bool(r.get("attack_success")) for r in ok)
    print(f"{os.path.basename(d)[7:]:58s} ok {len(ok):3d}/{len(recs):3d} asr {asr:3d} util {sum(bool(r.get('utility')) for r in ok):3d} cost {cost:.4f} other {dict((k, v) for k, v in st.items() if k != 'ok')}")
