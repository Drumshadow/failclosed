#!/usr/bin/env python3
"""Real-score detector latency per arm, from detector_score audit rows, to separate box load from code."""
import glob
import json
import os
import sqlite3
import statistics

for arm in ("canary-on-none-gpt-4o-mini", "canary2-on-none-gpt-4o-mini", "canary-on-none-qwen-2-5-72b-instruct"):
    d = os.path.expanduser(f"~/bench/failclosed/f4/runs/{arm}")
    lat, errs = [], 0
    for p in glob.glob(d + "/work/worker-*/state.db"):
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        for kind, payload in con.execute("select kind, payload_json from audit where kind in ('detector_score','detector_error')"):
            j = json.loads(payload)
            if kind == "detector_error":
                errs += 1
            if isinstance(j.get("latency_ms"), (int, float)):
                lat.append(j["latency_ms"])
    if lat:
        q = statistics.quantiles(lat, n=20)
        print(f"{arm:40s} n {len(lat):4d} p50 {statistics.median(lat):7.0f} ms p95 {q[18]:7.0f} ms max {max(lat):7.0f} ms >10s {sum(x >= 10000 for x in lat):3d} errors {errs}")
    else:
        print(arm, "no latency rows", "errors", errs)
