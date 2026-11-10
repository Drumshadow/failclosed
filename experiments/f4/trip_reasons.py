#!/usr/bin/env python3
"""Reasons recorded in detector_canary_failed rows, per F4 arm."""
import glob
import json
import os
import sqlite3
from collections import Counter

for d in sorted(glob.glob(os.path.expanduser("~/bench/failclosed/f4/runs/canary*-on-*"))):
    c = Counter()
    for p in glob.glob(d + "/work/worker-*/state.db"):
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        for (payload,) in con.execute("select payload_json from audit where kind='detector_canary_failed'"):
            try:
                c[json.loads(payload).get("reason")] += 1
            except ValueError:
                c["unparsed"] += 1
    print(os.path.basename(d), dict(c))
