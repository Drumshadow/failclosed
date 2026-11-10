#!/usr/bin/env python3
"""Kill a fault arm's driver when too many cases fail for infrastructure reasons.

usage: abort_watch.py GATEWAY_JSONL DRIVER_PID MARKER_FILE
A case is an infra error when its status is not ok. Timeouts count, because an arm full of them measures the
harness and not the guardrail. Writes MARKER_FILE when it aborts.
"""
import json
import os
import signal
import sys
import time

sys.path.insert(0, "/srv/gateway/failclosed")
from failclosed.abort import AbortGauge  # noqa: E402

path, pid, marker = sys.argv[1], int(sys.argv[2]), sys.argv[3]
while True:
    time.sleep(30)
    try:
        os.kill(pid, 0)
    except OSError:
        sys.exit(0)
    if not os.path.exists(path):
        continue
    gauge = AbortGauge(max_rate=0.2, min_samples=30)
    last = {}
    for line in open(path):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        last[r["id"]] = r
    for r in last.values():
        gauge.record(r.get("status") != "ok")
    if gauge.should_abort:
        open(marker, "w").write(f"infra error rate {gauge.rate:.2f} over {gauge.total} cases\n")
        os.kill(pid, signal.SIGTERM)
        sys.exit(0)
