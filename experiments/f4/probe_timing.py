#!/usr/bin/env python3
"""Probe-timeout timing per arm: client-side round latency from audit rows, and proxy-side
receipt-to-reply gaps for probe-length requests near each timeout."""
import glob
import json
import os
import sqlite3
import statistics
import sys

F4 = os.path.expanduser("~/bench/failclosed/f4")
pool = [json.loads(l) for l in open(F4 + "/canary_pool.jsonl") if l.strip()]
probe_len = {}
for p in pool:
    probe_len.setdefault(len(p["text"]), set()).add("I" if p["injection"] else "B")

arms = sys.argv[1:] or ["canary-on-none-gpt-4o-mini", "canary2-on-none-gpt-4o-mini",
                        "canary3-on-none-gpt-4o-mini", "canary-on-none-qwen-2-5-72b-instruct"]


def q(xs, f):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(f * len(xs)))] if xs else None


for arm in arms:
    d = f"{F4}/runs/{arm}"
    fails, real_to, real_lat, ok_lat, sessions = [], 0, [], [], 0
    for p in glob.glob(d + "/work/worker-*/state.db"):
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        sessions += con.execute("select count(*) from session").fetchone()[0]
        for ts, kind, payload in con.execute(
                "select ts, kind, payload_json from audit where kind in "
                "('detector_canary_failed','detector_canary_ok','detector_error','detector_score')"):
            j = json.loads(payload)
            if kind == "detector_canary_failed":
                fails.append((ts, j.get("reason"), j.get("probe"), j.get("latency_ms"), j.get("round")))
            elif kind == "detector_canary_ok":
                ok_lat.append(j.get("latency_ms"))
            elif kind == "detector_error":
                if "canary" not in (j.get("error") or "") and "timed out" in (j.get("error") or "").lower():
                    real_to += 1
            else:
                real_lat.append(j.get("latency_ms"))
    ev = [json.loads(l) for l in open(d + "/fault.jsonl") if l.strip()]
    recv = [e for e in ev if "chars" in e]
    reply = [e["t"] for e in ev if "verdict" in e]
    tos = [f for f in fails if f[1] == "probe_timeout"]
    print(f"== {arm}: sessions {sessions}, proxy requests {len(recv)}, proxy replies {len(reply)}, "
          f"unanswered {len(recv) - len(reply)}")
    print(f"   failed rows by reason: { {r: sum(1 for f in fails if f[1] == r) for r in set(f[1] for f in fails)} }")
    print(f"   probe_timeout rows: {len(tos)}; probe I/B: {sum(f[2]=='injection' for f in tos)}/{sum(f[2]=='benign' for f in tos)}; "
          f"round index==1: {sum(f[4]==1 for f in tos)}")
    lats = [f[3] for f in tos]
    if lats:
        print(f"   timeout round latency_ms min {min(lats)} p50 {q(lats,.5)} max {max(lats)}")
    if ok_lat:
        print(f"   ok round latency_ms p50 {q(ok_lat,.5)} p95 {q(ok_lat,.95)} max {max(ok_lat)}; n {len(ok_lat)}")
    if real_lat:
        print(f"   real score latency_ms p50 {q(real_lat,.5)} p95 {q(real_lat,.95)} max {max(real_lat)}; "
              f">=10s {sum(x >= 10000 for x in real_lat)}; real timeouts {real_to}")
    # Proxy side: for each timeout, probe-length receipts in the window the client was waiting.
    gaps, unanswered_near = [], 0
    for ts, _, probe, lat, _ in tos:
        start = ts - lat / 1000 - 2
        cands = [e for e in recv if start <= e["t"] <= ts + 1 and e["chars"] in probe_len
                 and ("I" if probe == "injection" else "B") in probe_len[e["chars"]]]
        for e in cands[:1]:
            # replies logged after this receipt; the matching one is at or after the first.
            later = [t for t in reply if t >= e["t"]]
            gaps.append(round(later[0] - e["t"], 2) if later else None)
            # requests received in the 10 s window vs replies sent in it: queue build-up.
            win_recv = sum(1 for r in recv if e["t"] <= r["t"] <= e["t"] + 10)
            win_rep = sum(1 for t in reply if e["t"] <= t <= e["t"] + 10)
            unanswered_near += win_recv - win_rep
    if gaps:
        g = [x for x in gaps if x is not None]
        print(f"   proxy: matched {len(gaps)}/{len(tos)} timeouts; first reply after probe receipt: "
              f"p50 {q(g,.5)} s max {max(g) if g else None} s; net unanswered in the 10 s windows {unanswered_near}")
    # Proxy-wide stall check: longest gaps between any two replies.
    rs = sorted(reply)
    stalls = sorted((round(b - a, 1), round(a)) for a, b in zip(rs, rs[1:]))[-5:]
    print(f"   longest reply-to-reply gaps (s, at t): {stalls}")
    if recv:
        print(f"   run window {round(recv[0]['t'])} .. {round(recv[-1]['t'])}")
