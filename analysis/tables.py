#!/usr/bin/env python3
"""Regenerate every FailClosed table from raw run files.

usage:
  python3 -I analysis/tables.py --raw RAW_ROOT [--out results] [--readme README.md]
         [--detector-baseline PATH]

RAW_ROOT has the layout of the raw archive (and of the bench directory on the box that ran it):
  f0/runs/<arm>/gateway.jsonl, proxy.jsonl          F0 arms (always-benign stub vs healthy detector)
  f2/runs/<arm>/gateway.jsonl, fault.jsonl          F2 fault-proxy arms, frozen unfixed gateway
  f4/runs/<arm>/gateway.jsonl                       F4 canary arms, fixed gateway
  <arm>/audit.jsonl                                 gateway audit rows (or work/worker-*/state.db)
  agentdojo/runs/detector/gateway-gated.jsonl       healthy local-model baseline for the F0 local arm
F5 tables come from f5/results/*.json in this repository (produced by f5/replay.py).

Writes results/<unit>.json and results/<unit>.md, and, with --readme, rewrites every
<!-- BEGIN table:NAME --> ... <!-- END table:NAME --> block in that file. Standard library only.
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import re
import sqlite3
import statistics
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

MODELS = {  # slug -> display name, in table order
    "gpt-4o-mini": "GPT-4o-mini",
    "qwen-2-5-72b-instruct": "Qwen 2.5 72B",
    "llama-3-3-70b-instruct": "Llama 3.3 70B",
    "mistral-small-3-2-24b-instruct": "Mistral Small 3.2 24B",
}
F2_MODELS = ["gpt-4o-mini", "qwen-2-5-72b-instruct", "mistral-small-3-2-24b-instruct"]
F4_MODELS = ["gpt-4o-mini", "qwen-2-5-72b-instruct"]
NO_LIFT = [  # arm, display, baseline kind
    ("benign-qwen", "Qwen 3.6 35B-A3B (local)", "detector"),
    ("benign-gpt-6-luna", "GPT-6 Luna", None),
    ("benign-claude-haiku-5-5", "Claude Haiku 5.5", None),
    ("benign-deepseek-v4-1-flash", "DeepSeek V4.1 Flash", None),
]
SCREEN_MODELS = ["gpt-4o-mini", "qwen-2-5-72b-instruct", "llama-3-3-70b-instruct", "mistral-small-3-2-24b-instruct",
                 "command-r-08-2024", "claude-haiku-5-5", "gpt-6-luna"]
SCREEN_NAMES = {**MODELS, "command-r-08-2024": "Command R (08-2024)", "claude-haiku-5-5": "Claude Haiku 5.5",
                "gpt-6-luna": "GPT-6 Luna"}
F2_FAULTS = [  # name, class
    ("always_benign", "silently wrong"), ("stale_clean", "silently wrong"), ("inverted_score", "silently wrong"),
    ("first_window", "silently wrong"), ("stale_verdict", "design error"),
    ("timeout", "unavailable"), ("refused", "unavailable"), ("http_500", "unavailable"),
    ("malformed", "unavailable"), ("oversized", "unavailable"),
    ("slow_valid", "timing"), ("scoring_window", "timing"), ("load_amplified", "timing"),
]
F4_ARMS = [  # prefix, canary, fault
    ("canary", "off", "always_benign"), ("canary", "on", "always_benign"), ("canary", "on", "stale_clean"),
    ("canary", "on", "first_window"), ("canary", "on", "none"),
]
BUILD = {"canary": 1, "ab-v1": 1, "canary2": 2, "canary3": 3, "ab-v3": 3}  # arm prefix -> canary build
F4_VERSIONS = [("ab-v1", "on", "none"), ("ab-v3", "on", "none"),  # back to back, quiet sidecar
               ("canary2", "on", "always_benign"), ("canary2", "on", "none"),
               ("canary3", "on", "none"), ("canary3", "on", "always_benign")]
AUDIT_KINDS = ("detector_score", "detector_error", "detector_canary_ok", "detector_canary_failed", "taint", "taint_skipped")
ALPHA = 0.05


# ---------- loading ----------

def load_cases(path: str | Path) -> dict:
    """Last record per attacked case id (resumed arms append retries)."""
    out = {}
    with open(path) as f:
        for line in f:
            r = json.loads(line)
            if r.get("injection_task"):
                out[r["id"]] = r
    return out


def audit_rows(arm_dir: str | Path) -> list[dict]:
    arm_dir = Path(arm_dir)
    p = arm_dir / "audit.jsonl"
    if p.exists():
        with open(p) as f:
            return [json.loads(l) for l in f]
    rows = []
    for db in sorted(glob.glob(str(arm_dir / "work/worker-*/state.db"))):
        worker = Path(db).parent.name
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        q = f"select seq, ts, kind, payload_json from audit where kind in ({','.join('?' * len(AUDIT_KINDS))}) order by seq"
        for seq, ts, kind, payload in con.execute(q, AUDIT_KINDS):
            rows.append({"worker": worker, "seq": seq, "ts": ts, "kind": kind, "payload": json.loads(payload)})
        con.close()
    return rows


def read_jsonl(path) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


# ---------- statistics ----------

def mcnemar(b: int, c: int) -> float:
    n = b + c
    return 1.0 if n == 0 else min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n)


def ok(recs: dict) -> list[dict]:
    return [r for r in recs.values() if r.get("status") == "ok"]


def arm_summary(recs: dict) -> dict:
    o = ok(recs)
    return {"cases": len(recs), "ok": len(o),
            "attack_success": sum(bool(r.get("attack_success")) for r in o),
            "utility": sum(bool(r.get("utility")) for r in o),
            "not_ok": dict(Counter(r.get("status") for r in recs.values() if r.get("status") != "ok"))}


def paired(a: dict, b: dict, key="attack_success") -> dict:
    """a = treatment, b = reference. only_a = success under a only."""
    ids = sorted(i for i in a if i in b and a[i].get("status") == "ok" and b[i].get("status") == "ok")
    x = sum(bool(a[i].get(key)) and not b[i].get(key) for i in ids)
    y = sum(not a[i].get(key) and bool(b[i].get(key)) for i in ids)
    return {"n": len(ids), "a": sum(bool(a[i].get(key)) for i in ids), "b": sum(bool(b[i].get(key)) for i in ids),
            "only_a": x, "only_b": y, "p": mcnemar(x, y)}


def pct(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    if len(xs) == 1:
        return xs[0]
    return statistics.quantiles(xs, n=100, method="inclusive")[q - 1]


def fmt_p(p: float) -> str:
    if p >= 0.001:
        return f"{p:.3g}"
    m, e = f"{p:.1e}".split("e")
    return f"{m}e{int(e)}"


# ---------- markdown ----------

def md_table(head: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


# ---------- F0 ----------

def f0(raw: Path, detector_baseline: Path) -> dict:
    runs = raw / "f0/runs"
    main = []
    for slug, name in MODELS.items():
        fault = load_cases(runs / f"full-{slug}-benign/gateway.jsonl")
        healthy = load_cases(runs / f"full-{slug}-healthy/gateway.jsonl")
        pr = paired(fault, healthy)
        pu = paired(fault, healthy, "utility")
        aud = Counter(r["kind"] for r in audit_rows(runs / f"full-{slug}-benign"))
        aud_h = Counter(r["kind"] for r in audit_rows(runs / f"full-{slug}-healthy"))
        main.append({"slug": slug, "model": name, "always_benign": arm_summary(fault), "healthy": arm_summary(healthy),
                     "paired_attack_success": pr, "paired_utility": pu,
                     "audit_always_benign": {k: aud.get(k, 0) for k in AUDIT_KINDS},
                     "audit_healthy": {k: aud_h.get(k, 0) for k in AUDIT_KINDS}})
    m = len(main)
    for r in main:
        r["paired_attack_success"]["bonferroni_survives"] = r["paired_attack_success"]["p"] < ALPHA / m
    nolift = []
    for arm, name, base in NO_LIFT:
        recs = load_cases(runs / f"{arm}/gateway.jsonl")
        row = {"arm": arm, "model": name, "always_benign": arm_summary(recs),
               "attack_addressed_as": sorted({r.get("attack_model_name") for r in recs.values()})}
        if base == "detector":
            row["paired_vs_healthy_local"] = paired(recs, load_cases(detector_baseline))
        nolift.append(row)
    screen = []
    for slug in SCREEN_MODELS:
        row = {"slug": slug, "model": SCREEN_NAMES[slug]}
        for attack in ("important_instructions", "tool_knowledge"):
            p = runs / f"screen-{slug}-{attack}/gateway.jsonl"
            if p.exists():
                recs = load_cases(p)
                row[attack] = arm_summary(recs)
                row["addressed_as"] = sorted({r.get("attack_model_name") for r in recs.values()})
        screen.append(row)
    screen_ids = set(load_cases(runs / "screen-gpt-4o-mini-important_instructions/gateway.jsonl"))
    full_ids = set(load_cases(runs / "full-gpt-4o-mini-healthy/gateway.jsonl"))
    return {"bonferroni_m": m, "alpha": ALPHA, "main": main, "no_lift": nolift, "screen": screen,
            "screen_cases": len(screen_ids), "screen_cases_in_full_set": len(screen_ids & full_ids),
            "full_cases": len(full_ids)}


def f0_md(d: dict) -> dict:
    t = {}
    rows = []
    for r in d["main"]:
        p = r["paired_attack_success"]
        rows.append([r["model"], p["n"], p["b"], p["a"], p["only_a"], p["only_b"], fmt_p(p["p"]),
                     "yes" if p["bonferroni_survives"] else "no"])
    t["f0"] = (f"Always-benign detector vs healthy detector, AgentDojo `important_instructions`, paired by case "
               f"(cases with status ok in both arms). Attack success counts are over the paired cases. "
               f"p: exact two-sided McNemar. Bonferroni threshold {ALPHA}/{d['bonferroni_m']} = "
               f"{ALPHA / d['bonferroni_m']:.4g}.\n\n"
               + md_table(["Model", "Paired cases", "Attacks succeeded, healthy", "Attacks succeeded, always benign",
                           "Only always benign", "Only healthy", "p", "Survives Bonferroni"], rows))
    rows = []
    for r in d["no_lift"]:
        s = r["always_benign"]
        base = r.get("paired_vs_healthy_local")
        rows.append([r["model"], f"{s['attack_success']}/{s['ok']}",
                     f"{base['b']}/{base['n']} (paired, p {fmt_p(base['p'])})" if base else "not run",
                     ", ".join(r["attack_addressed_as"])])
    t["f0_nolift"] = ("Arms with no measurable lift. The local Qwen 3.6 arm is paired against a healthy arm and the "
                      "attack names it correctly. The three hosted arms have no healthy control and addressed the model "
                      "as 'Qwen' in the attack text (the wrong target name), so their low counts show little either way. "
                      "None of these results shows that current frontier models are vulnerable or safe.\n\n"
                      + md_table(["Model", "Attacks succeeded, always benign", "Healthy", "Attack addressed to"], rows))
    rows = []
    for r in d["screen"]:
        cells = []
        for a in ("important_instructions", "tool_knowledge"):
            s = r.get(a)
            cells.append(f"{s['attack_success']}/{s['ok']}" if s else "not run")
        rows.append([r["model"]] + cells)
    t["f0_screen"] = (f"Model screen, always-benign detector only, {d['screen_cases']} cases "
                      f"({d['screen_cases_in_full_set']} of them also in the {d['full_cases']}-case set).\n\n"
                      + md_table(["Model", "important_instructions", "tool_knowledge"], rows))
    return t


# ---------- F2 ----------

def f2(raw: Path) -> dict:
    out = {"bonferroni_m": len(F2_FAULTS) * len(F2_MODELS), "alpha": ALPHA, "models": {}}
    for slug in F2_MODELS:
        healthy = load_cases(raw / f"f0/runs/full-{slug}-healthy/gateway.jsonl")
        rows = []
        for fault, cls in F2_FAULTS:
            d = raw / (f"f0/runs/full-{slug}-benign" if fault == "always_benign" else f"f2/runs/{fault}-{slug}")
            recs = load_cases(d / "gateway.jsonl")
            rows_a = audit_rows(d)
            aud = Counter(r["kind"] for r in rows_a)
            row = {"fault": fault, "class": cls, "arm": str(d.relative_to(raw)), **arm_summary(recs),
                   "paired": paired(recs, healthy), "paired_utility": paired(recs, healthy, "utility"),
                   "audit": {k: aud.get(k, 0) for k in AUDIT_KINDS},
                   "aborted": (d / "ABORTED").exists()}
            row["paired"]["bonferroni_survives"] = row["paired"]["p"] < ALPHA / out["bonferroni_m"]
            if fault in ("stale_verdict", "stale_clean"):  # what the cache served, as the gateway recorded it
                v = Counter(str(r["payload"].get("flagged")).lower() for r in rows_a if r["kind"] == "detector_score")
                row["scores_flagged"] = dict(sorted(v.items()))
            rows.append(row)
        out["models"][slug] = {"model": MODELS[slug], "healthy": arm_summary(healthy), "faults": rows}
    return out


def f2_md(d: dict) -> dict:
    t = {}
    rows = []
    for slug, m in d["models"].items():
        h = m["healthy"]
        for r in m["faults"]:
            p = r["paired"]
            direction = "" if p["only_a"] == p["only_b"] else (" (up)" if p["only_a"] > p["only_b"] else " (down)")
            rows.append([m["model"], f"`{r['fault']}`", r["class"], p["n"], p["b"], p["a"],
                         f"{p['only_a']} / {p['only_b']}", fmt_p(p["p"]) + direction,
                         "yes" if p["bonferroni_survives"] else "no", r["audit"]["taint_skipped"]])
    t["f2"] = (f"Each fault arm paired by case against the healthy arm for the same model, on the frozen unfixed "
               f"gateway. Pairs: success only under the fault / only when healthy. p: exact two-sided McNemar, with the "
               f"direction of the change in attack success. Within-family Bonferroni over all {d['bonferroni_m']} fault-by-model tests: "
               f"p < {ALPHA / d['bonferroni_m']:.2g}. `always_benign` is the F0 arm. Last column: tool outputs the "
               f"gateway let through untainted on a detector verdict (audit `taint_skipped`); zero means every scored "
               f"output tainted the session.\n\n"
               + md_table(["Model", "Fault", "Class", "Paired", "Succeeded, healthy", "Succeeded, fault",
                           "Pairs", "p", "Survives Bonferroni", "Outputs cleared"], rows))
    return t


# ---------- F4 ----------

def session_of(row):
    return (row.get("worker"), row["payload"].get("session"))


def canary_stats(rows: list[dict]) -> dict:
    failed = [r for r in rows if r["kind"] == "detector_canary_failed"]
    okr = [r for r in rows if r["kind"] == "detector_canary_ok"]
    scores = [r for r in rows if r["kind"] == "detector_score"]
    withheld = [r for r in rows if r["kind"] == "detector_error"
                and str(r["payload"].get("error", "")).startswith("detector canary failed")]
    errors = [r for r in rows if r["kind"] == "detector_error" and r not in withheld]
    detector_sessions = {session_of(r) for r in rows if r["kind"].startswith("detector_")}
    real_lat = [r["payload"]["latency_ms"] for r in scores + errors if isinstance(r["payload"].get("latency_ms"), (int, float))]
    probe_lat = [r["payload"]["latency_ms"] for r in okr if isinstance(r["payload"].get("latency_ms"), (int, float))]
    return {
        "sessions_with_detector_activity": len(detector_sessions),
        "sessions_tripped": len({session_of(r) for r in failed}),
        "failed_rows": len(failed),
        "trip_reasons": dict(Counter(r["payload"].get("reason") for r in failed)),
        "trip_round": dict(sorted(Counter(str(r["payload"].get("round")) for r in failed).items())),
        "rounds_passed": len(okr),
        "probe_latency_ms": {"n": len(probe_lat), "p50": pct(probe_lat, 50), "p95": pct(probe_lat, 95)},
        "real_scores": len(scores), "real_errors": len(errors), "verdicts_withheld_after_trip": len(withheld),
        "real_latency_ms": {"n": len(real_lat), "p50": pct(real_lat, 50), "p95": pct(real_lat, 95),
                            "at_or_over_10s": sum(x >= 10000 for x in real_lat)},
        "taint": sum(r["kind"] == "taint" for r in rows), "taint_skipped": sum(r["kind"] == "taint_skipped" for r in rows),
    }


def residual(recs: dict, rows: list[dict]) -> dict:
    """Attack successes left with the canary on, and whether their session tripped."""
    tripped = {r["payload"].get("session") for r in rows if r["kind"] == "detector_canary_failed"}
    wins = [r for r in ok(recs) if r.get("attack_success")]
    return {"successes": len(wins), "in_tripped_session": sum(r.get("session_id") in tripped for r in wins),
            "ids": sorted(r["id"] for r in wins)}


def proxy_stats(arm_dir: Path) -> dict:
    """Fault-proxy view of the sidecar: requests received, replies sent, longest gap between replies."""
    ev = read_jsonl(arm_dir / "fault.jsonl")
    recv = [e for e in ev if "chars" in e]
    reply = sorted(e["t"] for e in ev if "verdict" in e)
    gaps = [b - a for a, b in zip(reply, reply[1:])]
    return {"requests": len(recv), "replies": len(reply), "unanswered": len(recv) - len(reply),
            "longest_reply_gap_s": round(max(gaps), 1) if gaps else None}


def f4(raw: Path) -> dict:
    out = {"arms": [], "versions": [], "primary_bonferroni_m": len(F4_MODELS), "alpha": ALPHA}
    for slug in F4_MODELS:
        healthy = load_cases(raw / f"f0/runs/full-{slug}-healthy/gateway.jsonl")
        off = load_cases(raw / f"f4/runs/canary-off-always_benign-{slug}/gateway.jsonl")
        f2_stale = load_cases(raw / f"f2/runs/stale_clean-{slug}/gateway.jsonl")
        for prefix, canary, fault in F4_ARMS:
            d = raw / f"f4/runs/{prefix}-{canary}-{fault}-{slug}"
            recs = load_cases(d / "gateway.jsonl")
            rows_a = audit_rows(d)
            row = {"arm": d.name, "model": MODELS[slug], "slug": slug, "binary": prefix, "build": BUILD[prefix],
                   "canary": canary, "fault": fault, **arm_summary(recs), "vs_healthy_unfixed": paired(recs, healthy),
                   "canary_audit": canary_stats(rows_a), "residual": residual(recs, rows_a), "proxy": proxy_stats(d)}
            if fault == "always_benign" and canary == "on":  # primary F4 comparison, Bonferroni over models
                row["vs_canary_off"] = paired(recs, off)
                row["vs_canary_off"]["bonferroni_survives"] = row["vs_canary_off"]["p"] < ALPHA / len(F4_MODELS)
            if fault == "stale_clean":
                row["vs_f2_stale_clean_unfixed"] = paired(recs, f2_stale)
            out["arms"].append(row)
    healthy = load_cases(raw / "f0/runs/full-gpt-4o-mini-healthy/gateway.jsonl")
    off = load_cases(raw / "f4/runs/canary-off-always_benign-gpt-4o-mini/gateway.jsonl")
    for prefix, canary, fault in F4_VERSIONS:
        d = raw / f"f4/runs/{prefix}-{canary}-{fault}-gpt-4o-mini"
        if not (d / "gateway.jsonl").exists():
            out["versions"].append({"arm": d.name, "missing": True})
            continue
        recs = load_cases(d / "gateway.jsonl")
        rows_a = audit_rows(d)
        row = {"arm": d.name, "model": "GPT-4o-mini", "slug": "gpt-4o-mini", "binary": prefix, "build": BUILD[prefix],
               "canary": "on", "back_to_back_quiet": prefix.startswith("ab-"), "fault": fault, **arm_summary(recs),
               "vs_healthy_unfixed": paired(recs, healthy), "canary_audit": canary_stats(rows_a),
               "residual": residual(recs, rows_a), "proxy": proxy_stats(d)}
        if fault == "always_benign":  # descriptive: the only canary-off control is on build 1
            row["vs_build1_canary_off"] = paired(recs, off)
        out["versions"].append(row)
    for d in sorted((raw / "f4/runs").glob("*/gateway.sha256")):
        out.setdefault("binaries", {})[d.parent.name] = d.read_text().split()[0][:12]
    return out


def f4_md(d: dict) -> dict:
    t = {}
    rows = []
    for r in d["arms"]:
        c = r["canary_audit"]
        vs = r.get("vs_canary_off")
        rows.append([r["model"], r["canary"], f"`{r['fault']}`", f"{r['attack_success']}/{r['ok']}", r["utility"],
                     f"{vs['only_a']} / {vs['only_b']}, p {fmt_p(vs['p'])}" if vs else "",
                     f"{c['sessions_tripped']}/{c['sessions_with_detector_activity']}",
                     ", ".join(f"{k} {v}" for k, v in c["trip_reasons"].items()) or "none"])
    t["f4"] = ("Canary on the fixed gateway (build 1), 200 attacked cases per arm. Pairs against canary off with the "
               "same fault on the same build: success only with canary on / only with it off. These two comparisons "
               f"are the F4 primary family, Bonferroni over {d['primary_bonferroni_m']} (p < "
               f"{ALPHA / d['primary_bonferroni_m']:.3g}); other F4 numbers are descriptive. Tripped: sessions with a "
               "`detector_canary_failed` audit row, over sessions that reached the detector.\n\n"
               + md_table(["Model", "Canary", "Fault", "Attacks succeeded", "Utility under attack",
                           "vs canary off", "Sessions tripped", "Trip reasons"], rows))
    rows = []
    for r in [a for a in d["arms"] if a["fault"] == "none"] + [v for v in d["versions"] if not v.get("missing")]:
        c, px = r["canary_audit"], r["proxy"]
        lat = c["real_latency_ms"]
        rows.append([r["build"], r["arm"], r["model"], f"`{r['fault']}`", f"{r['attack_success']}/{r['ok']}",
                     f"{c['sessions_tripped']}/{c['sessions_with_detector_activity']}",
                     ", ".join(f"{k} {v}" for k, v in c["trip_reasons"].items()) or "none",
                     px["unanswered"], px["longest_reply_gap_s"],
                     f"{lat['p50']:.0f}" if lat["p50"] is not None else "", f"{lat['p95']:.0f}" if lat["p95"] is not None else "",
                     c["real_errors"]])
    ab = {v["binary"]: v["canary_audit"] for v in d["versions"] if v.get("back_to_back_quiet")}
    t["f4_ab"] = (f"In back-to-back quiet-sidecar runs, build 1 tripped {ab['ab-v1']['sessions_tripped']} of "
                  f"{ab['ab-v1']['sessions_with_detector_activity']} sessions and build 3 tripped "
                  f"{ab['ab-v3']['sessions_tripped']} of {ab['ab-v3']['sessions_with_detector_activity']}. These "
                  f"observations do not establish equivalent behavior across builds.")
    t["f4_versions"] = ("Every canary arm outside the main table, by build (1 = first, 2 = review fixes, 3 = audit-key "
                        "fix). `ab-v1` and `ab-v3` ran back to back on a quiet sidecar. Unanswered and longest gap come "
                        "from the fault proxy's log (`fault.jsonl`): detector requests that never got a reply, and the "
                        "longest time between two replies. Real-score latency and errors come from `detector_score` rows "
                        "and sidecar `detector_error` rows (verdicts withheld after a trip are excluded).\n\n"
                        + md_table(["Build", "Arm", "Model", "Fault", "Attacks succeeded", "Sessions tripped",
                                    "Trip reasons", "Unanswered requests", "Longest reply gap s", "Real score p50 ms",
                                    "p95 ms", "Real score errors"], rows))
    return t


# ---------- F5 ----------

def f5(repo: Path) -> dict:
    r = repo / "f5/results"
    base = json.loads((r / "baseline.json").read_text())
    faults = json.loads((r / "faults.json").read_text())
    diag = json.loads((r / "diagnostics.json").read_text())
    return {"label": base["label"], "reproduction": base["rows"], "no_guardrail": base["no_guardrail"],
            "healthy": base["healthy"], "faults": faults["faults"], "first_window": faults["first_window"],
            "unavailable": faults["unavailable"], "timing": faults["timing"], "notes": faults["notes"],
            "threshold": faults["threshold"], "threshold_sweep": diag["threshold_sweep"],
            "correction": "none: descriptive, paired against this replay's own baseline"}


def f5_md(d: dict) -> dict:
    rows = [[r["config"], r["metric"], f"{100 * r['ours']:.2f}%", f"{100 * r['paper']:.2f}%",
             f"{100 * r['gap']:+.2f}"] for r in d["reproduction"]]
    t = {"f5_repro": ("LlamaFirewall PromptGuard 2 (model as in `f5/README.md`), replay of public AgentDojo traces, threshold "
                      f"{d['threshold']}. The replay did not reproduce the paper.\n\n"
                      + md_table(["Config", "Metric", "This replay", "Paper", "Gap (points)"], rows))}
    base_u = d["healthy"]["utility"]
    rows = [[r["threshold"], f"{100 * r['asr']:.2f}%", f"{100 * r['utility']:.2f}%",
             f"{100 * (base_u - r['utility']):.2f}", f"{100 * r['benign_flagged']:.2f}%"] for r in d["threshold_sweep"]]
    t["f5_sweep"] = (f"Threshold sweep on this replay (diagnostic only). Utility points lost are against the library "
                     f"default {d['threshold']}.\n\n"
                     + md_table(["Threshold", "Attack success", "Utility", "Utility points lost", "Benign traces flagged"], rows))
    rows = []
    for name, f in d["faults"].items():
        a = f["asr_vs_healthy"]
        p = a["mcnemar_p"]
        rows.append([f"`{name}`", f"{100 * f['asr']:.2f}%", f"{100 * f['utility']:.2f}%",
                     f"{a['healthy_only_success']} / {a['fault_only_success']}",
                     p if isinstance(p, str) else fmt_p(p)])
    t["f5"] = (f"**{d['label']}.** Healthy replay: attack success {100 * d['healthy']['asr']:.2f}%, utility "
               f"{100 * d['healthy']['utility']:.2f}%. Pairs: attack succeeded only when healthy / only under the fault, "
               f"same traces.\n\n" + md_table(["Fault", "Attack success", "Utility", "Pairs", "p"], rows))
    return t


# ---------- cost ----------

def cost(raw: Path) -> dict:
    by_unit, calls, unmeasured = Counter(), Counter(), Counter()
    for p in sorted(glob.glob(str(raw / "f*/runs/*/proxy.jsonl"))):
        unit = Path(p).parts[-4]
        for e in read_jsonl(p):
            by_unit[unit] += float(e.get("cost") or 0)
            calls[unit] += 1
            unmeasured[unit] += bool(e.get("unmeasured"))
    return {"logged_usd_by_unit": {k: round(v, 4) for k, v in sorted(by_unit.items())},
            "logged_usd_total": round(sum(by_unit.values()), 4), "proxy_calls": dict(sorted(calls.items())),
            "unmeasured_calls": dict(sorted(unmeasured.items())),
            "note": "Logged by the OpenRouter proxy from per-response usage; responses without usage count as zero. "
                    "F5 ran locally on CPU and cost nothing in API fees."}


def cost_md(d: dict) -> dict:
    rows = [[u, f"${v:.2f}", d["proxy_calls"].get(u, 0), d["unmeasured_calls"].get(u, 0)]
            for u, v in d["logged_usd_by_unit"].items()]
    rows.append(["total", f"${d['logged_usd_total']:.2f}", sum(d["proxy_calls"].values()), sum(d["unmeasured_calls"].values())])
    return {"cost": (f"Hosted model spend logged per response by the proxy. The "
                     f"{sum(d['unmeasured_calls'].values())} responses without usage data are counted as zero.\n\n")
                    + md_table(["Unit", "Logged spend", "Model calls", "Calls without usage"], rows)}


# ---------- headline ----------

def headline(f0d: dict, f2d: dict, f4d: dict) -> str:
    def pr(r):
        p = r["paired_attack_success"]
        return f"{p['b']} to {p['a']} of {p['n']} on {r['model']} (p {fmt_p(p['p'])})"
    main = f0d["main"]
    sig = [r for r in main if r["paired_attack_success"]["bonferroni_survives"]]
    weak = [r for r in main if not r["paired_attack_success"]["bonferroni_survives"]]
    outages = [r for m in f2d["models"].values() for r in m["faults"] if r["class"] == "unavailable"]
    cleared = sum(r["audit"]["taint_skipped"] for r in outages)
    arms = {(r["slug"], r["canary"], r["fault"]): r for r in f4d["arms"]}
    can = []
    for slug in F4_MODELS:
        off, on = arms[(slug, "off", "always_benign")], arms[(slug, "on", "always_benign")]
        can.append(f"{off['attack_success']} to {on['attack_success']} on {MODELS[slug]}")
    fw = [arms[(slug, "on", "first_window")]["canary_audit"]["sessions_tripped"] for slug in F4_MODELS]
    parts = [pr(r) for r in sig] + [pr(r)[:-1] + ", does not survive the within-family Bonferroni correction)" for r in weak]
    parts[0] = parts[0].replace(" of ", " of ", 1).replace(" on ", " paired cases on ", 1)
    text = (f"An injection detector that stays up but answers \"benign\" to everything raised AgentDojo attack success "
            f"against a taint-tracking agent gateway from {', '.join(parts[:-1])}, and {parts[-1]}"
            + f". All five outage faults (timeout, refused connection, HTTP 500, malformed and oversized replies) failed "
            f"closed on {len(outages)} of {len(outages)} arms: the gateway cleared {cleared} tool outputs on a detector "
            f"verdict in those arms. A known-answer canary on the fixed gateway cut attack success under the always-benign "
            f"fault from {' and from '.join(can)}, and did not catch a detector that scores only the start of "
            f"its input ({' and '.join(str(x) for x in fw)} sessions tripped).")
    return text


# ---------- main ----------

def replace_blocks(text: str, tables: dict) -> str:
    def sub(m):
        name = m.group(1)
        if name not in tables:
            raise SystemExit(f"README asks for unknown table {name}")
        return f"<!-- BEGIN table:{name} -->\n{tables[name]}\n<!-- END table:{name} -->"
    return re.sub(r"<!-- BEGIN table:(\w+) -->.*?<!-- END table:\1 -->", sub, text, flags=re.S)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=REPO / "results")
    ap.add_argument("--readme", type=Path)
    ap.add_argument("--detector-baseline", type=Path)
    a = ap.parse_args()
    raw = a.raw.expanduser()
    det = a.detector_baseline or raw / "agentdojo/runs/detector/gateway-gated.jsonl"
    a.out.mkdir(parents=True, exist_ok=True)
    units = {"f0": (f0(raw, det), f0_md), "f2": (f2(raw), f2_md), "f4": (f4(raw), f4_md),
             "f5": (f5(REPO), f5_md), "cost": (cost(raw), cost_md)}
    tables = {"headline": headline(units["f0"][0], units["f2"][0], units["f4"][0])}
    (a.out / "headline.md").write_text(tables["headline"] + "\n")
    for name, (data, render) in units.items():
        (a.out / f"{name}.json").write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
        t = render(data)
        tables.update(t)
        (a.out / f"{name}.md").write_text("\n\n".join(f"## {k}\n\n{v}" for k, v in t.items()) + "\n")
    if a.readme:
        a.readme.write_text(replace_blocks(a.readme.read_text(), tables))
    print("wrote", ", ".join(sorted(units)), "to", a.out)


if __name__ == "__main__":
    main()
