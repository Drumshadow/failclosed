#!/usr/bin/env python3
"""Build the FailClosed raw-results archive: copy, scrub, scan, manifest, pack, recompute.

usage: python3 -I analysis/package_raw.py --bench ~/bench/failclosed \
          --detector-baseline ~/bench/agentdojo/runs/detector/gateway-gated.jsonl \
          --private-needles FILE --date 2026-11-10

Read-only on the bench tree. Writes <bench>/release/failclosed-raw-<date>.tar.gz and a scan report.
--private-needles names a file whose lines (one per line, 25+ characters) must not appear anywhere in the
archive; they are never printed. Gateway audit rows are exported from each worker's state.db as
audit.jsonl (detector and taint kinds only); nothing else from the database is shipped.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from tables import AUDIT_KINDS  # noqa: E402

ARM_FILES = ("gateway.jsonl", "proxy.jsonl", "fault.jsonl", "stub-calls.jsonl", "gateway.sha256", "gw-bench.commit", "ABORTED")
HOME = os.path.expanduser("~")
USER = os.path.basename(HOME)
HOST = os.uname().nodename
REWRITES = [(HOME, "~"), ("/home/" + USER, "~"), (HOST, "host")]
SCAN = {  # name -> regex; any hit after scrubbing fails the build
    "openrouter_key": r"sk-or-[A-Za-z0-9-]{8,}",
    "generic_secret_key": r"\bsk-[A-Za-z0-9]{20,}",
    "bearer_token": r"Bearer [A-Za-z0-9._-]{20,}",
    "age_secret_key": r"AGE-SECRET-KEY-1",
    "private_key_block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "tailnet_ip": r"\b100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.\d{1,3}\.\d{1,3}\b",
    "home_path": r"/home/(?!user/|emma/)[A-Za-z0-9_.-]+",  # /home/user, /home/emma: model-invented paths in AgentDojo banking
    "owner_user": re.escape(USER),
    "hostname": re.escape(HOST),
}
# Owner-identifying patterns (names, handles, domains) live in an untracked file so the public script
# does not list them: one regex per line in $FAILCLOSED_PRIVATE_PATTERNS or analysis/private_patterns.txt.
_private = Path(os.environ.get("FAILCLOSED_PRIVATE_PATTERNS", HERE / "private_patterns.txt"))
if _private.exists():
    for _i, _line in enumerate(l.strip() for l in _private.read_text().splitlines()):
        if _line and not _line.startswith("#"):
            SCAN[f"private_{_i}"] = _line


def scan_text(text: str, needles: list[str]) -> Counter:
    c = Counter()
    for name, rx in SCAN.items():
        n = len(re.findall(rx, text))
        if n:
            c[name] += n
    for nd in needles:
        if nd in text:
            c["private_persona_line"] += 1
    return c


def scrub(text: str) -> str:
    for a, b in REWRITES:
        text = text.replace(a, b)
    return text


def export_audit(arm: Path, dst: Path) -> int:
    n = 0
    with open(dst, "w") as out:
        for db in sorted(arm.glob("work/worker-*/state.db")):
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            q = f"select seq, ts, kind, payload_json from audit where kind in ({','.join('?' * len(AUDIT_KINDS))}) order by seq"
            for seq, ts, kind, payload in con.execute(q, AUDIT_KINDS):
                out.write(json.dumps({"worker": db.parent.name, "seq": seq, "ts": ts, "kind": kind,
                                      "payload": json.loads(payload)}) + "\n")
                n += 1
            con.close()
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", type=Path, required=True)
    ap.add_argument("--detector-baseline", type=Path, required=True)
    ap.add_argument("--private-needles", type=Path)
    ap.add_argument("--date", required=True)
    a = ap.parse_args()
    bench = a.bench.expanduser()
    needles = []
    if a.private_needles:
        needles = [l.strip() for l in a.private_needles.read_text().splitlines() if len(l.strip()) >= 25]
    name = f"failclosed-raw-{a.date}"
    release = bench / "release"
    stage_root = Path(tempfile.mkdtemp(prefix="fc-stage-", dir=release if release.exists() else None))
    stage = stage_root / name
    stage.mkdir(parents=True)

    sources = []  # (src, rel)
    arms = []
    for unit, pats in (("f0", ("full-*", "benign-*", "screen-*", "price*", "dry-*")), ("f2", ("*",)), ("f4", ("*",))):
        for pat in pats:
            for d in sorted((bench / unit / "runs").glob(pat)):
                if d.is_dir() and "smoke" not in d.name:
                    arms.append((unit, d))
    for unit, d in arms:
        for f in ARM_FILES:
            if (d / f).exists():
                sources.append((d / f, f"{unit}/runs/{d.name}/{f}"))
        for t in sorted(d.glob("*.toml.tmpl")):
            sources.append((t, f"{unit}/runs/{d.name}/{t.name}"))
    for p in sorted((bench / "f0/screen").glob("*.jsonl")):
        sources.append((p, f"f0/screen/{p.name}"))
    for unit in ("f0", "f2", "f4"):
        for p in sorted((bench / unit).glob("runs-*.log")):
            sources.append((p, f"{unit}/{p.name}"))
    sources.append((bench / "f4/canary_pool.jsonl", "f4/canary_pool.jsonl"))
    sources.append((a.detector_baseline.expanduser(), "agentdojo/runs/detector/gateway-gated.jsonl"))

    before, after = Counter(), Counter()
    for src, rel in sources:
        text = src.read_text(errors="strict")
        before += scan_text(text, needles)
        clean = scrub(text)
        after += scan_text(clean, needles)
        dst = stage / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(clean)
    audit_rows = 0
    for unit, d in arms:
        dst = stage / f"{unit}/runs/{d.name}/audit.jsonl"
        audit_rows += export_audit(d, dst)
        text = dst.read_text()
        before += scan_text(text, needles)
        clean = scrub(text)
        after += scan_text(clean, needles)
        dst.write_text(clean)
    shutil.copy(HERE / "RAW_README.md", stage / "README.md")

    report = {"files": len(sources) + len(arms) + 1, "arms": len(arms), "audit_rows": audit_rows,
              "hits_before_scrub": dict(before), "hits_after_scrub": dict(after),
              "rewrites": ["home directory -> ~", "user name in /home paths -> ~", "hostname -> host"],
              "excluded": ["work/ directories (worker state.db, age identities, configs with absolute paths, "
                           "stderr logs); only audit rows of kinds " + ", ".join(AUDIT_KINDS) + " are exported",
                           "the gateway persona file", "OpenRouter key file and secrets/", "smoke arms"]}
    if after:
        print(json.dumps(report, indent=1))
        sys.exit(f"scan found private strings after scrubbing; nothing packed. staging left at {stage}")

    files = sorted(p for p in stage.rglob("*") if p.is_file())
    with open(stage / "MANIFEST.sha256", "w") as m:
        for p in files:
            m.write(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(stage)}\n")
    release.mkdir(exist_ok=True)
    out = release / f"{name}.tar.gz"
    with tarfile.open(out, "w:gz") as tar:
        tar.add(stage, arcname=name, filter=lambda ti: (setattr(ti, "uname", "") or setattr(ti, "gname", "")
                                                        or setattr(ti, "uid", 0) or setattr(ti, "gid", 0) or ti))
    shutil.rmtree(stage_root)
    report["archive"] = str(out).replace(HOME, "~")
    report["bytes"] = out.stat().st_size
    report["sha256"] = hashlib.sha256(out.read_bytes()).hexdigest()
    (release / f"{name}.scan.json").write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
