#!/usr/bin/env bash
# FailClosed F0: always-benign detector in gated mode, attacked AgentDojo cases.
# usage: run_f0.sh <arm-label> <template> [extra driver args...]
# Resumable (driver skips finished cases). Stops the driver if MemAvailable drops under 8 GB.
set -u
ARM=$1; TMPL=$2; shift 2
F0=$HOME/bench/failclosed/f0
OUT=$F0/runs/$ARM
mkdir -p "$OUT"
cd "$HOME/bench/agentdojo"
sha256sum /srv/gateway/gw-bench/target/release/gateway > "$OUT/gateway.sha256"
git -C /srv/gateway/gw-bench rev-parse HEAD > "$OUT/gw-bench.commit"
cp "$TMPL" "$OUT/"

python3 "$F0/stub_detector.py" 8797 "$OUT/stub-calls.jsonl" &
STUB=$!
trap 'kill $STUB 2>/dev/null' EXIT

echo "START $ARM $(date -Is)"
.venv/bin/python driver.py --harness gateway --gateway-template "$TMPL" \
  --label "failclosed-$ARM" --out "$OUT/gateway.jsonl" --workers 3 --permissions allow \
  --kind injection --workdir "$OUT/work" "$@" &
DRV=$!

while kill -0 "$DRV" 2>/dev/null; do
  avail=$(awk '/MemAvailable/{print int($2/1048576)}' /proc/meminfo)
  if [ "$avail" -lt 8 ]; then
    echo "ABORT low memory: ${avail} GB $(date -Is)"
    kill "$DRV"
    wait "$DRV"
    exit 3
  fi
  sleep 20
done
wait "$DRV"
rc=$?
echo "END $ARM rc=$rc $(date -Is)"
echo ALL_DONE
