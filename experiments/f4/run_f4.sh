#!/usr/bin/env bash
# FailClosed F4: canary defense under detector faults, on the fixed bench binary (f3 fixes + canary code).
# usage: run_f4.sh <on|off> <fault> <slug> <openrouter-model> [driver args...]
set -u
CANARY=$1; FAULT=$2; SLUG=$3; MODEL=$4; shift 4
F0=$HOME/bench/failclosed/f0
F4=$HOME/bench/failclosed/f4
ARM=${PREFIX:-canary}-$CANARY-$FAULT-$SLUG
OUT=$F4/runs/$ARM
mkdir -p "$OUT"
BIN=${BIN:-$HOME/bench/failclosed/bin/gateway-canary}
TMPL=$OUT/config.toml.tmpl
sed -e "s#^base = .*#base = \"http://127.0.0.1:8798\"#" -e "s#^name = .*#name = \"$MODEL\"#" \
    -e "s#^persona_path = .*#persona_path = \"$F0/persona-neutral.md\"#" -e "s#^url = .*#url = \"http://127.0.0.1:8799\"#" \
    "$HOME/bench/gw/agentdojo/config-gated.toml.tmpl" > "$TMPL"
if [ "$CANARY" = on ]; then
  printf '\n[detector.canary]\nenabled = true\npool_path = "%s/canary_pool.jsonl"\nevery_n = 20\n' "$F4" >> "$TMPL"
fi
sha256sum "$BIN" > "$OUT/gateway.sha256"

python3 -I "$F0/or_proxy.py" 8798 "$HOME/bench/failclosed/secrets/openrouter_key" "$MODEL" 8 "$OUT/proxy.jsonl" &
PROXY=$!
(cd /srv/gateway/failclosed && exec .venv/bin/python -m failclosed.proxy --upstream http://127.0.0.1:8796 --fault "$FAULT" --port 8799 --log "$OUT/fault.jsonl") &
FP=$!
trap 'kill $PROXY $FP 2>/dev/null' EXIT

cd "$HOME/bench/agentdojo"
echo "START $ARM $(date -Is)"
.venv/bin/python driver.py --harness gateway --gateway-template "$TMPL" --gateway-cmd "$BIN --acp-v1" \
  --label "failclosed-$ARM" --out "$OUT/gateway.jsonl" --workers 3 --permissions allow \
  --kind injection --workdir "$OUT/work" --cases "$F0/screen/full-$SLUG.jsonl" "$@" &
DRV=$!
/srv/gateway/failclosed/.venv/bin/python "$HOME/bench/failclosed/f2/abort_watch.py" "$OUT/gateway.jsonl" "$DRV" "$OUT/ABORTED" &
wait "$DRV"
echo "END $ARM rc=$? $(date -Is) $(cat "$OUT/ABORTED" 2>/dev/null)"
