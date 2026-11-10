#!/usr/bin/env bash
# FailClosed F2: one proxy fault, one hosted model, on the frozen unfixed gateway. Paired against F0's healthy arm.
# usage: run_f2.sh <fault> <slug> <openrouter-model> [driver args...]
set -u
FAULT=$1; SLUG=$2; MODEL=$3; shift 3
F0=$HOME/bench/failclosed/f0
F2=$HOME/bench/failclosed/f2
ARM=$FAULT-$SLUG
OUT=$F2/runs/$ARM
mkdir -p "$OUT"
BIN=$HOME/bench/failclosed/bin/gateway-prefix
TMPL=$OUT/config.toml.tmpl
sed -e "s#^base = .*#base = \"http://127.0.0.1:8798\"#" -e "s#^name = .*#name = \"$MODEL\"#" \
    -e "s#^persona_path = .*#persona_path = \"$F0/persona-neutral.md\"#" -e "s#^url = .*#url = \"http://127.0.0.1:8799\"#" \
    "$HOME/bench/gw/agentdojo/config-gated.toml.tmpl" > "$TMPL"
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
[ "${ABORT_WATCH:-on}" = on ] && /srv/gateway/failclosed/.venv/bin/python "$F2/abort_watch.py" "$OUT/gateway.jsonl" "$DRV" "$OUT/ABORTED" &
wait "$DRV"
echo "END $ARM rc=$? $(date -Is) $(cat "$OUT/ABORTED" 2>/dev/null)"
