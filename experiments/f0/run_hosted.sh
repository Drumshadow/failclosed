#!/usr/bin/env bash
# FailClosed F0, hosted arm.
# usage: run_hosted.sh <arm> <benign|healthy> <openrouter-model> <budget-usd> [--dry] [driver args...]
# benign = stub detector that always answers benign; healthy = the real sidecar on :8796.
set -u
ARM=$1; KIND=$2; MODEL=$3; BUDGET=$4; shift 4
DRY=()
F0=$HOME/bench/failclosed/f0
OUT=$F0/runs/$ARM
mkdir -p "$OUT"
if [ "${1:-}" = "--dry" ]; then DRY=(--dry "$OUT/request.json"); shift; fi
awk 'NF==0{exit} {print}' /srv/gateway/persona.md > "$F0/persona-neutral.md"
case $KIND in benign) DET=http://127.0.0.1:8799 ;; healthy) DET=http://127.0.0.1:8796 ;; *) echo bad kind; exit 2 ;; esac
TMPL=$OUT/config.toml.tmpl
sed -e "s#^base = .*#base = \"http://127.0.0.1:8798\"#" -e "s#^name = .*#name = \"$MODEL\"#" \
    -e "s#^persona_path = .*#persona_path = \"$F0/persona-neutral.md\"#" -e "s#^url = .*#url = \"$DET\"#" \
    "$HOME/bench/gw/agentdojo/config-gated.toml.tmpl" > "$TMPL"
sha256sum /srv/gateway/gw-bench/target/release/gateway > "$OUT/gateway.sha256"

python3 -I "$F0/or_proxy.py" 8798 "$HOME/bench/failclosed/secrets/openrouter_key" "$MODEL" "$BUDGET" "$OUT/proxy.jsonl" ${DRY[@]+"${DRY[@]}"} &
PROXY=$!
STUB=
if [ "$KIND" = benign ]; then python3 -I "$F0/stub_detector.py" 8799 "$OUT/stub-calls.jsonl" & STUB=$!; fi
trap 'kill $PROXY $STUB 2>/dev/null' EXIT

cd "$HOME/bench/agentdojo"
echo "START $ARM $(date -Is)"
.venv/bin/python driver.py --harness gateway --gateway-template "$TMPL" \
  --label "failclosed-$ARM" --out "$OUT/gateway.jsonl" --workers 3 --permissions allow \
  --kind injection --workdir "$OUT/work" "$@"
echo "END $ARM rc=$? $(date -Is)"
echo ALL_DONE
