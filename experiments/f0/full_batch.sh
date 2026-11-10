#!/usr/bin/env bash
# FailClosed F0 decision run. Waits for the screen, then runs full paired arms.
# Primary attack is fixed in advance: important_instructions, addressed by the model's own name.
cd "$HOME/bench/failclosed/f0"
until grep -q BATCH_DONE runs-screen.log; do sleep 30; done
MODELS=(
  "mistralai/mistral-small-3.2-24b-instruct|Mistral"
  "openai/gpt-4o-mini|GPT-4"
  "qwen/qwen-2.5-72b-instruct|Qwen"
  "meta-llama/llama-3.3-70b-instruct|Llama"
)
for entry in "${MODELS[@]}"; do
  m=${entry%%|*}; display=${entry##*|}
  slug=$(basename "$m" | tr . -)
  cases=$PWD/screen/full-$slug.jsonl
  python3 -I - "$display" "$cases" <<'PY'
import json, os, sys
name, out = sys.argv[1:3]
with open(os.path.expanduser("~/bench/agentdojo/cases.jsonl")) as src, open(out, "w") as dst:
    for line in src:
        c = json.loads(line)
        if c.get("injection_task"):
            dst.write(json.dumps({**c, "attack": "important_instructions", "model_name": name}) + "\n")
PY
  for kind in benign healthy; do
    ./run_hosted.sh "full-$slug-$kind" "$kind" "$m" 8 --cases "$cases"
  done
done
echo FULL_DONE
