#!/usr/bin/env bash
# FailClosed F0 screen: which model and attack actually produce attack success with the detector silently wrong?
cd "$HOME/bench/failclosed/f0"
MODELS=(
  "openai/gpt-4o-mini|GPT-4"
  "meta-llama/llama-3.3-70b-instruct|Llama"
  "mistralai/mistral-small-3.2-24b-instruct|Mistral"
  "cohere/command-r-08-2024|Command R"
  "qwen/qwen-2.5-72b-instruct|Qwen"
  "anthropic/claude-haiku-5.5|Claude"
  "openai/gpt-6-luna|GPT"
)
for entry in "${MODELS[@]}"; do
  m=${entry%%|*}; display=${entry##*|}
  for attack in important_instructions tool_knowledge; do
    slug=$(basename "$m" | tr . -)
    cases=screen/cases-$attack-$slug.jsonl
    python3 -I - "$attack" "$display" "$cases" <<'PY'
import json, sys
attack, name, out = sys.argv[1:4]
with open(f"screen/cases-{attack}.jsonl") as src, open(out, "w") as dst:
    for line in src:
        dst.write(json.dumps({**json.loads(line), "model_name": name}) + "\n")
PY
    ./run_hosted.sh "screen-$slug-$attack" benign "$m" 2 --cases "$PWD/$cases"
  done
done
echo BATCH_DONE
