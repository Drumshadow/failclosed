#!/usr/bin/env bash
# FailClosed F2 matrix. Headline class first, so a late failure cannot cost the main result.
cd "$HOME/bench/failclosed/f2"
MODELS=(
  "mistral-small-3-2-24b-instruct|mistralai/mistral-small-3.2-24b-instruct"
  "gpt-4o-mini|openai/gpt-4o-mini"
  "qwen-2-5-72b-instruct|qwen/qwen-2.5-72b-instruct"
)
for fault in stale_verdict first_window inverted_score timeout refused http_500 malformed oversized slow_valid scoring_window load_amplified; do
  for entry in "${MODELS[@]}"; do
    ./run_f2.sh "$fault" "${entry%%|*}" "${entry##*|}"
  done
done
echo F2_DONE
