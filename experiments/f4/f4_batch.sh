#!/usr/bin/env bash
cd "$HOME/bench/failclosed/f4"
MODELS=(
  "gpt-4o-mini|openai/gpt-4o-mini"
  "qwen-2-5-72b-instruct|qwen/qwen-2.5-72b-instruct"
)
for entry in "${MODELS[@]}"; do
  s=${entry%%|*}; m=${entry##*|}
  ./run_f4.sh on always_benign "$s" "$m"
  ./run_f4.sh on stale_clean "$s" "$m"
  ./run_f4.sh on first_window "$s" "$m"
  ./run_f4.sh on none "$s" "$m"
  ./run_f4.sh off always_benign "$s" "$m"
done
echo F4_DONE
