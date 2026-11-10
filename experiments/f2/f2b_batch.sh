#!/usr/bin/env bash
# F2 repairs: finish the two aborted arms and run the stale-clean fault.
cd "$HOME/bench/failclosed/f2"
./run_f2.sh stale_verdict mistral-small-3-2-24b-instruct mistralai/mistral-small-3.2-24b-instruct --retry-failed
./run_f2.sh first_window qwen-2-5-72b-instruct qwen/qwen-2.5-72b-instruct --retry-failed
MODELS=(
  "mistral-small-3-2-24b-instruct|mistralai/mistral-small-3.2-24b-instruct"
  "gpt-4o-mini|openai/gpt-4o-mini"
  "qwen-2-5-72b-instruct|qwen/qwen-2.5-72b-instruct"
)
for entry in "${MODELS[@]}"; do
  ./run_f2.sh stale_clean "${entry%%|*}" "${entry##*|}"
done
echo F2B_DONE
