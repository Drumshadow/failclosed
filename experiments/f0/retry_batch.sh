#!/usr/bin/env bash
# Rerun cases voided by the proxy's old one-strike halt, after the decision batch ends.
cd "$HOME/bench/failclosed/f0"
until grep -q FULL_DONE runs-full.log; do sleep 30; done
cp or_proxy.py.new or_proxy.py
for entry in "mistral-small-3-2-24b-instruct|mistralai/mistral-small-3.2-24b-instruct" "llama-3-3-70b-instruct|meta-llama/llama-3.3-70b-instruct"; do
  slug=${entry%%|*}; m=${entry##*|}
  ./run_hosted.sh "full-$slug-healthy" healthy "$m" 8 --cases "$PWD/screen/full-$slug.jsonl" --retry-failed
done
echo RETRY_DONE
