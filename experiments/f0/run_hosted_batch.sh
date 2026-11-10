#!/usr/bin/env bash
cd $HOME/bench/failclosed/f0
for m in anthropic/claude-haiku-5.5 openai/gpt-6-luna deepseek/deepseek-v4.1-flash; do
  ./run_hosted.sh benign-$(basename $m | tr . -) benign $m 5 --retry-failed
done
echo BATCH_DONE
