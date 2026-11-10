#!/usr/bin/env bash
cd $HOME/bench/failclosed/f4
BIN=$HOME/bench/failclosed/bin/gateway-canary PREFIX=ab-v1 ./run_f4.sh on none gpt-4o-mini openai/gpt-4o-mini
BIN=$HOME/bench/failclosed/bin/gateway-canary3 PREFIX=ab-v3 ./run_f4.sh on none gpt-4o-mini openai/gpt-4o-mini
echo F4AB_DONE
