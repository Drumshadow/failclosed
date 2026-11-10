#!/usr/bin/env bash
cd $HOME/bench/failclosed/f4
export BIN=$HOME/bench/failclosed/bin/gateway-canary3 PREFIX=canary3
./run_f4.sh on none gpt-4o-mini openai/gpt-4o-mini
./run_f4.sh on always_benign gpt-4o-mini openai/gpt-4o-mini
echo F4D_DONE
