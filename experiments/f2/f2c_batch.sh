#!/usr/bin/env bash
cd $HOME/bench/failclosed/f2
export ABORT_WATCH=off
./run_f2.sh stale_verdict mistral-small-3-2-24b-instruct mistralai/mistral-small-3.2-24b-instruct --retry-failed
./run_f2.sh first_window qwen-2-5-72b-instruct qwen/qwen-2.5-72b-instruct --retry-failed
echo F2C_DONE
