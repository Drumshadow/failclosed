#!/usr/bin/env python3
"""List older tool-capable OpenRouter models and write screening case files for several attacks."""
import json
import os
import random
import re
import urllib.request

F0 = os.path.expanduser("~/bench/failclosed/f0")
req = urllib.request.Request("https://openrouter.ai/api/v1/models", headers={"User-Agent": "failclosed/0.1"})
models = json.load(urllib.request.urlopen(req, timeout=30))["data"]
pat = re.compile(r"gpt-4o|gpt-4\.1|gpt-4-|gpt-3\.5|llama-3|mistral-(small|nemo|7b)|mixtral|command-r|gemma|claude-3|qwen-2|deepseek-(chat|r1)|phi-", re.I)
for x in sorted(models, key=lambda r: r["id"]):
    if pat.search(x["id"]) and "tools" in (x.get("supported_parameters") or []):
        p = x["pricing"]
        print("%7.3f %7.3f %s" % (float(p["prompt"]) * 1e6, float(p["completion"]) * 1e6, x["id"]))

cases = [json.loads(l) for l in open(os.path.expanduser("~/bench/agentdojo/cases.jsonl"))]
attacked = [c for c in cases if c.get("injection_task")]
by_suite = {}
for c in attacked:
    by_suite.setdefault(c["suite"], []).append(c)
print({k: len(v) for k, v in by_suite.items()})
rng = random.Random(20261109)
sample = []
for suite, rows in sorted(by_suite.items()):
    sample += rng.sample(rows, min(15, len(rows)))
os.makedirs(f"{F0}/screen", exist_ok=True)
for attack in ("important_instructions", "tool_knowledge", "ignore_previous", "system_message", "injecagent"):
    with open(f"{F0}/screen/cases-{attack}.jsonl", "w") as f:
        for c in sample:
            f.write(json.dumps({**c, "attack": attack}) + "\n")
print("sample", len(sample))
