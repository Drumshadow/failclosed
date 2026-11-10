#!/usr/bin/env python3
"""Report the OpenRouter key's limit/usage (never the key), candidate prices, and token use per case."""
import json
import os
import re
import urllib.request

KEY = open(os.path.expanduser("~/bench/failclosed/secrets/openrouter_key")).read().strip()


def get(url, auth=False):
    h = {"User-Agent": "failclosed/0.1"}
    if auth:
        h["Authorization"] = "Bearer " + KEY
    return json.load(urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=30))


d = get("https://openrouter.ai/api/v1/key", auth=True)["data"]
print("key", {k: d.get(k) for k in ("limit", "limit_remaining", "usage", "is_free_tier")})

models = get("https://openrouter.ai/api/v1/models")["data"]
pat = re.compile(r"claude|gpt-|o\d-|gemini|llama-4|deepseek|qwen3|mistral-(medium|large)|grok", re.I)
rows = []
for m in models:
    if "tools" not in (m.get("supported_parameters") or []) or not pat.search(m["id"]):
        continue
    p = m.get("pricing") or {}
    rows.append((float(p.get("prompt", 0)) * 1e6, float(p.get("completion", 0)) * 1e6, float(p.get("input_cache_read") or 0) * 1e6, m["id"], m.get("created", 0)))
rows.sort(key=lambda r: -r[4])
print("n", len(rows))
for r in rows[:45]:
    print(f"{r[0]:8.3f} {r[1]:8.3f} cache {r[2]:7.3f}  {r[3]}")

path = os.path.expanduser("~/bench/agentdojo/runs/detector/gateway-gated.jsonl")
recs = [json.loads(l) for l in open(path)]
inj = [r for r in recs if r.get("injection_task")]
print("records", len(recs), "attacked", len(inj), "keys", sorted(recs[0].keys())[:40])
for k in ("usage", "tokens", "n_tool_calls"):
    print(k, json.dumps(inj[0].get(k))[:300])
