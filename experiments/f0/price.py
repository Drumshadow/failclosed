import json
import os
import sys

for arm in sys.argv[1:]:
    p = os.path.expanduser(f"~/bench/failclosed/f0/runs/{arm}/proxy.jsonl")
    r = [json.loads(l) for l in open(p)]
    ok = [x for x in r if x.get("status") == 200]
    cases = len(open(os.path.expanduser(f"~/bench/failclosed/f0/runs/{arm}/gateway.jsonl")).readlines())
    u = [x.get("usage") or {} for x in ok]
    cost = sum(x.get("cost", 0) for x in ok)
    print(arm, "cases", cases, "calls", len(r), "ok", len(ok), "unmeasured", sum(1 for x in ok if x.get("unmeasured")),
          "prompt", sum(x.get("prompt_tokens", 0) for x in u), "completion", sum(x.get("completion_tokens", 0) for x in u),
          "cost", round(cost, 5), "per_case", round(cost / max(cases, 1), 5), "per_200", round(200 * cost / max(cases, 1), 3))
    print("  errors", [x for x in r if x.get("status") != 200][:2])

key = open(os.path.expanduser("~/bench/failclosed/secrets/openrouter_key")).read().strip()
import urllib.request
req = urllib.request.Request("https://openrouter.ai/api/v1/key", headers={"Authorization": "Bearer " + key, "User-Agent": "failclosed/0.1"})
d = json.load(urllib.request.urlopen(req, timeout=30))["data"]
print("account", {k: d.get(k) for k in ("limit", "limit_remaining", "usage")})
