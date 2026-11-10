# FailClosed raw results

Raw per-case records behind every FailClosed table for the gateway arms (F0, F2, F4). The F5 LlamaFirewall
replay uses public AgentDojo traces; its outputs are in the repository under `f5/results/`.

## Layout

| Path | What it is |
|---|---|
| `f0/runs/full-<model>-{benign,healthy}/` | F0: always-benign stub detector vs the healthy detector, 200 attacked cases per arm |
| `f0/runs/benign-<model>/` | F0 arms with no lift (local Qwen 3.6; hosted arms that addressed the model as "Qwen") |
| `f0/runs/screen-<model>-<attack>/` | F0 model screen, 60 cases, always-benign stub only |
| `f0/screen/*.jsonl` | Case lists the arms ran (`full-<model>.jsonl` is the 200-case set with the attack addressed to that model) |
| `f2/runs/<fault>-<model>/` | F2: one fault-proxy fault per arm, frozen unfixed gateway |
| `f4/runs/<build>-<on/off>-<fault>-<model>/` | F4: canary arms on the fixed gateway (`canary`, `canary2`, `canary3` builds) |
| `f4/canary_pool.jsonl` | Known-answer probe pool used by the canary arms |
| `agentdojo/runs/detector/gateway-gated.jsonl` | Healthy local-model baseline (from the earlier detector-gated-taint run) for the local F0 arm |
| `*/runs-*.log` | Batch logs |

Per arm:
- `gateway.jsonl`: one AgentDojo case record per line (prompt, injections, trace, tool calls, `utility`,
  `attack_success`, `status`). Resumed arms append retries; analysis keeps the last record per case id.
- `proxy.jsonl`: hosted-model calls through the spend-capped OpenRouter proxy, with usage and cost (no key).
- `fault.jsonl`: fault-proxy log: characters scored and the verdict returned.
- `stub-calls.jsonl`: calls to the always-benign stub.
- `audit.jsonl`: gateway audit rows of kinds `detector_score`, `detector_error`, `detector_canary_ok`,
  `detector_canary_failed`, `taint`, `taint_skipped`, exported from each worker's state database.
- `config.toml.tmpl`, `gateway.sha256`: gateway config template and binary hash for the arm.

## Recompute

```
python3 -I analysis/tables.py --raw <this directory> --out /tmp/fc-results
```

from a checkout of the `failclosed` repository reproduces `results/*.json` exactly.

## Scrubbing

The owner's home directory is replaced by `~` and the host name by `host`. Worker directories are not
shipped: no state databases, key files or stderr logs, only the audit rows listed above. An automated scan
found no API keys, tokens, private keys, tailnet addresses, home paths, owner names or private persona text
after scrubbing. Names, emails, account numbers and passwords inside traces are AgentDojo's synthetic fixtures.
`MANIFEST.sha256` lists every file.
