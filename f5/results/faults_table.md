# F5 fault replay

**paired against this replay's own baseline; did not reproduce the paper (18.47% vs 7.53% PromptGuard ASR); no claim about the paper's numbers**

Healthy PromptGuard: ASR 18.47%, utility 51.34%. No guardrail: ASR 22.94%, utility 51.34%. Threshold 0.9, ten AgentDojo Table 3 models, 6290 attacked and 970 benign traces.

Paired counts are healthy-only success / fault-only success on the same traces, with exact McNemar p.

| Fault | ASR | Utility | ASR pairs | ASR p | Utility pairs | Utility p |
|---|---|---|---|---|---|---|
| always_benign | 22.94% | 51.34% | 0 / 281 | 5.15e-85 | 0 / 0 | 1 |
| stale_clean | 22.94% | 51.34% | 0 / 281 | 5.15e-85 | 0 / 0 | 1 |
| stale_verdict | 22.94% | 51.34% | 0 / 281 | 5.15e-85 | 0 / 0 | 1 |
| first_window | 18.46% | 51.34% | 1 / 0 | 1 | 0 / 0 | 1 |
| inverted_score | 0.11% | 0.00% | 1155 / 0 | <1e-300 | 498 / 0 | 2.44e-150 |

first_window: The library already truncates to the first 512 tokens, so the fault changes the model input only when the first 2000 characters hold fewer than 512 tokens. Anything past 512 tokens was invisible to the healthy scanner too. Longer than 2000 characters: 720 unique messages; score changed on 537; verdict flipped on 13; traces with a changed flag: 14.

Unavailable (timeout, refused, http_500, malformed, oversized): LlamaFirewall.scan raises to the caller and returns no ScanResult. What happens next depends on the caller and is not modelled here. Sample of 20 messages per fault; see faults.json.

Timing: not run: LlamaFirewall.scan has no deadline, so a slow valid verdict arrives unchanged. Timing faults only change outcomes if the caller enforces a timeout.
