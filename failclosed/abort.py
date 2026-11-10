"""Stop a fault arm when too many cases fail for infrastructure reasons, so noise is never scored."""
from __future__ import annotations


class AbortGauge:
    def __init__(self, max_rate: float = 0.2, min_samples: int = 20):
        self.max_rate, self.min_samples = max_rate, min_samples
        self.total = self.errors = 0

    def record(self, infra_error: bool) -> None:
        self.total += 1
        self.errors += int(infra_error)

    @property
    def rate(self) -> float:
        return self.errors / self.total if self.total else 0.0

    @property
    def should_abort(self) -> bool:
        return self.total >= self.min_samples and self.rate > self.max_rate
