"""Load the fault catalog."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT = Path(__file__).with_name("catalog.yaml")


@dataclass(frozen=True)
class Fault:
    name: str
    cls: str
    adapter: str
    expected: str
    params: dict = field(default_factory=dict)

    def with_params(self, **overrides) -> "Fault":
        return Fault(self.name, self.cls, self.adapter, self.expected, {**self.params, **overrides})


def load_catalog(path: str | Path = DEFAULT) -> dict[str, Fault]:
    raw = yaml.safe_load(Path(path).read_text())["faults"]
    return {n: Fault(n, v["class"], v["adapter"], v["expected"], v.get("params") or {}) for n, v in raw.items()}
