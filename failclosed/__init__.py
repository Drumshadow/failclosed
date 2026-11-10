"""FailClosed: measure what agent guardrails do when they break."""
from .abort import AbortGauge
from .catalog import Fault, load_catalog

__all__ = ["AbortGauge", "Fault", "load_catalog"]
