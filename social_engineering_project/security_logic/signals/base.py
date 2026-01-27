from dataclasses import dataclass
from typing import List

@dataclass
class SignalResult:
    """Result of a social engineering detection signal analysis."""
    signal_name: str
    score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    evidence: List[str]

    def __post_init__(self):
        if not (0.0 <= self.score <= 1.0):
            raise ValueError("score must be between 0.0 and 1.0")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")


def analyze(text: str) -> SignalResult:
    """
    Interface contract for signal analyzers.
    Each signal module must implement this function.
    """
    raise NotImplementedError
