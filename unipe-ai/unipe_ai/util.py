"""small helpers shared by the feature extractor and the detectors."""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def to_int(value: Any, default: int = 0) -> int:
    return int(to_float(value, float(default)))


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def mean(values: Iterable[float]) -> float:
    items = list(values)
    if not items:
        return 0.0
    return sum(items) / len(items)


def stdev(values: Iterable[float]) -> float:
    """sample standard deviation; 0.0 when there is nothing to spread."""
    items = list(values)
    if len(items) < 2:
        return 0.0
    avg = mean(items)
    variance = sum((v - avg) ** 2 for v in items) / (len(items) - 1)
    return math.sqrt(variance)


def shannon_entropy(text: str) -> float:
    """bits per character; random-looking strings score high, words score low."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if c.isdigit()) / len(text)
