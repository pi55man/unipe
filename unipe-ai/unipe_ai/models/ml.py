"""logistic regression over flow features, written out by hand.

the rules decide *what* a threat is; this model decides *how much to believe
it*. it is deliberately a linear model with ten inputs: it trains in a second,
needs no third-party packages, and every weight can be read and argued with.

train it with `python train.py`, which writes artifacts/flow_model.json.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from unipe_ai.util import to_float

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "artifacts" / "flow_model.json"

FEATURE_NAMES = (
    "log_packet_rate",
    "log_byte_rate",
    "log_packets",
    "log_duration_ms",
    "avg_packet_size_norm",
    "syn_only",
    "syn_ack_ratio_norm",
    "is_udp",
    "is_icmp",
    "src_is_martian",
)


def feature_vector(feat: dict[str, Any]) -> list[float]:
    """map a flow onto the fixed input vector the model was trained on.

    rates are log-compressed because they span six orders of magnitude, and the
    bounded features are scaled into roughly 0..1 so no single weight dominates.
    """
    packets = to_float(feat.get("packets"))
    duration_ms = max(to_float(feat.get("duration_ms")), 1.0)
    avg_size = to_float(feat.get("avg_packet_size"))
    syn_ack = to_float(feat.get("syn_ack_ratio"))
    return [
        _log1p(to_float(feat.get("packet_rate"))) / 15.0,
        _log1p(to_float(feat.get("byte_rate"))) / 25.0,
        _log1p(packets) / 15.0,
        _log1p(duration_ms) / 15.0,
        min(avg_size / 1500.0, 1.0),
        1.0 if feat.get("is_syn_only") else 0.0,
        min(syn_ack / 10.0, 1.0),
        1.0 if feat.get("is_udp") else 0.0,
        1.0 if feat.get("is_icmp") else 0.0,
        1.0 if feat.get("src_is_martian") else 0.0,
    ]


class LogisticModel:
    def __init__(
        self,
        weights: list[float],
        bias: float,
        feature_names: tuple[str, ...] = FEATURE_NAMES,
        metrics: dict[str, Any] | None = None,
    ) -> None:
        if len(weights) != len(feature_names):
            raise ValueError("weight count does not match feature count")
        self.weights = list(weights)
        self.bias = float(bias)
        self.feature_names = tuple(feature_names)
        self.metrics = metrics or {}

    def probability(self, feat: dict[str, Any]) -> float:
        return self.probability_of(feature_vector(feat))

    def probability_of(self, vector: list[float]) -> float:
        z = self.bias + sum(w * x for w, x in zip(self.weights, vector))
        return _sigmoid(z)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": "logistic_regression",
            "feature_names": list(self.feature_names),
            "weights": self.weights,
            "bias": self.bias,
            "metrics": self.metrics,
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> LogisticModel | None:
        """return None when the model has not been trained yet."""
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                weights=[float(w) for w in data["weights"]],
                bias=float(data["bias"]),
                feature_names=tuple(data.get("feature_names", FEATURE_NAMES)),
                metrics=data.get("metrics", {}),
            )
        except (ValueError, KeyError, TypeError):
            return None


def train(
    samples: list[list[float]],
    labels: list[int],
    epochs: int = 400,
    learning_rate: float = 0.5,
    l2: float = 0.001,
) -> tuple[list[float], float]:
    """plain batch gradient descent on the log-loss."""
    if not samples:
        raise ValueError("no training samples")
    n_features = len(samples[0])
    weights = [0.0] * n_features
    bias = 0.0
    n = len(samples)

    for _ in range(epochs):
        grad_w = [0.0] * n_features
        grad_b = 0.0
        for vector, label in zip(samples, labels):
            error = _sigmoid(bias + sum(w * x for w, x in zip(weights, vector))) - label
            for i, x in enumerate(vector):
                grad_w[i] += error * x
            grad_b += error
        for i in range(n_features):
            weights[i] -= learning_rate * (grad_w[i] / n + l2 * weights[i])
        bias -= learning_rate * (grad_b / n)

    return weights, bias


def evaluate(
    model: LogisticModel,
    samples: list[list[float]],
    labels: list[int],
    threshold: float = 0.5,
) -> dict[str, float]:
    tp = fp = tn = fn = 0
    for vector, label in zip(samples, labels):
        predicted = 1 if model.probability_of(vector) >= threshold else 0
        if predicted == 1 and label == 1:
            tp += 1
        elif predicted == 1 and label == 0:
            fp += 1
        elif predicted == 0 and label == 0:
            tn += 1
        else:
            fn += 1

    total = max(tp + fp + tn + fn, 1)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": round((tp + tn) / total, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
    }


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-min(z, 60.0)))
    exp_z = math.exp(max(z, -60.0))
    return exp_z / (1.0 + exp_z)


def _log1p(value: float) -> float:
    return math.log1p(max(value, 0.0))
