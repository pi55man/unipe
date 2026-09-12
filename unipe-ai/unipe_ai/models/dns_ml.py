"""DNS name classifier: logistic regression over label statistics.

trained by `python train.py` on benign names plus published-algorithm DGA
families (conficker / cryptolocker / necurs / banjori / …). same LogisticModel
machinery as the flow scorer — no extra packages.
"""

from __future__ import annotations

from pathlib import Path

from unipe_ai.features.dns_stats import (
    bigram_familiarity,
    consonant_ratio,
    longest_label,
    normalized_entropy,
    unique_char_ratio,
    vowel_ratio,
)
from unipe_ai.models.ml import LogisticModel
from unipe_ai.util import digit_ratio, shannon_entropy

DEFAULT_DNS_MODEL_PATH = Path(__file__).resolve().parents[2] / "artifacts" / "dns_model.json"

DNS_FEATURE_NAMES = (
    "label_len_norm",
    "bigram_familiarity",
    "normalized_entropy",
    "raw_entropy_norm",
    "vowel_ratio",
    "consonant_ratio",
    "digit_ratio",
    "unique_char_ratio",
    "letter_fraction",
)


def dns_feature_vector(qname: str) -> list[float]:
    label = longest_label(qname)
    if not label:
        return [0.0] * len(DNS_FEATURE_NAMES)
    letters = sum(1 for c in label if c.isalpha())
    return [
        min(len(label) / 40.0, 1.0),
        bigram_familiarity(label),
        normalized_entropy(label),
        min(shannon_entropy(label) / 5.0, 1.0),
        vowel_ratio(label),
        consonant_ratio(label),
        digit_ratio(label),
        unique_char_ratio(label),
        letters / max(len(label), 1),
    ]


def dns_probability(model: LogisticModel | None, qname: str) -> float | None:
    if model is None:
        return None
    return model.probability_of(dns_feature_vector(qname))


def load_dns_model(path: Path | None = None) -> LogisticModel | None:
    return LogisticModel.load(path or DEFAULT_DNS_MODEL_PATH)
