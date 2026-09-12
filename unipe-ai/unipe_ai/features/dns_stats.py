"""name-shape stats shared by the DNS detector and the DNS classifier."""

from __future__ import annotations

import math

from unipe_ai.util import shannon_entropy

_BIGRAM_LINES = (
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se",
    "ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur",
    "ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs",
    "un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh",
    "ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa",
    "ay ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa",
    "ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va um pp ua up lu go ht",
    "ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys",
)
COMMON_BIGRAMS = frozenset(pair for line in _BIGRAM_LINES for pair in line.split())
_VOWELS = frozenset("aeiou")


def longest_label(qname: str) -> str:
    labels = [label for label in qname.split(".") if label]
    if not labels:
        return ""
    return max(labels, key=len)


def parent_domain(qname: str) -> str:
    labels = [label for label in qname.split(".") if label]
    # need a subdomain so the last two labels are a real parent, not the name itself
    if len(labels) < 3:
        return ""
    return ".".join(labels[-2:])


def bigram_familiarity(label: str) -> float:
    pairs = [label[i : i + 2] for i in range(len(label) - 1)]
    pairs = [p for p in pairs if p.isalpha()]
    if not pairs:
        return 0.0
    return sum(1 for p in pairs if p.lower() in COMMON_BIGRAMS) / len(pairs)


def normalized_entropy(label: str) -> float:
    if len(label) < 2:
        return 0.0
    ceiling = math.log2(len(label))
    return shannon_entropy(label) / ceiling if ceiling > 0 else 0.0


def vowel_ratio(label: str) -> float:
    letters = [c for c in label.lower() if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c in _VOWELS) / len(letters)


def consonant_ratio(label: str) -> float:
    letters = [c for c in label.lower() if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c not in _VOWELS) / len(letters)


def unique_char_ratio(label: str) -> float:
    if not label:
        return 0.0
    return len(set(label.lower())) / len(label)
