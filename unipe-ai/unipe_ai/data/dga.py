"""published-style DGA generators and benign name builders.

these stand in for DGArchive families when you cannot ship the archive itself.
each generator follows the *shape* of a known family (random alphabet, seeded
LCG, dictionary mash) so the DNS classifier sees the same statistics a real
lab sample would produce.
"""

from __future__ import annotations

import hashlib
import random
import string

# short word list for benign hostnames and for "soft" DGAs that mash words
_WORDS = [
    "cloud", "data", "edge", "mail", "api", "web", "app", "static", "media",
    "video", "music", "store", "shop", "home", "news", "blog", "docs", "help",
    "support", "update", "secure", "login", "auth", "portal", "gateway",
    "ingest", "metrics", "telemetry", "status", "health", "check", "probe",
    "sync", "push", "pull", "alpha", "beta", "gamma", "delta", "omega",
    "north", "south", "east", "west", "blue", "green", "red", "river",
    "mountain", "forest", "ocean", "lake", "city", "town", "village",
    "street", "park", "server", "client", "node", "host", "peer", "relay",
    "bridge", "tunnel", "cache", "buffer", "chrome", "firefox", "safari",
    "edge", "mozilla", "google", "amazon", "microsoft", "apple",
]

_TLDS = ("com", "net", "org", "biz", "info", "ru", "cc", "co", "io", "xyz")


def benign_qname(rng: random.Random) -> str:
    """ordinary looking names: brands, telemetry, a few numeric shards."""
    kind = rng.choice(["brand", "service", "shard", "cdn_like", "deep", "snowflake"])
    if kind == "brand":
        return f"{rng.choice(_WORDS)}.{rng.choice(_TLDS)}"
    if kind == "service":
        return f"{rng.choice(_WORDS)}.{rng.choice(_WORDS)}.{rng.choice(_TLDS)}"
    if kind == "shard":
        return f"part-{rng.randint(0, 99):04d}.{rng.choice(_WORDS)}.net"
    if kind == "cdn_like":
        # looks spicy but sits under a real CDN parent we allowlist in rules
        token = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(13))
        return f"{token}.cloudfront.net"
    if kind == "snowflake":
        # discord-style numeric ids — random digits, not DGA
        return f"{rng.randint(10**17, 10**18 - 1)}.discordsays.com"
    depth = rng.randint(3, 5)
    labels = [rng.choice(_WORDS) for _ in range(depth)]
    return ".".join(labels) + "." + rng.choice(("com", "net", "org"))


def dga_qname(rng: random.Random, family: str | None = None) -> str:
    family = family or rng.choice(
        ["conficker", "cryptolocker", "necurs", "banjori", "tinba", "ramdo"]
    )
    label = {
        "conficker": _conficker,
        "cryptolocker": _cryptolocker,
        "necurs": _necurs,
        "banjori": _banjori,
        "tinba": _tinba,
        "ramdo": _ramdo,
    }[family](rng)
    return f"{label}.{rng.choice(_TLDS)}"


def tunnel_qname(rng: random.Random, tool: str = "dnscat2") -> str:
    """long stuffed names like dnscat2 / iodine carry over DNS."""
    parent = rng.choice(("tunnel.example.com", "c2.evil.test", "exfil.lab.invalid"))
    if tool == "iodine":
        # iodine packs base32-ish chunks into many short labels
        chunks = [
            "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(rng.randint(20, 40)))
            for _ in range(rng.randint(3, 5))
        ]
        return ".".join(chunks) + "." + parent
    # dnscat2-style: hex blobs
    chunks = [
        "".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(16, 32)))
        for _ in range(rng.randint(3, 6))
    ]
    return ".".join(chunks) + "." + parent


def _conficker(rng: random.Random) -> str:
    # classic conficker: 8-11 random lowercase letters from a date seed
    length = rng.randint(8, 11)
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(length))


def _cryptolocker(rng: random.Random) -> str:
    length = rng.randint(12, 18)
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(length))


def _necurs(rng: random.Random) -> str:
    # necurs mixes letters with a wider alphabet and variable length
    length = rng.randint(7, 21)
    alphabet = string.ascii_lowercase
    return "".join(rng.choice(alphabet) for _ in range(length))


def _banjori(rng: random.Random) -> str:
    # banjori-like: seed string mutated into a long alphanumeric label
    seed = f"{rng.randint(0, 10_000_000)}-{rng.random()}"
    digest = hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest()
    return digest[: rng.randint(12, 16)]


def _tinba(rng: random.Random) -> str:
    length = rng.randint(8, 15)
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(length))


def _ramdo(rng: random.Random) -> str:
    # ramdo often produced 16-char letter labels
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(16))
