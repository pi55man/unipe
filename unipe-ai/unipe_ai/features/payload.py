"""metadata-only parsing of the 64-byte payload sample exported by the ebpf side.

nothing here decrypts anything. for tls and quic we only look at the cleartext
handshake header bytes that sit in front of the encrypted body.
"""

from __future__ import annotations

import hashlib
from typing import Any

from unipe_ai.util import digit_ratio, shannon_entropy

DNS_HEADER_LEN = 12
MAX_LABEL_LEN = 63

# record types that are unusual for normal browsing and common in tunnels
TUNNEL_RECORD_TYPES = {10: "NULL", 16: "TXT", 255: "ANY"}

DNS_DEFAULTS: dict[str, Any] = {
    "dns_qname": "",
    "dns_qname_len": 0,
    "dns_label_count": 0,
    "dns_max_label_len": 0,
    "dns_entropy": 0.0,
    "dns_digit_ratio": 0.0,
    "dns_qtype": 0,
    "dns_qtype_name": "",
    "dns_sample_truncated": False,
    "dns_parsed": False,
}

TLS_DEFAULTS: dict[str, Any] = {
    "tls_is_handshake": False,
    "tls_is_client_hello": False,
    "tls_record_version": 0,
    "tls_client_version": 0,
    "tls_prefix_fingerprint": "",
}

QUIC_DEFAULTS: dict[str, Any] = {
    "quic_is_long_header": False,
    "quic_is_initial": False,
    "quic_version": 0,
}


def unhex(payload: str) -> bytes:
    if not payload:
        return b""
    try:
        return bytes.fromhex(payload)
    except ValueError:
        return b""


def parse_dns(payload: str) -> dict[str, Any]:
    """pull the query name and record type out of a dns message sample."""
    out = dict(DNS_DEFAULTS)
    data = unhex(payload)
    if len(data) <= DNS_HEADER_LEN:
        return out

    labels: list[str] = []
    truncated = False
    i = DNS_HEADER_LEN
    while i < len(data):
        length = data[i]
        i += 1
        if length == 0:
            break
        if length > MAX_LABEL_LEN:
            # not a length byte, so this is not a name we can trust
            truncated = True
            break
        if i + length > len(data):
            # the sample cut the name short; keep what we can see
            labels.append(_ascii(data[i:]))
            truncated = True
            break
        labels.append(_ascii(data[i : i + length]))
        i += length
    else:
        truncated = True

    if not labels:
        return out

    qname = ".".join(label for label in labels if label)
    if not qname:
        return out

    qtype = 0
    if not truncated and i + 2 <= len(data):
        qtype = int.from_bytes(data[i : i + 2], "big")

    joined = qname.replace(".", "")
    out.update(
        {
            "dns_qname": qname,
            "dns_qname_len": len(qname),
            "dns_label_count": len(labels),
            "dns_max_label_len": max(len(label) for label in labels),
            "dns_entropy": shannon_entropy(joined),
            "dns_digit_ratio": digit_ratio(joined),
            "dns_qtype": qtype,
            "dns_qtype_name": TUNNEL_RECORD_TYPES.get(qtype, ""),
            "dns_sample_truncated": truncated,
            "dns_parsed": True,
        }
    )
    return out


def parse_tls(payload: str) -> dict[str, Any]:
    """read the cleartext tls record and clienthello header, nothing else.

    the 64-byte sample stops inside the clienthello random, so this is a prefix
    fingerprint, not a full ja3/ja4 (those need the cipher and extension lists).
    """
    out = dict(TLS_DEFAULTS)
    data = unhex(payload)
    if len(data) < 11 or data[0] != 0x16:
        return out

    out["tls_is_handshake"] = True
    out["tls_record_version"] = int.from_bytes(data[1:3], "big")
    if data[5] != 0x01:
        return out

    out["tls_is_client_hello"] = True
    client_version = int.from_bytes(data[9:11], "big")
    out["tls_client_version"] = client_version
    seed = f"{out['tls_record_version']:04x},{client_version:04x}"
    out["tls_prefix_fingerprint"] = hashlib.sha256(seed.encode()).hexdigest()[:16]
    return out


def parse_quic(payload: str) -> dict[str, Any]:
    """quic long header is cleartext: first byte flags plus a 4-byte version."""
    out = dict(QUIC_DEFAULTS)
    data = unhex(payload)
    if len(data) < 5:
        return out

    first = data[0]
    if not first & 0x80:
        return out

    out["quic_is_long_header"] = True
    version = int.from_bytes(data[1:5], "big")
    out["quic_version"] = version
    # packet type bits are 4-5; 0 means Initial in quic v1
    out["quic_is_initial"] = version != 0 and ((first & 0x30) >> 4) == 0
    return out


def _ascii(raw: bytes) -> str:
    return raw.decode("ascii", "ignore")
