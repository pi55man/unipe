"""metadata-only parsing of the payload sample exported by the ebpf side.

nothing here decrypts anything. the exporter only ever samples dns messages and
tls/quic handshake records, and a handshake is cleartext by definition: it is
the negotiation that happens before any key is agreed. application data is
never captured, so there is nothing here that could be decrypted even in
principle.
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

TLS_RECORD_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
HANDSHAKE_SERVER_HELLO = 0x02

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_ALPN = 0x0010

# GREASE placeholders (RFC 8701) are random by design and must be dropped
# before fingerprinting, or the same client hashes differently every time.
GREASE = frozenset((n << 12) | 0x0A00 | (n << 4) | 0x0A for n in range(16))

TLS_DEFAULTS: dict[str, Any] = {
    "tls_is_handshake": False,
    "tls_is_client_hello": False,
    "tls_is_server_hello": False,
    "tls_record_version": 0,
    "tls_client_version": 0,
    "tls_server_version": 0,
    "tls_sample_complete": False,
    "tls_ciphers": (),
    "tls_extensions": (),
    "tls_curves": (),
    "tls_sni": "",
    "tls_alpn": (),
    "tls_ja3": "",
    "tls_ja3_hash": "",
    "tls_ja3s": "",
    "tls_ja3s_hash": "",
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
    """parse a TLS handshake record and compute its JA3 / JA3S fingerprint."""
    out = dict(TLS_DEFAULTS)
    data = unhex(payload)
    if len(data) < 6 or data[0] != TLS_RECORD_HANDSHAKE:
        return out

    out["tls_is_handshake"] = True
    out["tls_record_version"] = int.from_bytes(data[1:3], "big")
    record_len = int.from_bytes(data[3:5], "big")
    # fingerprinting half a hello would produce a hash that matches nothing,
    # so record whether the whole record made it into the sample
    out["tls_sample_complete"] = len(data) >= 5 + record_len

    handshake_type = data[5]
    if handshake_type == HANDSHAKE_CLIENT_HELLO:
        _read_client_hello(data, out)
    elif handshake_type == HANDSHAKE_SERVER_HELLO:
        _read_server_hello(data, out)
    return out


def _read_client_hello(data: bytes, out: dict[str, Any]) -> None:
    out["tls_is_client_hello"] = True
    # 5 bytes of record header, then 4 of handshake header
    pos = 9
    if pos + 2 > len(data):
        return
    client_version = int.from_bytes(data[pos : pos + 2], "big")
    out["tls_client_version"] = client_version
    pos += 2 + 32  # version, then the 32-byte random

    pos = _skip_vector(data, pos, 1)  # session id
    ciphers, pos = _read_u16_vector(data, pos, 2)
    pos = _skip_vector(data, pos, 1)  # compression methods
    out["tls_ciphers"] = ciphers

    extensions, curves, point_formats, sni, alpn = _read_extensions(data, pos)
    out["tls_extensions"] = extensions
    out["tls_curves"] = curves
    out["tls_sni"] = sni
    out["tls_alpn"] = alpn

    if out["tls_sample_complete"]:
        ja3 = ",".join(
            [
                str(client_version),
                _dashed(ciphers),
                _dashed(extensions),
                _dashed(curves),
                # point formats are single bytes, so no GREASE to strip
                "-".join(str(v) for v in point_formats),
            ]
        )
        out["tls_ja3"] = ja3
        out["tls_ja3_hash"] = _md5(ja3)


def _read_server_hello(data: bytes, out: dict[str, Any]) -> None:
    out["tls_is_server_hello"] = True
    pos = 9
    if pos + 2 > len(data):
        return
    server_version = int.from_bytes(data[pos : pos + 2], "big")
    out["tls_server_version"] = server_version
    pos += 2 + 32

    pos = _skip_vector(data, pos, 1)  # session id
    if pos < 0 or pos + 3 > len(data):
        return
    cipher = int.from_bytes(data[pos : pos + 2], "big")
    pos += 3  # the chosen cipher, then the chosen compression method

    extensions, _, _, _, _ = _read_extensions(data, pos)
    out["tls_ciphers"] = (cipher,)
    out["tls_extensions"] = extensions

    if out["tls_sample_complete"]:
        ja3s = f"{server_version},{cipher},{_dashed(extensions)}"
        out["tls_ja3s"] = ja3s
        out["tls_ja3s_hash"] = _md5(ja3s)


def _read_extensions(
    data: bytes,
    pos: int,
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...], str, tuple[str, ...]]:
    extensions: list[int] = []
    curves: tuple[int, ...] = ()
    point_formats: tuple[int, ...] = ()
    alpn: tuple[str, ...] = ()
    sni = ""

    if pos < 0 or pos + 2 > len(data):
        return (), curves, point_formats, sni, alpn

    total = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    end = min(pos + total, len(data))
    while pos + 4 <= end:
        ext_type = int.from_bytes(data[pos : pos + 2], "big")
        ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
        pos += 4
        if pos + ext_len > end:
            break
        body = data[pos : pos + ext_len]
        pos += ext_len
        extensions.append(ext_type)

        if ext_type == EXT_SUPPORTED_GROUPS:
            curves, _ = _read_u16_vector(body, 0, 2)
        elif ext_type == EXT_EC_POINT_FORMATS:
            point_formats = tuple(body[1:])
        elif ext_type == EXT_SERVER_NAME:
            sni = _read_sni(body)
        elif ext_type == EXT_ALPN:
            alpn = _read_alpn(body)

    return tuple(extensions), curves, point_formats, sni, alpn


def _read_sni(body: bytes) -> str:
    # list length (2), entry type (1), name length (2), then the name
    if len(body) < 5:
        return ""
    name_len = int.from_bytes(body[3:5], "big")
    if 5 + name_len > len(body):
        return ""
    return _ascii(body[5 : 5 + name_len])


def _read_alpn(body: bytes) -> tuple[str, ...]:
    protocols: list[str] = []
    pos = 2  # skip the list length
    while pos < len(body):
        size = body[pos]
        pos += 1
        if pos + size > len(body):
            break
        protocols.append(_ascii(body[pos : pos + size]))
        pos += size
    return tuple(protocols)


def _skip_vector(data: bytes, pos: int, len_bytes: int) -> int:
    """step over a length-prefixed block; -1 means the sample ran out."""
    if pos < 0 or pos + len_bytes > len(data):
        return -1
    size = int.from_bytes(data[pos : pos + len_bytes], "big")
    pos += len_bytes + size
    return pos if pos <= len(data) else -1


def _read_u16_vector(data: bytes, pos: int, len_bytes: int) -> tuple[tuple[int, ...], int]:
    if pos < 0 or pos + len_bytes > len(data):
        return (), -1
    size = int.from_bytes(data[pos : pos + len_bytes], "big")
    pos += len_bytes
    if pos + size > len(data):
        return (), -1
    values = tuple(
        int.from_bytes(data[i : i + 2], "big") for i in range(pos, pos + size - 1, 2)
    )
    return values, pos + size


def _dashed(values: tuple[int, ...]) -> str:
    return "-".join(str(v) for v in values if v not in GREASE)


def _md5(text: str) -> str:
    # md5 is what the ja3 spec calls for; it is an identifier, not security
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()


# v1 (RFC 9000), v2 (RFC 9369), and the draft versions still seen in the wild.
# checking against a list keeps random UDP from being read as a QUIC Initial.
KNOWN_QUIC_VERSIONS = frozenset(
    [0x00000001, 0x6B3343CF] + [0xFF000000 | draft for draft in range(20, 35)]
)


def parse_quic(payload: str) -> dict[str, Any]:
    """quic long header is cleartext: first byte flags plus a 4-byte version."""
    out = dict(QUIC_DEFAULTS)
    data = unhex(payload)
    if len(data) < 5:
        return out

    # bit 7 is the long-header flag and bit 6 is the "fixed bit", which every
    # real QUIC packet sets. requiring both lets us identify QUIC on any port
    # instead of only where we already expect it.
    first = data[0]
    if first & 0xC0 != 0xC0:
        return out

    out["quic_is_long_header"] = True
    version = int.from_bytes(data[1:5], "big")
    out["quic_version"] = version
    # packet type bits are 4-5; 0 means Initial in quic v1
    out["quic_is_initial"] = version in KNOWN_QUIC_VERSIONS and ((first & 0x30) >> 4) == 0
    return out


def _ascii(raw: bytes) -> str:
    return raw.decode("ascii", "ignore")
