"""Dependency-free encoder/decoder for v2ray/xray geosite .dat.

Schema (GeoSiteList):
    Domain      { Type type = 1; string value = 2 }   Type: RootDomain = 2
    GeoSite     { string country_code = 1; repeated Domain domain = 2 }
    GeoSiteList { repeated GeoSite entry = 1 }
RootDomain = suffix match (domain + subdomains). country_code stored uppercase;
xray upper-cases the tag on `ext:file.dat:<tag>` lookup.
"""
from __future__ import annotations

_ROOT_DOMAIN = 2


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _ld(field: int, data: bytes) -> bytes:
    return _tag(field, 2) + _varint(len(data)) + data


def _domain_msg(value: str) -> bytes:
    return _tag(1, 0) + _varint(_ROOT_DOMAIN) + _ld(2, value.encode("utf-8"))


def _geosite_msg(code: str, domains: list[str]) -> bytes:
    parts = [_ld(1, code.encode("utf-8"))]
    for d in domains:
        parts.append(_ld(2, _domain_msg(d)))
    return b"".join(parts)


def build_dat(categories: dict[str, list[str]]) -> bytes:
    """{code: [domains]} -> serialized GeoSiteList (domains sorted for determinism)."""
    out = bytearray()
    for code, domains in categories.items():
        out += _ld(1, _geosite_msg(code.upper(), sorted(domains)))
    return bytes(out)


def parse_dat(blob: bytes) -> dict[str, set[str]]:
    """Decode .dat back to {CODE: {domains}} (round-trip self-check)."""
    out: dict[str, set[str]] = {}
    for field, data in _iter_fields(blob):
        if field != 1:
            continue
        code, domains = _parse_geosite(data)
        out.setdefault(code, set()).update(domains)
    return out


def _parse_geosite(blob: bytes) -> tuple[str, set[str]]:
    code = ""
    domains: set[str] = set()
    for field, data in _iter_fields(blob):
        if field == 1:
            code = data.decode("utf-8", "replace")
        elif field == 2:
            domains.add(_parse_domain(data))
    return code, domains


def _parse_domain(blob: bytes) -> str:
    for field, data in _iter_fields(blob):
        if field == 2:
            return data.decode("utf-8", "replace")
    return ""


def _iter_fields(blob: bytes):
    i, n = 0, len(blob)
    while i < n:
        key, i = _read_varint(blob, i)
        field, wire = key >> 3, key & 0x7
        if wire == 2:
            length, i = _read_varint(blob, i)
            yield field, blob[i:i + length]
            i += length
        elif wire == 0:
            val, i = _read_varint(blob, i)
            yield field, val
        else:
            raise ValueError(f"unsupported wire type {wire}")


def _read_varint(blob: bytes, i: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        b = blob[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7
