"""Dependency-free encoder/decoder for v2ray/xray geoip .dat, plus iptoasn loader.

Schema (GeoIPList):
    CIDR      { bytes ip = 1; uint32 prefix = 2 }
    GeoIP     { string country_code = 1; repeated CIDR cidr = 2 }
    GeoIPList { repeated GeoIP entry = 1 }
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import os
import urllib.request

from .geosite import _iter_fields, _ld, _tag, _varint

IPTOASN_V4 = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"  # PDDL

Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def build_dat(entries: dict[str, list[Net]]) -> bytes:
    out = bytearray()
    for code, nets in entries.items():
        body = _ld(1, code.upper().encode())
        for n in nets:
            body += _ld(2, _ld(1, n.network_address.packed) + _tag(2, 0)
                        + _varint(n.prefixlen))
        out += _ld(1, body)
    return bytes(out)


def parse_dat(blob: bytes) -> dict[str, list[Net]]:
    out: dict[str, list[Net]] = {}
    for f, entry in _iter_fields(blob):
        if f != 1:
            continue
        code, nets = "", []
        for g, data in _iter_fields(entry):
            if g == 1:
                code = data.decode()
            elif g == 2:
                ip, plen = b"", 0
                for h, v in _iter_fields(data):
                    if h == 1:
                        ip = v
                    elif h == 2:
                        plen = v
                nets.append(ipaddress.ip_network((ipaddress.ip_address(ip), plen)))
        out.setdefault(code, []).extend(nets)
    return out


def collapse(nets) -> list[Net]:
    v4 = ipaddress.collapse_addresses(n for n in nets if n.version == 4)
    v6 = ipaddress.collapse_addresses(n for n in nets if n.version == 6)
    return [*v4, *v6]


def contains(nets: list[Net], ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return any(a in n for n in nets if n.version == a.version)


def nets_from_text(txt: str) -> list[Net]:
    out = []
    for line in txt.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            try:
                out.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    return out


def _download(url: str, retries: int = 3) -> bytes:
    last: Exception | None = None
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "commensal-builder"})
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 - retry any network error
            last = e
    raise OSError(f"failed to download {url}: {last}")


def iptoasn_v4() -> list[tuple[int, int, str, str, str]]:
    """[(start, end, asn, country, holder)] as integer ranges.
    IPTOASN_FILE (local path) overrides the download."""
    path = os.environ.get("IPTOASN_FILE")
    data = open(path, "rb").read() if path else _download(IPTOASN_V4)
    raw = gzip.decompress(data).decode("utf-8", "replace")
    rows = []
    for line in raw.splitlines():
        a, b, asn, cc, desc = (line.split("\t") + [""] * 5)[:5]
        if asn != "0":
            rows.append((int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b)),
                         asn, cc, desc))
    return rows


RIPESTAT = "https://stat.ripe.net/data/"


def _ripe(endpoint: str, resource: str) -> dict:
    url = f"{RIPESTAT}{endpoint}/data.json?resource={resource}&sourceapp=commensal-builder"
    return json.loads(_download(url))["data"]


def announced(asn: str) -> list[Net]:
    """Prefixes currently announced by an AS (RIPEstat)."""
    return [ipaddress.ip_network(p["prefix"], strict=False)
            for p in _ripe("announced-prefixes", f"AS{asn}").get("prefixes", [])]


def origin_asn(ip: str) -> int | None:
    asns = _ripe("prefix-overview", ip).get("asns") or []
    return asns[0].get("asn") if asns else None


def range_nets(start: int, end: int) -> list[Net]:
    return list(ipaddress.summarize_address_range(ipaddress.IPv4Address(start),
                                                  ipaddress.IPv4Address(end)))
