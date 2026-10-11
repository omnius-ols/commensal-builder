"""mobile-mini.dat: compact geosite for memory-limited clients.

Upstream categories are copied verbatim; compact categories are built here.
Independent of tutela.dat: a failure here never blocks the main build.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from . import allowlist, geosite
from .config import SOURCES
from .fetch import FetchError, fetch
from .normalize import normalize_text

OUT_NAME = "mobile-mini.dat"
UPSTREAM = ("https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/"
            "download/geosite.dat")

# Copied byte-for-byte (keeps full/keyword/regex rule types).
COPY = ("PRIVATE", "CATEGORY-RU", "CATEGORY-ADS")

# Upstream codes whose "@ads" entries form ru-tracking.
TRACKING_FROM = ("YANDEX", "SBER", "SBERBANK", "OZON", "WILDBERRIES", "AVITO",
                 "KINOPOISK", "2GIS", "MTS", "MEGAFON", "BEELINE")
BAN_FROM = ("MAILRU-GROUP", "MAILRU", "VK", "OK", "DZEN", "KASPERSKY")
BAN_EXTRA = {"kas-labs.com", "securelist.com", "securelist.ru", "kaspersky.net",
             "max.ru", "oneme.ru"}
# Root domains only: a subdomain of a banned root cannot be excepted.
BAN_EXCEPT = {"rustore.ru", "bizmrg.com", "vkcs.cloud", "vkcloud.ru",
              "vkcloud-storage.ru", "boosty.to", "donationalerts.com",
              "cybersport.ru", "gb.ru", "geekbrains.ru", "algoritmika.org",
              "algoritmika.su"}

COUNTERS = "https://easylist-downloads.adblockplus.org/cntblock.txt"
# (url, optional)
THREAT = [
    ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"
     "tif.medium-onlydomains.txt", False),
    ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/"
     "fake-onlydomains.txt", True),
    ("https://phishing.army/download/phishing_army_blocklist.txt", True),
    ("https://urlhaus.abuse.ch/downloads/hostfile/", True),
]
RU_ZONES = (".ru", ".su", ".xn--p1ai", ".xn--d1acj3b", ".moscow", ".xn--80adxhks")

IP_DETECT = {
    "ipify.org", "ipinfo.io", "ip-api.com", "ip-api.io", "ipapi.co", "ipapi.com",
    "ipapi.is", "ipwho.is", "ipwhois.app", "ifconfig.me", "ifconfig.co",
    "ifconfig.io", "icanhazip.com", "checkip.amazonaws.com", "checkip.dyndns.org",
    "ident.me", "myip.com", "ip.sb", "ip.nf", "wtfismyip.com", "ipecho.net",
    "db-ip.com", "ipgeolocation.io", "ip2location.io", "iplocation.net",
    "ipdata.co", "geojs.io", "freeipapi.com", "ipregistry.co", "seeip.org",
    "myexternalip.com", "whatismyipaddress.com", "geoip.maxmind.com",
    "geolocation-db.com", "2ip.ru", "2ip.io", "2ip.me", "myip.ru", "whoer.net",
    "ipv4-internet.yandex.net", "ipv6-internet.yandex.net",
}

# Must stay reachable: entries equal to or parent of these are dropped.
KEEP = {
    "gosuslugi.ru", "esia.gosuslugi.ru", "gu-st.ru", "mos.ru", "nalog.gov.ru",
    "nalog.ru", "sfr.gov.ru", "sberbank.ru", "online.sberbank.ru", "sber.ru",
    "id.sber.ru", "sberbank.com", "tbank.ru", "tinkoff.ru", "alfabank.ru",
    "vtb.ru", "online.vtb.ru", "gazprombank.ru", "raiffeisen.ru", "psbank.ru",
    "rshb.ru", "sovcombank.ru", "pochtabank.ru", "mtsbank.ru", "nspk.ru",
    "sbp.nspk.ru", "qr.nspk.ru", "mir-pay.ru", "ozon.ru", "ozone.ru",
    "wildberries.ru", "wb.ru", "wbbasket.ru", "wbstatic.net", "avito.ru",
    "avito.st", "megamarket.ru", "market.yandex.ru", "lamoda.ru", "dns-shop.ru",
    "mvideo.ru", "aliexpress.ru", "yandex.ru", "ya.ru", "yandex.net",
    "yastatic.net", "yandex.com", "avatars.mds.yandex.net", "music.yandex.ru",
    "taxi.yandex.ru", "go.yandex", "maps.yandex.ru", "disk.yandex.ru",
    "mail.yandex.ru", "passport.yandex.ru", "kinopoisk.ru",
    "startup.mobile.yandex.net", "mobile.yandex.net", "2gis.ru", "hh.ru",
    "rzd.ru", "aeroflot.ru", "tutu.ru",
} | BAN_EXCEPT

MIN = {"ads-ru": 1_000, "ru-metrics": 200, "ru-tracking": 50, "ru-ban": 200,
       "ip-detect": 20, "threat-ru": 500}
MUST_BLOCK = {"ru-ban": ("vk.com", "mail.ru", "max.ru", "kaspersky.com"),
              "ru-metrics": ("mc.yandex.ru",), "ip-detect": ("2ip.ru",)}


def _covered(d: str, s: set[str]) -> bool:
    p = d.split(".")
    return any(".".join(p[i:]) in s for i in range(len(p)))


def _blocks_keep(entry: str) -> bool:
    return any(k == entry or k.endswith("." + entry) for k in KEEP)


def _entries(blob: bytes) -> dict[str, bytes]:
    out = {}
    for field, data in geosite._iter_fields(blob):
        if field == 1:
            code = next((d.decode("utf-8", "replace")
                         for f, d in geosite._iter_fields(data) if f == 1), "")
            out[code.upper()] = data
    return out


def _domains(entry: bytes, attr: str | None = None) -> set[str]:
    """Root/full values of a raw GeoSite entry; keyword/regex are skipped."""
    out = set()
    for field, data in geosite._iter_fields(entry):
        if field != 2:
            continue
        t, v, attrs = 0, "", set()
        for f, d in geosite._iter_fields(data):
            if f == 1:
                t = d
            elif f == 2:
                v = d.decode("utf-8", "replace").lower()
            elif f == 3:
                attrs |= {d2.decode("utf-8", "replace")
                          for f2, d2 in geosite._iter_fields(d) if f2 == 1}
        if t in (2, 3) and v and (attr is None or attr in attrs):
            out.add(v)
    return out


def _get(url: str, optional: bool) -> set[str]:
    try:
        return normalize_text(fetch(url))
    except FetchError as e:
        if optional:
            print(f"[skip] {url}: {e}")
            return set()
        raise


def build() -> tuple[bytes, dict[str, int]]:
    up = _entries(fetch_bytes(UPSTREAM))
    missing = [c for c in COPY + BAN_FROM if c not in up]
    if missing:
        raise RuntimeError(f"upstream codes missing: {missing}")

    cats: dict[str, set[str]] = {}
    cats["ads-ru"] = set().union(*(_get(s.url, s.optional) for s in SOURCES
                                   if s.category == "ads-ru"))
    cats["ru-metrics"] = _get(COUNTERS, False)
    vendors = [c for c in up if c.endswith("-RU")] + [c for c in TRACKING_FROM if c in up]
    cats["ru-tracking"] = set().union(*(_domains(up[c], "ads") for c in vendors))
    ban = set().union(*(_domains(up[c]) for c in BAN_FROM)) | BAN_EXTRA
    cats["ru-ban"] = {d for d in ban if not _covered(d, BAN_EXCEPT)}
    cats["ip-detect"] = set(IP_DETECT)
    threat = set().union(*(_get(u, o) for u, o in THREAT))
    cats["threat-ru"] = {d for d in threat if d.endswith(RU_ZONES)}

    for c in cats:
        s = allowlist.strip_allowed(cats[c])
        dropped = sorted(d for d in s if _blocks_keep(d))
        cats[c] = s - set(dropped)
        if dropped:
            print(f"[keep] {c}: dropped {dropped}")

    blob = b"".join(geosite._ld(1, up[c]) for c in COPY)
    blob += geosite.build_dat({c: sorted(v) for c, v in cats.items()})
    return blob, {c: len(v) for c, v in cats.items()}


def fetch_bytes(url: str) -> bytes:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "commensal-builder"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read()


def check(blob: bytes) -> list[str]:
    errs = []
    parsed = {c.lower(): d for c, d in geosite.parse_dat(blob).items()}
    for c in (x.lower() for x in COPY):
        if not parsed.get(c):
            errs.append(f"{c}: empty")
    for c, n in MIN.items():
        if len(parsed.get(c, ())) < n:
            errs.append(f"{c}: {len(parsed.get(c, ()))} < {n}")
    for c, doms in MUST_BLOCK.items():
        for d in doms:
            if not _covered(d, parsed.get(c, set())):
                errs.append(f"{c}: {d} not blocked")
    ours = set().union(*(parsed.get(c, set()) for c in MIN))
    for k in sorted(KEEP):
        if _covered(k, ours):
            errs.append(f"keep: {k} blocked")
    return errs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="builder.mobile")
    ap.add_argument("--out", default="dist", type=Path)
    args = ap.parse_args(argv)
    try:
        blob, counts = build()
    except (FetchError, RuntimeError, OSError) as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        return 2
    print(f"[mobile] {counts}")
    errs = check(blob)
    if errs:
        for e in errs:
            print(f"[gate] {e}", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / OUT_NAME).write_bytes(blob)
    digest = hashlib.sha256(blob).hexdigest()
    (args.out / f"{OUT_NAME}.sha256sum").write_text(f"{digest}  {OUT_NAME}\n",
                                                    encoding="utf-8")
    print(f"[mobile] {OUT_NAME}: {len(blob)} bytes, sha256 {digest[:16]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
