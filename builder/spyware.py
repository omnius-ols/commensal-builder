"""laughing-man.dat + laughing-man-ip.dat: spyware and stalkerware infrastructure.

Sources, fetched on every build:
- mvt-project/mvt-indicators (MIT): index of STIX2 indicator files; the files are
  published by Amnesty International, AssoEchap and others (CC BY 4.0).
- AssoEchap/stalkerware-indicators network.csv (CC BY 4.0).
- vendor sites (curated).
An indicator is blocked as the exact host it names, never its parent domain.
Indicators on shared platforms are blocked as full: hosts; IPs on shared
infrastructure (CDNs, big clouds, shared web hosting) are dropped.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import io
import ipaddress
import json
import re
import sys
import time
from pathlib import Path

from . import geoip, geosite, protect
from .fetch import FetchError, fetch

OUT, OUT_IP = "laughing-man.dat", "laughing-man-ip.dat"
TAG = "SPYWARE"
INDEX = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"
# AssoEchap (CC BY 4.0): stalkerware websites and C2 (type,indicator,app).
ECHAP = ("https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/"
         "generated/network.csv")
# Sources whose last commit is older than this produce a warning (not a failure).
STALE_DAYS = 90
STALE_REPOS = ("mvt-project/mvt-indicators", "AssoEchap/stalkerware-indicators")

VENDORS = {
    "nsogroup.com", "rcslab.it", "mementolabs.com", "hackingteam.com", "finfisher.com",
    "cellebrite.com", "magnetforensics.com", "grayshift.com", "msab.com", "elcomsoft.com",
    "elcomsoft.ru", "belkasoft.com", "oxygenforensics.com", "oxygen-forensic.com",
}
# Indicators under these registrable domains are blocked as exact hosts (full:).
SHARED = {
    "firebaseio.com", "firebaseapp.com", "web.app", "appspot.com", "googleapis.com",
    "amazonaws.com", "cloudfront.net", "herokuapp.com", "azurewebsites.net", "github.io",
    "githubusercontent.com", "blogspot.com", "000webhostapp.com", "duckdns.org", "no-ip.org",
    "ddns.net", "ngrok.io", "ngrok-free.app", "netlify.app", "vercel.app", "pages.dev",
    "workers.dev", "glitch.me", "repl.co", "wixsite.com", "weebly.com", "wordpress.com",
    "google.com", "goo.gl", "bit.ly", "t.me", "telegram.org", "dropbox.com", "onrender.com",
    "fly.dev", "back4app.io", "parseapp.com", "azureedge.net", "windows.net", "cloudapp.net",
    "digitaloceanspaces.com", "ondigitalocean.app", "b-cdn.net", "akamaized.net",
    "fastly.net", "r2.dev", "supabase.co", "pythonanywhere.com", "sendgrid.net",
    "mailgun.org", "x.com", "twitter.com", "facebook.com", "youtube.com",
}
SLD2 = {"co.uk", "com.br", "com.mx", "com.ar", "com.tr", "co.in", "co.za", "com.au",
        "co.il", "com.ua"}
# Platform sites themselves are never blocked whole (URL paths are not routable).
POPULAR = {
    "github.com", "microsoft.com", "google.com", "apple.com", "icloud.com", "amazon.com",
    "facebook.com", "instagram.com", "whatsapp.com", "telegram.org", "t.me", "youtube.com",
    "twitter.com", "x.com", "dropbox.com", "mega.nz", "mediafire.com", "wikipedia.org",
    "cloudflare.com", "linkedin.com", "yahoo.com", "bing.com", "live.com", "outlook.com",
    "office.com", "gmail.com", "android.com", "gstatic.com", "googleusercontent.com",
    "play.google.com", "apkpure.com", "uptodown.com", "apkmirror.com", "samsung.com",
    "xiaomi.com",
}
# IPs announced by these ASes host unrelated sites (or are recycled quickly).
SHARED_ASN = {13335, 15169, 212238, 14618, 16509, 8075, 20940, 54113, 46606, 47583,
              398101, 40092}

MIN_RULES, MIN_IPS = 4000, 30
MUST = ("nsogroup.com", "cellebrite.com", "life360.com", "family.microsoft.com")
MUST_NOT = ("microsoft.com", "account.microsoft.com", "login.live.com", "google.com",
            "github.com", "apple.com", "icloud.com", "firebaseio.com", "amazonaws.com",
            "cloudflare.com", "whatsapp.com", "telegram.org")
_HOST = re.compile(r"[a-z0-9.-]+\.[a-z0-9-]{2,}")
_PAT = re.compile(r"(domain-name|url|ipv4-addr):value\s*=\s*'([^']+)'")


def _reg(d: str) -> str:
    p = d.split(".")
    return ".".join(p[-3:]) if len(p) >= 3 and ".".join(p[-2:]) in SLD2 else ".".join(p[-2:])


def _norm(h: str) -> str | None:
    h = re.sub(r"^[a-z]+://", "", h.strip().lower().strip(".")).split("/")[0].split(":")[0]
    h = h.removeprefix("www.")
    return h if _HOST.fullmatch(h) else None


def _index() -> list[str]:
    """Raw URLs of STIX2 files listed in the MVT index (minimal YAML scan)."""
    urls = []
    for block in re.split(r"\n\s*-\s*\n", fetch(INDEX)):
        g = {k: v for k, v in re.findall(r"^\s+(owner|repo|branch|path):\s*(\S+)\s*$",
                                         block, re.M)}
        if len(g) == 4:
            urls.append("https://raw.githubusercontent.com/"
                        f"{g['owner']}/{g['repo']}/{g['branch']}/{g['path']}")
    return urls


def build() -> tuple[set[tuple[int, str]], set[str]]:
    rules: set[tuple[int, str]] = {(2, d) for d in VENDORS}  # 2 root, 3 full
    ips: set[str] = set()
    urls = _index()
    if len(urls) < 10:
        raise RuntimeError(f"MVT index: only {len(urls)} files")
    raw: list[str] = []
    for u in urls:
        try:
            objs = json.loads(fetch(u)).get("objects", [])
        except (FetchError, ValueError) as e:
            print(f"[spyware] skip {u}: {e}", file=sys.stderr)
            continue
        raw += [v for o in objs for _, v in _PAT.findall(o.get("pattern", ""))]
    raw += [r[1] for r in csv.reader(io.StringIO(fetch(ECHAP)))
            if len(r) > 1 and r[0] in ("domain", "ipv4", "ipv6")]
    for v in raw:
        try:
            ips.add(str(ipaddress.ip_address(v.strip())))
            continue
        except ValueError:
            pass
        h = _norm(v)
        if not h:
            continue
        r = _reg(h)
        if h in POPULAR or (h == r and r in POPULAR):
            continue
        rules.add((3 if r in SHARED else 2, h))
    return rules, ips


def filter_ips(ips: set[str]) -> list[geoip.Net]:
    with concurrent.futures.ThreadPoolExecutor(6) as ex:
        asns = dict(zip(sorted(ips), ex.map(geoip.origin_asn, sorted(ips))))
    keep = [ipaddress.ip_network(ip) for ip, a in asns.items() if a not in SHARED_ASN]
    print(f"[spyware] ips {len(ips)}, dropped on shared infrastructure "
          f"{len(ips) - len(keep)}")
    return geoip.collapse(keep)


def warn_stale() -> None:
    for repo in STALE_REPOS:
        try:
            c = json.loads(fetch(f"https://api.github.com/repos/{repo}/commits?per_page=1"))
            ts = time.mktime(time.strptime(c[0]["commit"]["committer"]["date"],
                                           "%Y-%m-%dT%H:%M:%SZ"))
            age = (time.time() - ts) / 86400
            if age > STALE_DAYS:
                print(f"[spyware] WARNING: {repo} last commit {age:.0f} days ago",
                      file=sys.stderr)
        except (FetchError, ValueError, KeyError, IndexError) as e:
            print(f"[spyware] freshness check failed for {repo}: {e}", file=sys.stderr)


def _matches(host: str, rules: set[tuple[int, str]]) -> bool:
    p = host.split(".")
    return (3, host) in rules or any((2, ".".join(p[i:])) in rules for i in range(len(p)))


def check(rules, nets) -> list[str]:
    errs = []
    if len(rules) < MIN_RULES:
        errs.append(f"rules: {len(rules)} < {MIN_RULES}")
    if len(nets) < MIN_IPS:
        errs.append(f"ips: {len(nets)} < {MIN_IPS}")
    errs += [f"{d}: not blocked" for d in MUST if not _matches(d, rules)]
    errs += [f"{d}: blocked" for d in MUST_NOT if _matches(d, rules)]
    errs += protect.critical_domains("spyware", {d for t, d in rules if t == 2},
                                     {d for t, d in rules if t == 3})
    errs += protect.critical_ips("spyware-ip", nets)
    prev = protect.previous(OUT)
    if prev:
        errs += protect.delta("spyware", len(rules), len(geosite.parse_dat(prev).get(TAG, ())))
    prev = protect.previous(OUT_IP)
    if prev:
        errs += protect.delta("spyware-ip", len(nets), len(geoip.parse_dat(prev).get(TAG, ())))
    return errs


def _encode(rules: set[tuple[int, str]]) -> bytes:
    body = geosite._ld(1, TAG.encode())
    for t, d in sorted(rules):
        body += geosite._ld(2, geosite._tag(1, 0) + geosite._varint(t)
                            + geosite._ld(2, d.encode()))
    return geosite._ld(1, body)


def _write(out: Path, name: str, blob: bytes) -> None:
    (out / name).write_bytes(blob)
    digest = hashlib.sha256(blob).hexdigest()
    (out / f"{name}.sha256sum").write_text(f"{digest}  {name}\n", encoding="utf-8")
    print(f"[spyware] {name}: {len(blob)} bytes, sha256 {digest[:16]}...")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="builder.spyware")
    ap.add_argument("--out", default="dist", type=Path)
    args = ap.parse_args(argv)
    warn_stale()
    try:
        rules, ips = build()
        nets = filter_ips(ips)
    except (FetchError, RuntimeError, OSError) as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        return 2
    print(f"[spyware] rules {len(rules)} (full {sum(t == 3 for t, _ in rules)}), "
          f"ip nets {len(nets)}")
    errs = check(rules, nets)
    blob, blob_ip = _encode(rules), geoip.build_dat({TAG: nets})
    if set(geosite.parse_dat(blob).get(TAG, ())) != {d for _, d in rules}:
        errs.append("geosite round-trip mismatch")
    if errs:
        for e in errs:
            print(f"[gate] {e}", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    _write(args.out, OUT, blob)
    _write(args.out, OUT_IP, blob_ip)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
