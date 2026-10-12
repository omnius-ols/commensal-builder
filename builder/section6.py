"""section6.dat + section6-ip.dat: Russia-based services outside Russian TLDs.

Domains (tag SECTION-6): v2fly category-ru minus Russian TLDs (those are covered
by geosite:tld-ru), a few v2fly service lists, MIT whitelists, OFAC SDN websites
of Russia-based entities, and curated entries (vendors, subsidiaries, products
found by organization name in certificate logs).
IPs (tag SECTION-6): Russia by location (Loyalsoldier) + by registry (ipverse)
+ ASes registered in RU (iptoasn) + Russian-owned ASes registered abroad.
Independent of tutela.dat: a failure here never blocks the main build.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import re
import sys
from pathlib import Path

from . import geoip, geosite
from .fetch import FetchError, fetch
from .mobile import UPSTREAM, _covered, _domains, _entries, fetch_bytes

OUT, OUT_IP = "section6.dat", "section6-ip.dat"
TAG = "SECTION-6"

V2FLY_EXTRA = ("2GIS", "HABR", "FICBOOK", "SBER")
# MIT
MIT_LISTS = [
    "https://raw.githubusercontent.com/hydraponique/roscomvpn-geosite/master/data/whitelist",
    "https://raw.githubusercontent.com/hydraponique/roscomvpn-geosite/master/data/category-ru",
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt",
    "https://raw.githubusercontent.com/chebur-net/russia-mobile-whitelist/main/moscow-tele2/domains.txt",
    "https://raw.githubusercontent.com/chebur-net/russia-mobile-whitelist/main/spb-tele2/domains.txt",
]
# US Treasury OFAC SDN (public domain): websites of entities with an address in Russia.
OFAC = "https://www.treasury.gov/ofac/downloads/"
OFAC_SKIP = {"khazarshipping.ir", "kratol-aviation.ae", "cgtradefze.com"}

CURATED = {
    # services and products
    "1c.com", "bitrix24.com", "ctc.media", "gaijin.net", "nornickel.com", "rosneft.com",
    "soloviev.live", "trueconf.com", "amocrm.com", "appmetrica.io", "avito.com",
    "cdnvideo.com", "cdnvideo.net", "ddos-guard.net", "ivi.tv", "megafon.tv",
    "qrator.net", "securelist.com", "stormwall.pro", "taplink.cc",
    # surveillance vendors
    "aeza.net", "findface.pro", "norsi-trans.com", "ntechlab.com", "protei.com",
    "speechpro.com", "tevian.ai", "vasexperts.com", "visionlabs.ai", "ptsecurity.com",
    # subsidiaries abroad
    "a7a5.io", "alfabank.by", "belgazprombank.by", "bgpb.by", "gazprom-international.com",
    "grinex.io", "kasperskyos.com", "nexign.com", "phdays.com", "protei.me", "qrator.cz",
    "stormwall.network", "vtb.am", "vtb.by", "vtb.ge", "selectel.com",
}
# Found by organization name (O=) in OV/EV certificates.
CERT_LOG = set("""
1c-findir.tech 1c-wiseadvice.kz 1c.ai 1c.link 1c.market 1capp.com 1capp.net 1cdialog.com
1ci.com 1cinternational.com 1cmycloud.com 2050.earth adfox.net adsmobiledisruptor.one
appmetrica.com backtobackconf.com band.link bookmate.kz catboost.ai cito-training.com
cleanvir.us clients.site custservhelp.com cyberimmunityconf.com cybersaver.eu cybsi.cloud
datalens.tech deeptechnight.com deli.store dikidi.kz dikidi.tech diplodoc.com domyland.app
domyland.com domyland.dev e1c-ops.com edadeal.net education-az.com elama.tech
evetestpage.info facebook-web.com familiasegura.es fasten.com fraudshallnotpass.com
geh-serbia.rs getsysteminfo.com ilkharitam.com it-grad.com itechswiss.com itstandup.com
k-asap.com k-asap.eu kas.pr kaspersky-global.com kaspersky-xtraining.com kaspersky.ae
kaspersky.blog kaspersky.by kaspersky.care kaspersky.ch kaspersky.co.id kaspersky.co.il
kaspersky.com.mx kaspersky.dev kaspersky.hk kaspersky.no kaspersky.sg kaspersky.tn
kaspersky.ua kaspersky29.rest kasperskyclub.com kasperskycontenthub.com kasperskydaily.com
kasperskyesimstore.com kasperskygroup.com kasperskykudos.com kasperskykudosapac.com
kasperskykudoseu.com kasperskykudosla.com kasperskylab.com kasperskylab.de kasperskylab.fr
kasperskylabs.jp kasperskypartners.com kasperskyxtraining.com kdp.global
kes-cloud-internal.com kinopoisk.sport kips-training.com kips.site kms.racing kuberconf.com
kuberconf.io legal.direct lunnen.pro lxtk.org maxpatrol.com metrika-informer.com
midoritrading.kz money1c.com muz.lc mwscdn.com nexthopconf.com oblako.kz odna.co
perforator.tech posi.qa promo.page protection-center.online ptresearch.media qlyuker.io
qrshelf.online rosneft.com.sg rucola-benchmark.com safekids.kg securelist.com.br
securelist.fr securelist.it smartreserve.pro tdsd.pro theonlyway.click thesascon.com
threatpost.com tomorrowunlocked.com turbo.site umo.auto vendor-forms.com virusanalyst.com
wearemagiccamp.com xpeng.auto ya-edu.space ya.rs yabiz.kz yaff.tech yagr.tech yahall.am
yamagistrali.kz yandex.bike yandex.delivery yandex.gg yandex.site yandexext.com
yandexint.com yandexint.net yatalks2023.com ydocs.tech ymetrica.com ysda.education
z5h64q92x9.net
""".split())
# Not Russia-based, or IP-lookup services (blocked by their own rule elsewhere).
SKIP = {"windsurf.com", "medtrum.eu", "autobahn.db.com", "mizuhogroup.com", "wbgames.com",
        "checkip.amazonaws.com", "ifconfig.me", "ip.sb", "ipapi.is", "ipify.org",
        "iplocate.io", "showip.net", "api.sypexgeo.net", "api.ipify.org", "icanhazip.com"}

IP_SOURCES = [
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/ru.txt",  # CC BY-SA 4.0
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/ipv4-aggregated.txt",  # CC0
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/ipv6-aggregated.txt",  # CC0
]
# Russian-owned ASes registered abroad.
FOREIGN_AS = {
    "200107", "41983", "205282", "209671", "59692", "208398", "207304", "212066", "208795",
    "200449", "211112", "59796", "198652", "52160", "62197", "216202", "201356", "60611",
    "62170", "56742", "204230",
}

MIN_DOMAINS, MIN_V4 = 1000, 8000
MUST = ("habr.com", "kaspersky.com", "gaijin.net", "2gis.com", "ntechlab.com", "ptsecurity.com")
MUST_NOT = ("google.com", "youtube.com", "wikipedia.org", "github.com", "telegram.org",
            "cloudflare.com", "microsoft.com", "apple.com", "amazon.com", "proton.me")
MUST_IP = ("77.88.8.8", "87.250.250.242", "5.255.255.242")
MUST_NOT_IP = ("1.1.1.1", "8.8.8.8", "140.82.112.3", "208.80.154.224", "9.9.9.9")

_DOM = re.compile(r"^(?:\*\.|\+\.|\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)\.?$")


def _lines(txt: str) -> set[str]:
    out = set()
    for line in txt.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        for p in ("domain:", "full:", "domain-suffix,", "domain,", "||"):
            line = line.removeprefix(p)
        line = line.rstrip("^").split(",")[0].split()[0] if line else ""
        m = _DOM.match(line)
        if m:
            out.add(m.group(1))
    return out


def _ofac() -> set[str]:
    def rows(name):
        return csv.reader(io.StringIO(fetch(OFAC + name)))
    ru = {r[0] for r in rows("add.csv") if len(r) > 4 and r[4].strip().lower() == "russia"}
    remarks: dict[str, str] = {}
    for r in rows("sdn.csv"):
        if len(r) > 11 and r[0] in ru:
            remarks[r[0]] = r[11]
    for r in rows("sdn_comments.csv"):
        if len(r) > 1 and r[0] in remarks:
            remarks[r[0]] += " " + r[1]
    out = set()
    for text in remarks.values():
        for w in re.findall(r"Website\s+([^\s;]+)", text, re.I):
            w = re.sub(r"^(https?://)?(www\.)?", "", w.lower()).split("/")[0].rstrip(".,")
            if "." in w and not w.endswith(".onion") and w not in OFAC_SKIP:
                out.add(w)
    return out


def build_domains() -> set[str]:
    up = _entries(fetch_bytes(UPSTREAM))
    zones = {d for d in _domains(up["TLD-RU"]) if "." not in d} | {"ru", "su", "xn--p1ai"}
    doms = _domains(up["CATEGORY-RU"])
    for c in V2FLY_EXTRA:
        doms |= _domains(up.get(c, b""))
    for u in MIT_LISTS:
        doms |= _lines(fetch(u))
    try:
        doms |= _ofac()
    except FetchError as e:
        print(f"[section6] OFAC skipped: {e}", file=sys.stderr)
    doms |= CURATED | CERT_LOG
    doms = {d for d in doms if d.rsplit(".", 1)[-1] not in zones and d not in SKIP}
    return {d for d in doms if not _covered_strict(d, doms)}


def _covered_strict(d: str, s: set[str]) -> bool:
    p = d.split(".")
    return any(".".join(p[i:]) in s for i in range(1, len(p)))


def build_ips() -> list[geoip.Net]:
    nets = []
    for u in IP_SOURCES:
        nets += geoip.nets_from_text(fetch(u))
    for asn in sorted(FOREIGN_AS):
        nets += geoip.announced(asn)
    # Optional: ASes registered in RU announcing space outside RU registry blocks.
    try:
        for a, b, _, cc, _ in geoip.iptoasn_v4():
            if cc == "RU":
                nets += geoip.range_nets(a, b)
    except OSError as e:
        print(f"[section6] iptoasn skipped: {e}", file=sys.stderr)
    return geoip.collapse(nets)


def check(doms: set[str], nets: list[geoip.Net]) -> list[str]:
    errs = []
    v4 = sum(n.version == 4 for n in nets)
    if len(doms) < MIN_DOMAINS:
        errs.append(f"domains: {len(doms)} < {MIN_DOMAINS}")
    if v4 < MIN_V4:
        errs.append(f"ipv4 nets: {v4} < {MIN_V4}")
    errs += [f"{d}: not blocked" for d in MUST if not _covered(d, doms)]
    errs += [f"{d}: blocked" for d in MUST_NOT if _covered(d, doms)]
    errs += [f"{ip}: not blocked" for ip in MUST_IP if not geoip.contains(nets, ip)]
    errs += [f"{ip}: blocked" for ip in MUST_NOT_IP if geoip.contains(nets, ip)]
    return errs


def _write(out: Path, name: str, blob: bytes) -> None:
    (out / name).write_bytes(blob)
    digest = hashlib.sha256(blob).hexdigest()
    (out / f"{name}.sha256sum").write_text(f"{digest}  {name}\n", encoding="utf-8")
    print(f"[section6] {name}: {len(blob)} bytes, sha256 {digest[:16]}...")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="builder.section6")
    ap.add_argument("--out", default="dist", type=Path)
    args = ap.parse_args(argv)
    try:
        doms, nets = build_domains(), build_ips()
    except (FetchError, RuntimeError, OSError, KeyError) as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        return 2
    print(f"[section6] domains {len(doms)}, nets v4 {sum(n.version == 4 for n in nets)}, "
          f"v6 {sum(n.version == 6 for n in nets)}")
    errs = check(doms, nets)
    blob = geosite.build_dat({TAG: sorted(doms)})
    if geosite.parse_dat(blob).get(TAG) != doms:
        errs.append("geosite round-trip mismatch")
    blob_ip = geoip.build_dat({TAG: nets})
    if geoip.parse_dat(blob_ip).get(TAG) != nets:
        errs.append("geoip round-trip mismatch")
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
