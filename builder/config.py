"""Sources and category definitions."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Source:
    category: str
    url: str
    optional: bool = False  # missing/renamed (404) is skipped, not fatal


_HAGEZI_BASE = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main"
# Upstream dropped the domains/ folder (2026-08); every plain-domain list now
# lives in wildcard/ under a "-onlydomains" name, next to the wildcard-syntax
# variant of the same tier. The plain variants are what normalize.py expects,
# so only the paths change here. Every source below 404'd for a week and the
# quality gate refused to publish - a source path is the first thing to check
# when a scheduled build starts failing without any change on our side.
_HAGEZI = f"{_HAGEZI_BASE}/wildcard"

_NATIVE_VENDORS = [
    "xiaomi", "winoffice", "samsung", "lgwebos", "roku",
    "apple", "tiktok", "oppo-realme", "vivo", "huawei",
]

SOURCES: list[Source] = [
    # ads: aggregator + one HaGeZi tier (Pro, not Ultimate)
    Source("ads", "https://big.oisd.nl/domainswild2"),
    Source("ads", f"{_HAGEZI}/pro-onlydomains.txt"),
    # adslite: compact high-impact tier (HaGeZi Light). Sized to be fetched over
    # the network before a router starts; the full ads list is too large for that.
    Source("adslite", f"{_HAGEZI}/light-onlydomains.txt"),
    # threat: TIF Medium tier (malware+phishing+scam+crypto). Medium, not full TIF:
    # the full feed (~1.9M domains) does not fit a small resolver's memory.
    # Deduped against ads/native at build time (see __main__) so overlaps aren't
    # stored twice.
    Source("threat", f"{_HAGEZI}/tif.medium-onlydomains.txt"),
    # native: per-vendor device telemetry, merged into one category
    *[Source("native", f"{_HAGEZI}/native.{v}-onlydomains.txt")
      for v in _NATIVE_VENDORS],
    # ads-ru: Russian-language ad filters (AdGuard Russian filter #1 + RuAdList).
    # AdBlock/AdGuard syntax; only bare domain rules are extracted (cosmetic /
    # scriptlet / URL / regex / redirect rules are ignored — see normalize.py).
    # RuAdList's compiled list is served only from a mirror that can be flaky, so
    # it is optional: if it is unavailable the category still builds from AdGuard.
    Source("ads-ru", "https://filters.adtidy.org/extension/ublock/filters/1.txt"),
    Source("ads-ru", "https://easylist-downloads.adblockplus.org/advblock.txt",
           optional=True),
]

# Quality gate: a category below its floor means a broken build (do not publish).
CATEGORY_MIN: dict[str, int] = {
    "ads": 100_000,
    # Lowered from 50k (2026-08): the upstream Light tier is curated down over
    # time and now yields ~41k after the allowlist, so the old floor rejected a
    # healthy build. The floor guards against an empty or truncated fetch, not
    # against upstream trimming - a smaller adslite is fine, the tier exists to
    # stay small enough to be fetched over the network before a router starts.
    "adslite": 35_000,
    "threat": 100_000,
    "native": 1_000,
    "ads-ru": 1_000,   # AdGuard Russian alone clears this; RuAdList adds on top
}

# Deterministic category order (stable diff between builds).
CATEGORY_ORDER = ["ads", "adslite", "threat", "native", "ads-ru"]

# Live threat domains sampled to verify the fresh feed reached the built .dat.
THREAT_LIVE_SAMPLE = 5
