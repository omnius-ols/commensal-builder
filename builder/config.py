"""Sources and category definitions."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Source:
    category: str
    url: str
    optional: bool = False  # missing/renamed (404) is skipped, not fatal


_HAGEZI_BASE = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main"
_HAGEZI = f"{_HAGEZI_BASE}/domains"

_NATIVE_VENDORS = [
    "xiaomi", "winoffice", "samsung", "lgwebos", "roku",
    "apple", "tiktok", "oppo-realme", "vivo", "huawei",
]

SOURCES: list[Source] = [
    # ads: aggregator + one HaGeZi tier (Pro, not Ultimate)
    Source("ads", "https://big.oisd.nl/domainswild2"),
    Source("ads", f"{_HAGEZI}/pro.txt"),
    # adslite: compact high-impact tier (HaGeZi Light). Sized to be fetched over
    # the network before a router starts; the full ads list is too large for that.
    Source("adslite", f"{_HAGEZI}/light.txt"),
    # threat: TIF Medium tier (malware+phishing+scam+crypto). Medium, not full TIF:
    # the full feed (~1.9M domains) does not fit a small resolver's memory. The
    # tiered files live under wildcard/ (domains/ ships full tif.txt only). Deduped
    # against ads/native at build time (see __main__) so overlaps aren't stored twice.
    Source("threat", f"{_HAGEZI_BASE}/wildcard/tif.medium-onlydomains.txt"),
    # native: per-vendor device telemetry, merged into one category
    *[Source("native", f"{_HAGEZI}/native.{v}.txt") for v in _NATIVE_VENDORS],
]

# Quality gate: a category below its floor means a broken build (do not publish).
CATEGORY_MIN: dict[str, int] = {
    "ads": 100_000,
    "adslite": 50_000,
    "threat": 100_000,
    "native": 1_000,
}

# Deterministic category order (stable diff between builds).
CATEGORY_ORDER = ["ads", "adslite", "threat", "native"]

# Live threat domains sampled to verify the fresh feed reached the built .dat.
THREAT_LIVE_SAMPLE = 5
