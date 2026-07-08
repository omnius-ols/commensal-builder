"""Sources and category definitions."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Source:
    category: str
    url: str
    optional: bool = False  # missing/renamed (404) is skipped, not fatal


_HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains"

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
    # threat: single unified feed (malware+phishing+scam+crypto)
    Source("threat", f"{_HAGEZI}/tif.txt"),
    Source("threat", f"{_HAGEZI}/hoster.txt", optional=True),
    Source("threat", f"{_HAGEZI}/hoster-onlydomains.txt", optional=True),
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
