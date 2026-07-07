"""Canary gate over built categories.

must-block: known ad networks must be present; must-allow: critical endpoints
must appear in no category. Any failure raises CanaryError (release skipped).
"""
from __future__ import annotations

from . import allowlist
from .allowlist import _covered


class CanaryError(Exception):
    pass


def _blocked_self_or_parent(domain: str, category: set[str]) -> bool:
    """True if the domain itself (or a parent suffix) is blocked."""
    return _covered(domain, category)


def _blocked_any(domain: str, category: set[str]) -> bool:
    """True if the domain, a parent, or any subdomain is blocked. Curated lists
    often block subdomains (ad.doubleclick.net), not the apex."""
    if _covered(domain, category):
        return True
    suffix = "." + domain
    return any(e.endswith(suffix) for e in category)


def run(categories: dict[str, set[str]], threat_live_sample: list[str]) -> list[str]:
    """Run all probes. Returns a report; raises CanaryError on any failure."""
    report: list[str] = []
    failures: list[str] = []
    ads = categories.get("ads", set())
    threat = categories.get("threat", set())

    for d in sorted(allowlist.MUST_BLOCK_ADS):
        if _blocked_any(d, ads):
            report.append(f"  must-block OK: {d}")
        else:
            failures.append(f"must-block FAIL: {d} not blocked in ads")

    # sampled from domains that reached the category -> verifies .dat round-trip
    for d in threat_live_sample:
        if _covered(d, threat):
            report.append(f"  threat-live OK: {d}")
        else:
            failures.append(f"threat-live FAIL: {d} missing from threat")

    for d in sorted(allowlist.MUST_ALLOW):
        where = [cat for cat, doms in categories.items()
                 if _blocked_self_or_parent(d, doms)]
        if where:
            failures.append(f"must-allow FAIL: {d} in {', '.join(sorted(where))}")
        else:
            report.append(f"  must-allow OK: {d}")

    if failures:
        raise CanaryError("canary failed:\n" + "\n".join(failures))
    return report
