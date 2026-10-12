"""Gates shared by the independent artifacts (mobile-mini, thermoptic, spyware).

- CRITICAL / CRITICAL_IP: must never be blocked by any of them. Guards against an
  upstream list (accidentally or not) adding a major platform.
- delta: a sudden shrink or growth vs the previous release fails the build, so
  the previous file stays published.
"""
from __future__ import annotations

import ipaddress
import urllib.error
import urllib.request

LATEST = "https://github.com/omnius-ols/commensal-builder/releases/latest/download/"

CRITICAL = (
    "google.com", "youtube.com", "googlevideo.com", "gstatic.com", "googleapis.com",
    "telegram.org", "t.me", "whatsapp.com", "whatsapp.net", "signal.org",
    "github.com", "githubusercontent.com", "apple.com", "icloud.com", "microsoft.com",
    "live.com", "windowsupdate.com", "cloudflare.com", "cloudflare-dns.com",
    "wikipedia.org", "mozilla.org", "proton.me", "amazon.com", "amazonaws.com",
    "akamaized.net", "fastly.net", "letsencrypt.org", "digicert.com", "debian.org",
    "ubuntu.com", "python.org",
)
CRITICAL_IP = (
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "140.82.112.3",
    "208.80.154.224", "17.253.144.10", "13.107.42.14", "149.154.167.99",
    "2606:4700:4700::1111", "2001:4860:4860::8888",
)
SHRINK, GROW = 0.7, 2.0


def covered(d: str, roots: set[str]) -> bool:
    p = d.split(".")
    return any(".".join(p[i:]) in roots for i in range(len(p)))


def critical_domains(label: str, roots: set[str], full: set[str] = frozenset()) -> list[str]:
    return [f"{label}: critical {d} blocked" for d in CRITICAL
            if covered(d, roots) or d in full]


def critical_ips(label: str, nets) -> list[str]:
    errs = []
    for ip in CRITICAL_IP:
        a = ipaddress.ip_address(ip)
        if any(a in n for n in nets if n.version == a.version):
            errs.append(f"{label}: critical {ip} blocked")
    return errs


def previous(name: str) -> bytes | None:
    """The asset as currently published, or None (first run / not published)."""
    try:
        req = urllib.request.Request(LATEST + name, headers={"User-Agent": "commensal-builder"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.read()
    except (urllib.error.URLError, OSError):
        return None


def delta(label: str, now: int, prev: int | None) -> list[str]:
    if not prev:
        return []
    if now < prev * SHRINK or now > prev * GROW:
        return [f"{label}: {prev} -> {now} (allowed {SHRINK:.0%}..{GROW:.0%})"]
    return []
