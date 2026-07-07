"""Normalize blocklist lines to bare domains."""
from __future__ import annotations

import re

_HOSTS_IP = ("0.0.0.0", "127.0.0.1", "::", "::1")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$"
)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def normalize_line(line: str) -> str | None:
    """One line -> domain, or None for comments/junk/IPs."""
    s = line.strip()
    if not s or s[0] in "#!/":
        return None
    if " " in s or "\t" in s:  # hosts format: "0.0.0.0 example.com"
        parts = s.split()
        if parts[0] in _HOSTS_IP and len(parts) >= 2:
            s = parts[1]
        else:
            return None
    s = s.lstrip("*.")
    if s.startswith("||"):  # adblock ||domain^
        s = s[2:]
    s = s.rstrip("^").strip(".").lower()
    if not s or _IP_RE.match(s) or not _DOMAIN_RE.match(s):
        return None
    return s


def normalize_text(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        d = normalize_line(line)
        if d:
            out.add(d)
    return out
