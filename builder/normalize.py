"""Normalize blocklist lines to bare domains."""
from __future__ import annotations

import re

_HOSTS_IP = ("0.0.0.0", "127.0.0.1", "::", "::1")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"(?:xn--[a-z0-9-]{2,59}|[a-z]{2,63})$"   # TLD: normal alpha or punycode IDN (e.g. xn--p1ai)
)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def normalize_line(line: str) -> str | None:
    """One line -> bare domain, or None for comments/junk/IPs/non-domain rules.

    Understands hosts files, plain/wildcard domain lists, and AdBlock/AdGuard
    network rules (``||domain^`` with benign modifiers). Deliberately ignored:
    cosmetic (``##``), scriptlet (``#%#``), HTML (``#$#``) and extended-css
    rules; exception rules (``@@``); regex rules; redirect / domain-scoped /
    rewrite modifiers; and URL rules with a path. IDN is converted to Punycode.
    """
    s = line.strip()
    if not s or s[0] in "#!/[":
        return None
    if "##" in s or "#?#" in s or "#$#" in s or "#%#" in s or "#@#" in s:
        return None  # cosmetic / scriptlet / HTML / extended-css -> not a domain
    if s.startswith("@@"):
        return None  # exception (allowlist) rule -> ignore
    if " " in s or "\t" in s:  # hosts format: "0.0.0.0 example.com"
        parts = s.split()
        if parts[0] in _HOSTS_IP and len(parts) >= 2:
            s = parts[1]
        else:
            return None
    if s.startswith("||"):  # adblock network rule ||domain^[$modifiers]
        s = s[2:]
        if "$" in s:
            head, _, opts = s.partition("$")
            # modifiers that make it NOT a plain everywhere-domain block
            if any(k in opts for k in ("domain=", "redirect", "csp", "app=",
                                       "denyallow=", "removeparam", "replace=",
                                       "rewrite=")):
                return None
            s = head
        s = s.rstrip("^")
    s = s.lstrip("*.").strip(".").lower()
    # anything left with a path/wildcard/anchor/option is not a bare domain
    if not s or any(c in s for c in "/*|^$") or _IP_RE.match(s):
        return None
    if not s.isascii():
        try:
            s = s.encode("idna").decode("ascii")  # IDN -> Punycode
        except Exception:
            return None
    if not _DOMAIN_RE.match(s):
        return None
    return s


def normalize_text(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        d = normalize_line(line)
        if d:
            out.add(d)
    return out
