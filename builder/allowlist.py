"""Allowlist and canary invariants.

Allowed domains are subtracted from every category (suffix match): a domain is
dropped if it equals an allowed entry or is a subdomain of one.
"""
from __future__ import annotations

# Functional domains that must never be blocked (mail, social logins/embeds,
# players, affiliate redirects).
FUNCTIONAL_ALLOW: set[str] = {
    "sendgrid.net", "email.mailgun.net", "mandrillapp.com", "mailchimp.com",
    "graph.facebook.com", "staticxx.facebook.com",
    "platform.instagram.com", "badges.instagram.com",
    "widgets.pinterest.com", "redditmedia.com",
    "platform.twitter.com", "t.co",
    "sc-static.net",
    "skimresources.com", "dwin1.com", "gdeslon.ru",
    "pardot.com",
    "cdn.jwplayer.com", "f.vimeocdn.com",
}

# Critical endpoints (auth/payments/messaging/dev) that must not appear in any
# category. Subtracted as a guarantee; canary re-verifies removal worked.
MUST_ALLOW: set[str] = {
    "google.com", "github.com",
    "sendgrid.net", "t.co", "platform.twitter.com",
    "stripe.com", "paypal.com",
    "telegram.org", "t.me",
    "www.icloud.com",
    "tonapi.io", "api.etherscan.io",
}

# Must be blocked in ads after the build (empty filter / broken pipeline guard).
MUST_BLOCK_ADS: set[str] = {
    "doubleclick.net",
    "googlesyndication.com",
    "taboola.com",
}

SUBTRACT: set[str] = FUNCTIONAL_ALLOW | MUST_ALLOW


def strip_allowed(domains: set[str], allow: set[str] | None = None) -> set[str]:
    """Drop domains covered by an allow suffix."""
    allow = SUBTRACT if allow is None else allow
    if not allow:
        return set(domains)
    return {d for d in domains if not _covered(d, allow)}


def _covered(domain: str, allow: set[str]) -> bool:
    """True if domain equals an allow entry or is a subdomain of one."""
    if domain in allow:
        return True
    idx = domain.find(".")
    while idx != -1:
        if domain[idx + 1:] in allow:
            return True
        idx = domain.find(".", idx + 1)
    return False
