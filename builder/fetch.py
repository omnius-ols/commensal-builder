"""Source download (stdlib only)."""
from __future__ import annotations

import gzip
import time
import urllib.error
import urllib.request

_UA = "commensal-builder/0.1 (+https://github.com/)"


class FetchError(Exception):
    pass


def fetch(url: str, *, retries: int = 3, timeout: int = 180) -> str:
    """Download URL as text. 404 raises FetchError with .not_found = True."""
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": _UA, "Accept-Encoding": "gzip"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return raw.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                err = FetchError(f"404 Not Found: {url}")
                err.not_found = True  # type: ignore[attr-defined]
                raise err from e
            last = e
        except Exception as e:  # noqa: BLE001 - retry any network error
            last = e
        if attempt < retries:
            time.sleep(2 * attempt)
    raise FetchError(f"failed to download {url}: {last}")
