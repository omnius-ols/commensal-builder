"""manifest.json: version, sources, per-category counts, delta vs previous."""
from __future__ import annotations

import json
from datetime import datetime, timezone


def version_stamp(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.strftime("%Y.%m.%d-%H%M")


def build_manifest(
    *,
    version: str,
    git_sha: str,
    sources: list[dict],
    categories: dict[str, int],
    allowlist_removed: int,
    previous: dict | None,
) -> dict:
    manifest = {
        "version": version,
        "build": git_sha,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": sources,
        "categories": categories,
        "allowlist_removed": allowlist_removed,
    }
    prev_cats = (previous or {}).get("categories") or {}
    if prev_cats:
        manifest["delta_vs_previous"] = {
            cat: categories[cat] - prev_cats.get(cat, 0) for cat in categories
        }
    return manifest


def dumps(manifest: dict) -> str:
    return json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"


def load(path) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
