"""Build orchestrator: python -m builder [--out dist] [...].

fetch -> normalize -> subtract allowlist -> categories -> tutela.dat
-> round-trip parse -> quality gates + canary -> .srs sources + manifest.
Any gate failure exits non-zero (CI skips publishing).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from . import allowlist, canary, geosite, manifest as manifest_mod
from .config import CATEGORY_MIN, CATEGORY_ORDER, SOURCES, THREAT_LIVE_SAMPLE
from .fetch import FetchError, fetch
from .normalize import normalize_text


def _git_sha() -> str:
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        return sha[:12]
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return "local"


def _srs_source(domains: list[str]) -> dict:
    return {"version": 1, "rules": [{"domain_suffix": sorted(domains)}]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="builder")
    ap.add_argument("--out", default="dist", type=Path)
    ap.add_argument("--prev-manifest", type=Path, default=None,
                    help="previous manifest.json for delta")
    ap.add_argument("--allow-partial", action="store_true",
                    help="do not fail on category thresholds (local debug)")
    args = ap.parse_args(argv)

    out: Path = args.out
    (out / "lists").mkdir(parents=True, exist_ok=True)
    (out / "srs-src").mkdir(parents=True, exist_ok=True)

    # fetch + normalize into per-category sets
    cats: dict[str, set[str]] = {}
    src_stats: list[dict] = []
    threat_feed: set[str] = set()
    for s in SOURCES:
        try:
            text = fetch(s.url)
        except FetchError as e:
            if s.optional and getattr(e, "not_found", False):
                print(f"[skip] optional source missing: {s.url}")
                src_stats.append({"url": s.url, "category": s.category,
                                  "skipped": True})
                continue
            print(f"[FAIL] {s.url}: {e}", file=sys.stderr)
            return 2
        raw_lines = text.count("\n") + 1
        doms = normalize_text(text)
        cats.setdefault(s.category, set()).update(doms)
        if s.category == "threat":
            threat_feed |= doms
        src_stats.append({"url": s.url, "category": s.category,
                          "lines": raw_lines, "domains": len(doms)})
        print(f"[ok] {s.url}: {raw_lines} lines -> {len(doms)} domains "
              f"-> {s.category}")

    # subtract allowlist from every category
    removed_total = 0
    for cat in list(cats):
        before = len(cats[cat])
        cats[cat] = allowlist.strip_allowed(cats[cat])
        removed_total += before - len(cats[cat])
    print(f"[allowlist] removed {removed_total} domains")

    # threat dedup: drop threat domains already covered by an ads/native suffix. On
    # a resolver both categories load as separate matchers, so a domain present in
    # both is stored twice and wastes memory. Suffix-aware (a parent in ads covers
    # its subdomains in threat), not a plain set difference.
    if cats.get("threat"):
        covered = cats.get("ads", set()) | cats.get("native", set())
        before = len(cats["threat"])
        cats["threat"] = {d for d in cats["threat"]
                          if not allowlist._covered(d, covered)}
        print(f"[dedup] threat: {before} -> {len(cats['threat'])} "
              f"(-{before - len(cats['threat'])} covered by ads/native)")

    # build .dat (deterministic category order)
    ordered = {c: sorted(cats.get(c, set())) for c in CATEGORY_ORDER if cats.get(c)}
    dat = geosite.build_dat(ordered)
    (out / "tutela.dat").write_bytes(dat)
    print(f"[dat] tutela.dat: {len(dat)} bytes, "
          f"{ {c: len(v) for c, v in ordered.items()} }")

    # round-trip: parse back and verify counts
    parsed = {c.lower(): d for c, d in geosite.parse_dat(dat).items()}
    for c, doms in ordered.items():
        if len(parsed.get(c, set())) != len(doms):
            print(f"[FAIL] round-trip {c}: {len(parsed.get(c, set()))} != "
                  f"{len(doms)}", file=sys.stderr)
            return 3

    # quality gates
    threshold_fail = False
    for cat, minimum in CATEGORY_MIN.items():
        have = len(parsed.get(cat, set()))
        ok = have >= minimum
        print(f"[gate] {cat}: {have} (min {minimum}) {'OK' if ok else 'LOW'}")
        threshold_fail |= not ok

    # canary. Sample fresh-feed threat domains that SURVIVED processing (allowlist
    # + ads/native dedup). Dedup legitimately drops threat domains already covered
    # by ads, so sampling the raw feed would flag those as "missing from threat"
    # even though they are still blocked (by ads).
    sample = sorted(
        d for d in threat_feed if d in cats.get("threat", set())
    )[:THREAT_LIVE_SAMPLE]
    canary_fail = False
    try:
        for line in canary.run(parsed, sample):
            print(line)
    except canary.CanaryError as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        canary_fail = True

    # client artifacts: plain lists + sing-box rule-set sources
    for cat, doms in ordered.items():
        (out / "lists" / f"{cat}.txt").write_text(
            "\n".join(sorted(doms)) + "\n", encoding="utf-8")
        (out / "srs-src" / f"{cat}.json").write_text(
            json.dumps(_srs_source(doms), ensure_ascii=False), encoding="utf-8")

    # manifest
    prev = manifest_mod.load(args.prev_manifest) if args.prev_manifest else None
    man = manifest_mod.build_manifest(
        version=manifest_mod.version_stamp(),
        git_sha=_git_sha(),
        sources=src_stats,
        categories={c: len(v) for c, v in ordered.items()},
        allowlist_removed=removed_total,
        previous=prev,
    )
    (out / "manifest.json").write_text(manifest_mod.dumps(man), encoding="utf-8")
    print(f"[manifest] version {man['version']}")

    if threshold_fail or canary_fail:
        if args.allow_partial and threshold_fail and not canary_fail:
            print("[warn] thresholds not met, --allow-partial -> continue "
                  "(artifacts NOT for publishing)")
            return 0
        print("[ABORT] gates failed - do not publish", file=sys.stderr)
        return 1
    print("[done] all gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
