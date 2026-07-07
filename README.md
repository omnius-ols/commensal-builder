# commensal-builder

Compiles public DNS blocklists into ready-to-use artifacts for routers and DNS
filters:

- **`tutela.dat`** — v2ray/xray geosite file. Rules reference categories as
  `ext:tutela.dat:<category>`.
- **`<category>.srs`** — binary rule-sets for [sing-box](https://sing-box.sagernet.org/).
- **`manifest.json`** — build version, sources, per-category counts, delta vs the
  previous release.

Artifacts are published as GitHub Release assets (a `latest` tag with stable URLs
plus a versioned tag per build). Consumers point their auto-update at the release
URL.

## Categories

| Category | Contents | Sources |
|---|---|---|
| `ads` | ads / tracking | OISD Big, HaGeZi Pro |
| `threat` | malware/phishing/scam/crypto | HaGeZi TIF |
| `native` | device telemetry (SmartTV, OS vendors) | HaGeZi native.* |

## Pipeline

```
sources -> normalize -> subtract allowlist -> categories
  -> tutela.dat (+ round-trip check) -> quality gates + canary
  -> .srs (sing-box compile) + manifest.json -> GitHub Release
```

- **allowlist** — curated functional domains (transactional mail, social
  logins/embeds, embedded players, affiliate redirects). Subtracted from every
  category, so a curated "keep" always wins over any upstream.
- **Gates before publishing** — each category must exceed a domain floor; the
  built `.dat` is parsed back; **canary** checks that known ad domains are present
  and that critical endpoints (auth/payments/messaging) land in no category. Any
  gate failure means the release is not published and the previous one stays.

## Local run

No third-party dependencies (stdlib, Python 3.10+). `.srs` is compiled only in CI
(needs the sing-box binary); locally you get `.dat`, plain lists and the manifest:

```bash
python -m builder --out dist
# partial debug without thresholds (if not fetching all sources):
python -m builder --out dist --allow-partial
```

Inspect the built `.dat`:

```bash
python -c "from builder import geosite; d=geosite.parse_dat(open('dist/tutela.dat','rb').read()); print({k:len(v) for k,v in d.items()})"
```

## CI

`.github/workflows/build.yml` runs daily (02:00 UTC) and on `workflow_dispatch`.
On passing gates it publishes/updates the `latest` release and a versioned tag.
Lists are under their respective upstream licenses (OISD / HaGeZi); this repo only
aggregates and repackages.
