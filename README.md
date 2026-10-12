# commensal-builder

Compiles public DNS blocklists into ready-to-use artifacts for routers and DNS
filters:

- **`tutela.dat`** — v2ray/xray geosite file. Rules reference categories as
  `ext:tutela.dat:<category>`.
- **`<category>.srs`** — binary rule-sets for [sing-box](https://sing-box.sagernet.org/).
- **`manifest.json`** — build version, sources, per-category counts, delta vs the
  previous release.
- **`mobile-mini.dat`** — compact geosite for memory-limited clients
  (`python -m builder.mobile`): selected upstream categories (`private`,
  `category-ru`, `category-ads` and per-service ones for split routing) plus
  `ads-ru`, `ru-metrics`, `ru-tracking`, `ru-ban`, `ip-detect`, `threat-ru`,
  `split-extra`. Built separately; a failure keeps the previous file.
  Upstream categories: [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)
  (MIT, Copyright (c) 2019-present v2fly).
- **`section6.dat`** / **`section6-ip.dat`** — geosite and geoip, tag `section-6`
  (`python -m builder.section6`): Russia-based services outside Russian TLDs
  (those are covered by `geosite:tld-ru`) and Russian networks, including
  Russian-owned ASes registered abroad. Sources:
  [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) (MIT),
  [hydraponique/roscomvpn-geosite](https://github.com/hydraponique/roscomvpn-geosite) (MIT),
  [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) (MIT),
  [chebur-net/russia-mobile-whitelist](https://github.com/chebur-net/russia-mobile-whitelist) (MIT),
  OFAC SDN list (US Government, public domain),
  [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) (CC BY-SA 4.0 —
  `section6-ip.dat` is distributed under the same license),
  [ipverse/rir-ip](https://github.com/ipverse/rir-ip) (CC0),
  [iptoasn.com](https://iptoasn.com/) (PDDL), RIPEstat announced prefixes.
- **`laughing-man.dat`** / **`laughing-man-ip.dat`** — geosite and geoip, tag
  `spyware` (`python -m builder.spyware`): commercial spyware and stalkerware
  infrastructure and vendors. Indicators are blocked as exact hosts; IPs on
  shared infrastructure are dropped. Sources, fetched on every build:
  [mvt-project/mvt-indicators](https://github.com/mvt-project/mvt-indicators) (MIT)
  and the indicator files it lists, including
  [AmnestyTech/investigations](https://github.com/AmnestyTech/investigations) (CC BY 4.0),
  [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)
  (CC BY 4.0).

Each of these is built separately; a failure keeps the previous file.

Artifacts are published as GitHub Release assets (a `latest` tag with stable URLs
plus a versioned tag per build). Consumers point their auto-update at the release
URL.

## v2rayN routing

`v2rayn/` holds routing templates for v2rayN (Xray core). Set
*Settings → Routing rules source* to a template URL, then *Routing settings →
Import advanced rules*:

- `template.json` — needs `tutela.dat` and `mobile-mini.dat` in v2rayN `bin/`
  (the core will not start without them).
- `template-lite.json` — stock geosite/geoip only.

Each template adds three rule sets: `all-except-RU` (everything via proxy, RU
direct), `split` (listed services via proxy, the rest direct) and `RU-off` (all RU
domains, zones and IPs blocked; listed services and blocked sites via proxy; the
rest direct). To refresh an existing set, put `full*.json` / `split*.json` /
`ruoff*.json` into its URL field and use *Import rules from URL*.

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
