---
name: protect-deps
description: Audit third-party dependencies for known vulnerabilities and malicious packages and produce an SBOM — reads lockfiles for npm/pnpm/yarn/bun, pip/poetry/uv/Pipfile, Cargo, Go, Composer, Bundler, Pub, NuGet and Maven/Gradle, queries OSV.dev, prioritises with the CISA Known Exploited Vulnerabilities catalogue and FIRST EPSS, and writes a one-change-per-package upgrade plan plus a CycloneDX SBOM. Use in every security review, before releases, or when asked about vulnerable, outdated or malicious dependencies, SBOMs or supply-chain risk.
---

# Dependency audit and SBOM

```bash
node <kit>/skills/protect-deps/scripts/deps.mjs . --out .protectors
```

Outputs in `.protectors/`:
| File | Contents |
|---|---|
| `DEPENDENCIES.md` | Upgrade plan (one target version per package), then every advisory with CVSS, KEV, EPSS, fixed version and lockfile line |
| `deps.json` | Machine-readable result; the scanner merges these findings into `FINDINGS.md` and the score |
| `deps.sarif` | For GitHub code scanning |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM with purls, scopes and the vulnerabilities section |

Options: `--offline` (SBOM only) · `--exclude '^@yourco/'` (keep private package names local) · `--no-kev` · `--no-epss` ·
`--prod-only` (skip dev dependencies) · `--fail-on high` (CI) · `--json`.

## Privacy
Only package names, versions and ecosystems are sent to OSV.dev (and CVE ids to FIRST EPSS). No source code, no file
paths, no secrets. If the project's package names themselves are confidential, use `--exclude` or `--offline` and say so
in the report. Responses are cached for 24 hours in `.protectors/cache/`.

## How priority is decided
1. **Malicious package** (OSV `MAL-` advisories) → critical: remove now, rotate secrets on every machine that installed it.
2. **CISA KEV** (exploited in the wild) → critical, fix first regardless of CVSS.
3. **CVSS v3** base score (computed from the vector) or the advisory database's own rating, whichever is higher.
4. **EPSS ≥ 10%** (likely to be exploited within 30 days) → one level up.
5. **Dev-only** dependencies → one level down (they still matter for CI and developer machines).

## Fixing
- Follow the upgrade plan: it picks, per package, the lowest version that fixes every advisory with a published fix.
- Direct dependencies: bump in the manifest, regenerate the lockfile with the project's package manager, run the tests.
- Transitive dependencies: upgrade the direct parent; if none is available, use the ecosystem's override
  (`overrides` npm, `resolutions` yarn, `pnpm.overrides`, `[tool.uv] override-dependencies`, Cargo `[patch]`, Go `replace`).
- Major-version jumps: read the changelog, and run the full test suite.
- No fix published: decide whether the vulnerable function is reachable from this project (read the advisory and grep the
  call sites). Record the decision with evidence in `review.json` as `needs_validation` or a confirmed, accepted risk.
- Re-run `deps.mjs` after changes and show before/after counts.

## Also check (by reading)
- Install scripts (`preinstall`/`postinstall`) in new or unfamiliar packages; typosquats of popular names; packages with a
  single maintainer and a sudden major release; dependencies fetched from git URLs or tarballs.
- Lockfile committed and used in CI (`npm ci`, `pnpm install --frozen-lockfile`, `pip install --require-hashes`).
