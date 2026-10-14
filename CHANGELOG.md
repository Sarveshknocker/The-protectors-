# Changelog

## 0.2.0 — 2026-10-14
Upgrade informed by the leading open-source security tools (see `research/BENCHMARK.md`).

### Added
- **`protect-deps` skill and `deps.mjs`**: 14 lockfile/manifest formats (npm, pnpm, yarn v1/berry, bun, requirements,
  poetry, uv, pdm, Pipfile, Cargo, go.mod, Composer, Bundler, Pub, NuGet, Maven, Gradle); OSV.dev queries; malicious
  package detection; CVSS v3 scoring; CISA KEV and FIRST EPSS prioritisation; duplicate-advisory merging; one-target
  upgrade plan; CycloneDX 1.5 SBOM; SARIF; 24 h cache; `--offline`, `--exclude`, `--prod-only`, `--fail-on`.
- **Scanner**: `--history` (secrets anywhere in git history, with the introducing commit), `--baseline` /
  `--write-baseline` (CI fails on new findings only), stable fingerprints, CWE Top 25 (2024) tags and a compliance view,
  dependency findings merged into the report and score, project rules via `.protectors-rules.json`.
- **Rules (106 → 135)**: 18 secret providers (Hugging Face, Shopify, DigitalOcean, PyPI, Postman, Atlassian, Telegram,
  Discord, Azure Storage, GCP service accounts, Groq, Supabase, Linear, Doppler, Vault, Databricks, Docker Hub, age) with an
  entropy gate on generic credentials; LLM rules (model output executed, user text in system prompts); document rules
  (HTML→PDF renderers fed request data, PDF.js eval); GitHub Actions rules (multi-line script injection, GITHUB_ENV
  injection, self-hosted runners on PRs, missing permissions, secrets: inherit, curl|sh).
- **`rule-test.mjs`** and `tests/rules/`: every rule has annotated must-fire / must-not-fire cases; CI requires 100%.
- **Evidence contract**: `review.json` + `coverage.json` + `review-check.mjs` (+ `REVIEW_STATUS.md`); `finding-verifier`
  agent; severity anchors; safe local reproduction; anti-patterns. Report template gains coverage and needs-validation sections.
- Defense playbook: untrusted documents (PDF, HTML→PDF, Office, images).
- Orchestrator: common rationalizations, red flags, definition of done. Evals with planted issues. Codex plugin manifests.

### Fixed
- `xss.dangerous-html` flagged static string assignments (`el.innerHTML = '<b>x</b>'`) because `\s*` before the
  negative lookahead allowed backtracking.
- `scan.mjs` treated the project path after a value-less flag (e.g. `--history .`) as a flag value.

### Removed
- A stray `__pycache__/*.pyc` file from the templates.

## 0.1.0
- Initial release: recon, 106-rule scanner, deep review, platform defense playbooks and templates, verification, installer.
