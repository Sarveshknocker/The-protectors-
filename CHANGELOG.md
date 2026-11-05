# Changelog

## 0.3.1 — 2026-11-05
Scanner fixes from an external review. On the reviewer's 14-bug test app it now finds 13 (was 11); the remaining one,
an IDOR, is left to manual review by design.
- **R-1:** Python `requests.get(u, verify=False)` was also reported as "JWT verification disabled" (critical). The bare
  `verify=False` alternative is removed from the JWT rule; `tls.verification-disabled` covers it.
- **R-2:** `pull_request_target` checking out PR code was missed when `ref` was quoted, written as a flow mapping
  (`with: { ref: "${{ … }}" }`), or used `github.head_ref`.
- **R-3:** new `auth.weak-secret-constant`. `JWT_SECRET = "secret"` (or `SECRET_KEY`, session/signing/cookie secrets)
  as a short literal was missed, because `jwt.sign(x, JWT_SECRET)` hides the literal.
- **R-4:** new `xss.server-reflected`. Express `res.send('<h1>' + req.query.x)` / template literals, and Flask
  `return f"<…{request.args…}"`.
- **R-5:** `node-serialize` was reported at the import line; it is now reported at the `unserialize(...)` call.
- **R-6:** the README says plainly what the scanner cannot see (data flow, IDOR, business logic) and to pair it with
  Semgrep/CodeQL and gitleaks.
- Corpus: 137/137 rules covered, 158/158 planted cases detected, 0/119 false positives.

## 0.3.0 — 2026-11-05
Safety release, from an external review (P0 blockers).
- **Installer can no longer delete your files.** New shared `bin/kit-installer.mjs` (the same file in all of
  Sarvesh's kits). `--kit-dir` must be a new sub-folder of the project. A folder the kit did not create is never
  deleted. Only paths recorded in the manifest *and* produced by this kit are removed, so a tampered manifest cannot
  widen the delete. Existing files are never overwritten: `--force` backs them up to `<kit-dir>/backup/` and `remove`
  restores them. Covered by `tests/installer.mjs` (12 cases, run by `npm test`).
- **Kits no longer collide:** agents are prefixed (`protectors-security-reviewer`, …) and the orchestrator skill is
  renamed `protect` → `protectors`. Updating an older install removes the old copies the kit owned.
- **Checkpoint before autonomous edits:** a clean git tree and a `protectors/harden-<date>` branch (or file backups
  without git) before the first change. New "report only" mode.

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
- **Evidence contract**: `review.json` + `coverage.json` + `review-check.mjs` (+ `REVIEW_STATUS.md`); `protectors-finding-verifier`
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
