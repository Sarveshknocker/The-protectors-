---
name: protect-scan
description: Automated security scanning of a project — hard-coded secrets (35+ providers, entropy-checked, and in git history), injection, XSS, weak crypto, auth/session flaws, TLS/CORS misconfig, SSRF, path traversal, unsafe deserialisation, Electron/extension/mobile/Docker/Kubernetes/Terraform/CI misconfigurations, C/C++ memory safety, firmware (TLS, OTA, secure boot, debug ports) and driver (IOCTL, user-copy, device ACL) flaws, dependency and repo hygiene — plus ecosystem dependency audits. Produces Markdown, JSON and SARIF.
---

# Automated scan

## 1. The Protectors scanner (always)
```bash
node <kit>/skills/protect-scan/scripts/scan.mjs . --out .protectors --fail-on none
```
- 130+ rules mapped to CWE (with the 2024 CWE Top 25 flagged), OWASP Top 10, Mobile Top 10 and the OWASP Top 10 for LLM applications. Every rule has annotated true/false-positive tests.
- Families: secrets, injection, XSS, crypto, auth/session, TLS/CORS/config, files/SSRF/deserialisation, LLM features (model output executed, user text in the system prompt), document rendering (HTML→PDF engines fed request data, PDF.js eval), Electron, extensions, mobile, C/C++, firmware, kernel and Windows drivers, Docker/Kubernetes/Terraform, GitHub Actions (script injection incl. multi-line `run:` blocks, `GITHUB_ENV` injection, self-hosted runners on PRs, missing token permissions, curl|sh, unpinned actions).
- `--history` also scans every commit's added lines: a secret deleted from the code but still in git history is reported as `history.*` with the commit that introduced it; a secret still present notes when it first entered history.
- Dependency findings from `protect-deps` (`.protectors/deps.json`) are merged into the report and score (skip with `--no-deps`).
- Secrets are **redacted** in all output.
- Findings in tests/docs/fixtures are downgraded one level and tagged.
- Suppress a confirmed false positive: comment `protectors-ignore: <rule-id> <reason>` on the line (or the one above), or add to `.protectors-ignore.json` (committed, reviewable; `rule` may be `"*"` with a `path`; `reason` required).
- CI mode: `--fail-on high` exits 1 if any high/critical finding exists in source or history.
- **Baseline** for existing projects: `--write-baseline .protectors-baseline.json` once (commit it), then CI runs `--baseline .protectors-baseline.json --fail-on high` and fails only on **new** findings. The baseline stores fingerprints only, no code or secrets. Shrink it over time.
- **Project-specific rules**: add `.protectors-rules.json` at the project root (`[{ "id", "severity", "title", "pattern", "flags", "files", "fix", "cwe", "owasp" }]`); ids become `custom.<id>`. Test them like the built-ins: put annotated examples (`// ruleid: custom.<id>` above a bad line, `// ok: custom.<id>` above a good one) in a folder with a copy of the rules file and run `node <kit>/skills/protect-scan/scripts/rule-test.mjs <folder> --require-coverage`.

## 2. Ecosystem tools (run what applies and is available; don't install globally without need — prefer npx/pipx/uvx)
| Ecosystem | Command | Notes |
|---|---|---|
| Node | `npm audit --omit=dev --json` (or `pnpm audit`, `yarn npm audit`) | Prod deps first |
| Python | `uvx pip-audit -r requirements.txt` or `pipx run pip-audit` | Also `uvx bandit -r . -f json` |
| Go | `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` | Reachability-aware |
| Rust | `cargo audit` | |
| Java/Kotlin | `./gradlew dependencyCheckAnalyze` (OWASP DC) if configured | |
| .NET | `dotnet list package --vulnerable --include-transitive` | |
| PHP | `composer audit` | |
| Ruby | `bundle exec bundler-audit check --update` | Also `brakeman` for Rails |
| Any | `npx osv-scanner --recursive .` or the `osv-scanner` binary | Multi-ecosystem |
| Secrets (history) | `gitleaks detect --redact` (if installed) | Catches secrets removed from HEAD but still in history |
| Containers/IaC | `trivy fs --scanners vuln,misconfig,secret .` (if installed) | |
| C/C++ / firmware / drivers | `cppcheck --enable=warning,portability .`, `clang-tidy`, Linux: `make C=1` (sparse), the kernel tree's `checkpatch.pl --strict`; Windows: SDV + CodeQL driver queries | |
| SAST (optional) | `semgrep --config p/owasp-top-ten --sarif -o .protectors/semgrep.sarif` (if installed) | |

If a tool is missing, note it in the report as a recommended CI addition — don't fail the run.

## 3. Triage rules
- Every critical/high must be confirmed by reading the code in context (is the input actually user-controlled? is there upstream validation?).
- False positive → document why in REVIEW.md; suppress only with a reason.
- Dependency vulns: prioritise those reachable in production code paths; propose the minimal safe upgrade and check changelogs for breaking changes.
