# Benchmark: what the leading security tools do, and what this kit took

Researched October 2026 from the most-starred open-source projects in this kit's areas. Star counts are from the
GitHub API at the time. Only ideas were taken; all code here is original (see [CREDITS.md](../CREDITS.md)).

| Project | Stars | Licence | Best at | Taken into this kit |
|---|---|---|---|---|
| [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) | ~29.5k | MIT | An agent skill for audits with machine-checkable findings: a finding must name a crossed trust boundary; verdicts confirmed / needs-validation / rejected; severity only for confirmed; a coverage ledger so no run implies "the rest is fine"; independent verifiers; sandboxed local reproduction; validator scripts | The evidence contract (`review.json`), the coverage ledger (`coverage.json`), severity anchors, anti-patterns, the `finding-verifier` agent and `review-check.mjs` |
| [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | ~30k | MIT | Secret detection across git history, entropy checks, allowlists, baselines | `scan --history`, entropy gate on generic credentials, 18 new provider formats, fingerprint baselines |
| [aquasecurity/trivy](https://github.com/aquasecurity/trivy) · [anchore/syft](https://github.com/anchore/syft) | ~38k · ~10k | Apache-2.0 | Vulnerability + misconfiguration scanning, SBOM generation | CycloneDX SBOM from lockfiles, SARIF for dependency findings |
| [google/osv-scanner](https://github.com/google/osv-scanner) | ~11k | Apache-2.0 | Offline lockfile parsing for many ecosystems + OSV batch queries | 14 lockfile/manifest parsers, OSV `querybatch` + per-advisory lookups, fixed-version extraction |
| [semgrep/semgrep](https://github.com/semgrep/semgrep) | ~17k | LGPL-2.1 | Rule test files annotated with `ruleid:` / `ok:`; custom rules per project | `rule-test.mjs` with the same annotation idea, 100% rule coverage in CI, `.protectors-rules.json` |
| [ossf/scorecard](https://github.com/ossf/scorecard) · [zizmorcore/zizmor](https://github.com/zizmorcore/zizmor) | ~5.8k · ~6.7k | Apache-2.0 · MIT | GitHub Actions and repository posture | New CI rules: multi-line `run:` script injection, `GITHUB_ENV`/`GITHUB_PATH` injection, self-hosted runners on PRs, missing token permissions, `secrets: inherit`, curl-pipe-shell |
| [google/mantis](https://github.com/google/mantis) · [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) | ~2.4k · ~49k | Apache-2.0 · AGPL-3.0 | "Reproduce before you report" for AI security agents | Confirmed findings need a local reproduction (or a justified waiver); the test becomes the regression test. No live exploitation. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/) | public data | — | What attackers actually exploit / are likely to | Dependency prioritisation: KEV → critical, EPSS ≥ 10% → one level up |
| [jonaslejon/malicious-pdf](https://github.com/jonaslejon/malicious-pdf) | ~4.5k | BSD-2-Clause | Test payloads showing how PDFs phone home, leak NTLM hashes or trigger SSRF in converters | Not integrated (offensive payloads). Taken defensively: `doc.html-to-pdf-input` and `doc.pdfjs-eval` rules and an "untrusted documents" section in the defense playbook |
| [blacklanternsecurity/bbot](https://github.com/blacklanternsecurity/bbot) | ~10.7k | AGPL-3.0 | Recursive internet attack-surface discovery | Not integrated: this kit reviews code and never probes live systems. The README points users to run such tools themselves against domains they own |

## Measured
- Rule corpus: 135/135 rules covered, 150/150 planted issues detected, 0 false positives on 113 safe twins (it found and
  fixed a real false positive in the existing XSS rule: `el.innerHTML = '<b>static</b>'` was flagged).
- Dependency audit on a sample project (Django 2.2.0, PyYAML 5.3, lodash 4.17.15, minimist 0.0.8) against live OSV,
  CISA KEV and EPSS: 51 advisories after merging duplicate ids (87 before), one upgrade target per package, ~6 s.

## Not adopted, and why
- Live verification of leaked secrets against provider APIs (trufflehog): it sends the secret to a third party. We tell
  the user to rotate instead.
- Exploit generation or live probing (Shannon, malicious-pdf, bbot): outside a defensive, code-review kit.
- Full YAML/AST parsing: kept zero-dependency; the GitHub Actions multi-line rule uses indentation-aware regex instead.
