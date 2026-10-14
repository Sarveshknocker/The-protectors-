# Credits

The Protectors' code is original. These projects and data sources shaped ideas in it; thank you to their authors.

| Idea | Inspired by | Licence of the source |
|---|---|---|
| Evidence contract (boundary, trace, confirmed / needs-validation / rejected, severity only when confirmed), coverage ledger, independent verification, severity anchors, anti-patterns | [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) | MIT |
| Secret scanning across git history, entropy checks, baselines | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | MIT |
| Lockfile parsing across ecosystems and OSV batch queries | [google/osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 |
| SBOM generation and SARIF for dependency findings | [aquasecurity/trivy](https://github.com/aquasecurity/trivy), [anchore/syft](https://github.com/anchore/syft) | Apache-2.0 |
| Annotated rule tests (`ruleid:` / `ok:`) and project-specific rules | [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 (idea only, no code) |
| GitHub Actions security checks | [zizmorcore/zizmor](https://github.com/zizmorcore/zizmor), [ossf/scorecard](https://github.com/ossf/scorecard) | MIT, Apache-2.0 |
| Reproduce-before-report for AI security agents | [google/mantis](https://github.com/google/mantis) | Apache-2.0 |
| Untrusted-document threat model (phone-home, NTLM leak, converter SSRF), used defensively | [jonaslejon/malicious-pdf](https://github.com/jonaslejon/malicious-pdf) | BSD-2-Clause (idea only) |

Data: [OSV.dev](https://osv.dev) (vulnerabilities), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(exploited vulnerabilities), [FIRST EPSS](https://www.first.org/epss/) (exploit prediction), MITRE
[CWE Top 25](https://cwe.mitre.org/top25/), [OWASP Top 10](https://owasp.org/Top10/) and the
[OWASP Top 10 for LLM Applications](https://genai.owasp.org/).
