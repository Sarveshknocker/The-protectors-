# Common controls (every project)

## Mandatory
1. **Secrets**: remove from code → env/secret manager; add `.env.example` (names only); validate config at startup (`templates/node/env.ts` / pydantic-settings). Add committed-secret rotation + history purge to "Actions for you":
   ```bash
   git filter-repo --path <file> --invert-paths      # or --replace-text with a redaction list
   git push --force-with-lease --all                   # coordinate with the team first
   ```
2. **.gitignore** includes `templates/repo/gitignore-security.txt` entries.
3. **SECURITY.md** from template (contact, supported versions, response SLA).
4. **Dependency hygiene**: lockfile committed; Dependabot/Renovate; fix critical/high advisories reachable in prod.
5. **CI security workflow** (`templates/repo/security-ci.yml`): Protectors scan with SARIF upload, CodeQL (supported languages), dependency review on PRs, secret scanning. Least-privilege `permissions:`; third-party actions pinned by SHA.
6. **Error handling**: no silent catches in security-relevant paths; no stack traces to users.
7. **Logging**: structured, redacts secrets/PII; security events logged.

## Recommended
- Pre-commit secret scanning (gitleaks hook) and linting.
- SBOM generation on release (`npx @cyclonedx/cyclonedx-npm`, `syft`).
- Signed commits/tags and releases (Sigstore/cosign for containers).
- Branch protection: required reviews + required status checks (user action in GitHub settings).
- CODEOWNERS for security-sensitive paths (auth, payments, infra).
