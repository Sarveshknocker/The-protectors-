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

## Untrusted documents (PDF, HTML→PDF, Office, images)
Files and markup from users are an attack surface in their own right: PDFs can carry JavaScript, form actions and
remote references that "phone home" or leak NTLM hashes when opened; HTML-to-PDF and screenshot engines will fetch
any URL in the markup (cloud metadata, internal services, `file://`).
- **Server-side rendering of user HTML** (Puppeteer/Playwright, wkhtmltopdf, WeasyPrint, pdfkit): render only your own
  templates with escaped data; intercept requests and allow only your asset origin; disable JavaScript and local file access
  (`--disable-local-file-access`); run the renderer in a container with no cloud metadata route and no credentials.
- **Viewing untrusted PDFs in the browser**: PDF.js with `isEvalSupported: false` and pdfjs-dist ≥ 4.2.67 (CVE-2024-4367);
  serve uploads from a separate sandbox origin with `Content-Disposition: attachment` unless they must be shown inline,
  `X-Content-Type-Options: nosniff`, and a CSP of `sandbox` for the download route.
- **Processing uploads** (thumbnails, text extraction, conversion with LibreOffice/ImageMagick/Ghostscript/poppler): run in an
  isolated worker with CPU, memory and time limits, no network, an allow-list of types checked by content (magic bytes) not
  name, and the converter kept patched (they have a long CVE history). Strip active content before re-serving files.
- **Desktop apps opening documents**: never let a document trigger outbound requests to arbitrary hosts or UNC paths; block
  `file://` and `\\server\share` links in viewers built on Electron/WebView.
