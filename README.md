# The Protectors

**An autonomous cybersecurity verification team you install into any project, for use with any AI coding assistant.**
Call it once. It works out what your project is, analyses every file, builds a defense system suited to that platform, checks its own fixes, and writes a prioritised security report with the patches applied.

Works with **Claude Code, OpenAI Codex, Cursor, GitHub Copilot, Gemini CLI, Windsurf, Cline/Roo, Aider, Jules, Amp, Zed**, and chat-only AIs.

```
your project ─► 1. Recon ─────► 2. Scan ──────────► 3. Deep review ──► 4. Defense ─────► 5. Verify ──────► 6. Report
                what is it?      135 tested rules,    coverage ledger,    platform          re-scan, evidence  SECURITY_REPORT.md
                attack surface   git history, deps    evidence-backed     playbook +        contract, tests,   score before → after,
                risk per file    (OSV+KEV+EPSS), SBOM findings, verified hardened code     build              actions for you
```

## What's new in 0.2
| Capability | What it does |
|---|---|
| **Dependency audit + SBOM** | Reads 14 lockfile formats, asks OSV.dev which versions are vulnerable, flags malicious packages, ranks by CISA KEV (exploited in the wild) and EPSS (likely to be exploited), and gives **one upgrade per package**. Writes a CycloneDX 1.5 SBOM. Only package names and versions leave the machine; `--offline` and `--exclude` keep even those local. |
| **Secrets in git history** | `scan --history` finds credentials that were deleted from the code but are still in old commits, with the commit that introduced them. |
| **135 rules, every one tested** | 35+ secret providers with an entropy check, injection, XSS, crypto, auth, SSRF, LLM features (model output executed, user text in system prompts), HTML→PDF renderers fed request data, GitHub Actions (multi-line script injection, `GITHUB_ENV` injection, self-hosted runners on PRs, token permissions), and platform rules. Each rule has annotated must-fire and must-not-fire examples; CI fails if any rule misses or misfires. |
| **Your own rules** | `.protectors-rules.json` adds project-specific checks, tested the same way. |
| **Baseline for CI** | Accept today's findings once; CI then fails only on new ones. |
| **Evidence contract** | Manual findings are recorded as confirmed (with a local reproduction), needs-validation (no severity until a missing fact is settled) or rejected, against a coverage ledger of what was actually reviewed. A checker enforces it, so the report cannot overclaim. |
| **CWE Top 25 + OWASP view** | Every finding is mapped; the report shows which CWE Top 25 weaknesses are present. |

## What it protects
| Project type | Examples it detects | Defense playbook highlights |
|---|---|---|
| **Website** | Next.js, React, Vue, Svelte, Astro, Angular, static HTML | Nonce CSP + security headers, XSS sinks, CSRF, secrets in bundles, WAF rules (Cloudflare / AWS WAF / ModSecurity) |
| **API / backend** | Express, Fastify, Nest, FastAPI, Django, Flask, Spring, ASP.NET, Laravel, Rails, Go, Supabase/Firebase | Deny-by-default auth, IDOR checks, schema validation, rate limiting, JWT/OAuth hardening, SSRF guards, problem+json errors |
| **Mobile app** | Android, iOS, React Native/Expo, Flutter, Capacitor | Keychain/Keystore storage, TLS + pinning, R8/obfuscation, Play Integrity / App Attest, WebView & deep-link lockdown |
| **Desktop software** | Electron, Tauri, .NET, Python GUI | contextIsolation/sandbox, narrow IPC, navigation lockdown, fuses, signed updates, code signing |
| **Browser extension** | Chrome/Edge/Firefox MV2/MV3 | Least-privilege manifest, strict CSP, sender + schema validated messaging, MV3 migration |
| **CLI / library** | npm/PyPI packages, Go/Rust binaries, scripts | No-shell exec, path containment, package `files` allow-list, provenance publishing |
| **Cloud / IaC** | Terraform, Docker, Compose, Kubernetes, Helm, serverless, CI | Least-privilege IAM, no public buckets/ports, non-root containers, Pod Security, OIDC CI, pinned actions |
| **Firmware / IoT** | PlatformIO, Arduino, ESP-IDF, Zephyr, STM32, FreeRTOS, Yocto, embedded Rust | Per-device credentials, secure boot, signed OTA + anti-rollback, flash encryption, JTAG/SWD lockdown, TLS verification |
| **Drivers / kernel** | Linux kernel modules, Windows KMDF/WDM, macOS DriverKit, libusb/HID | IOCTL validation, checked user copies, info-leak prevention, device ACLs, `ExAllocatePool2`, no physical-memory primitives |

It also checks for **amateur-looking code**: committed secrets, silent `catch {}`, debug leftovers, missing validation, no lockfile/CI/SECURITY.md/tests, stack traces sent to users, and more (24-point checklist).

## Install into a project
Requires Node ≥ 18.

```bash
npx github:Sarveshknocker/The-protectors- init path/to/your-project
```
or
```bash
git clone https://github.com/Sarveshknocker/The-protectors-.git
node The-protectors-/bin/protectors.mjs init path/to/your-project
```

`init` copies the kit to `.protectors-kit/` and adds a short instruction section for every AI tool. It never overwrites your existing instructions:

| File | Read by |
|---|---|
| `AGENTS.md` | Codex, Jules, Amp, Aider, Zed, OpenCode, Factory, Devin… |
| `CLAUDE.md` + `.claude/skills/*` + `.claude/agents/*` | Claude Code |
| `GEMINI.md` | Gemini CLI |
| `.github/copilot-instructions.md` | GitHub Copilot |
| `.cursor/rules/the-protectors.mdc` | Cursor |
| `.windsurf/rules/the-protectors.md` | Windsurf |
| `.clinerules/the-protectors.md` | Cline / Roo Code |

Options: `--tools agents,cursor,claude` to install only some adapters · `update` to refresh · `remove` to uninstall (keeps your `.protectors/` reports).

**Claude Code plugin** (alternative): `/plugin marketplace add Sarveshknocker/The-protectors-` then `/plugin install the-protectors@the-protectors`.

## Use it
Open your project in your AI tool and say:

> Protect this project using The Protectors.

That's it. The AI runs all six phases on its own and writes everything to `.protectors/`:

| File | Contents |
|---|---|
| `recon.md` / `recon.json` | Project type, languages, entry points, per-file risk inventory |
| `FINDINGS.md` / `findings.json` / `findings.sarif` | Scanner results incl. git history and dependencies (secrets redacted); SARIF shows up in GitHub Code Scanning |
| `DEPENDENCIES.md` / `deps.json` / `sbom.cdx.json` | Upgrade plan, advisories with CVSS / KEV / EPSS, CycloneDX SBOM |
| `THREAT_MODEL.md` | Assets, trust boundaries, STRIDE threats |
| `review.json` / `coverage.json` / `REVIEW_STATUS.md` | Manual findings under the evidence contract and the coverage ledger |
| `SECURITY_REPORT.md` | Final report: score before → after, fixed/open issues, defenses implemented, **actions for you** |

It stops only for actions an AI shouldn't take on its own: rotating leaked keys, rewriting git history, deploying, or changing cloud settings. Those come back to you as a checklist with exact commands.

More prompts (including for chat-only AIs): [prompts/README.md](prompts/README.md).

## CLI (works without any AI too)
```bash
node bin/protectors.mjs recon <project>                    # what is it + risk inventory
node bin/protectors.mjs scan  <project> --fail-on high     # CI gate: exit 1 on high/critical
node bin/protectors.mjs scan  <project> --history          # + secrets anywhere in git history
node bin/protectors.mjs scan  <project> --write-baseline .protectors-baseline.json   # accept today's findings
node bin/protectors.mjs scan  <project> --baseline .protectors-baseline.json --fail-on high   # CI: new findings only
node bin/protectors.mjs deps  <project> [--offline] [--exclude '^@yourco/']   # vulnerabilities + SBOM
node bin/protectors.mjs rule-test <folder> --require-coverage   # test your .protectors-rules.json
node bin/protectors.mjs review-check <project> [--complete]     # evidence contract + coverage ledger
```
Suppress a confirmed false positive with a comment on or above the line (`// protectors-ignore: <rule-id> <reason>`), or in a committed `.protectors-ignore.json` (`[{ "rule": "<id>" | "*", "path": "prefix/", "reason": "…" }]`, where a reason is required).

## What's inside
```
skills/
  protect/              orchestrator: autonomous 6-phase workflow, severity model, ethics
  protect-recon/        project-type detection + per-file risk inventory        (scripts/recon.mjs)
  protect-scan/         135 tested rules, git history, baseline, custom rules → Markdown/JSON/SARIF
                        (scripts/scan.mjs, rules.mjs, rule-test.mjs)
  protect-deps/         lockfiles → OSV + CISA KEV + EPSS → upgrade plan + CycloneDX SBOM (scripts/deps.mjs)
  protect-deep-review/  coverage ledger + evidence contract, ASVS-aligned and anti-amateur checklists
  protect-defense/      9 platform playbooks + production templates (Node, Next.js, FastAPI, Django,
                        Electron, MV3 extension, Android, Docker, nginx/WAF, CI, firmware, Linux & Windows drivers)
  protect-verify/       verification loop, evidence checker (scripts/review-check.mjs), SECURITY_REPORT template
agents/                 recon-analyst, security-reviewer, finding-verifier, hardening-engineer, verification-auditor
evals/                  with-kit vs baseline cases with planted issues and graders
research/BENCHMARK.md   what we learned from the leading open-source security tools
adapters/entry.md       instruction block written into each AI tool's file
bin/protectors.mjs      installer + CLI
tests/run.mjs           end-to-end tests: vulnerable fixtures per platform, mock OSV/KEV/EPSS, git history, baseline
tests/rules/            annotated corpus: every rule must fire on `ruleid` lines and stay quiet on `ok` lines
```

## Limitations
- **No tool can prove there are no vulnerabilities.** Pattern scanning plus AI review finds most common and many subtle issues. Logic flaws in complex systems still benefit from human experts. For payments, health, finance or safety-critical devices, follow up with an independent penetration test.
- **Leaked secrets must be rotated by you.** Deleting them from the code isn't enough.
- **The scanner uses heuristics.** It's tuned for low noise and tested against vulnerable and clean fixtures, but review findings in context. The AI's deep-review phase does that triage.
- **Driver and firmware templates are reference patterns.** Build and test them with your toolchain (WDK / kernel tree / ESP-IDF) and run the listed analyzers (SDV, Driver Verifier, sparse, fuzzers) before shipping.
- **Dependency data comes from OSV.dev, CISA and FIRST.** Without network access, `deps` still writes the SBOM and says vulnerabilities were not checked.
- **Defensive use only.** Point it at projects you own or are authorised to assess. It never probes live systems. For your internet-facing attack surface (subdomains, exposed services), run a dedicated tool such as [bbot](https://github.com/blacklanternsecurity/bbot) yourself, only against domains you own.

## Related kits
[3D-animated-web-developer](https://github.com/Sarveshknocker/3D-animated-web-developer) · [The-Ai-Maker-](https://github.com/Sarveshknocker/The-Ai-Maker-) · [The-Hardware-engineering](https://github.com/Sarveshknocker/The-Hardware-engineering) · [Idea Enhancer](https://github.com/Sarveshknocker/-Idea-Enhancer-and-Value-Maximiser) · [The-Reconstructor](https://github.com/Sarveshknocker/The-Reconstructor).

## Credits
Ideas adapted (re-implemented, not copied) from leading open-source tools are listed in [CREDITS.md](CREDITS.md); the comparison is in [research/BENCHMARK.md](research/BENCHMARK.md).

## Develop
```bash
npm test              # all tests (offline: OSV/KEV/EPSS are mocked)
npm run test:rules    # rule corpus only
```
License: MIT.
