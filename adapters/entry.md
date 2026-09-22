## The Protectors — security verification team

This project has **The Protectors** security kit installed at `{{KIT}}/`. Works for websites, APIs, mobile apps, desktop software, browser extensions, CLIs/libraries, cloud/IaC, firmware/IoT and drivers. When the user asks to secure, harden, audit, verify, pentest-review, "make it professional/enterprise-ready", or says "protect this project", **follow the kit instead of improvising**:

| Task | Open and follow |
|---|---|
| Full autonomous verification + hardening (end to end) | `{{KIT}}/skills/protect/SKILL.md` |
| Identify project type & attack surface | `{{KIT}}/skills/protect-recon/SKILL.md` |
| Automated scanning (secrets, injection, misconfig, deps) | `{{KIT}}/skills/protect-scan/SKILL.md` |
| File-by-file manual review + anti-amateur check | `{{KIT}}/skills/protect-deep-review/SKILL.md` |
| Build the defense system for this project type | `{{KIT}}/skills/protect-defense/SKILL.md` |
| Verify fixes and write the report | `{{KIT}}/skills/protect-verify/SKILL.md` |

Sub-agent role briefs (if your tool supports sub-agents): `{{KIT}}/agents/`.
Scripts are dependency-free Node ≥ 18: run them with your terminal tool (or ask the user to run them).

**Mode: autonomous.** One request should produce a finished, verified result: recon → scan → deep review → defenses → verify → report in `.protectors/SECURITY_REPORT.md`. Don't stop for approvals; pause only for destructive/outward actions (history rewrites, credential rotation, deploys), which go in the report as "Actions for you".

Hard rules, always:
1. Defensive work on this project only; never probe third-party or production systems.
2. Never print, copy or commit secret values; a committed secret must be rotated, not just deleted.
3. Stay native to the project's language, framework and conventions; keep build and tests green.
4. Every claim in the report needs evidence (file:line, command output, test name).
