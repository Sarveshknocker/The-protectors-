# Ready-to-paste prompts

Agentic tools (Claude Code, Codex, Cursor, Copilot agent, Gemini CLI, Windsurf, Cline…) read the kit automatically after `init`.
For **chat-only AIs** (ChatGPT, Gemini web, Claude.ai): first run
`node bin/protectors.mjs recon <project>` and `node bin/protectors.mjs scan <project>`,
then attach `.protectors/recon.md`, `.protectors/FINDINGS.md` and the SKILL.md files mentioned below.

---

### 1. Full protection (autonomous, end to end)
```
Protect this project using The Protectors (.protectors-kit/skills/protect/SKILL.md).
Identify what it is, analyse every file, fix the vulnerabilities, build the defense system for this
platform, verify everything and give me the security report. Work autonomously.
```

### 2. Audit only (no code changes)
```
Using The Protectors, run recon, scan and deep review on this project and write SECURITY_REPORT.md
with prioritised findings and proposed patches — but do not modify any project files.
```

### 3. Focused hardening
```
Using The Protectors, harden <area: authentication / the API routes / the Electron main process /
the OTA update path / the IOCTL handlers> of this project. Follow the matching playbook and add tests.
```

### 4. Make it look professional
```
Using The Protectors' anti-amateur checklist (.protectors-kit/skills/protect-deep-review/references/anti-amateur.md),
clean up this repository so it looks enterprise-grade: secrets handling, validation, error handling,
logging, repo hygiene, CI. Keep behaviour identical and tests green.
```

### 5. Chat-only AI (no file access)
```
You are The Protectors security team. Follow the attached SKILL.md files. Attached are my recon and
scanner results. Step 1: tell me which files you need to read (highest risk first) and I will paste them.
Step 2: review them with the checklist. Step 3: give me complete patched files one at a time.
Step 4: write the SECURITY_REPORT. Never ask me to paste secret values.
```
