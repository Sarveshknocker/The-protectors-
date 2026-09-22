# Working on The Protectors kit itself

This repo is a tool-agnostic security kit, not an application. Rules for changing it:
- Skills live in `skills/<name>/SKILL.md` with frontmatter `name` (must equal the folder) and `description`. Bundled files go in `references/`, `templates/`, `scripts/` inside the skill and are referenced with those relative paths.
- Plain Markdown only; no tool-specific syntax in skills. Refer to kit files as `<kit>/…`.
- Scripts: zero-dependency Node ≥ 18 ESM (`.mjs`), cross-platform.
- **Scanner rules** (`skills/protect-scan/scripts/rules.mjs`): every new rule needs a positive fixture and must not fire on `tests`' clean fixtures or on the kit's own templates. Prefer precision over recall; the AI deep review covers what regexes can't.
- **Never commit secret-shaped strings.** Test fixtures assemble fake secrets at runtime (see `FAKE` in `tests/run.mjs`), otherwise GitHub push protection and secret scanners will flag this repo.
- Templates must type-check / compile against current library versions and pass the scanner.
- Run `npm test` before committing.
- `CLAUDE.md` just points here.
