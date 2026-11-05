#!/usr/bin/env node
// The Protectors — installer + CLI. Works for any AI coding tool.
//
//   node bin/protectors.mjs init   [targetDir] [--tools all|claude,cursor,...] [--kit-dir .protectors-kit] [--force]
//   node bin/protectors.mjs update [targetDir]   (re-copies kit, refreshes instruction blocks)
//   node bin/protectors.mjs remove [targetDir]   (removes only what the kit installed; leaves .protectors/ reports)
//   node bin/protectors.mjs recon|scan|deps|rule-test|review-check ... (proxies to the kit scripts)
//
// Or without cloning:  npx github:Sarveshknocker/The-protectors- init
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { installerCommand } from './kit-installer.mjs';

const KIT_SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const KIT = {
  id: 'the-protectors', name: 'The Protectors', marker: 'protectors', kitDir: '.protectors-kit', agentPrefix: 'protectors',
  parts: ['skills', 'agents', 'adapters', 'README.md', 'LICENSE'], ruleFile: 'the-protectors', kitSrc: KIT_SRC,
  description: 'The Protectors security kit — use for security audits, hardening, vulnerability fixes, secure coding and making code enterprise-ready',
  next: 'Next: open the project in your AI tool and say, e.g.\n  "Protect this project using The Protectors kit: analyse every file, harden it and give me the security report."',
  kept: '.protectors/ reports',
  legacyPaths: {
    '.claude/skills/protect': '.claude/skills/protectors',
    '.claude/agents/finding-verifier.md': '.claude/agents/protectors-finding-verifier.md',
    '.claude/agents/hardening-engineer.md': '.claude/agents/protectors-hardening-engineer.md',
    '.claude/agents/recon-analyst.md': '.claude/agents/protectors-recon-analyst.md',
    '.claude/agents/security-reviewer.md': '.claude/agents/protectors-security-reviewer.md',
    '.claude/agents/verification-auditor.md': '.claude/agents/protectors-verification-auditor.md',
  },
};

const [cmd = 'help', ...rest] = process.argv.slice(2);

function runScript(rel, args) {
  const r = spawnSync(process.execPath, [path.join(KIT_SRC, rel), ...args], { stdio: 'inherit' });
  process.exit(r.status ?? 1);
}

if (!installerCommand(KIT, cmd, rest)) {
  switch (cmd) {
    case 'recon': runScript('skills/protect-recon/scripts/recon.mjs', rest); break;
    case 'scan': runScript('skills/protect-scan/scripts/scan.mjs', rest); break;
    case 'deps': runScript('skills/protect-deps/scripts/deps.mjs', rest); break;
    case 'rule-test': runScript('skills/protect-scan/scripts/rule-test.mjs', rest); break;
    case 'review-check': runScript('skills/protect-verify/scripts/review-check.mjs', rest); break;
    default:
      console.log(`The Protectors — autonomous security verification team for any AI coding tool

Commands:
  init   [dir] [--tools all|agents,claude,gemini,copilot,cursor,windsurf,cline] [--kit-dir .protectors-kit] [--force]
  update [dir]        refresh kit + instruction files
  remove [dir]        uninstall: removes only what the kit installed, restores anything it backed up (keeps .protectors/ reports)
  recon  [dir]        identify project type + per-file risk inventory → .protectors/recon.{json,md}
  scan   [dir]        security scan → .protectors/FINDINGS.md, findings.json, findings.sarif
                      [--history] [--baseline f | --write-baseline f] [--fail-on …] [--json]
  deps   [dir]        dependency vulnerabilities (OSV + CISA KEV + EPSS) + CycloneDX SBOM
                      [--offline] [--exclude regex] [--prod-only] [--fail-on …]
  rule-test <dir>     run annotated rule tests (built-in + .protectors-rules.json) [--require-coverage]
  review-check [dir]  validate review.json + coverage.json evidence contract [--complete]

The installer never overwrites files it did not create; --force backs them up first and remove restores them.`);
  }
}
