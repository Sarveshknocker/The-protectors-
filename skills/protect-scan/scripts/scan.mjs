#!/usr/bin/env node
// The Protectors — security & code-quality scanner (zero dependencies).
// Usage: node scan.mjs [projectRoot] [--out .protectors] [--fail-on critical|high|medium|low|none] [--json]
//                      [--history [--max-commits 2000]] [--baseline file] [--write-baseline file] [--no-deps]
// Writes <out>/findings.json, <out>/findings.sarif, <out>/FINDINGS.md
// --history       also scans every commit's added lines for secrets (removed-but-still-in-history leaks)
// --baseline f    findings whose fingerprint is in f are marked "baseline" and do not fail the run (CI: new only)
// Dependency findings from <out>/deps.json (protect-deps) are merged unless --no-deps.
// Suppress a finding: add `protectors-ignore: <rule-id> <reason>` in a comment on the same or previous line,
// or list it in <root>/.protectors-ignore.json (committed) or .protectors/ignore.json (local):
//   [{ "rule": "id" | "*", "path": "prefix/", "reason": "..." }]   ("*" requires a path; reason is mandatory)
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { CODE_RULES, CONFIG_RULES, SECRET_RULES } from './rules.mjs';

const args = process.argv.slice(2);
const VALUE_FLAGS = /^--(out|fail-on|baseline|write-baseline|max-commits)$/;
const root = path.resolve(args.find((a, i) => !a.startsWith('--') && !VALUE_FLAGS.test(args[i - 1] ?? '')) ?? process.cwd());
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const scanHistory = args.includes('--history');
const maxCommits = Number(opt('--max-commits', 2000));
const baselineFile = opt('--baseline', null);
const writeBaselineFile = opt('--write-baseline', null);
const mergeDeps = !args.includes('--no-deps');
// CWE Top 25 Most Dangerous Software Weaknesses (MITRE, 2024 edition).
const CWE_TOP25 = ['CWE-79', 'CWE-787', 'CWE-89', 'CWE-352', 'CWE-22', 'CWE-125', 'CWE-78', 'CWE-416', 'CWE-862', 'CWE-434', 'CWE-94', 'CWE-20', 'CWE-77', 'CWE-287', 'CWE-269', 'CWE-502', 'CWE-200', 'CWE-863', 'CWE-918', 'CWE-119', 'CWE-476', 'CWE-798', 'CWE-190', 'CWE-400', 'CWE-306'];
const outDir = path.resolve(root, opt('--out', '.protectors'));
const failOn = opt('--fail-on', 'high');
const asJson = args.includes('--json');

const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', '.output', '.turbo', '.cache', 'coverage', 'vendor', '.venv', 'venv', '__pycache__', 'target', 'obj', 'Pods', '.gradle', '.idea', '.dart_tool', '.protectors', '.protectors-kit', '.immersive-kit', '.terraform', '.expo', 'site-packages', 'bower_components', '.pio', 'managed_components', 'sstate-cache']);
const SKIP_FILES = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|poetry\.lock|Pipfile\.lock|uv\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock|pubspec\.lock)$|\.min\.(js|css)$|\.map$|\.(png|jpe?g|gif|webp|avif|ico|svgz|pdf|zip|gz|tgz|jar|war|class|so|dll|dylib|exe|bin|woff2?|ttf|otf|eot|mp[34]|webm|mov|glb|gltf|hdr|exr|ktx2|wasm|lockb|db|sqlite)$/i;
const TEST_PATH = /(^|\/)(__tests__|__mocks__|tests?|spec|specs|fixtures?|examples?|samples?|docs?|e2e|cypress|playwright|stories)\/|\.(test|spec|stories)\.\w+$|_test\.(go|py)$/i;

// The kit's own installed copies (Claude Code adapter) contain rule regexes and must not be scanned.
const KIT_COPY = /^\.claude\/(skills\/protect(-[\w-]+)?|agents\/(recon-analyst|security-reviewer|hardening-engineer|verification-auditor)\.md)(\/|$)/;

function walk(dir, acc = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    if (IGNORE_DIRS.has(e.name) || e.isSymbolicLink()) continue;
    const full = path.join(dir, e.name);
    const rel = path.relative(root, full).split(path.sep).join('/');
    if (KIT_COPY.test(rel)) continue;
    if (e.isDirectory()) walk(full, acc);
    else acc.push(rel);
  }
  return acc;
}

// Ignore lists: .protectors-ignore.json (committed, reviewable) and .protectors/ignore.json (local).
// Entry: { "rule": "<id>" | "*", "path": "<path prefix>", "reason": "<why>" } — a reason is required.
const ignoreList = ['.protectors-ignore.json', path.join('.protectors', 'ignore.json')].flatMap((p) => {
  try { return JSON.parse(fs.readFileSync(path.join(root, p), 'utf8')); } catch { return []; }
}).filter((x) => x && x.rule && typeof x.reason === 'string' && x.reason.trim());
const isIgnored = (rule, file) => ignoreList.some((x) => (x.rule === rule || (x.rule === '*' && x.path)) && (!x.path || file.startsWith(x.path)));

// Project-specific rules: .protectors-rules.json
//   [{ "id": "no-legacy-auth", "severity": "high", "title": "...", "pattern": "regex", "flags": "i",
//      "files": "\\.(ts|js)$", "fix": "...", "cwe": "CWE-287", "owasp": "A07", "secret": false }]
// Ids are prefixed "custom."; test them with rule-test.mjs like the built-in rules.
const CUSTOM_RULES = (() => {
  const f = path.join(root, '.protectors-rules.json');
  if (!fs.existsSync(f)) return [];
  try {
    return JSON.parse(fs.readFileSync(f, 'utf8')).map((r) => {
      if (!r.id || !r.pattern || !SEV.includes(r.severity) || !r.title) throw new Error(`rule ${r.id ?? '?'} needs id, pattern, title and a valid severity`);
      return { id: `custom.${String(r.id).replace(/^custom\./, '')}`, severity: r.severity, title: r.title, fix: r.fix ?? null, cwe: r.cwe ?? null, owasp: r.owasp ?? null, secret: !!r.secret,
        re: new RegExp(r.pattern, `${(r.flags ?? '').replace(/g/g, '')}g`), files: new RegExp(r.files ?? '.'), ...(r.minEntropy ? { minEntropy: r.minEntropy } : {}) };
    });
  } catch (e) { console.error(`Invalid .protectors-rules.json: ${e.message}`); process.exit(2); }
})();

const findings = [];
const seen = new Set();
function report({ rule, file, line = 1, col = 1, snippet = '', severity, title, cwe, owasp, fix, category, context, ...extra }) {
  if (isIgnored(rule, file)) return;
  const key = `${rule}|${file}|${line}|${extra.commit ?? ''}`;
  if (seen.has(key)) return;
  seen.add(key);
  let sev = severity;
  context ??= TEST_PATH.test(file) ? 'test/docs' : 'source';
  if (context === 'test/docs' && category !== 'secret') sev = SEV[Math.min(SEV.indexOf(sev) + 1, SEV.length - 1)];
  findings.push({ rule, severity: sev, title, file, line, col, snippet: snippet.trim().slice(0, 180), cwe: cwe ?? null, owasp: owasp ?? null, fix: fix ?? null, category, context, ...extra });
}

function lineOf(text, idx) {
  let line = 1, last = 0;
  for (let i = 0; i < idx; i++) if (text.charCodeAt(i) === 10) { line++; last = i + 1; }
  return { line, col: idx - last + 1, lineText: text.slice(last, text.indexOf('\n', idx) === -1 ? undefined : text.indexOf('\n', idx)) };
}
function suppressed(text, idx, rule) {
  const start = text.lastIndexOf('\n', text.lastIndexOf('\n', idx - 1) - 1) + 1; // previous line start
  const end = text.indexOf('\n', idx);
  const window = text.slice(start, end === -1 ? undefined : end);
  return new RegExp(`protectors-ignore:?\\s*(${rule.replace(/\./g, '\\.')}|all)\\b`).test(window);
}
const redact = (s) => s.replace(/([A-Za-z0-9_\-+/=]{4})[A-Za-z0-9_\-+/=.]{6,}/g, '$1••••••');

/** Shannon entropy in bits per character. Random tokens score ~4–6; words and placeholders score low. */
const entropy = (s) => { const f = new Map(); for (const c of s) f.set(c, (f.get(c) ?? 0) + 1); let e = 0; for (const n of f.values()) { const p = n / s.length; e -= p * Math.log2(p); } return e; };
const secretValue = (match) => (match.match(/["'`]([^"'`]+)["'`]\s*$/) ?? [, match])[1];
const secretHash = (match) => crypto.createHash('sha256').update(secretValue(match)).digest('hex').slice(0, 16);
const SECRET_FIX = 'Remove the secret from the code, ROTATE it at the provider (it is compromised once committed), load it from environment/secret manager, and purge it from git history.';

/** Yields the usable matches of one secret rule in a text (used for files and for git history lines). */
function* secretMatches(rule, text) {
  rule.re.lastIndex = 0;
  let m, n = 0;
  while ((m = rule.re.exec(text)) && n < 25) {
    if (m[0].length === 0) { rule.re.lastIndex++; continue; }
    n++;
    if (rule.unless && rule.unless.test(m[0])) continue;
    if (rule.minEntropy && entropy(secretValue(m[0])) < rule.minEntropy) continue;
    yield m;
  }
}

function applyRule(rule, file, text, category) {
  if (rule.requires && !rule.requires.test(text)) return;
  if (rule.requiresNot && rule.requiresNot.test(text)) return;
  if (rule.unless && rule.unless.test(text) && category !== 'secret') return;
  if (category === 'secret') {
    for (const m of secretMatches(rule, text)) {
      if (suppressed(text, m.index, rule.id)) continue;
      const { line, col, lineText } = lineOf(text, m.index);
      report({ rule: rule.id, file, line, col, snippet: redact(lineText), severity: rule.severity, title: rule.title, cwe: rule.cwe ?? 'CWE-798', owasp: rule.owasp ?? 'A07', fix: rule.fix ?? SECRET_FIX, category, secretHash: secretHash(m[0]) });
    }
    return;
  }
  rule.re.lastIndex = 0;
  let m, n = 0;
  while ((m = rule.re.exec(text)) && n < 25) {
    if (m[0].length === 0) { rule.re.lastIndex++; continue; }
    n++;
    if (suppressed(text, m.index, rule.id)) continue;
    const { line, col, lineText } = lineOf(text, m.index);
    report({ rule: rule.id, file, line, col, snippet: lineText, severity: rule.severity, title: rule.title, cwe: rule.cwe, owasp: rule.owasp, fix: rule.fix, category });
    if (rule.fileLevel) break;
  }
}

// ---------- scan files ----------
const files = walk(root);
let scanned = 0;
for (const file of files) {
  if (SKIP_FILES.test(file)) continue;
  const full = path.join(root, file);
  let stat;
  try { stat = fs.statSync(full); } catch { continue; }
  if (stat.size > 1_500_000) continue;
  let text;
  try { text = fs.readFileSync(full, 'utf8'); } catch { continue; }
  if (text.includes('\u0000')) continue; // binary
  if (/\.(js|css)$/.test(file) && text.length > 5000 && text.split('\n').length < 5) continue; // minified bundle
  scanned++;
  for (const r of SECRET_RULES) applyRule(r, file, text, 'secret');
  for (const r of CODE_RULES) if (r.files.test(file)) applyRule(r, file, text, 'code');
  for (const r of CONFIG_RULES) if (r.files.test(file)) applyRule(r, file, text, 'config');
  for (const r of CUSTOM_RULES) if (r.files.test(file)) applyRule(r, file, text, r.secret ? 'secret' : 'custom');
}

// ---------- repository-level checks ----------
const exists = (p) => fs.existsSync(path.join(root, p));
const read = (p) => { try { return fs.readFileSync(path.join(root, p), 'utf8'); } catch { return ''; } };
const repo = (rule, severity, title, fix, file = '.', cwe = null, owasp = null) => report({ rule, file, severity, title, fix, cwe, owasp, category: 'repo' });

for (const f of files) {
  if (/(^|\/)\.env(\.[\w-]+)?$/.test(f) && !/\.(example|sample|template|defaults?)$/.test(f)) {
    const content = read(f);
    if (/=\s*\S/.test(content)) repo('repo.env-file-committed', 'high', 'Environment file with values present in the repository', 'Add it to .gitignore, remove from git (git rm --cached), rotate every value it contained, ship a .env.example instead.', f, 'CWE-538', 'A05');
  }
  if (/\.(pem|key|p12|pfx|jks|keystore|ppk)$/i.test(f) || /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/.test(f)) {
    if (!/public|\.pub$|cert\.pem$|chain\.pem$|fullchain/i.test(f)) repo('repo.key-material', 'critical', 'Private key / keystore file in the repository', 'Remove it, rotate/re-issue the key, purge from history (git filter-repo), store in a secret manager.', f, 'CWE-321', 'A02');
  }
}
const gi = read('.gitignore');
if (!exists('.gitignore')) repo('repo.no-gitignore', 'medium', 'No .gitignore', 'Add a .gitignore covering secrets (.env*, *.pem), build output and dependencies.');
else if (!/(^|\n)\s*\/?\.env/.test(gi)) repo('repo.gitignore-env', 'medium', '.gitignore does not exclude .env files', 'Add `.env`, `.env.*` and `!.env.example` to .gitignore.', '.gitignore');
if (!files.some((f) => /(^|\/)security\.md$/i.test(f))) repo('repo.no-security-policy', 'low', 'No SECURITY.md (vulnerability disclosure policy)', 'Add SECURITY.md with supported versions and a private reporting channel.');
if (!exists('.github/dependabot.yml') && !exists('renovate.json') && !exists('.github/renovate.json')) repo('repo.no-dependency-updates', 'low', 'No automated dependency updates', 'Add .github/dependabot.yml (or Renovate) for all ecosystems in the repo.');

const pkg = (() => { try { return JSON.parse(read('package.json')); } catch { return null; } })();
if (pkg) {
  const lock = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'bun.lock'].some(exists);
  if (!lock && Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).length) repo('deps.no-lockfile', 'medium', 'No lockfile — builds are not reproducible', 'Commit the lockfile and use `npm ci` / `pnpm install --frozen-lockfile` in CI.', 'package.json', 'CWE-1357', 'A06');
  for (const [name, v] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
    if (v === '*' || v === 'latest' || /^(git|https?):/.test(String(v))) repo('deps.unpinned', 'medium', `Dependency "${name}" is unpinned (${v})`, 'Pin to a semver range and rely on the lockfile.', 'package.json', 'CWE-1357', 'A06');
  }
  for (const [s, cmd] of Object.entries(pkg.scripts ?? {})) {
    if (/^(pre|post)?install$/.test(s) && /(curl|wget)[^|]*\|\s*(ba)?sh/.test(cmd)) repo('deps.install-script-pipe', 'high', `npm ${s} script pipes a download into a shell`, 'Remove; vendor or verify the script by checksum.', 'package.json', 'CWE-494', 'A08');
  }
}
const req = read('requirements.txt');
if (req) {
  const unpinned = req.split(/\r?\n/).filter((l) => l.trim() && !l.startsWith('#') && !l.startsWith('-') && !/[=<>~]=|===/.test(l));
  if (unpinned.length) repo('deps.python-unpinned', 'low', `${unpinned.length} unpinned Python requirement(s)`, 'Pin versions (pip-compile / uv lock) and use hashes (--require-hashes) for production.', 'requirements.txt', 'CWE-1357', 'A06');
}

// ---------- git history (secrets that were committed, even if later removed) ----------
let history = null;
if (scanHistory) {
  const git = spawnSync('git', ['-C', root, 'log', '--all', '-p', '--no-color', '--no-ext-diff', '-U0', `--max-count=${maxCommits}`, '--format=%x00%H %cI'], { encoding: 'utf8', maxBuffer: 1024 * 1024 * 1024 });
  if (git.status !== 0) history = { error: (git.stderr || 'git not available').trim().split('\n')[0] };
  else {
    const headHashes = new Set(findings.filter((f) => f.secretHash).map((f) => f.secretHash));
    const byHash = new Map(); let commits = 0;
    let commit = null; let date = null; let file = null; let line = 0;
    for (const raw of git.stdout.split('\n')) {
      if (raw.startsWith('\u0000')) { [commit, date] = raw.slice(1).split(' '); commits++; file = null; continue; }
      if (raw.startsWith('+++ ')) { file = raw.startsWith('+++ b/') ? raw.slice(6) : null; continue; }
      if (raw.startsWith('@@')) { line = Number(raw.match(/\+(\d+)/)?.[1] ?? 0); continue; }
      if (!file || !raw.startsWith('+') || raw.startsWith('+++')) continue;
      const text = raw.slice(1); line++;
      if (SKIP_FILES.test(file) || KIT_COPY.test(file) || /protectors-ignore/.test(text)) continue;
      for (const r of SECRET_RULES) for (const m of secretMatches(r, text)) {
        const h = secretHash(m[0]);
        // git log runs newest → oldest, so the last write wins: keep the first commit that introduced it.
        byHash.set(`${r.id}|${h}`, { rule: r, h, file, line: line - 1, commit, date, snippet: redact(text) });
      }
    }
    let leaked = 0;
    for (const { rule: r, h, file: f, line: l, commit: c, date: d, snippet } of byHash.values()) {
      const head = findings.find((x) => x.secretHash === h);
      if (head) { head.firstCommit = c.slice(0, 12); head.firstCommitDate = d; continue; }
      if (headHashes.has(h)) continue;
      const before = findings.length;
      report({ rule: `history.${r.id.replace(/^secret\./, '')}`, file: f, line: l, snippet, severity: r.severity, title: `${r.title} in git history (removed from the current code)`, cwe: 'CWE-798', owasp: 'A07', category: 'secret', context: 'history', commit: c.slice(0, 12), commitDate: d, secretHash: h,
        fix: `Still readable by anyone with the repository: ROTATE it now, then purge it (git filter-repo --replace-text) and force-push; ask forks/clones to re-clone. First committed in ${c.slice(0, 12)}.` });
      if (findings.length > before) leaked++;
    }
    history = { commits, secretsOnlyInHistory: leaked };
  }
}

// ---------- dependency findings from protect-deps ----------
let deps = null;
if (mergeDeps) {
  try {
    const d = JSON.parse(fs.readFileSync(path.join(outDir, 'deps.json'), 'utf8'));
    deps = { generatedAt: d.generatedAt, packages: d.packageCount, online: d.online, findings: d.findings.length };
    for (const f of d.findings) { if (!isIgnored(f.rule, f.file)) findings.push(f); }
  } catch { /* deps not run */ }
}

// ---------- fingerprints, baseline, compliance tags ----------
const norm = (s) => String(s ?? '').replace(/\s+/g, ' ').trim();
for (const f of findings) {
  f.fingerprint = crypto.createHash('sha256').update([f.rule, f.file, f.secretHash ?? f.vuln?.id ?? norm(f.snippet)].join('|')).digest('hex').slice(0, 20);
  if (f.cwe && CWE_TOP25.includes(f.cwe)) f.cweTop25 = true;
}
let baseline = null;
if (baselineFile) {
  try {
    const b = JSON.parse(fs.readFileSync(path.resolve(root, baselineFile), 'utf8'));
    const known = new Set((b.findings ?? b).map((x) => x.fingerprint ?? x));
    for (const f of findings) if (known.has(f.fingerprint)) f.baseline = true;
    baseline = { file: baselineFile, known: known.size, matched: findings.filter((f) => f.baseline).length };
  } catch (e) { console.error(`Cannot read baseline ${baselineFile}: ${e.message}`); process.exit(2); }
}
if (writeBaselineFile) {
  const out = path.resolve(root, writeBaselineFile);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify({ generatedAt: new Date().toISOString(), note: 'Accepted existing findings. Only fingerprints are stored (no code, no secrets). Review and shrink this file over time.', findings: findings.map((f) => ({ fingerprint: f.fingerprint, rule: f.rule, file: f.file })) }, null, 2));
}

// ---------- score ----------
const live = findings.filter((f) => !f.baseline);
const weight = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };
const counts = Object.fromEntries(SEV.map((s) => [s, findings.filter((f) => f.severity === s).length]));
const penalty = SEV.reduce((s, k) => s + Math.min(counts[k] * weight[k], k === 'critical' ? 100 : k === 'high' ? 60 : k === 'medium' ? 30 : 10), 0);
const score = Math.max(0, 100 - penalty);
const grade = counts.critical ? 'F' : score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
findings.sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);

const owaspCounts = {};
for (const f of findings) if (f.owasp) owaspCounts[f.owasp] = (owaspCounts[f.owasp] ?? 0) + 1;
const top25 = [...new Set(findings.filter((f) => f.cweTop25).map((f) => f.cwe))];
const result = { generatedAt: new Date().toISOString(), root, filesScanned: scanned, score, grade, counts, newCounts: baseline ? Object.fromEntries(SEV.map((s) => [s, live.filter((f) => f.severity === s).length])) : undefined, history, deps, baseline, compliance: { owasp: owaspCounts, cweTop25: top25 }, findings };

// ---------- outputs ----------
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'findings.json'), JSON.stringify(result, null, 2));

const allRules = [...SECRET_RULES, ...CODE_RULES, ...CONFIG_RULES, ...CUSTOM_RULES];
const sarifLevel = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const sarif = {
  $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
  runs: [{
    tool: { driver: { name: 'The Protectors', informationUri: 'https://github.com/Sarveshknocker/The-protectors-', rules: [...new Set(findings.map((f) => f.rule))].map((id) => {
      const r = allRules.find((x) => x.id === id); const f = findings.find((x) => x.rule === id);
      return { id, shortDescription: { text: f.title }, help: { text: f.fix ?? '' }, properties: { tags: ['security', f.cwe, f.owasp, f.category, f.cweTop25 ? 'cwe-top-25' : null].filter(Boolean), 'security-severity': String({ critical: 9.5, high: 7.5, medium: 5, low: 2, info: 0.5 }[r?.severity ?? f.severity]) } };
    }) } },
    results: findings.map((f) => ({ ruleId: f.rule, level: sarifLevel[f.severity], message: { text: `${f.title}. Fix: ${f.fix ?? ''}` }, partialFingerprints: { protectorsFingerprint: f.fingerprint }, ...(f.baseline ? { baselineState: 'unchanged' } : baseline ? { baselineState: 'new' } : {}), locations: [{ physicalLocation: { artifactLocation: { uri: f.file === '.' ? 'README.md' : f.file }, region: { startLine: f.line, startColumn: f.col } } }] })),
  }],
};
fs.writeFileSync(path.join(outDir, 'findings.sarif'), JSON.stringify(sarif, null, 2));

const icon = { critical: '🟥', high: '🟧', medium: '🟨', low: '🟦', info: '⬜' };
const where = (f) => `\`${f.file}:${f.line}\`${f.commit ? ` @${f.commit}` : ''}${f.context === 'test/docs' ? ' _(test/docs)_' : ''}${f.baseline ? ' _(baseline)_' : ''}`;
const md = `# Security findings

_Generated ${result.generatedAt} · ${scanned} files scanned${history?.commits ? ` · ${history.commits} commits of history` : ''}${deps ? ` · ${deps.packages} dependencies` : ''} · **Score ${score}/100 (grade ${grade})**_

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |
${baseline ? `\n**New since baseline:** ${SEV.map((s) => `${s} ${result.newCounts[s]}`).join(' · ')} (${baseline.matched} accepted in \`${baseline.file}\`)\n` : ''}
${findings.length ? `| Sev | Rule | Location | Issue | Fix |
|---|---|---|---|---|
${findings.map((f) => `| ${icon[f.severity]} ${f.severity} | \`${f.rule}\` | ${where(f)} | ${f.title}${f.cwe ? ` (${f.cwe}${f.cweTop25 ? ', Top 25' : ''})` : ''}${f.firstCommit ? ` — in history since ${f.firstCommit}` : ''} | ${f.fix ?? ''} |`).join('\n')}` : 'No findings. 🎉'}

## Compliance view
- OWASP categories hit: ${Object.entries(owaspCounts).sort().map(([k, v]) => `${k} ×${v}`).join(', ') || 'none'}
- CWE Top 25 (2024) weaknesses present: ${top25.join(', ') || 'none'}
${history?.error ? `- Git history not scanned: ${history.error}\n` : ''}${!scanHistory ? '- Git history not scanned (run with `--history`).\n' : ''}${deps ? '' : '- Dependencies not audited (run `protect-deps` first; its findings are merged here).\n'}
> Static pattern analysis. Confirm each finding in context and reproduce high/critical ones with a test (see protect-deep-review).
`;
fs.writeFileSync(path.join(outDir, 'FINDINGS.md'), md);

if (asJson) console.log(JSON.stringify(result, null, 2));
else {
  console.log(`\nThe Protectors scan — ${root}`);
  console.log(`Score ${score}/100 (grade ${grade}) · ${scanned} files · critical ${counts.critical} · high ${counts.high} · medium ${counts.medium} · low ${counts.low}`);
  // protectors-ignore: log.sensitive (prints a count, not a secret)
  if (history?.commits) console.log(`History: ${history.commits} commits, ${history.secretsOnlyInHistory} secret(s) only in history`);
  if (baseline) console.log(`Baseline: ${baseline.matched} accepted; new → ${SEV.map((s) => `${s} ${result.newCounts[s]}`).join(' · ')}`);
  console.log('');
  for (const f of findings.slice(0, 60)) console.log(`${icon[f.severity]} ${f.severity.padEnd(8)} ${f.rule.padEnd(30)} ${f.file}:${f.line}${f.commit ? ' @' + f.commit : ''}${f.baseline ? ' (baseline)' : ''}`);
  if (findings.length > 60) console.log(`… ${findings.length - 60} more in ${path.relative(process.cwd(), path.join(outDir, 'FINDINGS.md'))}`);
  console.log(`\nReports: ${path.relative(process.cwd(), outDir) || outDir}/FINDINGS.md, findings.json, findings.sarif\n`);
}
const threshold = SEV.indexOf(failOn);
process.exit(failOn !== 'none' && live.some((f) => SEV.indexOf(f.severity) <= threshold && (f.context === 'source' || f.context === 'history')) ? 1 : 0);
