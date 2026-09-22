#!/usr/bin/env node
// The Protectors — security & code-quality scanner (zero dependencies).
// Usage: node scan.mjs [projectRoot] [--out .protectors] [--fail-on critical|high|medium|low|none] [--json]
// Writes <out>/findings.json, <out>/findings.sarif, <out>/FINDINGS.md
// Suppress a finding: add `protectors-ignore: <rule-id> <reason>` in a comment on the same or previous line,
// or list it in <root>/.protectors-ignore.json (committed) or .protectors/ignore.json (local):
//   [{ "rule": "id" | "*", "path": "prefix/", "reason": "..." }]   ("*" requires a path; reason is mandatory)
import fs from 'node:fs';
import path from 'node:path';
import { CODE_RULES, CONFIG_RULES, SECRET_RULES } from './rules.mjs';

const args = process.argv.slice(2);
const root = path.resolve(args.find((a, i) => !a.startsWith('--') && !args[i - 1]?.startsWith('--')) ?? process.cwd());
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const outDir = path.resolve(root, opt('--out', '.protectors'));
const failOn = opt('--fail-on', 'high');
const asJson = args.includes('--json');

const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', '.output', '.turbo', '.cache', 'coverage', 'vendor', '.venv', 'venv', '__pycache__', 'target', 'obj', 'Pods', '.gradle', '.idea', '.dart_tool', '.protectors', '.protectors-kit', '.immersive-kit', '.terraform', '.expo', 'site-packages', 'bower_components', '.pio', 'managed_components', 'sstate-cache']);
const SKIP_FILES = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|poetry\.lock|Pipfile\.lock|uv\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock|pubspec\.lock)$|\.min\.(js|css)$|\.map$|\.(png|jpe?g|gif|webp|avif|ico|svgz|pdf|zip|gz|tgz|jar|war|class|so|dll|dylib|exe|bin|woff2?|ttf|otf|eot|mp[34]|webm|mov|glb|gltf|hdr|exr|ktx2|wasm|lockb|db|sqlite)$/i;
const TEST_PATH = /(^|\/)(__tests__|__mocks__|tests?|spec|specs|fixtures?|examples?|samples?|docs?|e2e|cypress|playwright|stories)\/|\.(test|spec|stories)\.\w+$|_test\.(go|py)$/i;

function walk(dir, acc = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    if (IGNORE_DIRS.has(e.name) || e.isSymbolicLink()) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, acc);
    else acc.push(path.relative(root, full).split(path.sep).join('/'));
  }
  return acc;
}

// Ignore lists: .protectors-ignore.json (committed, reviewable) and .protectors/ignore.json (local).
// Entry: { "rule": "<id>" | "*", "path": "<path prefix>", "reason": "<why>" } — a reason is required.
const ignoreList = ['.protectors-ignore.json', path.join('.protectors', 'ignore.json')].flatMap((p) => {
  try { return JSON.parse(fs.readFileSync(path.join(root, p), 'utf8')); } catch { return []; }
}).filter((x) => x && x.rule && typeof x.reason === 'string' && x.reason.trim());
const isIgnored = (rule, file) => ignoreList.some((x) => (x.rule === rule || (x.rule === '*' && x.path)) && (!x.path || file.startsWith(x.path)));

const findings = [];
const seen = new Set();
function report({ rule, file, line = 1, col = 1, snippet = '', severity, title, cwe, owasp, fix, category }) {
  if (isIgnored(rule, file)) return;
  const key = `${rule}|${file}|${line}`;
  if (seen.has(key)) return;
  seen.add(key);
  let sev = severity;
  const context = TEST_PATH.test(file) ? 'test/docs' : 'source';
  if (context !== 'source' && category !== 'secret') sev = SEV[Math.min(SEV.indexOf(sev) + 1, SEV.length - 1)];
  findings.push({ rule, severity: sev, title, file, line, col, snippet: snippet.trim().slice(0, 180), cwe: cwe ?? null, owasp: owasp ?? null, fix: fix ?? null, category, context });
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

function applyRule(rule, file, text, category) {
  if (rule.requires && !rule.requires.test(text)) return;
  if (rule.requiresNot && rule.requiresNot.test(text)) return;
  if (rule.unless && rule.unless.test(text) && category !== 'secret') return;
  rule.re.lastIndex = 0;
  let m, n = 0;
  while ((m = rule.re.exec(text)) && n < 25) {
    if (m[0].length === 0) { rule.re.lastIndex++; continue; }
    n++;
    if (category === 'secret' && rule.unless && rule.unless.test(m[0])) continue;
    if (suppressed(text, m.index, rule.id)) continue;
    const { line, col, lineText } = lineOf(text, m.index);
    report({ rule: rule.id, file, line, col, snippet: category === 'secret' ? redact(lineText) : lineText, severity: rule.severity, title: rule.title, cwe: rule.cwe ?? 'CWE-798', owasp: rule.owasp ?? 'A07', fix: rule.fix ?? 'Remove the secret from the code, ROTATE it at the provider (it is compromised once committed), load it from environment/secret manager, and purge it from git history.', category });
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

// ---------- score ----------
const weight = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };
const counts = Object.fromEntries(SEV.map((s) => [s, findings.filter((f) => f.severity === s).length]));
const penalty = SEV.reduce((s, k) => s + Math.min(counts[k] * weight[k], k === 'critical' ? 100 : k === 'high' ? 60 : k === 'medium' ? 30 : 10), 0);
const score = Math.max(0, 100 - penalty);
const grade = counts.critical ? 'F' : score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
findings.sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);

const result = { generatedAt: new Date().toISOString(), root, filesScanned: scanned, score, grade, counts, findings };

// ---------- outputs ----------
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'findings.json'), JSON.stringify(result, null, 2));

const allRules = [...SECRET_RULES, ...CODE_RULES, ...CONFIG_RULES];
const sarifLevel = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const sarif = {
  $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
  runs: [{
    tool: { driver: { name: 'The Protectors', informationUri: 'https://github.com/Sarveshknocker/The-protectors-', rules: [...new Set(findings.map((f) => f.rule))].map((id) => {
      const r = allRules.find((x) => x.id === id); const f = findings.find((x) => x.rule === id);
      return { id, shortDescription: { text: f.title }, help: { text: f.fix ?? '' }, properties: { tags: [f.cwe, f.owasp, f.category].filter(Boolean), 'security-severity': String({ critical: 9.5, high: 7.5, medium: 5, low: 2, info: 0.5 }[r?.severity ?? f.severity]) } };
    }) } },
    results: findings.map((f) => ({ ruleId: f.rule, level: sarifLevel[f.severity], message: { text: `${f.title}. Fix: ${f.fix ?? ''}` }, locations: [{ physicalLocation: { artifactLocation: { uri: f.file === '.' ? 'README.md' : f.file }, region: { startLine: f.line, startColumn: f.col } } }] })),
  }],
};
fs.writeFileSync(path.join(outDir, 'findings.sarif'), JSON.stringify(sarif, null, 2));

const icon = { critical: '🟥', high: '🟧', medium: '🟨', low: '🟦', info: '⬜' };
const md = `# Security findings

_Generated ${result.generatedAt} · ${scanned} files scanned · **Score ${score}/100 (grade ${grade})**_

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |

${findings.length ? `| Sev | Rule | Location | Issue | Fix |
|---|---|---|---|---|
${findings.map((f) => `| ${icon[f.severity]} ${f.severity} | \`${f.rule}\` | \`${f.file}:${f.line}\`${f.context !== 'source' ? ' _(test/docs)_' : ''} | ${f.title}${f.cwe ? ` (${f.cwe})` : ''} | ${f.fix ?? ''} |`).join('\n')}` : 'No findings. 🎉'}

> Static pattern analysis. Confirm each finding in context; complement with dependency audit (npm audit / pip-audit / osv-scanner) and a manual review of the high-risk files in recon.md.
`;
fs.writeFileSync(path.join(outDir, 'FINDINGS.md'), md);

if (asJson) console.log(JSON.stringify(result, null, 2));
else {
  console.log(`\nThe Protectors scan — ${root}`);
  console.log(`Score ${score}/100 (grade ${grade}) · ${scanned} files · critical ${counts.critical} · high ${counts.high} · medium ${counts.medium} · low ${counts.low}\n`);
  for (const f of findings.slice(0, 60)) console.log(`${icon[f.severity]} ${f.severity.padEnd(8)} ${f.rule.padEnd(30)} ${f.file}:${f.line}`);
  if (findings.length > 60) console.log(`… ${findings.length - 60} more in ${path.relative(process.cwd(), path.join(outDir, 'FINDINGS.md'))}`);
  console.log(`\nReports: ${path.relative(process.cwd(), outDir) || outDir}/FINDINGS.md, findings.json, findings.sarif\n`);
}
const threshold = SEV.indexOf(failOn);
process.exit(failOn !== 'none' && findings.some((f) => SEV.indexOf(f.severity) <= threshold && f.context === 'source') ? 1 : 0);
