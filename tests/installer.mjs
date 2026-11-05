// Installer safety tests, shared by every kit (same file in each repo; it reads the kit's bin from package.json).
// Each case is a way an installer can damage a user's project; see bin/kit-installer.mjs for the rules.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const BIN = path.join(ROOT, Object.values(pkg.bin)[0]);
const run = (...args) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' });
const info = JSON.parse(run('kit-info').stdout);
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), `${info.id}-inst-`));
const write = (p, s) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, s); };
const read = (p) => fs.readFileSync(p, 'utf8');
function snapshot(dir) {
  const out = {};
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); e.isDirectory() ? walk(p) : (out[path.relative(dir, p).split(path.sep).join('/')] = read(p)); } };
  walk(dir); return out;
}
const firstSkill = info.owned.find((p) => p.startsWith('.claude/skills/'));
const firstAgent = info.owned.find((p) => p.startsWith('.claude/agents/'));
const manifestOf = (dir, kitDir = info.kitDir) => path.join(dir, kitDir, 'manifest.json');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

test('init then remove leaves the project exactly as it was', () => {
  const dir = tmp();
  write(path.join(dir, 'AGENTS.md'), '# Mine\n\nMy rules.\n');
  write(path.join(dir, 'src', 'app.js'), 'keep\n');
  const before = snapshot(dir);
  let r = run('init', dir); assert.equal(r.status, 0, r.stderr);
  const m = JSON.parse(read(manifestOf(dir)));
  assert.equal(m.kit, info.id);
  for (const p of info.owned) assert.ok(fs.existsSync(path.join(dir, p)), `missing ${p}`);
  assert.match(read(path.join(dir, 'AGENTS.md')), /My rules\./);
  r = run('update', dir); assert.equal(r.status, 0, r.stderr);
  r = run('remove', dir); assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(snapshot(dir), before);
});

test('--kit-dir pointing at an existing user folder is refused and the folder is untouched', () => {
  const dir = tmp();
  write(path.join(dir, 'src', 'app.js'), 'important\n');
  const r = run('init', dir, '--kit-dir', 'src', '--tools', 'agents');
  assert.equal(r.status, 2, r.stdout + r.stderr);
  assert.equal(read(path.join(dir, 'src', 'app.js')), 'important\n');
  assert.ok(!fs.existsSync(path.join(dir, 'AGENTS.md')), 'nothing may be written after a refusal');
});

test('--kit-dir outside the project, the project itself, or overlapping kit paths is refused', () => {
  const dir = tmp();
  write(path.join(dir, 'keep.txt'), 'x');
  for (const bad of ['.', '..', '../elsewhere', os.tmpdir(), '.claude', '.claude/skills', 'AGENTS.md']) {
    const r = run('init', dir, '--kit-dir', bad);
    assert.equal(r.status, 2, `--kit-dir ${bad} was accepted`);
  }
  assert.deepEqual(Object.keys(snapshot(dir)), ['keep.txt']);
});

test('a kit folder made by another tool is never deleted', () => {
  const dir = tmp();
  write(path.join(dir, '.other-kit', 'manifest.json'), JSON.stringify({ kit: 'someone-else', version: '1.0.0', kitDir: '.other-kit', tools: [] }));
  write(path.join(dir, '.other-kit', 'data.txt'), 'theirs');
  assert.equal(run('init', dir, '--kit-dir', '.other-kit').status, 2);
  assert.equal(run('remove', dir, '--kit-dir', '.other-kit').status, 2);
  assert.equal(read(path.join(dir, '.other-kit', 'data.txt')), 'theirs');
});

test('a tampered manifest cannot make remove or update delete anything outside the kit', () => {
  const parent = tmp(); const dir = path.join(parent, 'project');
  write(path.join(parent, 'outside.txt'), 'outside');
  write(path.join(dir, 'src', 'app.js'), 'keep');
  assert.equal(run('init', dir).status, 0);
  const mf = manifestOf(dir); const m = JSON.parse(read(mf));
  fs.writeFileSync(mf, JSON.stringify({ ...m, kitDir: '../..' }));
  assert.equal(run('remove', dir).status, 2, 'remove followed a kitDir that leaves the project');
  fs.writeFileSync(mf, JSON.stringify({ ...m, owned: [...m.owned, 'src', '../outside.txt', 'src/app.js'], backups: ['../outside.txt', 'src'] }));
  assert.equal(run('update', dir).status, 0);
  fs.writeFileSync(mf, JSON.stringify({ ...JSON.parse(read(mf)), owned: ['src', '../outside.txt', ...m.owned] }));
  assert.equal(run('remove', dir).status, 0);
  assert.equal(read(path.join(dir, 'src', 'app.js')), 'keep');
  assert.equal(read(path.join(parent, 'outside.txt')), 'outside');
});

test('your own skill with the same name is not overwritten; --force backs it up and remove restores it', () => {
  const dir = tmp();
  const mine = path.join(dir, firstSkill, 'SKILL.md');
  write(mine, 'MY OWN SKILL\n');
  let r = run('init', dir);
  assert.equal(r.status, 2, 'install overwrote a user skill without --force');
  assert.match(r.stderr, new RegExp(firstSkill.replace(/[.]/g, '\\.')));
  assert.equal(read(mine), 'MY OWN SKILL\n');
  assert.ok(!fs.existsSync(path.join(dir, info.kitDir)), 'a refused install must not leave a kit folder');
  r = run('init', dir, '--force'); assert.equal(r.status, 0, r.stderr);
  assert.notEqual(read(mine), 'MY OWN SKILL\n');
  assert.equal(read(path.join(dir, info.kitDir, 'backup', firstSkill, 'SKILL.md')), 'MY OWN SKILL\n');
  r = run('update', dir); assert.equal(r.status, 0, r.stderr);
  assert.equal(read(path.join(dir, info.kitDir, 'backup', firstSkill, 'SKILL.md')), 'MY OWN SKILL\n', 'update lost the backup');
  r = run('remove', dir); assert.equal(r.status, 0, r.stderr);
  assert.equal(read(mine), 'MY OWN SKILL\n');
});

test('another kit installed in the same project survives install and remove', () => {
  const dir = tmp();
  write(path.join(dir, '.claude', 'agents', 'other-kit-reviewer.md'), 'OTHER AGENT');
  write(path.join(dir, '.claude', 'skills', 'other-kit', 'SKILL.md'), 'OTHER SKILL');
  write(path.join(dir, 'AGENTS.md'), '<!-- other-kit:start -->\nOther kit block\n<!-- other-kit:end -->\n');
  assert.equal(run('init', dir).status, 0);
  assert.equal(run('remove', dir).status, 0);
  assert.equal(read(path.join(dir, '.claude', 'agents', 'other-kit-reviewer.md')), 'OTHER AGENT');
  assert.equal(read(path.join(dir, '.claude', 'skills', 'other-kit', 'SKILL.md')), 'OTHER SKILL');
  assert.equal(read(path.join(dir, 'AGENTS.md')), '<!-- other-kit:start -->\nOther kit block\n<!-- other-kit:end -->\n');
});

test('installs made by older kit versions (no ownership list) update and remove cleanly', () => {
  const dir = tmp();
  assert.equal(run('init', dir).status, 0);
  const mf = manifestOf(dir); const m = JSON.parse(read(mf));
  fs.writeFileSync(mf, JSON.stringify({ version: '0.1.0', kitDir: m.kitDir, tools: m.tools, installedAt: m.installedAt }));
  let r = run('update', dir); assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(read(mf)).kit, info.id);
  r = run('remove', dir); assert.equal(r.status, 0, r.stderr);
  assert.ok(!fs.existsSync(path.join(dir, firstAgent ?? firstSkill)));
});

test('copies under names used by older versions are removed only when they are provably this kit’s', () => {
  const pairs = Object.entries(info.legacyPaths);
  if (!pairs.length && !info.legacyMarkers.length) return;
  const dir = tmp();
  assert.equal(run('init', dir).status, 0);
  const mf = manifestOf(dir); const m = JSON.parse(read(mf));
  fs.writeFileSync(mf, JSON.stringify({ version: '0.2.0', kitDir: m.kitDir, tools: m.tools }));
  // Recreate what an old install left behind, plus one foreign file that happens to use an old name.
  const foreign = pairs.find(([, now]) => now.startsWith('.claude/agents/'))?.[0];
  for (const [old, now] of pairs) {
    const src = path.join(dir, now);
    if (old === foreign) write(path.join(dir, old), '---\nname: x\ndescription: somebody else’s agent\n---\n');
    else if (fs.existsSync(src)) fs.cpSync(src, path.join(dir, old), { recursive: true });
  }
  for (const mk of info.legacyMarkers) fs.appendFileSync(path.join(dir, 'AGENTS.md'), `\n<!-- ${mk}:start -->\nold block\n<!-- ${mk}:end -->\n`);
  const r = run('update', dir); assert.equal(r.status, 0, r.stderr);
  for (const [old] of pairs) {
    if (old === foreign) assert.ok(fs.existsSync(path.join(dir, old)), `deleted a foreign file at ${old}`);
    else assert.ok(!fs.existsSync(path.join(dir, old)), `old copy ${old} was left behind`);
  }
  for (const mk of info.legacyMarkers) assert.doesNotMatch(read(path.join(dir, 'AGENTS.md')), new RegExp(`${mk}:start`));
  assert.match(read(path.join(dir, 'AGENTS.md')), new RegExp(`${info.marker}:start`));
});

test('--tools limits what is written, and update/remove without an install change nothing', () => {
  const dir = tmp();
  assert.equal(run('update', dir).status, 1);
  assert.equal(run('remove', dir).status, 1);
  assert.equal(run('init', dir, '--tools', 'notepad').status, 2);
  assert.equal(run('init', dir, '--tools', 'gemini').status, 0);
  assert.ok(fs.existsSync(path.join(dir, 'GEMINI.md')));
  assert.ok(!fs.existsSync(path.join(dir, 'CLAUDE.md')));
  assert.ok(!fs.existsSync(path.join(dir, '.claude')));
  assert.equal(run('init', ROOT).status, 2, 'installed the kit into itself');
});

test('agent names carry the kit prefix so kits cannot collide', () => {
  assert.match(info.agentPrefix ?? '', /^[a-z0-9]+$/, 'kit config needs an agentPrefix');
  const agents = info.owned.filter((p) => p.startsWith('.claude/agents/')).map((p) => path.basename(p, '.md'));
  for (const a of agents) {
    assert.ok(a.startsWith(`${info.agentPrefix}-`), `agent ${a} lacks the kit prefix "${info.agentPrefix}-"`);
    const fm = read(path.join(ROOT, 'agents', `${a}.md`)).match(/^---\r?\n(?:[\s\S]*?\n)?name:\s*(\S+)/);
    assert.equal(fm?.[1], a, `agents/${a}.md frontmatter name must equal its file name`);
  }
});

test('CLI scripts detect "run directly" by real path (macOS /var symlinks, Windows 8.3 short names)', () => {
  // `import.meta.url === pathToFileURL(argv[1])` silently does nothing when the script is reached through a symlink or
  // a short name, which is how macOS and Windows CI runners spell their temp folders.
  const bad = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) { if (e.name !== 'node_modules') walk(p); } else if (p.endsWith('.mjs')) { const s = read(p); if (/process\.argv\[1\][^\n]*===|===[^\n]*process\.argv\[1\]/.test(s) && !/realPath\(process\.argv\[1\]\)/.test(s)) bad.push(path.relative(ROOT, p)); } } };
  walk(path.join(ROOT, 'skills'));
  assert.deepEqual(bad, [], 'use the realPath() entry check');
});

let failed = 0;
for (const t of tests) {
  try { await t.fn(); console.log(`✔ installer: ${t.name}`); }
  catch (e) { failed++; console.log(`✘ installer: ${t.name}\n  ${String(e.message).split('\n').join('\n  ')}`); }
}
console.log(`\ninstaller: ${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
