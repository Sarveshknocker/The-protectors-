// Shared installer for Sarvesh's AI kits (The Protectors, Roblox Studio Company, Hardware Engineering,
// 3D-animated-web-developer, The Reconstructor, The AI Maker, Idea Enhancer). The SAME file ships in every kit:
// change it in one, copy it to all, run each kit's `npm test`.
//
// Safety rules (each one has a test in tests/installer.mjs):
//   1. Every path the installer touches resolves inside the target project. --kit-dir must be a sub-folder.
//   2. It deletes only what it created: the kit folder (recognised by its manifest) and the paths listed in the
//      manifest, and only those the current kit could have produced, so a crafted manifest cannot widen the delete.
//   3. It never overwrites a file or folder it does not own (e.g. your own .claude/skills/<name>). --force moves the
//      existing one into <kit-dir>/backup/ first, and `remove` puts it back.
//   4. Shared instruction files (AGENTS.md, CLAUDE.md, ...) are edited only between this kit's own markers.
import fs from 'node:fs';
import path from 'node:path';

const MANIFEST = 'manifest.json';
const AGENTS_MD_NOTE = 'Codex, Jules, Amp, Aider, Zed, OpenCode, Factory, Devin & other AGENTS.md readers';

const die = (msg, code = 2) => { console.error(`✖ ${msg}`); process.exit(code); };
const posix = (p) => p.split(path.sep).join('/');

/**
 * cfg: { id, name, marker, kitDir, parts, ruleFile, description, next, kept, kitSrc, agentPrefix,
 *        claudeBlock?, legacyMarkers?: [old marker], legacyPaths?: { 'old/path': 'current/path it became' } }
 * Legacy paths (names used by older kit versions) are removed on update/remove only when they are provably this kit's:
 * same frontmatter description as the item they became, or content that points into this kit's folder.
 * Returns true when `cmd` was an installer command (init, update, remove, kit-info).
 */
export function installerCommand(cfg, cmd, argv) {
  if (!['init', 'update', 'remove', 'kit-info'].includes(cmd)) return false;
  const flag = (name, def) => { const i = argv.indexOf(name); return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : def; };
  const valued = new Set(['--tools', '--kit-dir']);
  const positional = argv.filter((a, i) => !a.startsWith('--') && !valued.has(argv[i - 1]));
  const target = path.resolve(positional[0] ?? process.cwd());
  const k = kit(cfg);
  if (cmd === 'kit-info') { console.log(JSON.stringify({ id: cfg.id, kitDir: cfg.kitDir, agentPrefix: cfg.agentPrefix, legacyPaths: cfg.legacyPaths ?? {}, legacyMarkers: cfg.legacyMarkers ?? [], marker: cfg.marker, tools: Object.keys(k.tools), owned: k.ownedPaths(Object.keys(k.tools)) }, null, 2)); return true; }
  if (cmd === 'init') k.install(target, { tools: k.resolveTools(flag('--tools', 'all')), kitDir: flag('--kit-dir', cfg.kitDir), force: argv.includes('--force') });
  if (cmd === 'update') {
    const found = k.findInstall(target, flag('--kit-dir', null));
    if (!found) die(`${cfg.name} is not installed in ${target}: run init first.`, 1);
    k.install(target, { tools: found.manifest.tools, kitDir: found.kitDir, force: argv.includes('--force') });
  }
  if (cmd === 'remove') k.remove(target, flag('--kit-dir', null));
  return true;
}

function kit(cfg) {
  const START = `<!-- ${cfg.marker}:start -->`;
  const END = `<!-- ${cfg.marker}:end -->`;
  const tools = {
    agents: { file: 'AGENTS.md', block: true, note: AGENTS_MD_NOTE },
    claude: { file: 'CLAUDE.md', block: true, note: 'Claude Code (+ skills & agents copied into .claude/)' },
    gemini: { file: 'GEMINI.md', block: true, note: 'Gemini CLI' },
    copilot: { file: '.github/copilot-instructions.md', block: true, note: 'GitHub Copilot' },
    cursor: { file: `.cursor/rules/${cfg.ruleFile}.mdc`, note: 'Cursor', wrap: (b) => `---\ndescription: ${cfg.description}\nglobs:\nalwaysApply: false\n---\n\n${b}` },
    windsurf: { file: `.windsurf/rules/${cfg.ruleFile}.md`, note: 'Windsurf', wrap: (b) => `---\ntrigger: model_decision\ndescription: ${cfg.description}\n---\n\n${b}` },
    cline: { file: `.clinerules/${cfg.ruleFile}.md`, note: 'Cline / Roo Code', wrap: (b) => b },
  };
  const skills = () => fs.readdirSync(path.join(cfg.kitSrc, 'skills')).filter((s) => fs.statSync(path.join(cfg.kitSrc, 'skills', s)).isDirectory());
  const agents = () => (fs.existsSync(path.join(cfg.kitSrc, 'agents')) ? fs.readdirSync(path.join(cfg.kitSrc, 'agents')).filter((a) => a.endsWith('.md')) : []);

  // Every non-shared path this kit may create in a project, relative and POSIX-style.
  function ownedPaths(toolList) {
    const out = toolList.filter((t) => !tools[t].block).map((t) => tools[t].file);
    if (toolList.includes('claude')) {
      out.push(...skills().map((s) => `.claude/skills/${s}`), ...agents().map((a) => `.claude/agents/${a}`));
    }
    return out;
  }
  function sources(toolList) {
    const map = new Map();
    for (const t of toolList) if (!tools[t].block) map.set(tools[t].file, { kind: 'rule', tool: t });
    if (toolList.includes('claude')) {
      for (const s of skills()) map.set(`.claude/skills/${s}`, { kind: 'dir', from: path.join(cfg.kitSrc, 'skills', s) });
      for (const a of agents()) map.set(`.claude/agents/${a}`, { kind: 'file', from: path.join(cfg.kitSrc, 'agents', a) });
    }
    return map;
  }

  function inside(root, rel, what) {
    const abs = path.resolve(root, rel);
    const r = path.relative(root, abs);
    if (!r || r.startsWith('..') || path.isAbsolute(r)) die(`${what} must be a path inside ${root} (got "${rel}").`);
    return abs;
  }
  function readJSON(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; } }
  // Installs from kit versions before this installer have no `kit` field; recognise them by shape.
  const isOurs = (m) => !!m && (m.kit === cfg.id || (m.kit === undefined && typeof m.version === 'string' && typeof m.kitDir === 'string' && Array.isArray(m.tools)));

  function findInstall(root, kitDirFlag) {
    const kitDir = kitDirFlag ?? cfg.kitDir;
    const abs = inside(root, kitDir, '--kit-dir');
    const manifest = readJSON(path.join(abs, MANIFEST));
    if (!manifest) return null;
    if (!isOurs(manifest)) die(`${posix(path.relative(root, abs))}/ belongs to another tool (${manifest.kit ?? 'unknown'}); not touching it.`);
    if (manifest.kitDir !== undefined && path.resolve(root, manifest.kitDir) !== abs) die(`manifest in ${kitDir} points at "${manifest.kitDir}"; refusing (it may have been tampered with).`);
    const known = Object.keys(tools);
    return { kitDir: posix(path.relative(root, abs)), abs, manifest: { ...manifest, tools: (manifest.tools ?? []).filter((t) => known.includes(t)) } };
  }

  function copyDir(src, dst) {
    fs.mkdirSync(dst, { recursive: true });
    for (const e of fs.readdirSync(src, { withFileTypes: true })) {
      const s = path.join(src, e.name), d = path.join(dst, e.name);
      e.isDirectory() ? copyDir(s, d) : fs.copyFileSync(s, d);
    }
  }
  const copyAny = (s, d) => {
    if (!fs.existsSync(s)) return;
    if (fs.statSync(s).isDirectory()) copyDir(s, d);
    else { fs.mkdirSync(path.dirname(d), { recursive: true }); fs.copyFileSync(s, d); }
  };

  function upsertBlock(file, body) {
    const block = `${START}\n${body.trim()}\n${END}\n`;
    const prev = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    const re = new RegExp(`${START}[\\s\\S]*?${END}\\n?`);
    const next = re.test(prev) ? prev.replace(re, block) : (prev ? prev.replace(/\s*$/, '\n\n') : '') + block;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, next);
  }
  function removeBlock(file, marker = cfg.marker) {
    if (!fs.existsSync(file)) return false;
    const prev = fs.readFileSync(file, 'utf8');
    const next = prev.replace(new RegExp(`\\n*<!-- ${marker}:start -->[\\s\\S]*?<!-- ${marker}:end -->\\n?`), '\n');
    if (next === prev) return false;
    next.trim() ? fs.writeFileSync(file, next.replace(/^\n+/, '').replace(/\n+$/, '\n')) : fs.rmSync(file);
    return true;
  }

  // Older kit versions used other names. Remove those copies only when they are provably ours.
  const descriptionOf = (p) => {
    const file = fs.existsSync(p) && fs.statSync(p).isDirectory() ? path.join(p, 'SKILL.md') : p;
    try { return fs.readFileSync(file, 'utf8').match(/^description:\s*(.+)$/m)?.[1].trim() ?? null; } catch { return null; }
  };
  function cleanupLegacy(root, kitRel) {
    for (const marker of cfg.legacyMarkers ?? []) {
      for (const t of Object.values(tools)) if (t.block && removeBlock(path.join(root, t.file), marker)) console.log(`  - old ${marker} block removed from ${t.file}`);
    }
    const current = sources(Object.keys(tools));
    for (const [oldRel, newRel] of Object.entries(cfg.legacyPaths ?? {})) {
      const p = inside(root, oldRel, 'legacy path');
      if (!fs.existsSync(p) || current.has(oldRel)) continue;
      const src = current.get(newRel);
      const sameDescription = src?.from && descriptionOf(p) !== null && descriptionOf(p) === descriptionOf(src.from);
      let pointsHere = false;
      try { pointsHere = fs.statSync(p).isFile() && fs.readFileSync(p, 'utf8').includes(`${kitRel}/skills/`); } catch {}
      if (sameDescription || pointsHere) { fs.rmSync(p, { recursive: true, force: true }); console.log(`  - old copy ${oldRel} (now ${newRel})`); }
      else console.log(`  ? kept ${oldRel}: it does not look like ${cfg.name}'s old copy`);
    }
  }

  function resolveTools(spec) {
    if (!spec || spec === 'all') return Object.keys(tools);
    const list = spec.split(',').map((s) => s.trim()).filter(Boolean);
    const bad = list.filter((t) => !tools[t]);
    if (bad.length) die(`Unknown tool(s): ${bad.join(', ')}. Valid: ${Object.keys(tools).join(', ')}`);
    return list;
  }

  function install(root, { tools: toolList, kitDir, force }) {
    if (root === path.resolve(cfg.kitSrc)) die('Refusing to install the kit into itself. Pass a target project folder.');
    if (!fs.existsSync(root)) fs.mkdirSync(root, { recursive: true });
    const kitAbs = inside(root, kitDir, '--kit-dir');
    const kitRel = posix(path.relative(root, kitAbs));
    const prevManifest = readJSON(path.join(kitAbs, MANIFEST));
    if (fs.existsSync(kitAbs) && !isOurs(prevManifest)) {
      die(`${kitRel}/ already exists and was not created by ${cfg.name}. Refusing to delete it; choose another --kit-dir.`);
    }
    // Paths we may replace: listed in our previous manifest, or (legacy installs without a list) anything this kit ships.
    // Either way only paths this kit can produce, so a tampered manifest cannot widen what is replaced or deleted.
    const allowed = new Set(ownedPaths(Object.keys(tools)));
    const prevOwned = new Set((prevManifest ? (prevManifest.owned ?? ownedPaths((prevManifest.tools ?? []).filter((t) => tools[t]))) : []).filter((p) => allowed.has(p)));
    const prevBackups = (prevManifest?.backups ?? []).filter((p) => allowed.has(p));
    const plan = sources(toolList);
    const shared = Object.values(tools).map((t) => t.file);
    for (const rel of [...plan.keys(), ...shared]) {
      if (rel === kitRel || rel.startsWith(`${kitRel}/`) || kitRel.startsWith(`${rel}/`)) die(`--kit-dir "${kitRel}" overlaps ${rel}; choose a folder of its own.`);
    }
    const conflicts = [...plan.keys()].filter((rel) => fs.existsSync(inside(root, rel, 'install path')) && !prevOwned.has(rel));
    if (conflicts.length && !force) {
      die(`these already exist and do not belong to ${cfg.name}:\n  ${conflicts.join('\n  ')}\nNothing was changed. Rename them, install with --tools that skip them, or re-run with --force (they are backed up to ${kitRel}/backup/ and restored by remove).`);
    }

    // Keep earlier backups across the kit-folder refresh.
    const stash = prevBackups.length ? fs.mkdtempSync(path.join(root, `.${cfg.id}-stash-`)) : null;
    if (stash) for (const rel of prevBackups) copyAny(path.join(kitAbs, 'backup', rel), path.join(stash, rel));
    fs.rmSync(kitAbs, { recursive: true, force: true });
    for (const p of cfg.parts) copyAny(path.join(cfg.kitSrc, p), path.join(kitAbs, p));
    const backups = [...prevBackups];
    if (stash) { copyAny(stash, path.join(kitAbs, 'backup')); fs.rmSync(stash, { recursive: true, force: true }); }
    for (const rel of conflicts) {
      copyAny(inside(root, rel, 'install path'), path.join(kitAbs, 'backup', rel));
      backups.push(rel);
    }

    // Paths a previous install owned that this one no longer produces (renamed skills, dropped tools): clean up.
    for (const rel of prevOwned) if (!plan.has(rel)) fs.rmSync(inside(root, rel, 'manifest path'), { recursive: true, force: true });
    if (prevManifest) cleanupLegacy(root, kitRel);

    const version = readJSON(path.join(cfg.kitSrc, 'package.json'))?.version ?? '0.0.0';
    const entry = fs.readFileSync(path.join(cfg.kitSrc, 'adapters', 'entry.md'), 'utf8').replaceAll('{{KIT}}', kitRel);
    const written = [];
    for (const t of toolList) {
      const def = tools[t];
      const file = inside(root, def.file, 'instruction file');
      // Claude Code also gets native skills, so its CLAUDE.md block can stay short (cfg.claudeBlock).
      const body = t === 'claude' && cfg.claudeBlock ? cfg.claudeBlock.replaceAll('{{KIT}}', kitRel) : entry;
      if (def.block) upsertBlock(file, body);
      else { fs.rmSync(file, { recursive: true, force: true }); fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, def.wrap(body)); }
      written.push(`${def.file}  (${def.note})`);
    }
    for (const [rel, src] of plan) {
      if (src.kind === 'rule') continue;
      const dst = inside(root, rel, 'install path');
      fs.rmSync(dst, { recursive: true, force: true });
      copyAny(src.from, dst);
    }
    if (toolList.includes('claude')) written.push('.claude/skills/*, .claude/agents/*  (Claude Code native)');

    fs.writeFileSync(path.join(kitAbs, MANIFEST), JSON.stringify({ kit: cfg.id, version, kitDir: kitRel, tools: toolList, owned: [...plan.keys()], backups, installedAt: new Date().toISOString() }, null, 2) + '\n');
    console.log(`\n✔ ${cfg.name} ${version} installed into ${root}`);
    console.log(`  Kit: ${kitRel}/`);
    for (const w of written) console.log(`  + ${w}`);
    for (const b of conflicts) console.log(`  ! replaced your ${b} (backup: ${kitRel}/backup/${b}; restored on remove)`);
    if (cfg.next) console.log(`\n${cfg.next}\n`);
  }

  function remove(root, kitDirFlag) {
    const found = findInstall(root, kitDirFlag);
    if (!found) die(`${cfg.name} is not installed in ${root} (no ${kitDirFlag ?? cfg.kitDir}/${MANIFEST}). Nothing removed.`, 1);
    const { abs, manifest } = found;
    // Only paths this kit can produce, whatever the manifest says.
    const allowed = new Set(ownedPaths(Object.keys(tools)));
    const listed = manifest.owned ?? ownedPaths(manifest.tools);
    for (const t of manifest.tools) if (tools[t].block && removeBlock(inside(root, tools[t].file, 'instruction file'))) console.log(`  - ${cfg.name} block removed from ${tools[t].file}`);
    for (const rel of listed) {
      if (!allowed.has(rel)) { console.log(`  ? skipped "${rel}" (listed in the manifest but not a ${cfg.name} path)`); continue; }
      const p = inside(root, rel, 'manifest path');
      if (fs.existsSync(p)) { fs.rmSync(p, { recursive: true, force: true }); console.log(`  - ${rel}`); }
    }
    for (const rel of manifest.backups ?? []) {
      if (!allowed.has(rel)) continue;
      const b = path.join(abs, 'backup', rel);
      if (fs.existsSync(b)) { copyAny(b, inside(root, rel, 'backup path')); console.log(`  ↺ restored your ${rel}`); }
    }
    cleanupLegacy(root, found.kitDir);
    fs.rmSync(abs, { recursive: true, force: true });
    for (const d of ['.claude/skills', '.claude/agents', '.claude', '.cursor/rules', '.cursor', '.windsurf/rules', '.windsurf', '.clinerules']) {
      const p = path.join(root, d);
      try { if (fs.readdirSync(p).length === 0) fs.rmdirSync(p); } catch {}
    }
    console.log(`✔ Removed ${cfg.name} from ${root}${cfg.kept ? ` (kept ${cfg.kept})` : ''}.`);
  }

  return { tools, ownedPaths, resolveTools, install, remove, findInstall };
}
