// Lockfile / manifest parsers → [{ name, version, ecosystem, file, line, direct, dev }]
// Zero dependencies: each format is parsed with the minimum structure needed to read exact versions.
import fs from 'node:fs';
import path from 'node:path';

const lineAt = (text, needle) => { const i = needle ? text.indexOf(needle) : -1; return i < 0 ? 1 : text.slice(0, i).split('\n').length; };
const pkgOf = (name, version, ecosystem, file, text, extra = {}) => ({ name, version, ecosystem, file, line: lineAt(text, extra.needle ?? name), direct: extra.direct ?? null, dev: extra.dev ?? false });
const tomlPackages = (text) => [...text.matchAll(/\[\[package\]\]\s*\n([\s\S]*?)(?=\n\[\[|\n\[(?!\[)|$)/g)].map((m) => ({
  name: m[1].match(/^name\s*=\s*"([^"]+)"/m)?.[1], version: m[1].match(/^version\s*=\s*"([^"]+)"/m)?.[1], source: m[1].match(/^source\s*=\s*(.+)$/m)?.[1] ?? '', block: m[1],
})).filter((p) => p.name && p.version);

export const PARSERS = [
  { test: /(^|\/)package-lock\.json$|(^|\/)npm-shrinkwrap\.json$/, parse(text, file) {
    const j = JSON.parse(text); const out = [];
    const root = j.packages?.[''] ?? {};
    const directs = new Set(Object.keys({ ...root.dependencies, ...root.devDependencies, ...root.optionalDependencies }));
    if (j.packages) {
      for (const [key, p] of Object.entries(j.packages)) {
        if (!key || !p.version || p.link) continue;
        const name = p.name ?? key.slice(key.lastIndexOf('node_modules/') + 13);
        out.push(pkgOf(name, p.version, 'npm', file, text, { needle: `"${key}"`, direct: key === `node_modules/${name}` && directs.has(name), dev: !!p.dev }));
      }
    } else {
      const walk = (deps, top) => { for (const [name, p] of Object.entries(deps ?? {})) { if (p.version && !/^(file|link|git)/.test(p.version)) out.push(pkgOf(name, p.version, 'npm', file, text, { needle: `"${name}"`, direct: top, dev: !!p.dev })); walk(p.dependencies, false); } };
      walk(j.dependencies, true);
    }
    return out;
  } },
  { test: /(^|\/)pnpm-lock\.yaml$/, parse(text, file) {
    const out = []; const block = text.split(/\n(?=\S)/).find((b) => b.startsWith('packages:')) ?? '';
    for (const m of block.matchAll(/^ {2}['"]?\/?((?:@[^/@\s'"]+\/)?[^/@\s'"(]+)[@/](\d[^('":\s]*)/gm)) out.push(pkgOf(m[1], m[2], 'npm', file, text, { needle: m[0].trim() }));
    const importers = text.match(/^(importers:|dependencies:|devDependencies:)[\s\S]*?(?=\n\S)/m)?.[0] ?? '';
    const directs = new Set([...importers.matchAll(/^ {2,6}['"]?((?:@[^/\s'"]+\/)?[^\s:'"]+)['"]?:\s*$/gm)].map((m) => m[1]));
    return out.map((p) => ({ ...p, direct: directs.size ? directs.has(p.name) : null }));
  } },
  { test: /(^|\/)yarn\.lock$/, parse(text, file) {
    const out = [];
    for (const m of text.matchAll(/^("?)(@?[^@\s"][^@\s"]*)@[^\n]*:\n((?: {2}.*\n?)+)/gm)) {
      const v = m[3].match(/^ {2}version:?\s+"?([^"\s]+)"?/m)?.[1];
      if (v && !/^0\.0\.0-use\.local$/.test(v)) out.push(pkgOf(m[2], v, 'npm', file, text, { needle: m[0].split('\n')[0] }));
    }
    return out;
  } },
  { test: /(^|\/)bun\.lock$/, parse(text, file) {
    return [...text.matchAll(/^\s*"[^"]+":\s*\[\s*"((?:@[^/"]+\/)?[^@"]+)@(\d[^"]*)"/gm)].map((m) => pkgOf(m[1], m[2], 'npm', file, text, { needle: `"${m[1]}@${m[2]}"` }));
  } },
  { test: /(^|\/)(requirements[\w.-]*\.txt|constraints\.txt)$/, parse(text, file) {
    return [...text.matchAll(/^\s*([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*===?\s*([\w.!+-]+)/gm)].map((m) => pkgOf(m[1], m[2], 'PyPI', file, text, { needle: m[0].trim(), direct: true }));
  } },
  { test: /(^|\/)(poetry|uv|pdm)\.lock$/, parse(text, file) {
    return tomlPackages(text).filter((p) => !/editable|virtual|directory/.test(p.source)).map((p) => pkgOf(p.name, p.version, 'PyPI', file, text, { needle: `name = "${p.name}"`, dev: /category\s*=\s*"dev"/.test(p.block) }));
  } },
  { test: /(^|\/)Pipfile\.lock$/, parse(text, file) {
    const j = JSON.parse(text); const out = [];
    for (const [section, dev] of [['default', false], ['develop', true]]) for (const [name, p] of Object.entries(j[section] ?? {})) if (p.version) out.push(pkgOf(name, p.version.replace(/^==/, ''), 'PyPI', file, text, { needle: `"${name}"`, dev }));
    return out;
  } },
  { test: /(^|\/)Cargo\.lock$/, parse(text, file) {
    return tomlPackages(text).filter((p) => /registry\+/.test(p.source)).map((p) => pkgOf(p.name, p.version, 'crates.io', file, text, { needle: `name = "${p.name}"` }));
  } },
  { test: /(^|\/)go\.mod$/, parse(text, file) {
    const out = [];
    const add = (mod, ver, rest) => out.push(pkgOf(mod, ver.replace(/^v/, ''), 'Go', file, text, { needle: `${mod} ${ver}`, direct: !/\/\/\s*indirect/.test(rest ?? '') }));
    for (const b of text.matchAll(/^require\s*\(([\s\S]*?)^\)/gm)) for (const m of b[1].matchAll(/^\s*(\S+)\s+(v\S+)(.*)$/gm)) add(m[1], m[2], m[3]);
    for (const m of text.matchAll(/^require\s+(\S+)\s+(v\S+)(.*)$/gm)) add(m[1], m[2], m[3]);
    return out;
  } },
  { test: /(^|\/)composer\.lock$/, parse(text, file) {
    const j = JSON.parse(text);
    return [...(j.packages ?? []).map((p) => [p, false]), ...(j['packages-dev'] ?? []).map((p) => [p, true])].filter(([p]) => p.version && !/^dev-/.test(p.version))
      .map(([p, dev]) => pkgOf(p.name, p.version.replace(/^v/, ''), 'Packagist', file, text, { needle: `"name": "${p.name}"`, dev }));
  } },
  { test: /(^|\/)Gemfile\.lock$/, parse(text, file) {
    const specs = text.match(/^GEM\n[\s\S]*?specs:\n([\s\S]*?)(?=\n\S|\n\n)/m)?.[1] ?? '';
    return [...specs.matchAll(/^ {4}([\w.-]+) \(([^)\s]+)\)$/gm)].map((m) => pkgOf(m[1], m[2].split('-')[0], 'RubyGems', file, text, { needle: `    ${m[1]} (${m[2]})` }));
  } },
  { test: /(^|\/)pubspec\.lock$/, parse(text, file) {
    return [...text.matchAll(/^ {2}([\w-]+):\n((?: {4}.*\n?)+)/gm)].filter((m) => /source:\s*hosted/.test(m[2])).map((m) => ({
      ...pkgOf(m[1], m[2].match(/version:\s*"?([^"\s]+)/)?.[1], 'Pub', file, text, { needle: `  ${m[1]}:` }), direct: /dependency:\s*"?direct/.test(m[2]), dev: /direct dev/.test(m[2]),
    })).filter((p) => p.version);
  } },
  { test: /(^|\/)packages\.lock\.json$/, parse(text, file) {
    const j = JSON.parse(text); const out = []; const seen = new Set();
    for (const fw of Object.values(j.dependencies ?? {})) for (const [name, p] of Object.entries(fw)) {
      if (!p.resolved || p.type === 'Project' || seen.has(name + p.resolved)) continue; seen.add(name + p.resolved);
      out.push(pkgOf(name, p.resolved, 'NuGet', file, text, { needle: `"${name}"`, direct: p.type === 'Direct' }));
    }
    return out;
  } },
  { test: /(^|\/)pom\.xml$/, parse(text, file) {
    return [...text.matchAll(/<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<$]+)<\/version>([\s\S]*?)<\/dependency>/g)]
      .map((m) => pkgOf(`${m[1].trim()}:${m[2].trim()}`, m[3].trim(), 'Maven', file, text, { needle: `<artifactId>${m[2]}</artifactId>`, direct: true, dev: /<scope>\s*test\s*<\/scope>/.test(m[4]) }));
  } },
  { test: /(^|\/)gradle\.lockfile$/, parse(text, file) {
    return [...text.matchAll(/^([\w.-]+):([\w.-]+):([\w.+-]+)=(.*)$/gm)].map((m) => pkgOf(`${m[1]}:${m[2]}`, m[3], 'Maven', file, text, { needle: m[0], dev: !/(runtime|compile)Classpath/.test(m[4]) }));
  } },
];

const IGNORE = new Set(['node_modules', '.git', 'vendor', '.venv', 'venv', 'dist', 'build', 'target', '.protectors', '.protectors-kit', '.next', '.nuxt', 'coverage', '.terraform', 'Pods', '.gradle', '.dart_tool', 'bower_components']);

export function findLockfiles(root) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 8) return;
    let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (IGNORE.has(e.name) || e.isSymbolicLink()) continue;
      const full = path.join(dir, e.name); const rel = path.relative(root, full).split(path.sep).join('/');
      if (e.isDirectory()) walk(full, depth + 1);
      else if (PARSERS.some((p) => p.test.test(rel))) out.push(rel);
    }
  };
  walk(root, 0);
  return out.sort();
}

export function parseLockfile(root, rel) {
  const parser = PARSERS.find((p) => p.test.test(rel));
  const text = fs.readFileSync(path.join(root, rel), 'utf8');
  try { return parser.parse(text, rel).filter((p) => p.name && p.version); }
  catch (e) { return { error: `${rel}: ${e.message}` }; }
}

/** Package URL (purl) per https://github.com/package-url/purl-spec */
export function purl(p) {
  const enc = (s) => encodeURIComponent(s).replace(/%2F/g, '/');
  switch (p.ecosystem) {
    case 'npm': return `pkg:npm/${p.name.startsWith('@') ? '%40' + enc(p.name.slice(1)) : enc(p.name)}@${enc(p.version)}`;
    case 'PyPI': return `pkg:pypi/${p.name.toLowerCase().replace(/[_.]+/g, '-')}@${enc(p.version)}`;
    case 'Go': return `pkg:golang/${enc(p.name)}@v${enc(p.version)}`;
    case 'crates.io': return `pkg:cargo/${enc(p.name)}@${enc(p.version)}`;
    case 'Packagist': return `pkg:composer/${enc(p.name)}@${enc(p.version)}`;
    case 'RubyGems': return `pkg:gem/${enc(p.name)}@${enc(p.version)}`;
    case 'Pub': return `pkg:pub/${enc(p.name)}@${enc(p.version)}`;
    case 'NuGet': return `pkg:nuget/${enc(p.name)}@${enc(p.version)}`;
    case 'Maven': { const [g, a] = p.name.split(':'); return `pkg:maven/${enc(g)}/${enc(a)}@${enc(p.version)}`; }
    default: return `pkg:generic/${enc(p.name)}@${enc(p.version)}`;
  }
}
