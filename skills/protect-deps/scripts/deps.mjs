#!/usr/bin/env node
// The Protectors — dependency vulnerability audit + SBOM (zero dependencies, Node >= 18).
//
//   node deps.mjs [projectRoot] [--out .protectors] [--offline] [--exclude <regex>] [--no-kev] [--no-epss]
//                 [--include-dev] [--fail-on critical|high|medium|low|none] [--json]
//
// 1. Finds lockfiles/manifests (npm, pnpm, yarn, bun, pip/poetry/uv/Pipfile, Cargo, Go, Composer, Bundler,
//    Pub, NuGet, Maven/Gradle) and reads exact versions.
// 2. Writes a CycloneDX 1.5 SBOM (sbom.cdx.json).
// 3. Unless --offline: asks OSV.dev which versions are affected (only package names + versions are sent,
//    never code), then prioritises with the CISA Known Exploited Vulnerabilities catalogue and FIRST EPSS.
// 4. Writes deps.json, DEPENDENCIES.md and deps.sarif. The scanner merges deps.json into its report.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { findLockfiles, parseLockfile, purl } from './lockfiles.mjs';

const OSV = () => process.env.PROTECTORS_OSV_API ?? 'https://api.osv.dev/v1';
const KEV = () => process.env.PROTECTORS_KEV_URL ?? 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS = () => process.env.PROTECTORS_EPSS_API ?? 'https://api.first.org/data/v1/epss';
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const DAY = 86_400_000;

// ---------- CVSS v3.x base score (FIRST specification) ----------
export function cvss3(vector) {
  const m = Object.fromEntries(String(vector).split('/').slice(1).map((kv) => kv.split(':')));
  if (!/^CVSS:3/.test(vector) || !m.AV) return null;
  const changed = m.S === 'C';
  const W = { AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 }, CIA: { H: 0.56, L: 0.22, N: 0 } };
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exploit = 8.22 * W.AV[m.AV] * W.AC[m.AC] * PR * W.UI[m.UI];
  if ([impact, exploit].some(Number.isNaN)) return null;
  if (impact <= 0) return 0;
  const roundup = (x) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
  return roundup(Math.min(changed ? 1.08 * (impact + exploit) : impact + exploit, 10));
}
export const sevFromScore = (s) => (s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : s > 0 ? 'low' : 'info');
const sevFromLabel = (l) => ({ CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' }[String(l).toUpperCase()] ?? null);

// ---------- HTTP with a small on-disk cache ----------
function cache(dir) {
  const file = (key) => path.join(dir, crypto.createHash('sha256').update(key).digest('hex').slice(0, 32) + '.json');
  return {
    get(key, ttl) { try { const f = file(key); if (Date.now() - fs.statSync(f).mtimeMs < ttl) return JSON.parse(fs.readFileSync(f, 'utf8')); } catch {} return null; },
    set(key, value) { try { fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(file(key), JSON.stringify(value)); } catch {} return value; },
  };
}
async function http(url, opts = {}) {
  const u = new URL(url);
  if (u.protocol !== 'https:' && !['127.0.0.1', 'localhost'].includes(u.hostname)) throw new Error(`refusing non-https request to ${u.host}`);
  for (let attempt = 0; ; attempt++) {
    const r = await fetch(u, { ...opts, headers: { 'user-agent': 'the-protectors (+https://github.com/Sarveshknocker/The-protectors-)', 'content-type': 'application/json', ...opts.headers } });
    if (r.ok) return r.json();
    if (attempt < 2 && (r.status === 429 || r.status >= 500)) { await new Promise((res) => setTimeout(res, 500 * 2 ** attempt)); continue; }
    throw new Error(`HTTP ${r.status} from ${u.host}${u.pathname}`);
  }
}
async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}

/** Fixed versions for this package from an OSV record's affected ranges. */
function fixedVersions(vuln, p) {
  const out = new Set();
  for (const a of vuln.affected ?? []) {
    if (a.package?.ecosystem !== p.ecosystem || a.package?.name.toLowerCase() !== p.name.toLowerCase()) continue;
    for (const r of a.ranges ?? []) if (r.type !== 'GIT') for (const e of r.events ?? []) if (e.fixed) out.add(e.fixed);
  }
  return [...out];
}

/** Compares dotted versions numerically (1.10.0 > 1.9.9; 1.0.0-rc1 < 1.0.0). */
export function cmpVersion(a, b) {
  const split = (v) => String(v).replace(/^v/, '').split(/[.+]/).flatMap((x) => x.split(/(?<=\d)(?=[a-z-])|(?<=[a-z])(?=\d)/i));
  const num = (s) => /^\d+$/.test(s);
  const pa = split(a); const pb = split(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    let x = pa[i]; let y = pb[i];
    // A missing numeric part equals 0 (2.0 == 2.0.0); a pre-release tag sorts before the release (1.0.0-rc1 < 1.0.0).
    if (x === undefined) { if (num(y)) x = '0'; else return 1; }
    if (y === undefined) { if (num(x)) y = '0'; else return -1; }
    const nx = num(x); const ny = num(y);
    if (nx && ny) { if (+x !== +y) return +x - +y; } else if (nx !== ny) return nx ? 1 : -1; else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
/** The lowest fixed version above the installed one (stays on the closest release line). */
export const nextFixed = (fixed, current) => fixed.filter((f) => cmpVersion(f, current) > 0).sort(cmpVersion)[0] ?? null;

function severityOf(vuln) {
  let score = null; let vector = null;
  for (const s of [...(vuln.severity ?? []), ...(vuln.affected ?? []).flatMap((a) => a.severity ?? [])]) {
    if (s.type === 'CVSS_V3') { const v = cvss3(s.score); if (v !== null && (score === null || v > score)) { score = v; vector = s.score; } }
    else if (s.type === 'CVSS_V4' && !vector) vector = s.score;
  }
  const label = sevFromLabel(vuln.database_specific?.severity ?? (vuln.affected ?? []).map((a) => a.database_specific?.severity ?? a.ecosystem_specific?.severity).find(Boolean));
  const fromScore = score !== null ? sevFromScore(score) : null;
  const sev = [fromScore, label].filter(Boolean).sort((a, b) => SEV.indexOf(a) - SEV.indexOf(b))[0] ?? 'medium';
  return { severity: sev, cvss: score, vector };
}

export async function audit(root, opts = {}) {
  const o = { out: '.protectors', offline: false, exclude: null, kev: true, epss: true, includeDev: true, ...opts };
  const outDir = path.resolve(root, o.out);
  const c = cache(path.join(outDir, 'cache'));
  const lockfiles = findLockfiles(root);
  const errors = []; let packages = [];
  for (const f of lockfiles) { const r = parseLockfile(root, f); if (r.error) errors.push(r.error); else packages.push(...r); }
  const excluded = o.exclude ? new RegExp(o.exclude) : null;
  const key = (p) => `${p.ecosystem}|${p.name}|${p.version}`;
  const unique = [...new Map(packages.map((p) => [key(p), p])).values()];

  const result = { generatedAt: new Date().toISOString(), root, lockfiles, packageCount: unique.length, errors, online: !o.offline, sources: [], findings: [] };
  if (!o.offline) {
    const queryable = unique.filter((p) => !(excluded && excluded.test(p.name)));
    result.excluded = unique.length - queryable.length;
    const ids = new Map(); // key -> [vuln ids]
    try {
      for (let i = 0; i < queryable.length; i += 500) {
        const batch = queryable.slice(i, i + 500);
        const r = await http(`${OSV()}/querybatch`, { method: 'POST', body: JSON.stringify({ queries: batch.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }) });
        r.results.forEach((res, k) => { if (res.vulns?.length) ids.set(key(batch[k]), res.vulns.map((v) => v.id)); });
      }
      result.sources.push('OSV.dev');
      const allIds = [...new Set([...ids.values()].flat())];
      const vulns = new Map((await pool(allIds, 8, async (id) => [id, c.get(`osv:${id}`, DAY) ?? c.set(`osv:${id}`, await http(`${OSV()}/vulns/${encodeURIComponent(id)}`))])));

      let kev = new Set();
      if (o.kev) {
        try { const j = c.get('kev', DAY) ?? c.set('kev', await http(KEV())); kev = new Set((j.vulnerabilities ?? []).map((v) => v.cveID)); result.sources.push('CISA KEV'); }
        catch (e) { errors.push(`CISA KEV unavailable: ${e.message}`); }
      }
      const cves = [...new Set([...vulns.values()].flatMap((v) => [v.id, ...(v.aliases ?? [])]).filter((x) => /^CVE-/.test(x)))];
      const epss = new Map();
      if (o.epss && cves.length) {
        try {
          for (let i = 0; i < cves.length; i += 80) {
            const chunk = cves.slice(i, i + 80); const k = `epss:${chunk.join(',')}`;
            const j = c.get(k, DAY) ?? c.set(k, await http(`${EPSS()}?cve=${chunk.join(',')}`));
            for (const d of j.data ?? []) epss.set(d.cve, { epss: Number(d.epss), percentile: Number(d.percentile) });
          }
          result.sources.push('FIRST EPSS');
        } catch (e) { errors.push(`EPSS unavailable: ${e.message}`); }
      }

      for (const p of packages) {
        if (!o.includeDev && p.dev) continue;
        for (const id of ids.get(key(p)) ?? []) {
          const v = vulns.get(id); if (!v) continue;
          const aliases = [...new Set([id, ...(v.aliases ?? [])])];
          const cveList = aliases.filter((a) => /^CVE-/.test(a));
          const inKev = cveList.some((x) => kev.has(x));
          const ep = cveList.map((x) => epss.get(x)).filter(Boolean).sort((a, b) => b.epss - a.epss)[0] ?? null;
          const malicious = aliases.some((a) => /^MAL-/.test(a));
          let { severity, cvss, vector } = severityOf(v);
          const why = [];
          if (malicious) { severity = 'critical'; why.push('known malicious package'); }
          if (inKev) { severity = 'critical'; why.push('in CISA KEV (exploited in the wild)'); }
          else if (ep && ep.epss >= 0.1 && severity !== 'critical') { severity = SEV[SEV.indexOf(severity) - 1]; why.push(`EPSS ${(ep.epss * 100).toFixed(1)}%`); }
          if (p.dev && !inKev && !malicious && severity !== 'info') { severity = SEV[SEV.indexOf(severity) + 1]; why.push('dev-only dependency'); }
          const fixed = fixedVersions(v, p);
          result.findings.push({
            rule: malicious ? 'deps.malicious' : 'deps.vulnerable', severity, category: 'dependency', context: 'source',
            title: `${p.name}@${p.version} — ${malicious ? 'malicious package' : (v.summary ?? id)}`.slice(0, 200),
            file: p.file, line: p.line, col: 1, snippet: `${p.ecosystem} ${p.name} ${p.version}`,
            cwe: (v.database_specific?.cwe_ids ?? [])[0] ?? 'CWE-1395', owasp: 'A06',
            fix: malicious ? 'Remove the package now, rotate any secrets on machines that installed it, and audit install scripts.' : fixed.length ? `Upgrade ${p.name} to ${fixed.join(' or ')} (or later).` : 'No fixed version published: assess reachability, mitigate, or replace the package.',
            package: { name: p.name, version: p.version, ecosystem: p.ecosystem, purl: purl(p), direct: p.direct, dev: p.dev },
            vuln: { id, aliases, cvss, vector, kev: inKev, epss: ep, fixed, published: v.published, url: `https://osv.dev/vulnerability/${id}` }, priority: why,
          });
        }
      }
      // One advisory is often published under several ids (GHSA, PYSEC, CVE…): merge them per package and lockfile.
      const merged = [];
      for (const f of result.findings) {
        const twin = merged.find((g) => g.package.purl === f.package.purl && g.file === f.file && g.vuln.aliases.some((a) => f.vuln.aliases.includes(a)));
        if (!twin) { merged.push(f); continue; }
        const better = SEV.indexOf(f.severity) < SEV.indexOf(twin.severity) ? f : twin;
        const other = better === f ? twin : f;
        better.vuln.aliases = [...new Set([...better.vuln.aliases, ...other.vuln.aliases])];
        better.vuln.fixed = [...new Set([...better.vuln.fixed, ...other.vuln.fixed])];
        better.vuln.kev ||= other.vuln.kev; better.vuln.cvss ??= other.vuln.cvss; better.vuln.epss ??= other.vuln.epss;
        if (/^GHSA-/.test(other.vuln.id) && !/^GHSA-/.test(better.vuln.id)) { better.vuln.id = other.vuln.id; better.vuln.url = other.vuln.url; }
        merged.splice(merged.indexOf(twin), 1, better);
      }
      for (const f of merged) {
        f.vuln.fixedNext = nextFixed(f.vuln.fixed, f.package.version);
        if (f.rule === 'deps.vulnerable') f.fix = f.vuln.fixedNext ? `Upgrade ${f.package.name} to ${f.vuln.fixedNext} or later.` : 'No fixed version published: check whether the vulnerable code is reachable, mitigate, or replace the package.';
      }
      result.findings = merged
        .sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || (b.vuln.epss?.epss ?? 0) - (a.vuln.epss?.epss ?? 0));
    } catch (e) { errors.push(`OSV query failed (${e.message}); SBOM written, vulnerabilities not checked. Re-run online or use --offline.`); result.online = false; }
  }
  // Upgrade plan: one target per package = the highest "next fixed" version among its advisories.
  const plan = new Map();
  for (const f of result.findings) {
    if (f.rule !== 'deps.vulnerable') continue;
    const k = `${f.package.ecosystem}|${f.package.name}|${f.package.version}`;
    const e = plan.get(k) ?? { ecosystem: f.package.ecosystem, name: f.package.name, from: f.package.version, to: null, fixes: 0, unfixed: 0, worst: 'info', kev: false, direct: f.package.direct, dev: f.package.dev, files: new Set() };
    if (f.vuln.fixedNext) { e.fixes++; if (!e.to || cmpVersion(f.vuln.fixedNext, e.to) > 0) e.to = f.vuln.fixedNext; } else e.unfixed++;
    if (SEV.indexOf(f.severity) < SEV.indexOf(e.worst)) e.worst = f.severity;
    e.kev ||= f.vuln.kev; e.files.add(f.file); plan.set(k, e);
  }
  result.upgradePlan = [...plan.values()].map((e) => ({ ...e, files: [...e.files] })).sort((a, b) => Number(b.kev) - Number(a.kev) || SEV.indexOf(a.worst) - SEV.indexOf(b.worst) || b.fixes - a.fixes);
  result.counts = Object.fromEntries(SEV.map((s) => [s, result.findings.filter((f) => f.severity === s).length]));

  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'sbom.cdx.json'), JSON.stringify(sbom(root, unique, result.findings), null, 2));
  fs.writeFileSync(path.join(outDir, 'deps.json'), JSON.stringify(result, null, 2));
  fs.writeFileSync(path.join(outDir, 'deps.sarif'), JSON.stringify(sarif(result), null, 2));
  fs.writeFileSync(path.join(outDir, 'DEPENDENCIES.md'), markdown(result, unique));
  return result;
}

export function sbom(root, packages, findings) {
  let name = path.basename(path.resolve(root)); let version;
  try { const pj = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')); name = pj.name ?? name; version = pj.version; } catch {}
  let toolVersion = '0.0.0';
  try { toolVersion = JSON.parse(fs.readFileSync(new URL('../../../package.json', import.meta.url), 'utf8')).version; } catch {}
  const vulns = new Map();
  for (const f of findings) {
    const v = vulns.get(f.vuln.id) ?? { id: f.vuln.id, source: { name: 'OSV', url: f.vuln.url }, ratings: [], affects: [], ...(f.fix ? { recommendation: f.fix } : {}) };
    if (f.vuln.cvss !== null && !v.ratings.length) v.ratings.push({ score: f.vuln.cvss, severity: f.severity, method: 'CVSSv31', vector: f.vuln.vector });
    else if (!v.ratings.length) v.ratings.push({ severity: f.severity, method: 'other' });
    if (!v.affects.some((a) => a.ref === f.package.purl)) v.affects.push({ ref: f.package.purl });
    vulns.set(f.vuln.id, v);
  }
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${crypto.randomUUID()}`, version: 1,
    metadata: { timestamp: new Date().toISOString(), tools: { components: [{ type: 'application', name: 'the-protectors', version: toolVersion }] }, component: { type: 'application', name, ...(version ? { version } : {}), 'bom-ref': 'root' } },
    components: packages.map((p) => ({ type: 'library', 'bom-ref': purl(p), name: p.name, version: p.version, purl: purl(p), scope: p.dev ? 'optional' : 'required', properties: [{ name: 'protectors:source', value: p.file }, ...(p.direct !== null ? [{ name: 'protectors:direct', value: String(p.direct) }] : [])] })),
    vulnerabilities: [...vulns.values()],
  };
}

function sarif(r) {
  const level = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
  return { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{
    tool: { driver: { name: 'The Protectors (deps)', informationUri: 'https://github.com/Sarveshknocker/The-protectors-', rules: [...new Set(r.findings.map((f) => f.vuln.id))].map((id) => { const f = r.findings.find((x) => x.vuln.id === id); return { id, shortDescription: { text: f.title }, helpUri: f.vuln.url, properties: { tags: ['security', 'dependency', f.cwe], 'security-severity': String(f.vuln.cvss ?? { critical: 9.5, high: 7.5, medium: 5, low: 2, info: 0.5 }[f.severity]) } }; }) } },
    results: r.findings.map((f) => ({ ruleId: f.vuln.id, level: level[f.severity], message: { text: `${f.title}. ${f.fix}` }, locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }] })),
  }] };
}

function markdown(r, packages) {
  const eco = Object.entries(packages.reduce((m, p) => ({ ...m, [p.ecosystem]: (m[p.ecosystem] ?? 0) + 1 }), {})).map(([k, v]) => `${k} ${v}`).join(' · ');
  const rows = r.findings.map((f) => `| ${f.severity} | ${f.package.name}@${f.package.version}${f.package.direct ? ' (direct)' : ''}${f.package.dev ? ' (dev)' : ''} | [${f.vuln.id}](${f.vuln.url})${f.vuln.aliases.find((a) => /^CVE-/.test(a)) ? ' / ' + f.vuln.aliases.find((a) => /^CVE-/.test(a)) : ''} | ${f.vuln.cvss ?? '—'} | ${f.vuln.kev ? '**yes**' : '—'} | ${f.vuln.epss ? (f.vuln.epss.epss * 100).toFixed(1) + '%' : '—'} | ${f.vuln.fixedNext ?? 'none'} | \`${f.file}:${f.line}\` |`);
  return `# Dependencies

_Generated ${r.generatedAt} · ${r.packageCount} packages (${eco || 'none found'}) from ${r.lockfiles.length} lockfile(s) · sources: ${r.sources.join(', ') || 'offline (SBOM only)'}_

| Critical | High | Medium | Low |
|---|---|---|---|
| ${r.counts.critical} | ${r.counts.high} | ${r.counts.medium} | ${r.counts.low} |

${r.upgradePlan?.length ? `## Upgrade plan
One change per package fixes every advisory that has a fix. Do these first (KEV, then severity).

| Package | From | To | Fixes | No fix yet | Worst | KEV | Type |
|---|---|---|---|---|---|---|---|
${r.upgradePlan.map((e) => `| ${e.name} | ${e.from} | ${e.to ?? '—'} | ${e.fixes} | ${e.unfixed} | ${e.worst} | ${e.kev ? '**yes**' : '—'} | ${e.direct === true ? 'direct' : e.direct === false ? 'transitive' : '?'}${e.dev ? ', dev' : ''} |`).join('\n')}

Transitive packages are fixed by upgrading the direct dependency that pulls them in, or with an override/resolution.

## Advisories
` : ''}${rows.length ? `Ordered by severity, then exploit probability. KEV = listed by CISA as exploited in the wild (fix first). EPSS = probability of exploitation in the next 30 days.

| Severity | Package | Advisory | CVSS | KEV | EPSS | Fixed in | Where |
|---|---|---|---|---|---|---|---|
${rows.join('\n')}` : r.online ? 'No known vulnerabilities in the resolved versions.' : 'Vulnerabilities were not checked (offline).'}

${r.errors.length ? `## Notes\n${r.errors.map((e) => `- ${e}`).join('\n')}\n` : ''}
SBOM: \`sbom.cdx.json\` (CycloneDX 1.5). Lockfiles: ${r.lockfiles.map((f) => `\`${f}\``).join(', ') || 'none'}.
Only package names and versions are sent to OSV.dev; use \`--exclude '^@yourco/'\` to keep private package names local, or \`--offline\`.
`;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const args = process.argv.slice(2);
  const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
  const root = path.resolve(args.find((a, i) => !a.startsWith('--') && !args[i - 1]?.match(/^--(out|exclude|fail-on)$/)) ?? process.cwd());
  const failOn = opt('--fail-on', 'none');
  const r = await audit(root, { out: opt('--out', '.protectors'), offline: args.includes('--offline'), exclude: opt('--exclude', null), kev: !args.includes('--no-kev'), epss: !args.includes('--no-epss'), includeDev: !args.includes('--prod-only') });
  if (args.includes('--json')) console.log(JSON.stringify(r, null, 2));
  else {
    console.log(`\nThe Protectors deps — ${r.packageCount} packages in ${r.lockfiles.length} lockfile(s) · ${r.online ? r.sources.join(', ') : 'offline'}`);
    console.log(`critical ${r.counts.critical} · high ${r.counts.high} · medium ${r.counts.medium} · low ${r.counts.low}\n`);
    for (const e of r.upgradePlan ?? []) console.log(`${e.worst.padEnd(8)} ${e.name}@${e.from} → ${e.to ?? 'no fix yet'}  (${e.fixes} advisories fixed${e.unfixed ? `, ${e.unfixed} without a fix` : ''}${e.kev ? ', KNOWN EXPLOITED' : ''})`);
    for (const e of r.errors) console.log(`note: ${e}`);
    console.log(`\nReports: ${path.join(opt('--out', '.protectors'), 'DEPENDENCIES.md')}, deps.json, deps.sarif, sbom.cdx.json\n`);
  }
  const t = SEV.indexOf(failOn);
  process.exit(failOn !== 'none' && r.findings.some((f) => SEV.indexOf(f.severity) <= t) ? 1 : 0);
}
