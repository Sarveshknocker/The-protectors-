#!/usr/bin/env node
// Rule regression tests in the style of semgrep's annotated test files.
//
//   node rule-test.mjs <corpusDir> [--require-coverage] [--json]
//
// In any corpus file, a comment containing
//   ruleid: <rule>[, <rule>]   → the next code line (or this line, if the comment trails code) MUST be reported
//   ok: <rule>[, <rule>]       → that line must NOT be reported for those rules
//   ruleid-file: <rule>        → the rule must fire somewhere in this file (file-level rules)
//   ok-file: <rule>            → the rule must not fire anywhere in this file
// Placeholders {{FAKE:<kind>}} are replaced with generated secret-shaped values at run time, so the corpus
// itself never contains anything that looks like a real credential.
// --require-coverage fails when a built-in or custom rule has no `ruleid` case.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** Deterministic secret-shaped values (never real; built at run time). */
export function fake(kind) {
  let seed = [...kind].reduce((s, c) => (s * 31 + c.charCodeAt(0)) >>> 0, 7);
  const r = (chars, n) => Array.from({ length: n }, () => { seed = (seed * 1103515245 + 12345) >>> 0; return chars[seed % chars.length]; }).join('');
  const AN = 'ABCDEFGHJKLMNPQRSUVWXYZabcdfghjkmnpqruvwxyz23456789'; const UP = 'ABCDEFGHJKLMNPQRUVWXYZ23456789'; const HEX = '0123456789abcdef';
  const v = {
    aws: 'AKIA' + r(UP, 16), 'aws-secret': r(AN + '/+', 40), github: 'ghp' + '_' + r(AN, 36), gitlab: 'glpat-' + r(AN, 20), slack: 'xoxb-' + r(AN, 24),
    'slack-webhook': 'https://hooks.slack.com/services/T' + r(UP, 8) + '/B' + r(UP, 8) + '/' + r(AN, 24), stripe: ['sk', 'live', r(AN, 24)].join('_'),
    google: 'AIza' + r(AN, 35), openai: 'sk-proj-' + r(AN, 48), anthropic: 'sk-ant-' + 'api03-' + r(AN, 90), twilio: 'SK' + r(HEX, 32),
    sendgrid: 'SG.' + r(AN, 22) + '.' + r(AN, 43), npm: 'npm_' + r(AN, 36), razorpay: 'rzp_' + 'live_' + r(AN, 14), huggingface: 'hf_' + r(AN, 34),
    shopify: 'shpat_' + r(HEX, 32), digitalocean: 'dop_v1_' + r(HEX, 64), pypi: 'pypi-' + 'AgEIcHlwaS5vcmc' + r(AN, 60), postman: 'PMAK-' + r(HEX, 24) + '-' + r(HEX, 34),
    atlassian: 'ATATT3' + r(AN, 120), telegram: '1234567890:AA' + r(AN, 33), discord: 'https://discord.com/api/webhooks/123456789012345678/' + r(AN, 68),
    azure: 'DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=' + r(AN, 86) + '==', gcp: '{"type": "service_account", "project_id": "demo", "private_key_id": "' + r(HEX, 40) + '"}',
    groq: 'gsk_' + r(AN, 52), supabase: 'sbp_' + r(HEX, 40), linear: 'lin_api_' + r(AN, 40), doppler: 'dp.pt.' + r(AN, 43), vault: 'hvs.' + r(AN, 95),
    databricks: 'dapi' + r(HEX, 32), dockerhub: 'dckr_pat_' + r(AN, 27), age: 'AGE-SECRET-KEY-1' + r(UP, 58), pem: '-----BEGIN ' + 'RSA PRIVATE KEY-----',
    dburl: 'postgres://admin:' + r(AN, 12) + '@db.internal.acme.io:5432/app', jwt: 'eyJ' + r(AN, 24) + '.eyJ' + r(AN, 24) + '.' + r(AN, 24), generic: r(AN, 24),
  }[kind];
  if (!v) throw new Error(`Unknown FAKE kind: ${kind}`);
  return v;
}

const ANNOT = /\b(ruleid|ok)(-file)?:\s*([\w.-]+(?:\s*,\s*[\w.-]+)*)/;
const COMMENT_ONLY = /^\s*(\/\/|#|<!--|\/\*|\*|--|;|%)/;

function walk(dir, base = dir, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, base, acc); else acc.push(path.relative(base, full).split(path.sep).join('/'));
  }
  return acc;
}

export function runCorpus(corpus, { requireCoverage = false } = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'protectors-rules-'));
  const expectations = [];
  for (const rel of walk(corpus)) {
    const text = fs.readFileSync(path.join(corpus, rel), 'utf8').replace(/\{\{FAKE:([\w-]+)\}\}/g, (_, k) => fake(k));
    fs.mkdirSync(path.dirname(path.join(tmp, rel)), { recursive: true });
    fs.writeFileSync(path.join(tmp, rel), text);
    const lines = text.split('\n');
    lines.forEach((l, i) => {
      const m = l.match(ANNOT); if (!m) return;
      let target = i + 1;
      if (!m[2] && COMMENT_ONLY.test(l)) { target = i + 2; while (target <= lines.length && (!lines[target - 1].trim() || ANNOT.test(lines[target - 1]) && COMMENT_ONLY.test(lines[target - 1]))) target++; }
      for (const rule of m[3].split(',').map((s) => s.trim())) expectations.push({ kind: m[1], fileLevel: !!m[2], rule, file: rel, line: target });
    });
  }
  const r = spawnSync(process.execPath, [path.join(HERE, 'scan.mjs'), tmp, '--out', path.join(tmp, '.protectors'), '--fail-on', 'none', '--no-deps'], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`scanner failed: ${r.stderr}`);
  const { findings } = JSON.parse(fs.readFileSync(path.join(tmp, '.protectors', 'findings.json'), 'utf8'));
  const hit = (e) => findings.some((f) => f.rule === e.rule && f.file === e.file && (e.fileLevel || f.line === e.line));
  const failures = [];
  const perRule = new Map();
  for (const e of expectations) {
    const s = perRule.get(e.rule) ?? { tp: 0, fn: 0, tn: 0, fp: 0 }; perRule.set(e.rule, s);
    const h = hit(e);
    if (e.kind === 'ruleid') { if (h) s.tp++; else { s.fn++; failures.push(`MISSED   ${e.rule} at ${e.file}:${e.line}${e.fileLevel ? ' (file)' : ''}`); } }
    else if (h) { s.fp++; failures.push(`FALSE+   ${e.rule} at ${e.file}:${e.line}${e.fileLevel ? ' (file)' : ''}`); } else s.tn++;
  }
  // Coverage: every rule in the catalogue (and custom rules found in the corpus root) needs at least one ruleid case.
  const catalogue = spawnSync(process.execPath, ['--input-type=module', '-e', `import(${JSON.stringify(pathToFileURL(path.join(HERE, 'rules.mjs')).href)}).then((m) => console.log(JSON.stringify([...m.SECRET_RULES, ...m.CODE_RULES, ...m.CONFIG_RULES].map((x) => x.id))))`], { encoding: 'utf8' });
  let ids = JSON.parse(catalogue.stdout);
  try { ids = ids.concat(JSON.parse(fs.readFileSync(path.join(corpus, '.protectors-rules.json'), 'utf8')).map((x) => `custom.${x.id.replace(/^custom\./, '')}`)); } catch {}
  const covered = new Set(expectations.filter((e) => e.kind === 'ruleid').map((e) => e.rule));
  const uncovered = ids.filter((id) => !covered.has(id));
  if (requireCoverage) for (const id of uncovered) failures.push(`NO TEST  ${id}`);
  fs.rmSync(tmp, { recursive: true, force: true });
  return { rules: ids.length, covered: ids.length - uncovered.length, uncovered, expectations: expectations.length, perRule: Object.fromEntries(perRule), failures };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const args = process.argv.slice(2);
  const corpus = args.find((a) => !a.startsWith('--'));
  if (!corpus) { console.error('usage: rule-test.mjs <corpusDir> [--require-coverage] [--json]'); process.exit(2); }
  const res = runCorpus(path.resolve(corpus), { requireCoverage: args.includes('--require-coverage') });
  if (args.includes('--json')) console.log(JSON.stringify(res, null, 2));
  else {
    const t = Object.values(res.perRule).reduce((a, s) => ({ tp: a.tp + s.tp, fn: a.fn + s.fn, tn: a.tn + s.tn, fp: a.fp + s.fp }), { tp: 0, fn: 0, tn: 0, fp: 0 });
    console.log(`Rule tests: ${res.expectations} expectations · ${res.covered}/${res.rules} rules covered · detected ${t.tp}/${t.tp + t.fn} · false positives ${t.fp}/${t.fp + t.tn}`);
    for (const f of res.failures) console.log(f);
    if (!args.includes('--require-coverage') && res.uncovered.length) console.log(`Uncovered: ${res.uncovered.join(', ')}`);
  }
  process.exit(res.failures.length ? 1 : 0);
}
