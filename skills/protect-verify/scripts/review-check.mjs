#!/usr/bin/env node
// The Protectors — evidence contract checker for manual review findings and the coverage ledger.
//
//   node review-check.mjs [projectRoot] [--out .protectors] [--complete] [--json]
//
// Validates <out>/review.json (findings with verdicts) and <out>/coverage.json (what was reviewed), checks every
// cited file:line exists, enforces the evidence rules below, and writes <out>/REVIEW_STATUS.md.
// Exit 1 on any error; with --complete also when coverage still has planned/in-progress/candidate units.
//
// Evidence contract (adapted from the verification discipline of professional audit workflows):
// - confirmed        → names the boundary (attacker, input, control, crossed, affected), traces entrypoint → sink,
//                      has a severity with a rationale, a fix (invariant + change) and reproduction evidence:
//                      a test/harness run, or an explicit reproduction_waiver saying why execution adds nothing.
// - needs_validation → a concrete boundary hypothesis blocked on a missing fact: blocker + validation_plan, NO severity.
// - rejected         → the reason it is not a vulnerability. Kept so later runs do not re-report it.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const VERDICTS = ['confirmed', 'needs_validation', 'rejected'];
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const UNIT_STATUSES = ['planned', 'in_progress', 'covered', 'candidate', 'blocked', 'deferred', 'out_of_scope', 'not_applicable'];
const OPEN_STATUSES = ['planned', 'in_progress', 'candidate'];
const EVIDENCE_TYPES = ['test', 'harness', 'reading', 'scanner', 'config'];
const BOUNDARY = ['attacker', 'input', 'control', 'crossed', 'affected'];

export function check(root, { out = '.protectors', complete = false } = {}) {
  const errors = []; const warnings = [];
  const dir = path.resolve(root, out);
  const load = (f) => { try { return JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); } catch (e) { if (e.code !== 'ENOENT') errors.push(`${f}: ${e.message}`); return null; } };
  const review = load('review.json'); const coverage = load('coverage.json');
  if (!review) errors.push('review.json is missing (write [] findings if the review found nothing, with coverage.json proving what was read)');
  if (!coverage) errors.push('coverage.json is missing');
  const findings = Array.isArray(review) ? review : review?.findings ?? [];
  const units = coverage?.units ?? [];
  const lineCounts = new Map();
  const at = (where, file, line) => {
    if (typeof file !== 'string' || !file || path.isAbsolute(file) || file.split(/[\\/]/).includes('..')) { errors.push(`${where}: file must be a repository-relative path`); return; }
    const full = path.join(root, file);
    if (!fs.existsSync(full)) { errors.push(`${where}: ${file} does not exist`); return; }
    if (line === undefined) return;
    if (!Number.isInteger(line) || line < 1) { errors.push(`${where}: line must be a positive integer`); return; }
    if (!lineCounts.has(file)) lineCounts.set(file, fs.readFileSync(full, 'utf8').split('\n').length);
    if (line > lineCounts.get(file)) errors.push(`${where}: ${file}:${line} is past the end of the file (${lineCounts.get(file)} lines)`);
  };
  const str = (v) => typeof v === 'string' && v.trim().length > 0;

  // ---- coverage ledger ----
  const unitIds = new Set();
  for (const [i, u] of units.entries()) {
    const w = `coverage unit ${u.id ?? '#' + i}`;
    if (!str(u.id) || !/^[a-z0-9][a-z0-9._:/-]*$/.test(u.id)) errors.push(`${w}: id must be lowercase [a-z0-9._:/-]`);
    else if (unitIds.has(u.id)) errors.push(`${w}: duplicate id`); else unitIds.add(u.id);
    for (const k of ['surface', 'boundary', 'attack_class']) if (!str(u[k])) errors.push(`${w}: ${k} is required`);
    if (!UNIT_STATUSES.includes(u.status)) errors.push(`${w}: status must be one of ${UNIT_STATUSES.join(', ')}`);
    if (['covered', 'candidate'].includes(u.status)) {
      if (!Array.isArray(u.reviewed_paths) || !u.reviewed_paths.length) errors.push(`${w}: ${u.status} needs reviewed_paths`);
      else u.reviewed_paths.forEach((p) => at(w, p));
    }
    if (['blocked', 'deferred', 'out_of_scope', 'not_applicable'].includes(u.status) && !str(u.note)) errors.push(`${w}: ${u.status} needs a note saying why`);
    if (u.status === 'candidate' && !(u.findings ?? []).length) errors.push(`${w}: candidate must link the finding fingerprints it produced`);
  }

  // ---- findings ----
  const fps = new Set();
  for (const [i, f] of findings.entries()) {
    const w = `finding ${f.fingerprint ?? '#' + i}`;
    if (!str(f.fingerprint) || !/^[a-z0-9][a-z0-9._:/-]*$/.test(f.fingerprint)) errors.push(`${w}: fingerprint must be lowercase [a-z0-9._:/-]`);
    else if (fps.has(f.fingerprint)) errors.push(`${w}: duplicate fingerprint`); else fps.add(f.fingerprint);
    if (!VERDICTS.includes(f.verdict)) { errors.push(`${w}: verdict must be one of ${VERDICTS.join(', ')}`); continue; }
    if (!str(f.title)) errors.push(`${w}: title is required`);
    if (f.unit !== undefined && !unitIds.has(f.unit)) errors.push(`${w}: unit "${f.unit}" is not in coverage.json`);
    if (f.unit === undefined) errors.push(`${w}: link it to a coverage unit (unit)`);
    if (f.verdict !== 'rejected') {
      for (const k of BOUNDARY) if (!str(f.boundary?.[k])) errors.push(`${w}: boundary.${k} is required (who, with what input, defeats which control, across which boundary, affecting what)`);
      if (!Array.isArray(f.trace) || !f.trace.length) errors.push(`${w}: trace is required`);
      else f.trace.forEach((t, k) => { if (!['entrypoint', 'propagation', 'sink'].includes(t.kind)) errors.push(`${w}: trace[${k}].kind must be entrypoint, propagation or sink`); at(`${w} trace[${k}]`, t.file, t.line); if (!str(t.note)) errors.push(`${w}: trace[${k}].note is required`); });
    }
    if (f.verdict === 'confirmed') {
      if (!SEVERITIES.includes(f.severity)) errors.push(`${w}: confirmed findings need severity (${SEVERITIES.join('|')})`);
      if (!str(f.severity_rationale)) errors.push(`${w}: severity_rationale is required (the demonstrated impact that justifies it)`);
      if (!str(f.root_cause)) errors.push(`${w}: root_cause is required`);
      const kinds = new Set((f.trace ?? []).map((t) => t.kind));
      if (!kinds.has('entrypoint') || !kinds.has('sink')) errors.push(`${w}: a confirmed trace needs an entrypoint and a sink`);
      if (!Array.isArray(f.evidence) || !f.evidence.length) errors.push(`${w}: evidence is required`);
      else f.evidence.forEach((e, k) => { if (!EVIDENCE_TYPES.includes(e.type)) errors.push(`${w}: evidence[${k}].type must be ${EVIDENCE_TYPES.join('|')}`); if (!str(e.result)) errors.push(`${w}: evidence[${k}].result is required`); if (e.file) at(`${w} evidence[${k}]`, e.file, e.line); if (['test', 'harness'].includes(e.type) && !str(e.command)) errors.push(`${w}: evidence[${k}] of type ${e.type} needs the command that ran it`); });
      const reproduced = (f.evidence ?? []).some((e) => ['test', 'harness'].includes(e.type));
      if (!reproduced && !str(f.reproduction_waiver)) errors.push(`${w}: confirmed without a test/harness needs reproduction_waiver (why running code adds nothing, e.g. a committed secret)`);
      if (!reproduced && str(f.reproduction_waiver)) warnings.push(`${w}: confirmed by reading only (${f.reproduction_waiver})`);
      if (!str(f.fix?.invariant) || !str(f.fix?.change)) errors.push(`${w}: fix.invariant and fix.change are required`);
      const status = f.status ?? 'open';
      if (!['open', 'fixed', 'accepted_risk'].includes(status)) errors.push(`${w}: status must be open, fixed or accepted_risk`);
      if (status === 'fixed' && !str(f.fix?.regression_test)) errors.push(`${w}: fixed findings need fix.regression_test (the test that failed before and passes now)`);
      if (status === 'fixed' && str(f.fix?.regression_test)) at(`${w} regression_test`, f.fix.regression_test.split(/[:#\s]/)[0]);
      if (status === 'accepted_risk' && (!str(f.risk_owner) || !str(f.risk_reason))) errors.push(`${w}: accepted_risk needs risk_owner and risk_reason`);
    } else {
      if (f.severity !== undefined) errors.push(`${w}: only confirmed findings carry a severity`);
      if (f.verdict === 'needs_validation' && (!str(f.blocker) || !str(f.validation_plan))) errors.push(`${w}: needs_validation needs blocker (the missing fact) and validation_plan (a safe way to settle it)`);
      if (f.verdict === 'rejected' && !str(f.reason)) errors.push(`${w}: rejected findings need a reason`);
    }
  }
  for (const u of units) for (const fp of u.findings ?? []) if (!fps.has(fp)) errors.push(`coverage unit ${u.id}: links unknown finding ${fp}`);

  const count = (s) => units.filter((u) => u.status === s).length;
  const open = units.filter((u) => OPEN_STATUSES.includes(u.status));
  if (complete && open.length) errors.push(`coverage is not complete: ${open.length} unit(s) still ${[...new Set(open.map((u) => u.status))].join('/')}: ${open.slice(0, 5).map((u) => u.id).join(', ')}`);
  if (units.length && !units.some((u) => u.status === 'covered' || u.status === 'candidate')) warnings.push('no unit is covered yet');

  const conf = findings.filter((f) => f.verdict === 'confirmed');
  const summary = {
    units: units.length, covered: count('covered') + count('candidate'), open: open.length, blocked: count('blocked'), deferred: count('deferred'), outOfScope: count('out_of_scope') + count('not_applicable'),
    confirmed: Object.fromEntries(SEVERITIES.map((s) => [s, conf.filter((f) => f.severity === s).length])),
    fixed: conf.filter((f) => f.status === 'fixed').length, acceptedRisk: conf.filter((f) => f.status === 'accepted_risk').length,
    needsValidation: findings.filter((f) => f.verdict === 'needs_validation').length, rejected: findings.filter((f) => f.verdict === 'rejected').length,
  };
  if (review || coverage) fs.writeFileSync(path.join(dir, 'REVIEW_STATUS.md'), markdown(summary, findings, units, errors, warnings));
  return { ok: !errors.length, errors, warnings, summary };
}

function markdown(s, findings, units, errors, warnings) {
  const conf = findings.filter((f) => f.verdict === 'confirmed').sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  const nv = findings.filter((f) => f.verdict === 'needs_validation');
  const cell = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
  return `# Review status

${errors.length ? `**${errors.length} contract error(s) — this review is not reportable yet.**\n\n${errors.map((e) => `- ${e}`).join('\n')}\n` : 'Evidence contract: **passed**.'}
${warnings.length ? `\nWarnings:\n${warnings.map((w) => `- ${w}`).join('\n')}\n` : ''}
## Coverage
${s.covered}/${s.units} units reviewed · ${s.open} open · ${s.blocked} blocked · ${s.deferred} deferred · ${s.outOfScope} out of scope / not applicable.
${s.open || s.blocked || s.deferred ? 'Coverage is **partial**: do not describe this review as complete.' : ''}

| Unit | Surface | Boundary | Attack class | Status | Note |
|---|---|---|---|---|---|
${units.map((u) => `| \`${u.id}\` | ${cell(u.surface)} | ${cell(u.boundary)} | ${cell(u.attack_class)} | ${u.status} | ${cell(u.note)} |`).join('\n')}

## Confirmed (${conf.length})
${conf.length ? `| Severity | Finding | Status | Boundary crossed | Evidence |
|---|---|---|---|---|
${conf.map((f) => `| ${f.severity} | ${cell(f.title)} (\`${f.fingerprint}\`) | ${f.status ?? 'open'} | ${cell(f.boundary?.crossed)} | ${(f.evidence ?? []).map((e) => e.type).join(', ')}${f.reproduction_waiver ? ' (waiver)' : ''} |`).join('\n')}` : 'None.'}

## Needs validation (${nv.length}) — no severity until settled
${nv.length ? nv.map((f) => `- **${cell(f.title)}** (\`${f.fingerprint}\`): blocked on ${cell(f.blocker)}. Plan: ${cell(f.validation_plan)}`).join('\n') : 'None.'}

Rejected candidates: ${s.rejected} (kept in review.json so they are not re-reported).
`;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const args = process.argv.slice(2);
  const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
  const root = path.resolve(args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--out') ?? process.cwd());
  const r = check(root, { out: opt('--out', '.protectors'), complete: args.includes('--complete') });
  if (args.includes('--json')) console.log(JSON.stringify(r, null, 2));
  else {
    const s = r.summary;
    console.log(`Review: ${s.covered}/${s.units} units covered (${s.open} open) · confirmed ${SEVERITIES.map((k) => `${k} ${s.confirmed[k]}`).join(' · ')} · fixed ${s.fixed} · needs validation ${s.needsValidation} · rejected ${s.rejected}`);
    for (const e of r.errors) console.log(`ERROR  ${e}`);
    for (const w of r.warnings) console.log(`warn   ${w}`);
    console.log(r.ok ? 'Evidence contract passed.' : 'Evidence contract failed.');
  }
  process.exit(r.ok ? 0 : 1);
}
