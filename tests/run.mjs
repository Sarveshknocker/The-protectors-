// End-to-end tests: vulnerable fixture projects per platform → recon type + scanner detections.
// Fake secrets are assembled at runtime so this repository never contains secret-shaped strings.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import http from 'node:http';
import { fileURLToPath } from 'node:url';

const KIT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(KIT, 'bin', 'protectors.mjs');
const node = (args) => spawnSync(process.execPath, args, { encoding: 'utf8' });
const cli = (args) => node([CLI, ...args]);

const FAKE = {
  aws: 'AKIA' + 'QW3RTY7UIOP4ASDF'.slice(0, 16),
  stripe: ['sk', 'live', 'x9Y8w7V6u5T4s3R2q1P0o9N8'].join('_'),
  ghp: 'ghp' + '_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
  pem: '-----BEGIN ' + 'RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----',
};

function fixture(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'protectors-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}
function recon(dir) {
  const r = node([path.join(KIT, 'skills/protect-recon/scripts/recon.mjs'), dir]);
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(fs.readFileSync(path.join(dir, '.protectors/recon.json'), 'utf8'));
}
function scan(dir, extra = ['--fail-on', 'none']) {
  const r = node([path.join(KIT, 'skills/protect-scan/scripts/scan.mjs'), dir, ...extra]);
  const res = JSON.parse(fs.readFileSync(path.join(dir, '.protectors/findings.json'), 'utf8'));
  return { ...res, status: r.status, stderr: r.stderr, rules: new Set(res.findings.map((f) => f.rule)) };
}
const expectRules = (res, ids) => { for (const id of ids) assert.ok(res.rules.has(id), `expected ${id}; got ${[...res.rules].join(', ')}`); };

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

// ---------------------------------------------------------------- API (Express)
test('Express API: classified as api; secrets, SQLi, command injection, JWT, CORS, errors detected', () => {
  const dir = fixture({
    'package.json': JSON.stringify({ name: 'shop-api', dependencies: { express: '^4.19.0', jsonwebtoken: '^9.0.0', cors: '*' } }),
    'server.js': [
      "const express = require('express'); const cors = require('cors'); const jwt = require('jsonwebtoken');",
      "const { exec } = require('child_process');",
      `const AWS_KEY = '${FAKE.aws}';`,
      `const stripe = require('stripe')('${FAKE.stripe}');`,
      'const app = express(); app.use(cors());',
      "app.get('/user', (req, res) => db.query(\"SELECT * FROM users WHERE id = '\" + req.query.id + \"'\"));",
      "app.get('/ping', (req, res) => exec(`ping -c 1 ${req.query.host}`));",
      "app.post('/login', (req, res) => res.json({ t: jwt.sign({ u: 1 }, 'secret123') }));",
      "app.get('/file', (req, res) => res.sendFile(req.query.name));",
      "app.get('/proxy', async (req, res) => res.send(await fetch(req.query.url)));",
      'app.use((err, req, res, next) => res.status(500).json({ error: err.stack }));',
      'app.listen(3000);',
    ].join('\n'),
    '.env': 'DB_PASSWORD=hunter2hunter2\n',
  });
  const r = recon(dir);
  assert.equal(r.primaryType, 'api');
  assert.ok(r.highRisk.some((f) => f.file === 'server.js'));
  const s = scan(dir);
  expectRules(s, ['secret.aws-access-key', 'secret.stripe-live', 'inj.sql-concat', 'inj.command', 'auth.jwt-weak-secret', 'cors.wildcard-credentials',
    'file.path-traversal', 'ssrf.user-url', 'config.stack-trace-leak', 'repo.env-file-committed', 'repo.no-gitignore', 'deps.unpinned', 'deps.no-lockfile']);
  assert.equal(s.grade, 'F');
  // Secrets must be redacted in every output file.
  for (const f of ['findings.json', 'findings.sarif', 'FINDINGS.md']) {
    const out = fs.readFileSync(path.join(dir, '.protectors', f), 'utf8');
    assert.ok(!out.includes(FAKE.aws) && !out.includes(FAKE.stripe), `secret leaked in ${f}`);
  }
});

test('CLI exits non-zero on high findings with --fail-on high, zero with none', () => {
  const dir = fixture({ 'app.py': "import pickle\ndef load(b):\n    return pickle.loads(b)\n" });
  assert.equal(scan(dir, ['--fail-on', 'high']).status, 1);
  assert.equal(scan(dir, ['--fail-on', 'none']).status, 0);
});

// ---------------------------------------------------------------- Website (Next.js)
test('Next.js website: XSS sink, open redirect, source maps, powered-by detected', () => {
  const dir = fixture({
    'package.json': JSON.stringify({ dependencies: { next: '15.0.0', react: '19.0.0' } }),
    'package-lock.json': '{}',
    'app/page.tsx': 'export default function P({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} /> }',
    'app/api/go/route.ts': "export function GET(request) { return redirect(request.query.next) }",
    'next.config.mjs': 'export default { productionBrowserSourceMaps: true }',
  });
  const r = recon(dir);
  assert.deepEqual(r.types.map((t) => t.id).sort(), ['api', 'website']);
  const s = scan(dir);
  expectRules(s, ['xss.dangerous-html', 'xss.open-redirect', 'web.source-maps-prod', 'web.next-powered-by']);
});

// ---------------------------------------------------------------- Desktop (Electron)
test('Electron app: classified desktop; insecure webPreferences and raw IPC exposure detected', () => {
  const dir = fixture({
    'package.json': JSON.stringify({ main: 'main.js', devDependencies: { electron: '^31.0.0' } }),
    'main.js': "new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\nshell.openExternal(url);",
    'preload.js': "contextBridge.exposeInMainWorld('api', { ipcRenderer });",
  });
  assert.equal(recon(dir).primaryType, 'desktop');
  expectRules(scan(dir), ['electron.insecure-webprefs', 'electron.open-external', 'electron.expose-ipc']);
});

// ---------------------------------------------------------------- Browser extension
test('Browser extension: classified; broad permissions, weak CSP, MV2, unvalidated messages detected', () => {
  const dir = fixture({
    'manifest.json': JSON.stringify({ manifest_version: 2, name: 'x', version: '1', permissions: ['<all_urls>', 'cookies', 'debugger'], content_security_policy: "script-src 'self' 'unsafe-eval'; object-src 'self'" }, null, 2),
    'background.js': 'chrome.runtime.onMessage.addListener((msg, sender, send) => { doThing(msg.cmd); });',
  });
  const r = recon(dir);
  assert.equal(r.primaryType, 'browser-extension');
  expectRules(scan(dir), ['ext.broad-host-permissions', 'ext.dangerous-permissions', 'ext.weak-csp', 'ext.mv2', 'ext.unvalidated-message']);
});

// ---------------------------------------------------------------- Mobile (Android)
test('Android app: classified mobile; manifest misconfig, insecure storage, WebView bridge detected', () => {
  const dir = fixture({
    'app/src/main/AndroidManifest.xml': '<manifest><application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true"><activity android:name=".Deep" android:exported="true"></activity></application></manifest>',
    'app/src/main/java/com/x/Main.kt': 'val prefs = getSharedPreferences("p", 0); prefs.edit().putString("token", t)\nwebView.addJavascriptInterface(Bridge(), "Android")',
    'app/build.gradle': 'android { buildTypes { release { minifyEnabled false } } }',
  });
  assert.equal(recon(dir).primaryType, 'mobile');
  expectRules(scan(dir), ['android.debuggable', 'android.allow-backup', 'android.cleartext', 'android.exported', 'android.minify-off', 'mobile.insecure-storage', 'mobile.webview-js-bridge']);
});

// ---------------------------------------------------------------- Python (Flask / Django)
test('Python web: debug, TLS off, weak hash, yaml.load, shell=True, secret key detected', () => {
  const dir = fixture({
    'requirements.txt': 'flask\nrequests==2.32.0\npyyaml\n',
    'app.py': [
      'import hashlib, yaml, subprocess, requests',
      "app.secret_key = 'dev-key-1234'",
      'def h(p): return hashlib.md5(p.encode()).hexdigest()',
      'def cfg(s): return yaml.load(s)',
      "def run(host): subprocess.run(f'ping {host}', shell=True)",
      "def get(u): return requests.get(u, verify=False)",
      'app.run(debug=True)',
    ].join('\n'),
  });
  const r = recon(dir);
  assert.ok(r.types.some((t) => t.id === 'api'));
  expectRules(scan(dir), ['auth.session-secret-literal', 'crypto.weak-hash', 'deser.unsafe', 'inj.command', 'tls.verification-disabled', 'config.debug-enabled', 'deps.python-unpinned']);
});

// ---------------------------------------------------------------- Cloud / infra
test('Infra: Dockerfile, compose, Terraform, k8s and CI misconfigurations detected', () => {
  const dir = fixture({
    Dockerfile: 'FROM node\nENV API_TOKEN=abc123\nADD https://example.com/x.sh /x.sh\nCMD ["node","s.js"]\n',
    'docker-compose.yml': 'services:\n  app:\n    privileged: true\n',
    'main.tf': 'resource "aws_security_group" "db" {\n  ingress {\n    from_port = 5432\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\nresource "aws_s3_bucket_acl" "b" { acl = "public-read" }\n',
    'k8s/deploy.yaml': 'kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - securityContext:\n            privileged: true\n',
    '.github/workflows/ci.yml': 'on: issues\npermissions: write-all\njobs:\n  a:\n    steps:\n      - uses: someone/action@v1\n      - run: echo "${{ github.event.issue.title }}"\n',
    [`keys/deploy.pem`]: FAKE.pem,
  });
  const r = recon(dir);
  assert.equal(r.primaryType, 'cloud-infra');
  expectRules(scan(dir), ['docker.root-user', 'docker.latest-tag', 'docker.secret-in-env', 'docker.add-remote', 'compose.privileged', 'tf.open-ingress', 'tf.public-bucket',
    'k8s.privileged', 'ci.write-all', 'ci.unpinned-action', 'ci.script-injection', 'repo.key-material', 'secret.private-key']);
});

// ---------------------------------------------------------------- Firmware (ESP32 / Arduino / ESP-IDF)
test('Firmware: classified; hard-coded Wi-Fi creds, TLS no-verify, insecure OTA, unsafe C, sdkconfig detected', () => {
  const dir = fixture({
    'platformio.ini': '[env:esp32]\nplatform = espressif32\nframework = arduino\n',
    'src/main.cpp': [
      '#include <WiFi.h>',
      '#define WIFI_PASSWORD "Sup3rS3cretWifi"',
      'WiFiClientSecure client;',
      'void setup() { client.setInsecure(); WiFi.begin("home", WIFI_PASSWORD); }',
      'void handle(char *in) { char buf[16]; strcpy(buf, in); Serial.printf(in); }',
      'void ota() { httpUpdate.update(client, "http://updates.example.net/fw.bin"); }',
    ].join('\n'),
    'sdkconfig': 'CONFIG_IDF_TARGET="esp32"\n# CONFIG_SECURE_BOOT is not set\n# CONFIG_FLASH_ENCRYPTION_ENABLED is not set\nCONFIG_ESP_TLS_INSECURE=y\n',
    'Core/Src/main.c': 'void init(void){ FLASH_OBProgramInitTypeDef ob; ob.RDPLevel = OB_RDP_LEVEL_0; }',
  });
  const r = recon(dir);
  assert.equal(r.primaryType, 'firmware', JSON.stringify(r.types));
  assert.ok(r.types[0].frameworks.includes('platformio') && r.types[0].frameworks.includes('esp-idf'));
  const s = scan(dir);
  expectRules(s, ['secret.c-define', 'fw.tls-no-verify', 'fw.insecure-ota', 'c.banned-functions', 'c.format-string', 'fw.secure-boot-off', 'fw.flash-encryption-off', 'fw.insecure-sdkconfig', 'fw.debug-interfaces']);
  const out = fs.readFileSync(path.join(dir, '.protectors/FINDINGS.md'), 'utf8');
  assert.ok(!out.includes('Sup3rS3cretWifi'), 'Wi-Fi password leaked in report');
});

// ---------------------------------------------------------------- Linux kernel module
test('Linux kernel module: classified driver; ioctl w/o capability, unchecked copy_from_user, infoleak, alloc overflow', () => {
  const dir = fixture({
    Makefile: 'obj-m += demo.o\n',
    'demo.c': [
      '#include <linux/module.h>',
      '#include <linux/fs.h>',
      'struct info { int a; char b; long c; };',
      'static long demo_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {',
      '  struct info i; char kbuf[64]; void *p;',
      '  copy_from_user(kbuf, (void __user *)arg, cmd);',
      '  p = kmalloc(cmd * sizeof(struct info), GFP_KERNEL);',
      '  i.a = 1;',
      '  if (copy_to_user((void __user *)arg, &i, sizeof(i))) return -EFAULT;',
      '  return 0;',
      '}',
      'static const struct file_operations fops = { .unlocked_ioctl = demo_ioctl };',
      'MODULE_LICENSE("GPL");',
    ].join('\n'),
  });
  const r = recon(dir);
  assert.equal(r.primaryType, 'driver');
  assert.ok(r.highRisk.some((f) => f.file === 'demo.c' && f.tags.includes('kernel-boundary')));
  expectRules(scan(dir), ['kernel.ioctl-no-capability', 'kernel.user-copy-unchecked', 'kernel.infoleak', 'c.alloc-overflow']);
});

// ---------------------------------------------------------------- Windows kernel driver
test('Windows driver: classified; METHOD_NEITHER, deprecated pool, device ACL, physical memory primitive', () => {
  const dir = fixture({
    'driver.inf': '[Version]\nSignature="$WINDOWS NT$"\n',
    'driver.c': [
      '#include <ntddk.h>',
      '#define IOCTL_MAP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)',
      'NTSTATUS DriverEntry(PDRIVER_OBJECT d, PUNICODE_STRING r) {',
      '  PDEVICE_OBJECT dev; IoCreateDevice(d, 0, &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);',
      '  PVOID p = ExAllocatePoolWithTag(NonPagedPool, 64, \'tseT\');',
      '  return STATUS_SUCCESS; }',
      'NTSTATUS Map(PHYSICAL_ADDRESS a, SIZE_T n) { PVOID v = MmMapIoSpace(a, n, MmNonCached); return 0; }',
    ].join('\n'),
  });
  assert.equal(recon(dir).primaryType, 'driver');
  expectRules(scan(dir), ['win.method-neither', 'win.deprecated-pool', 'win.insecure-device-acl', 'win.dangerous-primitive']);
});

test('Safe C patterns are not flagged', () => {
  const dir = fixture({
    'src/ok.c': [
      '#include <stdio.h>',
      'void f(const char *in) { char b[32]; snprintf(b, sizeof b, "%s", in); printf("%s\\n", b); }',
      'void *g(size_t n) { return calloc(n, sizeof(int)); }',
    ].join('\n'),
    '.gitignore': '.env\n', 'SECURITY.md': 'x', '.github/dependabot.yml': 'version: 2',
  });
  const s = scan(dir);
  assert.equal(s.findings.length, 0, JSON.stringify(s.findings, null, 1));
});

// ---------------------------------------------------------------- Precision
test('Clean, well-configured project has no critical/high findings', () => {
  const dir = fixture({
    'package.json': JSON.stringify({ name: 'clean', bin: { clean: 'cli.js' }, dependencies: { zod: '^3.23.0' } }),
    'package-lock.json': '{}',
    '.gitignore': 'node_modules\n.env\n.env.*\n!.env.example\n',
    'SECURITY.md': '# Security',
    '.github/dependabot.yml': 'version: 2',
    'cli.js': "import { execFile } from 'node:child_process';\nimport crypto from 'node:crypto';\nconst token = crypto.randomBytes(32).toString('hex');\nexecFile('git', ['status']);\nconst url = 'https://api.example.com';\n",
    '.env.example': 'SESSION_SECRET=\n',
  });
  assert.equal(recon(dir).primaryType, 'cli');
  const s = scan(dir, ['--fail-on', 'high']);
  assert.equal(s.counts.critical + s.counts.high, 0, JSON.stringify(s.findings, null, 1));
  assert.equal(s.status, 0);
  assert.equal(s.grade, 'A');
});

test('Suppression comments and ignore.json are honoured; test paths are downgraded', () => {
  const dir = fixture({
    'src/a.js': "// protectors-ignore: inj.eval sandboxed interpreter, input is constant\neval('1+1');",
    'src/b.js': "eval(userInput);",
    'tests/c.test.js': "eval(x);",
    '.protectors/ignore.json': JSON.stringify([{ rule: 'crypto.weak-hash', path: 'legacy/', reason: 'checksum only' }]),
    'legacy/sum.js': "require('crypto').createHash('md5');",
  });
  const s = scan(dir);
  const evals = s.findings.filter((f) => f.rule === 'inj.eval');
  assert.deepEqual(evals.map((f) => f.file).sort(), ['src/b.js', 'tests/c.test.js']);
  assert.equal(evals.find((f) => f.file === 'tests/c.test.js').severity, 'medium');
  assert.ok(!s.rules.has('crypto.weak-hash'));
});

test('SARIF output is valid 2.1.0 with rules and locations', () => {
  const dir = fixture({ 'x.js': "const h = require('crypto').createHash('sha1');" });
  scan(dir);
  const sarif = JSON.parse(fs.readFileSync(path.join(dir, '.protectors/findings.sarif'), 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  const run = sarif.runs[0];
  assert.ok(run.tool.driver.rules.some((r) => r.id === 'crypto.weak-hash'));
  assert.ok(run.results.every((x) => x.locations[0].physicalLocation.region.startLine >= 1));
});

// ---------------------------------------------------------------- Kit self-checks
test('Kit templates themselves pass the scanner (no critical/high)', () => {
  const dir = fixture({});
  fs.cpSync(path.join(KIT, 'skills/protect-defense/templates'), path.join(dir, 'src'), { recursive: true });
  const s = scan(dir);
  const bad = s.findings.filter((f) => ['critical', 'high'].includes(f.severity));
  assert.equal(bad.length, 0, JSON.stringify(bad, null, 1));
});

test('init → update → remove round-trip keeps user content intact', () => {
  const dir = fixture({ 'AGENTS.md': '# Team rules\nUse pnpm.\n', 'package.json': '{}' });
  let r = cli(['init', dir]);
  assert.equal(r.status, 0, r.stderr);
  const agents = fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf8');
  assert.match(agents, /Use pnpm\./);
  assert.match(agents, /\.protectors-kit\/skills\/protect\/SKILL\.md/);
  for (const f of ['CLAUDE.md', 'GEMINI.md', '.github/copilot-instructions.md', '.cursor/rules/the-protectors.mdc', '.windsurf/rules/the-protectors.md', '.clinerules/the-protectors.md', '.claude/skills/protect/SKILL.md', '.claude/agents/security-reviewer.md', '.protectors-kit/skills/protect-scan/scripts/scan.mjs']) {
    assert.ok(fs.existsSync(path.join(dir, f)), `missing ${f}`);
  }
  r = cli(['update', dir]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal((fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf8').match(/protectors:start/g) ?? []).length, 1);
  fs.mkdirSync(path.join(dir, '.protectors'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.protectors/SECURITY_REPORT.md'), 'keep');
  r = cli(['remove', dir]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(fs.readFileSync(path.join(dir, 'AGENTS.md'), 'utf8'), '# Team rules\nUse pnpm.\n');
  assert.ok(!fs.existsSync(path.join(dir, '.protectors-kit')));
  assert.ok(!fs.existsSync(path.join(dir, '.claude/skills/protect')));
  assert.ok(fs.existsSync(path.join(dir, '.protectors/SECURITY_REPORT.md')));
});

test('Installed kit (all adapters) never scans its own copies; user .claude files still scanned', () => {
  const dir = fixture({ 'package.json': '{}', 'index.html': '<html></html>', '.claude/hooks/run.js': 'eval(userInput);' });
  cli(['init', dir]);
  const s = scan(dir);
  const kitHits = s.findings.filter((f) => /^\.claude\/(skills|agents)\/|^\.protectors-kit\//.test(f.file));
  assert.equal(kitHits.length, 0, JSON.stringify(kitHits.slice(0, 3), null, 1));
  assert.ok(s.findings.some((f) => f.file === '.claude/hooks/run.js' && f.rule === 'inj.eval'), 'user-owned .claude files must still be scanned');
  const r = recon(dir);
  assert.ok(!r.inventory.some((f) => f.file.startsWith('.claude/skills/protect')));
});

test('Installed kit scripts run from inside the target project', () => {
  const dir = fixture({ 'package.json': '{}', 'index.html': '<html></html>' });
  cli(['init', dir, '--tools', 'agents']);
  const r = node([path.join(dir, '.protectors-kit/skills/protect-scan/scripts/scan.mjs'), dir, '--fail-on', 'none']);
  assert.equal(r.status, 0, r.stderr);
  const s = JSON.parse(fs.readFileSync(path.join(dir, '.protectors/findings.json'), 'utf8'));
  assert.ok(!s.findings.some((f) => f.file.startsWith('.protectors-kit/')), 'kit must not scan itself inside a project');
});

test('Every skill has valid frontmatter and referenced files exist', () => {
  for (const s of fs.readdirSync(path.join(KIT, 'skills'))) {
    const md = fs.readFileSync(path.join(KIT, 'skills', s, 'SKILL.md'), 'utf8');
    const fm = md.match(/^---\nname: ([\w-]+)\ndescription: (.+)\n---/);
    assert.ok(fm, `${s}: bad frontmatter`);
    assert.equal(fm[1], s);
    for (const ref of md.matchAll(/`((?:references|templates|scripts)\/[\w./-]+\.\w+)`/g)) {
      assert.ok(fs.existsSync(path.join(KIT, 'skills', s, ref[1])), `${s}: missing ${ref[1]}`);
    }
  }
  // Playbooks referenced by recon exist for every type the classifier can emit.
  for (const t of ['website', 'api', 'mobile', 'desktop', 'browser-extension', 'cli-library', 'cloud-infra', 'firmware', 'driver', 'common']) {
    assert.ok(fs.existsSync(path.join(KIT, 'skills/protect-defense/references', `${t}.md`)), `missing playbook ${t}`);
  }
});

// ---------------------------------------------------------------- v0.2: rules corpus, deps, history, baseline, evidence
const { runCorpus, fake } = await import(new URL('../skills/protect-scan/scripts/rule-test.mjs', import.meta.url));
const { cvss3, cmpVersion, nextFixed } = await import(new URL('../skills/protect-deps/scripts/deps.mjs', import.meta.url));
const { findLockfiles, parseLockfile, purl } = await import(new URL('../skills/protect-deps/scripts/lockfiles.mjs', import.meta.url));
const { check: reviewCheck } = await import(new URL('../skills/protect-verify/scripts/review-check.mjs', import.meta.url));
const nodeAsync = (args, opts = {}) => new Promise((resolve) => {
  const child = spawn(process.execPath, args, { cwd: opts.cwd, env: { ...process.env, ...(opts.env ?? {}) } });
  let stdout = ''; let stderr = '';
  child.stdout.on('data', (d) => { stdout += d; }); child.stderr.on('data', (d) => { stderr += d; });
  child.on('close', (status) => resolve({ status, stdout, stderr }));
});
const DEPS = path.join(KIT, 'skills/protect-deps/scripts/deps.mjs');
const SCAN = path.join(KIT, 'skills/protect-scan/scripts/scan.mjs');

test('Rule corpus: every rule fires on its ruleid lines and stays quiet on its ok lines', () => {
  const r = runCorpus(path.join(KIT, 'tests/rules'), { requireCoverage: true });
  assert.deepEqual(r.failures, [], r.failures.join('\n'));
  assert.ok(r.rules >= 135 && r.covered === r.rules, `${r.covered}/${r.rules}`);
});

test('CVSS v3 calculator and version ordering match the specs', () => {
  assert.equal(cvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'), 5.5);
  assert.equal(cvss3('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3('CVSS:4.0/AV:N'), null);
  assert.ok(cmpVersion('1.10.0', '1.9.9') > 0);
  assert.ok(cmpVersion('1.0.0-rc1', '1.0.0') < 0);
  assert.equal(cmpVersion('2.0', '2.0.0'), 0);
  assert.ok(cmpVersion('4.17.21', '4.17.3') > 0);
  assert.equal(nextFixed(['1.11.28', '2.2.10', '3.0.3'], '2.2.0'), '2.2.10');
  assert.equal(nextFixed(['1.0.0'], '2.0.0'), null);
});

const LOCKS = {
  'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { lodash: '^4' }, devDependencies: { minimist: '0.0.8' } }, 'node_modules/lodash': { version: '4.17.15' }, 'node_modules/minimist': { version: '0.0.8', dev: true }, 'node_modules/lodash/node_modules/ms': { version: '2.0.0' }, 'node_modules/evil-pkg': { version: '1.0.0' } } }),
  'web/yarn.lock': '# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.24.0"\n  resolved "x"\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n',
  'app/pnpm-lock.yaml': "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      axios:\n        specifier: ^1.6.0\n        version: 1.6.0\n\npackages:\n\n  axios@1.6.0:\n    resolution: {integrity: x}\n\n  '@types/node@20.1.0':\n    resolution: {integrity: y}\n\nsnapshots:\n\n  axios@1.6.0: {}\n",
  'requirements.txt': 'Django==2.2.0\nrequests>=2\nPyYAML[extra]==5.3  # pinned\n',
  'svc/poetry.lock': '[[package]]\nname = "jinja2"\nversion = "2.10"\ncategory = "main"\n\n[[package]]\nname = "pytest"\nversion = "7.0.0"\ncategory = "dev"\n',
  'rs/Cargo.lock': '[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
  'go/go.mod': 'module example.com/app\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.17.0\n\tgithub.com/pkg/errors v0.9.1 // indirect\n)\n',
  'php/composer.lock': JSON.stringify({ packages: [{ name: 'guzzlehttp/guzzle', version: '7.4.0' }], 'packages-dev': [{ name: 'phpunit/phpunit', version: 'v9.0.0' }] }),
  'rb/Gemfile.lock': 'GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (6.1.0)\n    nokogiri (1.11.0-x86_64-linux)\n\nPLATFORMS\n  ruby\n',
  'dart/pubspec.lock': 'packages:\n  http:\n    dependency: "direct main"\n    description:\n      name: http\n    source: hosted\n    version: "0.13.0"\n  mylib:\n    dependency: "direct main"\n    source: path\n    version: "1.0.0"\n',
  'cs/packages.lock.json': JSON.stringify({ version: 1, dependencies: { 'net8.0': { 'Newtonsoft.Json': { type: 'Direct', resolved: '12.0.1' }, 'App.Core': { type: 'Project' } } } }),
  'java/pom.xml': '<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope></dependency></dependencies></project>',
  'kt/gradle.lockfile': 'com.fasterxml.jackson.core:jackson-databind:2.9.8=compileClasspath,runtimeClasspath\nempty=\n',
};

test('Lockfile parsers read exact versions across 12 formats; purls are spec-shaped', () => {
  const dir = fixture(LOCKS);
  const files = findLockfiles(dir);
  assert.equal(files.length, Object.keys(LOCKS).length, files.join(', '));
  const all = files.flatMap((f) => parseLockfile(dir, f));
  const has = (eco, name, version) => assert.ok(all.some((p) => p.ecosystem === eco && p.name === name && p.version === version), `missing ${eco} ${name}@${version}`);
  has('npm', 'lodash', '4.17.15'); has('npm', 'ms', '2.0.0'); has('npm', '@babel/core', '7.24.0'); has('npm', 'left-pad', '1.3.0'); has('npm', 'axios', '1.6.0'); has('npm', '@types/node', '20.1.0');
  has('PyPI', 'Django', '2.2.0'); has('PyPI', 'PyYAML', '5.3'); has('PyPI', 'jinja2', '2.10'); has('crates.io', 'smallvec', '1.6.0'); has('Go', 'golang.org/x/net', '0.17.0');
  has('Packagist', 'guzzlehttp/guzzle', '7.4.0'); has('Packagist', 'phpunit/phpunit', '9.0.0'); has('RubyGems', 'nokogiri', '1.11.0'); has('Pub', 'http', '0.13.0');
  has('NuGet', 'Newtonsoft.Json', '12.0.1'); has('Maven', 'org.apache.logging.log4j:log4j-core', '2.14.1'); has('Maven', 'com.fasterxml.jackson.core:jackson-databind', '2.9.8');
  assert.ok(!all.some((p) => p.name === 'requests' || p.name === 'app' || p.name === 'mylib' || p.name === 'App.Core'), 'unpinned, workspace, path and project entries are skipped');
  const npm = parseLockfile(dir, 'package-lock.json');
  assert.equal(npm.find((p) => p.name === 'lodash').direct, true);
  assert.equal(npm.find((p) => p.name === 'ms').direct, false);
  assert.equal(npm.find((p) => p.name === 'minimist').dev, true);
  assert.equal(parseLockfile(dir, 'svc/poetry.lock').find((p) => p.name === 'pytest').dev, true);
  assert.equal(parseLockfile(dir, 'java/pom.xml').find((p) => p.name === 'junit:junit').dev, true);
  assert.equal(purl({ ecosystem: 'npm', name: '@babel/core', version: '7.24.0' }), 'pkg:npm/%40babel/core@7.24.0');
  assert.equal(purl({ ecosystem: 'PyPI', name: 'PyYAML', version: '5.3' }), 'pkg:pypi/pyyaml@5.3');
  assert.equal(purl({ ecosystem: 'Maven', name: 'junit:junit', version: '4.12' }), 'pkg:maven/junit/junit@4.12');
  assert.equal(npm.find((p) => p.name === 'ms').line, LOCKS['package-lock.json'].slice(0, LOCKS['package-lock.json'].indexOf('"node_modules/lodash/node_modules/ms"')).split('\n').length);
});

/** Mock OSV / CISA KEV / FIRST EPSS on 127.0.0.1, recording every request. */
async function mockVulnServer() {
  const seen = [];
  const VULNS = {
    'GHSA-aaaa': { id: 'GHSA-aaaa', aliases: ['CVE-2021-0001'], summary: 'Prototype pollution in lodash', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }], affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }, { type: 'GIT', events: [{ fixed: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' }] }] }] },
    'PYSEC-1': { id: 'PYSEC-1', aliases: ['CVE-2021-0001', 'GHSA-aaaa'], summary: 'dup', affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'ECOSYSTEM', events: [{ fixed: '4.17.20' }] }] }] },
    'GHSA-bbbb': { id: 'GHSA-bbbb', aliases: ['CVE-2021-0002'], summary: 'ReDoS', database_specific: { severity: 'MODERATE' }, affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '4.17.19' }] }] }] },
    'GHSA-cccc': { id: 'GHSA-cccc', aliases: ['CVE-2021-0003'], summary: 'minimist pollution', database_specific: { severity: 'LOW' }, affected: [{ package: { ecosystem: 'npm', name: 'minimist' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '0.2.4' }] }] }] },
    'MAL-2024-1': { id: 'MAL-2024-1', summary: 'Malicious code in evil-pkg', affected: [{ package: { ecosystem: 'npm', name: 'evil-pkg' } }] },
    'GHSA-dddd': { id: 'GHSA-dddd', aliases: ['CVE-2021-0004'], summary: 'Django SQLi', database_specific: { severity: 'LOW' }, affected: [{ package: { ecosystem: 'PyPI', name: 'Django' }, ranges: [{ type: 'ECOSYSTEM', events: [{ fixed: '2.2.10' }] }] }] },
  };
  const BY_PKG = { 'npm|lodash': ['GHSA-aaaa', 'PYSEC-1', 'GHSA-bbbb'], 'npm|minimist': ['GHSA-cccc'], 'npm|evil-pkg': ['MAL-2024-1'], 'PyPI|Django': ['GHSA-dddd'] };
  const server = http.createServer((req, res) => {
    let body = ''; req.on('data', (d) => { body += d; });
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, body });
      const json = (o) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
      if (req.url === '/osv/querybatch') return json({ results: JSON.parse(body).queries.map((q) => ({ vulns: (BY_PKG[`${q.package.ecosystem}|${q.package.name}`] ?? []).map((id) => ({ id })) })) });
      if (req.url.startsWith('/osv/vulns/')) return json(VULNS[decodeURIComponent(req.url.slice(11))]);
      if (req.url === '/kev') return json({ vulnerabilities: [{ cveID: 'CVE-2021-0004' }] });
      if (req.url.startsWith('/epss')) return json({ data: [{ cve: 'CVE-2021-0002', epss: '0.42', percentile: '0.97' }] });
      res.writeHead(404); res.end();
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { server, seen, env: { PROTECTORS_OSV_API: `${base}/osv`, PROTECTORS_KEV_URL: `${base}/kev`, PROTECTORS_EPSS_API: `${base}/epss` } };
}

test('deps: OSV + KEV + EPSS prioritisation, alias merge, malicious packages, upgrade plan, SBOM, scanner merge', async () => {
  const { server, seen, env } = await mockVulnServer();
  try {
    const dir = fixture({ 'package-lock.json': LOCKS['package-lock.json'], 'requirements.txt': 'Django==2.2.0\n', 'package.json': JSON.stringify({ name: 'shop', version: '1.2.3' }) });
    const r = await nodeAsync([DEPS, dir, '--fail-on', 'critical'], { env });
    assert.equal(r.status, 1, 'critical findings fail the run');
    const d = JSON.parse(fs.readFileSync(path.join(dir, '.protectors/deps.json'), 'utf8'));
    const by = (pkg, id) => d.findings.find((f) => f.package.name === pkg && f.vuln.aliases.includes(id));
    const lodash = d.findings.filter((f) => f.package.name === 'lodash');
    assert.equal(lodash.length, 2, 'GHSA-aaaa and PYSEC-1 share CVE-2021-0001 and merge into one finding');
    const a = by('lodash', 'CVE-2021-0001');
    assert.equal(a.vuln.id, 'GHSA-aaaa'); assert.equal(a.vuln.cvss, 9.8); assert.equal(a.severity, 'critical');
    assert.ok(!a.vuln.fixed.some((v) => /deadbeef/.test(v)), 'GIT commit ranges are not versions');
    assert.equal(a.vuln.fixedNext, '4.17.20');
    assert.equal(by('lodash', 'CVE-2021-0002').severity, 'high', 'EPSS 42% raises MODERATE to high');
    assert.equal(by('minimist', 'CVE-2021-0003').severity, 'info', 'LOW on a dev-only dependency drops a level');
    assert.equal(by('Django', 'CVE-2021-0004').severity, 'critical', 'CISA KEV makes it critical');
    assert.equal(by('Django', 'CVE-2021-0004').vuln.kev, true);
    const mal = d.findings.find((f) => f.rule === 'deps.malicious');
    assert.equal(mal.package.name, 'evil-pkg'); assert.equal(mal.severity, 'critical');
    const plan = Object.fromEntries(d.upgradePlan.map((e) => [e.name, e]));
    assert.equal(plan.lodash.to, '4.17.20'); assert.equal(plan.lodash.fixes, 2); assert.equal(plan.Django.kev, true);
    assert.equal(d.upgradePlan[0].name, 'Django', 'KEV first');
    const sbom = JSON.parse(fs.readFileSync(path.join(dir, '.protectors/sbom.cdx.json'), 'utf8'));
    assert.equal(sbom.bomFormat, 'CycloneDX'); assert.equal(sbom.specVersion, '1.5'); assert.equal(sbom.metadata.component.name, 'shop');
    assert.ok(sbom.components.some((c) => c.purl === 'pkg:npm/lodash@4.17.15'));
    assert.ok(sbom.vulnerabilities.some((v) => v.id === 'GHSA-aaaa' && v.affects[0].ref === 'pkg:npm/lodash@4.17.15'));
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, '.protectors/deps.sarif'), 'utf8')).version, '2.1.0');
    assert.match(fs.readFileSync(path.join(dir, '.protectors/DEPENDENCIES.md'), 'utf8'), /## Upgrade plan[\s\S]*\| Django \| 2\.2\.0 \| 2\.2\.10 \|/);
    const query = JSON.parse(seen.find((s) => s.url === '/osv/querybatch').body);
    assert.ok(query.queries.every((q) => Object.keys(q).sort().join() === 'package,version'), 'only package + version leave the machine');
    // the scanner merges dependency findings into its report and score
    const s = scan(dir);
    assert.ok(s.rules.has('deps.vulnerable') && s.rules.has('deps.malicious'));
    assert.equal(s.deps.findings, d.findings.length);
  } finally { server.close(); }
});

test('deps: --offline and --exclude keep package names local', async () => {
  const { server, seen, env } = await mockVulnServer();
  try {
    const dir = fixture({ 'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/@acme/secret-sauce': { version: '1.0.0' }, 'node_modules/lodash': { version: '4.17.15' } } }) });
    let r = await nodeAsync([DEPS, dir, '--offline'], { env });
    assert.equal(r.status, 0); assert.equal(seen.length, 0, 'offline makes no requests');
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, '.protectors/sbom.cdx.json'), 'utf8')).components.length, 2);
    r = await nodeAsync([DEPS, dir, '--exclude', '^@acme/'], { env });
    assert.equal(r.status, 0);
    assert.ok(!seen.some((s) => s.body.includes('secret-sauce')), 'excluded names never sent');
  } finally { server.close(); }
});

test('Secrets in git history: removed secrets are reported with their commit; live ones note first commit', () => {
  const dir = fixture({ 'README.md': '# demo\n' });
  const git = (...a) => { const r = spawnSync('git', ['-C', dir, '-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...a], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); return r.stdout; };
  git('init', '-q'); git('add', '.'); git('commit', '-qm', 'init');
  fs.writeFileSync(path.join(dir, 'config.js'), `const token = "${fake('github')}";\nconst stripe = "${fake('stripe')}";\n`);
  git('add', '.'); git('commit', '-qm', 'add keys');
  const leakCommit = git('rev-parse', 'HEAD').trim().slice(0, 12);
  fs.writeFileSync(path.join(dir, 'config.js'), `const token = process.env.GITHUB_TOKEN;\nconst stripe = "${fake('stripe')}";\n`);
  git('add', '.'); git('commit', '-qm', 'remove github token');
  let s = scan(dir);
  assert.ok(!s.rules.has('history.github-token'), 'not without --history');
  s = scan(dir, ['--history', '--fail-on', 'high']);
  assert.equal(s.status, 1);
  const h = s.findings.find((f) => f.rule === 'history.github-token');
  assert.ok(h, [...s.rules].join(', '));
  assert.equal(h.commit, leakCommit); assert.equal(h.context, 'history'); assert.ok(!h.snippet.includes(fake('github')), 'redacted');
  const live = s.findings.find((f) => f.rule === 'secret.stripe-live');
  assert.equal(live.firstCommit, leakCommit, 'live secret knows when it entered history');
  assert.ok(!s.rules.has('history.stripe-live'), 'a secret still in HEAD is not duplicated as a history finding');
  assert.equal(s.history.secretsOnlyInHistory, 1);
});

test('Baseline: accepted findings stop failing CI; new ones still fail', () => {
  const dir = fixture({ 'server.js': "const { exec } = require('child_process');\nexec(`ls ${process.argv[2]}`);\n" });
  let s = scan(dir, ['--write-baseline', '.protectors-baseline.json', '--fail-on', 'high']);
  assert.equal(s.status, 1);
  s = scan(dir, ['--baseline', '.protectors-baseline.json', '--fail-on', 'high']);
  assert.equal(s.status, 0, 'only baselined findings → pass');
  assert.ok(s.findings.every((f) => f.baseline));
  fs.appendFileSync(path.join(dir, 'server.js'), "db.query(\"SELECT * FROM t WHERE id = '\" + req.query.id + \"'\");\n");
  s = scan(dir, ['--baseline', '.protectors-baseline.json', '--fail-on', 'high']);
  assert.equal(s.status, 1, 'new finding fails');
  assert.equal(s.newCounts.critical, 1);
  const sarif = JSON.parse(fs.readFileSync(path.join(dir, '.protectors/findings.sarif'), 'utf8'));
  assert.ok(sarif.runs[0].results.some((r) => r.baselineState === 'new') && sarif.runs[0].results.some((r) => r.baselineState === 'unchanged'));
  assert.ok(!fs.readFileSync(path.join(dir, '.protectors-baseline.json'), 'utf8').includes('exec('), 'baseline stores no code');
});

test('Findings carry CWE Top 25 and compliance summary; invalid custom rules are rejected', () => {
  const dir = fixture({ 'a.js': "app.get('/f', (req, res) => res.sendFile(req.query.name));\n" });
  const s = scan(dir);
  assert.ok(s.findings.find((f) => f.rule === 'file.path-traversal').cweTop25);
  assert.ok(s.compliance.cweTop25.includes('CWE-22'));
  fs.writeFileSync(path.join(dir, '.protectors-rules.json'), '[{ "id": "x" }]');
  const r = node([SCAN, dir, '--fail-on', 'none']);
  assert.equal(r.status, 2); assert.match(r.stderr, /Invalid \.protectors-rules\.json/);
});

test('Evidence contract: a well-formed review passes; each broken rule is caught', () => {
  const dir = fixture({ 'src/routes/orders.ts': 'line1\nline2\nline3\n', 'src/services/orders.ts': 'a\nb\nc\nd\n', 'test/orders.idor.test.ts': 'test\n' });
  const out = path.join(dir, '.protectors'); fs.mkdirSync(out);
  const coverage = { units: [
    { id: 'api/orders:authz', surface: 'REST /api/orders', boundary: 'user → other users', attack_class: 'authorization', status: 'covered', reviewed_paths: ['src/routes/orders.ts'], findings: ['idor.orders'] },
    { id: 'infra/cdn', surface: 'CDN', boundary: 'browser → app', attack_class: 'headers', status: 'blocked', note: 'not in repo' },
  ] };
  const good = { fingerprint: 'idor.orders', verdict: 'confirmed', unit: 'api/orders:authz', title: 'IDOR', root_cause: 'no owner filter',
    boundary: { attacker: 'customer', input: 'GET /orders/:id', control: 'ownership', crossed: 'user → others', affected: 'orders' },
    trace: [{ kind: 'entrypoint', file: 'src/routes/orders.ts', line: 2, note: 'route' }, { kind: 'sink', file: 'src/services/orders.ts', line: 4, note: 'findById' }],
    evidence: [{ type: 'test', command: 'npm test', file: 'test/orders.idor.test.ts', result: '200 for other user' }],
    severity: 'high', severity_rationale: 'reads any order', fix: { invariant: 'owner only', change: 'filter by owner', regression_test: 'test/orders.idor.test.ts' }, status: 'fixed' };
  const nv = { fingerprint: 'csp.edge', verdict: 'needs_validation', unit: 'infra/cdn', title: 'CSP maybe at edge', boundary: good.boundary, trace: [good.trace[0]], blocker: 'CDN config absent', validation_plan: 'owner checks headers' };
  const write = (findings, cov = coverage) => { fs.writeFileSync(path.join(out, 'review.json'), JSON.stringify({ findings })); fs.writeFileSync(path.join(out, 'coverage.json'), JSON.stringify(cov)); return reviewCheck(dir); };
  let r = write([good, nv]);
  assert.deepEqual(r.errors, []); assert.equal(r.summary.confirmed.high, 1); assert.equal(r.summary.needsValidation, 1);
  assert.ok(fs.existsSync(path.join(out, 'REVIEW_STATUS.md')));
  const broken = (patch, re) => { const e = write(patch).errors.join('\n'); assert.match(e, re); };
  broken([{ ...good, evidence: [{ type: 'reading', result: 'looked at it' }] }, nv], /reproduction_waiver/);
  broken([good, { ...nv, severity: 'high' }], /only confirmed findings carry a severity/);
  broken([{ ...good, trace: [{ ...good.trace[0], line: 99 }, good.trace[1]] }, nv], /past the end of the file/);
  broken([{ ...good, trace: [good.trace[1]] }, nv], /entrypoint and a sink/);
  broken([{ ...good, fix: { invariant: 'x', change: 'y' } }, nv], /regression_test/);
  broken([{ ...good, unit: 'nope' }, nv], /not in coverage\.json/);
  broken([good, { ...nv, blocker: '' }], /blocker/);
  broken([{ ...good, boundary: { ...good.boundary, crossed: '' } }, nv], /boundary\.crossed/);
  r = write([good, nv], { units: [...coverage.units, { id: 'api/upload', surface: 'upload', boundary: 'internet → fs', attack_class: 'files', status: 'planned' }] });
  assert.deepEqual(r.errors, []);
  assert.match(reviewCheck(dir, { complete: true }).errors.join('\n'), /coverage is not complete: 1 unit/);
});

test('Orchestrator and entry block route to every skill; plugin manifests agree with package.json', () => {
  const orchestrator = fs.readFileSync(path.join(KIT, 'skills/protect/SKILL.md'), 'utf8');
  const entry = fs.readFileSync(path.join(KIT, 'adapters/entry.md'), 'utf8');
  for (const s of fs.readdirSync(path.join(KIT, 'skills'))) {
    if (s !== 'protect') assert.ok(orchestrator.includes(s), `protect/SKILL.md does not mention ${s}`);
    assert.ok(entry.includes(`skills/${s}/SKILL.md`), `entry.md does not list ${s}`);
  }
  const pkg = JSON.parse(fs.readFileSync(path.join(KIT, 'package.json'), 'utf8'));
  for (const f of ['.claude-plugin/plugin.json', '.codex-plugin/plugin.json']) {
    const m = JSON.parse(fs.readFileSync(path.join(KIT, f), 'utf8'));
    assert.equal(m.name, pkg.name, f); assert.equal(m.version, pkg.version, f);
  }
  assert.equal(JSON.parse(fs.readFileSync(path.join(KIT, '.agents/plugins/marketplace.json'), 'utf8')).plugins[0].name, pkg.name);
});

test('Evals are well formed (with a should-not-trigger case)', () => {
  const e = JSON.parse(fs.readFileSync(path.join(KIT, 'evals/cases.json'), 'utf8'));
  const ids = new Set();
  for (const c of e.cases) { assert.ok(c.id && !ids.has(c.id)); ids.add(c.id); assert.ok(c.prompt && c.graders.length >= 2 && c.expected, c.id); }
  assert.ok(e.cases.some((c) => c.kind === 'negative'));
});

let failed = 0;
for (const t of tests) {
  try { await t.fn(); console.log(`✔ ${t.name}`); }
  catch (e) { failed++; console.log(`✖ ${t.name}\n   ${e.message.split('\n').slice(0, 12).join('\n   ')}`); }
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
