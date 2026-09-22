// End-to-end tests: vulnerable fixture projects per platform → recon type + scanner detections.
// Fake secrets are assembled at runtime so this repository never contains secret-shaped strings.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
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
  return { ...res, status: r.status, rules: new Set(res.findings.map((f) => f.rule)) };
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

let failed = 0;
for (const t of tests) {
  try { t.fn(); console.log(`✔ ${t.name}`); }
  catch (e) { failed++; console.log(`✖ ${t.name}\n   ${e.message.split('\n').slice(0, 12).join('\n   ')}`); }
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed ? 1 : 0);
