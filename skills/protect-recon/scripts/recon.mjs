#!/usr/bin/env node
// The Protectors — project reconnaissance (zero dependencies).
// Identifies project type(s), languages, frameworks, entry points and builds a per-file risk inventory.
// Usage: node recon.mjs [projectRoot] [--out .protectors]
// Writes <out>/recon.json and <out>/recon.md
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const root = path.resolve(args.find((a) => !a.startsWith('--')) ?? process.cwd());
const outIdx = args.indexOf('--out');
const outDir = path.resolve(root, outIdx >= 0 ? args[outIdx + 1] : '.protectors');

export const IGNORE_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', '.output', '.turbo',
  '.cache', 'coverage', 'vendor', '.venv', 'venv', 'env', '__pycache__', '.mypy_cache', '.pytest_cache', 'target',
  'bin/Debug', 'bin/Release', 'obj', '.pio', 'managed_components', 'sstate-cache', 'downloads', 'x64', 'ARM64', 'Pods', 'DerivedData', '.gradle', '.idea', '.dart_tool', '.protectors',
  '.protectors-kit', '.immersive-kit', '.terraform', '.expo', 'android/app/build', 'ios/build',
]);
const MAX_FILES = 50000;

function walk(dir, acc) {
  if (acc.length >= MAX_FILES) return acc;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    const rel = path.relative(root, full).split(path.sep).join('/');
    if (IGNORE_DIRS.has(e.name) || IGNORE_DIRS.has(rel)) continue;
    if (/^\.claude\/(skills\/protect(-[\w-]+)?|agents\/(recon-analyst|security-reviewer|hardening-engineer|verification-auditor)\.md)(\/|$)/.test(rel)) continue; // kit's own copies
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) walk(full, acc);
    else {
      let size = 0;
      try { size = fs.statSync(full).size; } catch {}
      acc.push({ rel, size });
    }
    if (acc.length >= MAX_FILES) break;
  }
  return acc;
}
const files = walk(root, []);
const rels = files.map((f) => f.rel);
const exists = (p) => fs.existsSync(path.join(root, p));
const read = (p) => { try { return fs.readFileSync(path.join(root, p), 'utf8'); } catch { return ''; } };
const any = (re) => rels.some((r) => re.test(r));
const count = (re) => rels.filter((r) => re.test(r)).length;

// ---------- languages ----------
const LANG = {
  JavaScript: /\.(m|c)?jsx?$/, TypeScript: /\.(m|c)?tsx?$/, Python: /\.py$/, Java: /\.java$/, Kotlin: /\.kts?$/,
  Swift: /\.swift$/, 'Objective-C': /\.(m|mm)$/, Dart: /\.dart$/, Go: /\.go$/, Rust: /\.rs$/, 'C#': /\.cs$/,
  PHP: /\.php$/, Ruby: /\.rb$/, 'C/C++': /\.(c|cc|cpp|cxx|h|hpp)$/, Shell: /\.(sh|bash|ps1)$/, HCL: /\.tf$/,
  HTML: /\.html?$/, Vue: /\.vue$/, Svelte: /\.svelte$/, SQL: /\.sql$/,
};
const languages = Object.entries(LANG).map(([k, re]) => [k, count(re)]).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1])
  .map(([name, files]) => ({ name, files }));

// ---------- manifests ----------
const pkg = (() => { try { return JSON.parse(read('package.json')); } catch { return {}; } })();
const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
const has = (d) => Object.prototype.hasOwnProperty.call(deps, d);
const pyText = [read('requirements.txt'), read('pyproject.toml'), read('Pipfile'), read('setup.py')].join('\n').toLowerCase();
const pyHas = (d) => new RegExp(`(^|[\\s"'\\[])${d}([\\s=<>~!\\[;"',]|$)`, 'm').test(pyText);
const gradle = rels.filter((r) => /build\.gradle(\.kts)?$/.test(r)).map(read).join('\n');
const pom = read('pom.xml');
const composer = read('composer.json');
const gemfile = read('Gemfile');
const gomod = read('go.mod');
const cargo = read('Cargo.toml');
const csproj = rels.filter((r) => /\.csproj$/.test(r)).map(read).join('\n');

// Browser extension: a manifest.json with manifest_version
const extManifests = rels.filter((r) => /(^|\/)manifest\.json$/.test(r)).filter((r) => /"manifest_version"\s*:/.test(read(r)));

// ---------- classification ----------
const types = [];
const add = (id, label, evidence, frameworks = []) => types.push({ id, label, evidence, frameworks });

if (extManifests.length) {
  const mv = /"manifest_version"\s*:\s*(\d)/.exec(read(extManifests[0]))?.[1];
  add('browser-extension', `Browser extension (Manifest V${mv ?? '?'})`, extManifests);
}
if (has('electron')) add('desktop', 'Desktop app (Electron)', ['package.json: electron'], ['electron']);
if (exists('src-tauri/tauri.conf.json') || exists('src-tauri/Cargo.toml')) add('desktop', 'Desktop app (Tauri)', ['src-tauri/'], ['tauri']);
if (/UseWPF|UseWindowsForms|Microsoft\.Maui|Avalonia/i.test(csproj)) add('desktop', 'Desktop app (.NET)', ['*.csproj'], ['dotnet-desktop']);
if (pyHas('pyqt5') || pyHas('pyqt6') || pyHas('pyside6') || pyHas('tkinter') || pyHas('kivy')) add('desktop', 'Desktop app (Python GUI)', ['python deps'], ['python-gui']);

if (has('react-native') || has('expo')) add('mobile', 'Mobile app (React Native / Expo)', ['package.json'], ['react-native']);
if (exists('pubspec.yaml') && /flutter:/.test(read('pubspec.yaml'))) add('mobile', 'Mobile app (Flutter)', ['pubspec.yaml'], ['flutter']);
if (any(/(^|\/)AndroidManifest\.xml$/) && !types.some((t) => t.id === 'mobile')) add('mobile', 'Mobile app (Android native)', rels.filter((r) => /AndroidManifest\.xml$/.test(r)).slice(0, 3), ['android']);
if (any(/\.xcodeproj\/|Info\.plist$/) && any(/\.swift$|\.m$/) && !types.some((t) => t.id === 'mobile')) add('mobile', 'Mobile/Apple app (iOS/macOS native)', ['*.xcodeproj'], ['ios']);
if (has('@capacitor/core') || has('cordova')) add('mobile', 'Mobile app (Capacitor/Cordova hybrid)', ['package.json'], ['hybrid']);

// Firmware / embedded
const cmakeText = rels.filter((r) => /(^|\/)CMakeLists\.txt$|\.cmake$/.test(r)).slice(0, 20).map(read).join('\n');
const makeText = rels.filter((r) => /(^|\/)(Makefile|Kbuild|makefile)$/.test(r)).slice(0, 20).map(read).join('\n');
const fw = [
  exists('platformio.ini') && 'platformio', any(/\.ino$/) && 'arduino', (exists('sdkconfig') || exists('sdkconfig.defaults') || any(/idf_component\.yml$/) || /idf_component_register|\$ENV\{IDF_PATH\}/.test(cmakeText)) && 'esp-idf',
  (exists('west.yml') || exists('prj.conf') || /find_package\(Zephyr/.test(cmakeText)) && 'zephyr', any(/\.ioc$/) && 'stm32cube', any(/FreeRTOSConfig\.h$/) && 'freertos',
  any(/(^|\/)(conf\/local\.conf|meta-[\w-]+\/conf\/layer\.conf)$/) && 'yocto', any(/(^|\/)Config\.in$/) && /BR2_/.test(rels.filter((r) => /defconfig$/.test(r)).slice(0, 5).map(read).join('')) && 'buildroot',
  (/arm-none-eabi|riscv\d*-unknown-elf|xtensa-|avr-gcc|-mcpu=cortex/.test(cmakeText + makeText)) && 'bare-metal-toolchain', any(/\.ld$/) && any(/startup_\w+\.(s|S|c)$/) && 'mcu-startup',
  /embassy-|cortex-m-rt|esp-hal|#!\[no_std\]/.test(cargo + rels.filter((r) => /main\.rs$/.test(r)).slice(0, 3).map(read).join('')) && 'rust-embedded',
].filter(Boolean);
if (fw.length) add('firmware', `Firmware / embedded (${fw.join(', ')})`, ['toolchain / SDK files'], fw);

// Drivers / kernel
const cSrc = rels.filter((r) => /\.(c|h|cpp)$/.test(r)).slice(0, 400);
const cText = (re) => cSrc.some((r) => re.test(read(r)));
const drv = [
  (/obj-m\s*[+:]?=/.test(makeText) || cText(/MODULE_LICENSE\s*\(|module_init\s*\(/)) && 'linux-kernel-module',
  (any(/\.inf$/) && (cText(/DriverEntry\s*\(|WDF_DRIVER_CONFIG|IoCreateDevice/) || rels.some((r) => /\.vcxproj$/.test(r) && /WindowsKernelModeDriver|WindowsUserModeDriver|DriverType/.test(read(r))))) && 'windows-driver',
  (any(/\.iig$/) || rels.some((r) => /Info\.plist$/.test(r) && /IOKitPersonalities/.test(read(r)))) && 'macos-driverkit',
  cText(/libusb_|hid_open|hidapi/) && 'usb-userspace-driver',
].filter(Boolean);
if (drv.length) add('driver', `Driver / kernel code (${drv.join(', ')})`, ['kernel/driver sources'], drv);

// Web frontend
const feFw = ['next', 'nuxt', 'astro', '@sveltejs/kit', '@remix-run/react', 'gatsby', '@angular/core', 'vue', 'react', 'svelte', 'solid-js'].filter(has);
if (feFw.length && !types.some((t) => ['mobile', 'desktop', 'browser-extension'].includes(t.id))) add('website', `Website / web app (${feFw[0]})`, ['package.json'], feFw);
else if (!Object.keys(deps).length && count(/\.html?$/) > 0 && !types.length) add('website', 'Static website (HTML/CSS/JS)', rels.filter((r) => /\.html?$/.test(r)).slice(0, 3), ['static']);

// Backend / API
const beNode = ['express', 'fastify', 'koa', '@nestjs/core', 'hapi', '@hapi/hapi', 'hono', 'elysia', 'apollo-server', '@apollo/server', 'graphql-yoga', '@trpc/server'].filter(has);
const bePy = ['django', 'flask', 'fastapi', 'starlette', 'tornado', 'aiohttp', 'sanic', 'djangorestframework'].filter(pyHas);
const beOther = [
  /spring-boot/.test(gradle + pom) && 'spring-boot', /"laravel\/framework"/.test(composer) && 'laravel', /symfony\//.test(composer) && 'symfony',
  /rails/.test(gemfile) && 'rails', /sinatra/.test(gemfile) && 'sinatra', /gin-gonic|labstack\/echo|gofiber|go-chi|gorilla\/mux/.test(gomod) && 'go-http',
  /actix-web|axum|rocket|warp/.test(cargo) && 'rust-http', /Microsoft\.AspNetCore|Sdk\.Web/.test(csproj) && 'aspnet-core',
].filter(Boolean);
const beAll = [...beNode, ...bePy, ...beOther];
const nextApi = has('next') && any(/(^|\/)(app|src\/app)\/api\/.*route\.(t|j)s$|(^|\/)(pages|src\/pages)\/api\//);
if (beAll.length || nextApi) {
  const full = types.some((t) => t.id === 'website') || nextApi || bePy.includes('django') || beOther.includes('rails') || beOther.includes('laravel');
  add('api', full ? `Backend / API (${[...beAll, nextApi && 'next-api-routes'].filter(Boolean).join(', ')})` : `API service (${beAll.join(', ')})`, ['dependency manifests'], [...beAll, ...(nextApi ? ['next-api'] : [])]);
}
if (has('@supabase/supabase-js') || has('firebase') || has('firebase-admin')) add('baas', 'Backend-as-a-Service client (Supabase/Firebase)', ['package.json'], ['supabase', 'firebase'].filter((x) => Object.keys(deps).some((d) => d.includes(x))));

// Cloud / infra
const iac = [
  any(/\.tf$/) && 'terraform', any(/(^|\/)(Dockerfile|Containerfile)(\..+)?$/) && 'docker', any(/docker-compose.*\.ya?ml$|compose\.ya?ml$/) && 'compose',
  rels.some((r) => /\.ya?ml$/.test(r) && /^\s*kind:\s*(Deployment|Service|Ingress|Pod|StatefulSet|DaemonSet)/m.test(read(r))) && 'kubernetes',
  any(/(^|\/)Chart\.yaml$/) && 'helm', any(/serverless\.ya?ml$/) && 'serverless', any(/(^|\/)(template|samconfig)\.ya?ml$|cdk\.json$/) && 'aws-sam/cdk',
  any(/\.bicep$/) && 'bicep', any(/Pulumi\.ya?ml$/) && 'pulumi',
].filter(Boolean);
if (iac.length) add('cloud-infra', `Cloud / infrastructure-as-code (${iac.join(', ')})`, ['IaC files'], iac);

// CLI / library
if (pkg.bin) add('cli', 'CLI tool (Node)', ['package.json: bin']);
if (/\[project\.scripts\]|entry_points|console_scripts/.test(pyText)) add('cli', 'CLI tool (Python)', ['pyproject/setup']);
if (/\[\[bin\]\]/.test(cargo) || (exists('main.go') && !beOther.includes('go-http'))) add('cli', 'CLI / binary', ['Cargo.toml / main.go']);
if (!types.length && (pkg.main || pkg.exports || pkg.module)) add('library', 'Library / package (npm)', ['package.json: main/exports']);
if (!types.length && /\[project\]|setup\(/.test(pyText)) add('library', 'Library / package (Python)', ['pyproject/setup']);
if (!types.length && languages.length) add('scripts', `Scripts / tooling (${languages[0].name})`, ['source files']);
if (!types.length) add('unknown', 'Unknown', []);

// ---------- entry points & sensitive surfaces ----------
const entryPoints = rels.filter((r) =>
  /(^|\/)(server|app|main|index|manage|wsgi|asgi|program|startup)\.(m?[jt]s|py|go|rs|cs|php|rb|java|kt)$/.test(r) ||
  /(^|\/)(app|src\/app)\/api\/.*route\.(t|j)s$/.test(r) || /(^|\/)(pages|src\/pages)\/api\//.test(r) ||
  /(^|\/)(background|service[-_]?worker|content[-_]?script|preload)\.(m?[jt]s)$/.test(r) ||
  /(^|\/)(middleware)\.(t|j)s$/.test(r) || /(^|\/)(routes|controllers|handlers|views|endpoints)\//.test(r) && /\.(m?[jt]s|py|go|php|rb|java|kt|cs)$/.test(r),
).slice(0, 200);

// Per-file risk tags (first 256 KB of text files only)
const TAGS = [
  ['auth', /\b(passport|jwt|jsonwebtoken|bcrypt|argon2|session|login|signin|oauth|authenticate|authorize|next-auth|@auth\/|clerk|supabase\.auth|firebase\.auth|LoginView|IdentityUser)\b/i],
  ['crypto', /\b(crypto\.|createCipher|createHash|hashlib|Cipher\.|AES|RSA|SecretKey|MessageDigest|bcrypt|argon2|pbkdf2|scrypt)\b/],
  ['db', /\b(SELECT\s|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|mongoose|prisma|sequelize|knex|typeorm|drizzle|sqlalchemy|cursor\.execute|objects\.raw|pg\.|mysql|sqlite3|MongoClient|redis)\b/i],
  ['input', /\b(req\.(body|query|params|headers|cookies)|request\.(form|args|json|GET|POST|data)|searchParams|FormData|getParameter\(|\$_(GET|POST|REQUEST|COOKIE)|@RequestParam|@RequestBody|onMessage|addEventListener\(\s*['"]message)\b/],
  ['exec', /\b(child_process|exec\(|execSync|spawn\(|subprocess|os\.system|Runtime\.getRuntime|Process\.Start|shell_exec|popen|eval\(|new Function\()/],
  ['file-io', /\b(fs\.(read|write|createReadStream|unlink)|open\(|sendFile|res\.download|multer|formidable|UploadedFile|FileInputStream|File\.(Read|Write))\w*/],
  ['network', /\b(fetch\(|axios|http\.request|requests\.(get|post)|urllib|HttpClient|OkHttp|URLSession|WebSocket|net\.connect)\b/],
  ['html-render', /(innerHTML|outerHTML|dangerouslySetInnerHTML|v-html|\{@html|document\.write|insertAdjacentHTML|\|\s*safe\b|mark_safe|Html\.Raw|render_template_string)/],
  ['config', /\b(process\.env|os\.environ|getenv|ConfigurationManager|dotenv|BuildConfig\.)\b/],
  ['ipc', /\b(ipcMain|ipcRenderer|contextBridge|chrome\.runtime|browser\.runtime|postMessage|invoke\(|tauri::command)\b/],
  ['payments', /\b(stripe|razorpay|paypal|braintree|checkout|payment)\b/i],
  ['pii', /\b(email|phone|address|ssn|aadhaar|pan_?number|dob|date_of_birth|passport)\b/i],
  ['kernel-boundary', /\b(copy_from_user|copy_to_user|get_user|put_user|unlocked_ioctl|compat_ioctl|__user|IRP_MJ_DEVICE_CONTROL|IoControlCode|METHOD_NEITHER|ProbeForRead|ProbeForWrite|WdfRequestRetrieve\w+Buffer|IOUserClient|ExternalMethod)\b/],
  ['firmware-update', /\b(esp_ota_\w+|esp_https_ota|Update\.begin|OTA|ota_\w+|mcuboot|bootutil|dfu_\w+|HAL_FLASH_Program|flash_write|nvs_set_\w+|boot_set_pending)\b/],
  ['device-io', /\b(HAL_UART_\w+|uart_\w+|Serial\.(read|available)|i2c_\w+|spi_\w+|HAL_I2C_\w+|HAL_SPI_\w+|esp_wifi_\w+|WiFi\.begin|BLE\w+|ble_gatts?_\w+|esp_ble_\w+|mqtt_\w+|coap_\w+)\b/],
];
const TEXT_EXT = /\.(m?[jt]sx?|cjs|py|java|kt|kts|swift|m|mm|dart|go|rs|cs|php|rb|c|cc|cpp|h|hpp|sh|bash|ps1|tf|html?|vue|svelte|astro|sql|ya?ml|json|toml|xml|gradle|plist|env.*|ini|cfg|conf|properties|dockerfile)$/i;
const inventory = files.map((f) => {
  const isText = TEXT_EXT.test(f.rel) || /(^|\/)(Dockerfile|Containerfile|Makefile|Procfile|\.env[^/]*)$/.test(f.rel);
  const tags = [];
  if (isText && f.size < 2_000_000) {
    let t = '';
    try { const fd = fs.openSync(path.join(root, f.rel), 'r'); const buf = Buffer.alloc(Math.min(f.size, 262144)); fs.readSync(fd, buf, 0, buf.length, 0); fs.closeSync(fd); t = buf.toString('utf8'); } catch {}
    for (const [tag, re] of TAGS) if (re.test(t)) tags.push(tag);
  }
  if (/(^|\/)\.env(\.|$)/.test(f.rel) && !/\.(example|sample|template)$/.test(f.rel)) tags.push('secret-file');
  if (/\.(pem|key|p12|pfx|jks|keystore|ppk)$/i.test(f.rel) || /id_(rsa|ed25519|ecdsa)$/.test(f.rel)) tags.push('key-material');
  const weight = { exec: 5, auth: 4, 'secret-file': 5, 'key-material': 5, db: 3, input: 3, 'html-render': 3, crypto: 3, ipc: 3, payments: 3, 'file-io': 2, network: 1, config: 1, pii: 2, 'kernel-boundary': 6, 'firmware-update': 4, 'device-io': 3 };
  const risk = tags.reduce((s, t) => s + (weight[t] ?? 0), 0);
  return { file: f.rel, bytes: f.size, text: isText, tags, risk };
});
const highRisk = inventory.filter((f) => f.risk >= 6).sort((a, b) => b.risk - a.risk);

// ---------- hygiene signals ----------
const hygiene = {
  readme: any(/^readme(\.\w+)?$/i), license: any(/^(license|licence|copying)(\.\w+)?$/i), securityPolicy: any(/(^|\/)security\.md$/i),
  contributing: any(/^contributing(\.\w+)?$/i), gitignore: exists('.gitignore'), editorconfig: exists('.editorconfig'),
  envExample: any(/(^|\/)\.env\.(example|sample|template)$/), ci: any(/^\.github\/workflows\/|^\.gitlab-ci\.yml$|^azure-pipelines\.yml$|^\.circleci\//),
  dependabotOrRenovate: exists('.github/dependabot.yml') || exists('renovate.json') || exists('.github/renovate.json'),
  codeowners: any(/(^|\/)CODEOWNERS$/),
  lockfile: ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'bun.lock', 'poetry.lock', 'Pipfile.lock', 'uv.lock', 'Cargo.lock', 'go.sum', 'composer.lock', 'Gemfile.lock', 'pubspec.lock', 'packages.lock.json'].filter(exists),
  tests: count(/(^|\/)(__tests__|tests?|spec)\/|\.(test|spec)\.\w+$|_test\.(go|py)$|Tests?\.(cs|java|kt|swift)$/),
  linters: ['.eslintrc', '.eslintrc.js', '.eslintrc.json', '.eslintrc.cjs', 'eslint.config.js', 'eslint.config.mjs', 'eslint.config.ts', 'biome.json', '.flake8', 'ruff.toml', '.pylintrc', '.golangci.yml', '.rubocop.yml', 'phpstan.neon', 'detekt.yml', '.swiftlint.yml', 'analysis_options.yaml', 'clippy.toml'].filter(exists).concat(/\[tool\.ruff\]|\[tool\.pylint|\[tool\.flake8/.test(pyText) ? ['pyproject lint config'] : []),
  typescriptStrict: /"strict"\s*:\s*true/.test(read('tsconfig.json')),
  gitignoresEnv: /(^|\n)\s*\.env/.test(read('.gitignore')),
};

const recon = {
  generatedAt: new Date().toISOString(),
  root,
  name: pkg.name ?? path.basename(root),
  types,
  primaryType: types[0]?.id ?? 'unknown',
  languages,
  packageManagers: [exists('package.json') && 'npm-compatible', pyText.trim() && 'python', exists('go.mod') && 'go', exists('Cargo.toml') && 'cargo', (gradle || pom) && 'jvm', exists('composer.json') && 'composer', exists('Gemfile') && 'bundler', csproj && 'nuget', exists('pubspec.yaml') && 'pub'].filter(Boolean),
  entryPoints,
  hygiene,
  stats: { files: files.length, textFiles: inventory.filter((f) => f.text).length, truncated: files.length >= MAX_FILES, highRiskFiles: highRisk.length },
  highRisk: highRisk.slice(0, 100),
  inventory,
};

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'recon.json'), JSON.stringify(recon, null, 2));

const yes = (b) => (b ? '✅' : '❌');
const md = `# Recon — ${recon.name}

_Generated ${recon.generatedAt} by The Protectors. Facts only._

## Project type
${types.map((t) => `- **${t.label}** — evidence: ${t.evidence.join(', ') || 'n/a'}`).join('\n')}

**Primary:** \`${recon.primaryType}\` → playbook: \`skills/protect-defense/references/${recon.primaryType}.md\`

## Languages
${languages.map((l) => `- ${l.name}: ${l.files} files`).join('\n') || '- none'}

## Stats
- Files scanned: ${recon.stats.files}${recon.stats.truncated ? ' (TRUNCATED)' : ''} — text: ${recon.stats.textFiles}
- High-risk files (score ≥ 6): ${highRisk.length}
- Entry points: ${entryPoints.length}

## Highest-risk files (review every one)
| Risk | File | Tags |
|---|---|---|
${highRisk.slice(0, 40).map((f) => `| ${f.risk} | \`${f.file}\` | ${f.tags.join(', ')} |`).join('\n') || '| – | none | – |'}

## Entry points
${entryPoints.slice(0, 50).map((e) => `- \`${e}\``).join('\n') || '- none detected'}

## Repository hygiene
| Item | Status |
|---|---|
| README | ${yes(hygiene.readme)} |
| LICENSE | ${yes(hygiene.license)} |
| SECURITY.md | ${yes(hygiene.securityPolicy)} |
| CONTRIBUTING | ${yes(hygiene.contributing)} |
| .gitignore (ignores .env) | ${yes(hygiene.gitignore)} (${yes(hygiene.gitignoresEnv)}) |
| .env.example | ${yes(hygiene.envExample)} |
| CI pipeline | ${yes(hygiene.ci)} |
| Dependabot/Renovate | ${yes(hygiene.dependabotOrRenovate)} |
| CODEOWNERS | ${yes(hygiene.codeowners)} |
| Lockfile | ${hygiene.lockfile.join(', ') || '❌'} |
| Test files | ${hygiene.tests} |
| Linters | ${hygiene.linters.join(', ') || '❌'} |
| TS strict | ${exists('tsconfig.json') ? yes(hygiene.typescriptStrict) : 'n/a'} |
`;
fs.writeFileSync(path.join(outDir, 'recon.md'), md);
console.log(`✔ Recon: ${types.map((t) => t.label).join(' + ')}`);
console.log(`  ${files.length} files, ${highRisk.length} high-risk → ${path.relative(process.cwd(), outDir) || outDir}`);
