// Rule catalogue for The Protectors scanner.
// Each rule: id, severity (critical|high|medium|low|info), title, cwe, owasp, files (RegExp on path), re (RegExp on content, needs /g),
// fix (one-line remediation), optional `unless` (RegExp — if the file matches it, the rule is skipped),
// optional `fileLevel` (report once per file instead of per match).

const CODE = /\.(m?[jt]sx?|cjs|vue|svelte|astro)$/i;
const JS = CODE;
const PY = /\.py$/i;
const JAVA = /\.(java|kt|kts)$/i;
const PHP = /\.php$/i;
const RB = /\.rb$/i;
const GO = /\.go$/i;
const CS = /\.cs$/i;
const ANY_SRC = /\.(m?[jt]sx?|cjs|vue|svelte|astro|py|java|kts?|php|rb|go|cs|rs|swift|dart|m|mm|c|cc|cpp|cxx|h|hpp|ino|sh|bash|ps1)$/i;
const C_SRC = /\.(c|cc|cpp|cxx|h|hpp|ino)$/i;
const CONFIG = /\.(json|ya?ml|toml|ini|cfg|conf|properties|xml|env[^/]*|tf|tfvars|gradle|plist)$|(^|\/)(\.env[^/]*|Dockerfile[^/]*|docker-compose[^/]*)$/i;

export const SECRET_RULES = [
  { id: 'secret.aws-access-key', severity: 'critical', title: 'AWS access key ID', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'secret.aws-secret-key', severity: 'critical', title: 'AWS secret access key', re: /aws_?secret_?access_?key["'\s:=]+[A-Za-z0-9/+=]{40}\b/gi },
  { id: 'secret.github-token', severity: 'critical', title: 'GitHub token', re: /\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g },
  { id: 'secret.gitlab-token', severity: 'critical', title: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20}\b/g },
  { id: 'secret.slack-token', severity: 'critical', title: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,72}\b/g },
  { id: 'secret.slack-webhook', severity: 'high', title: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g },
  { id: 'secret.stripe-live', severity: 'critical', title: 'Stripe live secret key', re: /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/g },
  { id: 'secret.google-api-key', severity: 'high', title: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'secret.openai-key', severity: 'critical', title: 'OpenAI API key', re: /\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-proj-[A-Za-z0-9_-]{40,}\b/g },
  { id: 'secret.anthropic-key', severity: 'critical', title: 'Anthropic API key', re: /\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/g },
  { id: 'secret.twilio', severity: 'high', title: 'Twilio API key', re: /\bSK[0-9a-fA-F]{32}\b/g },
  { id: 'secret.sendgrid', severity: 'critical', title: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { id: 'secret.npm-token', severity: 'critical', title: 'npm access token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'secret.razorpay', severity: 'critical', title: 'Razorpay live key', re: /\brzp_live_[A-Za-z0-9]{14,}\b/g },
  { id: 'secret.private-key', severity: 'critical', title: 'Private key block', re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/g },
  { id: 'secret.db-url-with-password', severity: 'high', title: 'Database URL with embedded password', re: /\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp|mssql):\/\/[^\s:/"'@]+:[^\s@"'/$]{3,}@[^\s"']+/g, unless: /localhost|127\.0\.0\.1|example|user:pass|username:password|\$\{/ },
  { id: 'secret.c-define', severity: 'high', title: 'Credential hard-coded in a #define / constant (firmware)',
    re: /#define\s+\w*(PASS(WORD|WD)?|PSK|SECRET|TOKEN|API_?KEY|AUTH_?KEY)\w*\s+"(?![^"]*(your|change|example|xxx|placeholder))[^"]{6,}"|\b(const\s+)?char\s*\*?\s*\w*(pass(word)?|psk|secret|token|api_?key)\w*\s*(\[\s*\d*\s*\])?\s*=\s*"(?![^"]*(your|change|example|xxx|placeholder))[^"]{6,}"/gi },
  { id: 'secret.jwt', severity: 'medium', title: 'Hard-coded JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { id: 'secret.generic-assignment', severity: 'high', title: 'Hard-coded credential in assignment',
    re: /\b(pass(word|wd)?|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|jwt[_-]?secret|session[_-]?secret)\b["']?\s*[:=]\s*["'`](?![^"'`]*(\$\{|\{\{|<|%s|your|change|example|placeholder|xxx|\*\*\*|process\.env|os\.environ|getenv|dummy|test|todo|redacted))[^"'`\s]{8,}["'`]/gi },
];

export const CODE_RULES = [
  // ---------- Injection ----------
  { id: 'inj.eval', severity: 'high', cwe: 'CWE-95', owasp: 'A03', title: 'Dynamic code execution (eval / new Function)', files: /\.(m?[jt]sx?|cjs|py|php|rb)$/i,
    re: /(^|[^\w.])(eval|new\s+Function)\s*\(|\bexec\s*\(\s*(compile|request|input|data|code|payload|f["'])/g, fix: 'Remove eval; use a parser (JSON.parse, ast.literal_eval) or a lookup table of allowed operations.' },
  { id: 'inj.command', severity: 'critical', cwe: 'CWE-78', owasp: 'A03', title: 'OS command built from dynamic input', files: ANY_SRC,
    re: /\b(exec|execSync|spawnSync?)\s*\(\s*(`[^`]*\$\{|["'][^"']*["']\s*\+)|\bos\.system\s*\(\s*(f["']|[^)]*[+%]|[a-z_]+\s*\))|subprocess\.\w+\([^)]*shell\s*=\s*True|Runtime\.getRuntime\(\)\.exec\([^)]*\+|\b(shell_exec|system|passthru|popen|proc_open)\s*\(\s*\$|Process\.Start\([^)]*\+|exec\.Command\(\s*"(sh|bash|cmd)"/g,
    fix: 'Call the binary directly with an argument array (execFile/spawn without shell, subprocess.run([...])), and allow-list arguments.' },
  { id: 'inj.sql-concat', severity: 'critical', cwe: 'CWE-89', owasp: 'A03', title: 'SQL built by string concatenation / interpolation', files: ANY_SRC,
    re: /(["'`]\s*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^\n]{0,200}?(\$\{|["'`]\s*\+\s*[\w$])|\b(execute|query|raw|rawQuery|executeQuery|exec)\s*\(\s*(f["'](SELECT|INSERT|UPDATE|DELETE)|["'](SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*(%|\+|\.format))|\$queryRawUnsafe|\$executeRawUnsafe|sequelize\.query\(\s*`[^`]*\$\{)/gi,
    fix: 'Use parameterised queries / prepared statements or the ORM query builder; never interpolate input into SQL.' },
  { id: 'inj.nosql', severity: 'high', cwe: 'CWE-943', owasp: 'A03', title: 'NoSQL query from raw request object', files: JS,
    re: /\.(find|findOne|updateOne|deleteOne|findOneAndUpdate)\(\s*req\.(body|query)\b|\$where\s*:/g, fix: 'Validate & cast input with a schema (zod/joi) before building queries; strip $-operators (express-mongo-sanitize).' },
  { id: 'inj.ssti', severity: 'high', cwe: 'CWE-1336', owasp: 'A03', title: 'Server-side template built from input', files: /\.(py|m?[jt]s|php|rb)$/i,
    re: /render_template_string\s*\(|Template\s*\(\s*(request|req)\.|ejs\.render\s*\(\s*req\.|Handlebars\.compile\s*\(\s*req\./g, fix: 'Render fixed template files and pass input as context variables only.' },
  { id: 'inj.ldap-xpath', severity: 'medium', cwe: 'CWE-90', owasp: 'A03', title: 'LDAP/XPath query concatenation', files: ANY_SRC,
    re: /\(\s*["'`]\((uid|cn|mail)=["'`]?\s*\+|xpath\s*\(\s*["'`][^"'`]*["'`]\s*\+/gi, fix: 'Escape per RFC 4515 / use parameterised XPath.' },

  // ---------- XSS / client ----------
  { id: 'xss.dangerous-html', severity: 'high', cwe: 'CWE-79', owasp: 'A03', title: 'Raw HTML sink', files: /\.(m?[jt]sx?|vue|svelte|astro|html?|cshtml|py|php|erb)$/i,
    re: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(?!DOMPurify|sanitize|purify)|\.(innerHTML|outerHTML)\s*[+]?=\s*(?!["'`][^"'`$]*["'`]\s*;?$)|\bv-html\s*=|\{@html\s|document\.write\s*\(|insertAdjacentHTML\s*\(|\|\s*safe\b|mark_safe\s*\(|@Html\.Raw\s*\(|<%==/gm,
    fix: 'Render as text, or sanitise with DOMPurify (client) / bleach/nh3 (Python) with a strict allow-list first.' },
  { id: 'xss.open-redirect', severity: 'medium', cwe: 'CWE-601', owasp: 'A01', title: 'Redirect to user-controlled URL', files: ANY_SRC,
    re: /\b(res\.redirect|redirect|HttpResponseRedirect|Redirect)\s*\(\s*(req|request)\.(query|params|GET|args|body|form)/g, fix: 'Allow-list redirect targets or only accept relative paths starting with a single "/".' },
  { id: 'xss.postmessage-any-origin', severity: 'high', cwe: 'CWE-346', owasp: 'A01', title: 'postMessage without origin check / to "*"', files: JS,
    re: /postMessage\([^)]*,\s*["']\*["']\)|addEventListener\(\s*["']message["']\s*,\s*(\(\s*)?(e|ev|event|msg)\s*\)?\s*=>\s*\{(?![^}]*origin)/g, fix: 'Send to an explicit origin and verify event.origin against an allow-list before using event.data.' },

  // ---------- Crypto ----------
  { id: 'crypto.weak-hash', severity: 'high', cwe: 'CWE-328', owasp: 'A02', title: 'MD5/SHA-1 used (weak for security purposes)', files: ANY_SRC,
    re: /createHash\(\s*["'](md5|sha1)["']\)|hashlib\.(md5|sha1)\s*\(|MessageDigest\.getInstance\(\s*["'](MD5|SHA-?1)["']\)|\bmd5\s*\(\s*\$|\bsha1\s*\(\s*\$|MD5\.Create\(|SHA1\.Create\(|crypto\/md5|crypto\/sha1/g,
    fix: 'Passwords: argon2id/bcrypt/scrypt. Integrity/signatures: SHA-256+ / HMAC-SHA-256. MD5/SHA-1 only for non-security checksums (annotate why).' },
  { id: 'crypto.weak-cipher', severity: 'high', cwe: 'CWE-327', owasp: 'A02', title: 'Weak or unauthenticated cipher mode', files: ANY_SRC,
    re: /\b(des|rc4|rc2|blowfish|3des|des-ede3?)(-cbc|-ecb)?["']|aes-\d{3}-ecb|AES\/ECB|Cipher\.getInstance\(\s*["']AES["']\)|MODE_ECB|createCipher\(/gi,
    fix: 'Use AES-256-GCM or ChaCha20-Poly1305 with a random 96-bit nonce per message (or libsodium secretbox).' },
  { id: 'crypto.insecure-random', severity: 'high', cwe: 'CWE-338', owasp: 'A02', title: 'Non-cryptographic RNG used for security value', files: ANY_SRC,
    re: /(token|secret|password|otp|nonce|salt|session|api_?key|reset|verification|code)\w*\s*[:=]\s*[^;\n]*(Math\.random\(\)|random\.(random|randint|choice)\(|new Random\(|rand\(\)|mt_rand\()/gi,
    fix: 'Use crypto.randomBytes / crypto.getRandomValues / secrets.token_urlsafe / SecureRandom / random_bytes.' },
  { id: 'crypto.hardcoded-iv-salt', severity: 'medium', cwe: 'CWE-329', owasp: 'A02', title: 'Static IV / salt', files: ANY_SRC,
    re: /\b(iv|salt|nonce)\s*[:=]\s*(Buffer\.from\(\s*)?["'][A-Za-z0-9+/=]{8,}["']/gi, fix: 'Generate a fresh random IV/nonce per encryption and a unique random salt per password.' },
  { id: 'crypto.plaintext-password-compare', severity: 'high', cwe: 'CWE-256', owasp: 'A07', title: 'Password compared/stored in plaintext', files: ANY_SRC,
    re: /\b(user|account|row|record)\.password\s*(===?|!==?)\s*(req|request|body|password|input)|password\s*==\s*request\./gi, fix: 'Store argon2id/bcrypt hashes and verify with the library\'s constant-time verify().' },

  // ---------- Auth / session ----------
  { id: 'auth.jwt-none-or-noverify', severity: 'critical', cwe: 'CWE-347', owasp: 'A02', title: 'JWT verification disabled or "none" allowed', files: ANY_SRC,
    re: /algorithms\s*[:=]\s*\[[^\]]*["']none["']|verify\s*=\s*False|options\s*=\s*\{\s*["']verify_signature["']\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true|\.decode\(\s*token\s*\)(?![\s\S]{0,40}verify)/g,
    fix: 'Always jwt.verify with an explicit algorithms allow-list (e.g. ["RS256"]), audience, issuer and expiry.' },
  { id: 'auth.jwt-weak-secret', severity: 'high', cwe: 'CWE-798', owasp: 'A02', title: 'JWT signed with a literal secret', files: ANY_SRC,
    re: /jwt\.sign\([^,]+,\s*["'][^"']{1,64}["']|jwt\.encode\([^,]+,\s*["'][^"']{1,64}["']/g, fix: 'Load a ≥ 256-bit secret from the environment/secret manager, or use asymmetric keys (RS256/EdDSA).' },
  { id: 'auth.insecure-cookie', severity: 'medium', cwe: 'CWE-614', owasp: 'A05', title: 'Cookie without Secure/HttpOnly/SameSite', files: ANY_SRC,
    re: /(httpOnly|httponly|HttpOnly)\s*[:=]\s*(false|False)|(secure|Secure)\s*[:=]\s*(false|False)\b|SESSION_COOKIE_SECURE\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False|sameSite\s*:\s*["']none["'](?![^}]*secure\s*:\s*true)/g,
    fix: 'Set HttpOnly, Secure, SameSite=Lax (or Strict), and a __Host- prefix for session cookies.' },
  { id: 'auth.csrf-disabled', severity: 'high', cwe: 'CWE-352', owasp: 'A01', title: 'CSRF protection disabled', files: ANY_SRC,
    re: /@csrf_exempt|csrf\(\)\.disable\(\)|\.csrf\(\s*(csrf\s*->\s*csrf\.disable\(\)|AbstractHttpConfigurer::disable)|WTF_CSRF_ENABLED\s*=\s*False|protect_from_forgery\s+except|skip_before_action\s+:verify_authenticity_token/g,
    fix: 'Keep CSRF protection on for cookie-authenticated endpoints; exempt only token-authenticated APIs deliberately.' },
  { id: 'auth.session-secret-literal', severity: 'high', cwe: 'CWE-798', owasp: 'A07', title: 'Session/app secret is a literal', files: ANY_SRC,
    re: /session\(\s*\{[^}]*secret\s*:\s*["'][^"']+["']|SECRET_KEY\s*=\s*["'](?!\{\{)[^"']{4,}["']|app\.secret_key\s*=\s*["'][^"']+["']|APP_KEY=base64:[A-Za-z0-9+/=]{20,}/g,
    fix: 'Read the secret from the environment and fail fast at startup if it is missing or shorter than 32 bytes.' },

  // ---------- Transport / config ----------
  { id: 'tls.verification-disabled', severity: 'critical', cwe: 'CWE-295', owasp: 'A02', title: 'TLS certificate verification disabled', files: /\.(m?[jt]sx?|cjs|py|java|kt|go|cs|rb|php|swift|dart|ya?ml|json|env[^/]*)$/i,
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*["']?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|ServerCertificateValidationCallback\s*=|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|badCertificateCallback\s*=.*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)|ssl_verify\s*:\s*false/g,
    fix: 'Never disable verification; for private CAs pass the CA bundle explicitly.' },
  { id: 'cors.wildcard-credentials', severity: 'high', cwe: 'CWE-942', owasp: 'A05', title: 'Permissive CORS', files: ANY_SRC,
    re: /cors\(\s*\)|origin\s*:\s*(["']\*["']|true)|Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allow_origins\s*=\s*\[\s*["']\*["']\s*\]|AllowAnyOrigin\(\)/g,
    fix: 'Allow-list exact origins from config; never combine a wildcard/reflected origin with credentials.' },
  { id: 'config.debug-enabled', severity: 'high', cwe: 'CWE-489', owasp: 'A05', title: 'Debug mode enabled in code', files: /\.(py|m?[jt]s|php|rb|java|kt|cs|env[^/]*|ya?ml|json|properties)$/i,
    re: /^\s*DEBUG\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True|APP_DEBUG\s*=\s*true|app\.debug\s*=\s*True|UseDeveloperExceptionPage\(\)(?![\s\S]{0,80}IsDevelopment)/gm,
    fix: 'Drive debug from environment (default off) and never expose stack traces in production.' },
  { id: 'config.stack-trace-leak', severity: 'medium', cwe: 'CWE-209', owasp: 'A05', title: 'Error details returned to the client', files: ANY_SRC,
    re: /res\.(status\(\d+\)\.)?(send|json)\(\s*(err|error|e)(\.stack|\.message)?\s*\)|res\.(status\(\d+\)\.)?json\(\s*\{\s*(error|message)\s*:\s*(err|error|e)\.(stack|message)|return\s+str\(e\)|traceback\.format_exc\(\)\s*(\)|,)/g,
    fix: 'Log the error server-side with a correlation id; return a generic message + the id.' },
  { id: 'config.http-url', severity: 'low', cwe: 'CWE-319', owasp: 'A02', title: 'Plain-HTTP endpoint', files: /\.(m?[jt]sx?|cjs|py|java|kt|swift|dart|go|cs|rb|php|env[^/]*|ya?ml|json|xml|plist)$/i,
    re: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|\[::1\]|schemas\.|www\.w3\.org|xmlns|example\.(com|org)|ns\.adobe|purl\.org|json-schema\.org)[a-z0-9.-]+/gi, fix: 'Use https:// for all external endpoints.' },

  // ---------- Files / SSRF / deserialisation ----------
  { id: 'file.path-traversal', severity: 'high', cwe: 'CWE-22', owasp: 'A01', title: 'File path built from request input', files: ANY_SRC,
    re: /(sendFile|readFile|readFileSync|createReadStream|download|unlink|open|send_file|File\.Open|new File|os\.Open|fopen|file_get_contents|include|require)\s*\(\s*[^)]*\b(req|request)\.(params|query|body|GET|args|form|files)|path\.join\([^)]*(req|request)\.(params|query|body)/g,
    fix: 'Resolve against a fixed base dir, then verify the resolved path starts with that base; allow-list file names.' },
  { id: 'ssrf.user-url', severity: 'high', cwe: 'CWE-918', owasp: 'A10', title: 'Server-side request to user-supplied URL', files: ANY_SRC,
    re: /\b(fetch|axios\.(get|post)|got|request|requests\.(get|post)|urlopen|http\.Get|HttpClient\.\w+Async|file_get_contents|curl_init)\s*\(\s*(req|request)\.(query|body|params|GET|args|form)/g,
    fix: 'Allow-list hosts/schemes, resolve DNS and block private/link-local ranges (169.254.169.254), disable redirects.' },
  { id: 'deser.unsafe', severity: 'critical', cwe: 'CWE-502', owasp: 'A08', title: 'Unsafe deserialisation', files: ANY_SRC,
    re: /pickle\.loads?\(|cPickle\.loads?\(|yaml\.load\((?![^)]*Loader\s*=\s*(yaml\.)?SafeLoader)|yaml\.unsafe_load|marshal\.loads|jsonpickle\.decode|ObjectInputStream\(|BinaryFormatter|unserialize\(\s*\$|Marshal\.load|node-serialize|serialize-javascript.*unsafe|TypeNameHandling\.(All|Auto|Objects)/g,
    fix: 'Use JSON with schema validation; yaml.safe_load; never deserialise untrusted binary formats.' },
  { id: 'upload.unrestricted', severity: 'medium', cwe: 'CWE-434', owasp: 'A04', title: 'File upload without size/type limits', files: JS,
    re: /multer\(\s*\{(?![^}]*(limits|fileFilter))[^}]*\}\s*\)|multer\(\s*\)/g, fix: 'Set limits.fileSize, a MIME/extension allow-list via fileFilter, store outside web root with random names, scan if possible.' },
  { id: 'regex.redos', severity: 'low', cwe: 'CWE-1333', owasp: 'A06', title: 'RegExp built from input (ReDoS)', files: JS,
    re: /new RegExp\(\s*(req|request)\./g, fix: 'Escape input (escape-string-regexp) and cap input length, or use RE2.' },
  { id: 'proto.pollution', severity: 'medium', cwe: 'CWE-1321', owasp: 'A08', title: 'Deep merge of request data (prototype pollution)', files: JS,
    re: /(_\.merge|_\.defaultsDeep|merge|deepmerge|Object\.assign)\(\s*[^,]+,\s*req\.(body|query)/g, fix: 'Validate with a schema first; use Object.create(null)/Map; block __proto__/constructor keys.' },

  // ---------- Logging / privacy ----------
  { id: 'log.sensitive', severity: 'medium', cwe: 'CWE-532', owasp: 'A09', title: 'Sensitive value written to logs', files: ANY_SRC,
    re: /(console\.(log|info|debug)|logger\.\w+|logging\.\w+|print|Log\.[dive]|System\.out\.println)\s*\([^)]*\b(password|passwd|secret|token|apiKey|api_key|authorization|cardNumber|cvv|ssn)\b/gi,
    fix: 'Never log credentials/PII; use a structured logger with redaction paths.' },

  // ---------- Electron ----------
  { id: 'electron.insecure-webprefs', severity: 'critical', cwe: 'CWE-94', owasp: 'A05', title: 'Electron: nodeIntegration on / contextIsolation off / sandbox off / webSecurity off', files: JS,
    re: /nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|sandbox\s*:\s*false|webSecurity\s*:\s*false|allowRunningInsecureContent\s*:\s*true|enableRemoteModule\s*:\s*true|nodeIntegrationInSubFrames\s*:\s*true/g,
    fix: 'nodeIntegration:false, contextIsolation:true, sandbox:true, webSecurity:true; expose a minimal API via contextBridge.' },
  { id: 'electron.open-external', severity: 'high', cwe: 'CWE-939', owasp: 'A03', title: 'Electron: shell.openExternal with unvalidated URL', files: JS,
    re: /^(?!.*(protocol|allow|ALLOW|isSafe|isAllowed|isTrusted)).*shell\.openExternal\(\s*(?!["'`]https:)/gm, fix: 'Parse the URL and allow only https: to known hosts; deny everything else.' },
  { id: 'electron.expose-ipc', severity: 'high', cwe: 'CWE-749', owasp: 'A01', title: 'Electron: raw ipcRenderer exposed to renderer', files: JS,
    re: /exposeInMainWorld\([^)]*ipcRenderer\s*[,)]|exposeInMainWorld\([^)]*\{\s*ipcRenderer\s*\}/g, fix: 'Expose specific functions that call fixed channels; validate args in ipcMain handlers and check event.senderFrame.url.' },

  // ---------- Browser extension (code) ----------
  { id: 'ext.remote-code', severity: 'critical', cwe: 'CWE-829', owasp: 'A08', title: 'Extension loads/executes remote code', files: JS,
    re: /chrome\.scripting\.executeScript\([^)]*\bfunc\s*:\s*new Function|eval\(\s*(await\s+)?(response|res|data)|importScripts\(\s*["']https?:/g, fix: 'MV3 forbids remote code: bundle all logic; fetch data (JSON), never code.' },
  { id: 'ext.unvalidated-message', severity: 'high', cwe: 'CWE-20', owasp: 'A03', title: 'Extension message handler without sender validation', files: JS,
    re: /runtime\.onMessage(External)?\.addListener\(\s*(async\s*)?\(?\s*\w+\s*,\s*\w+\s*,?\s*\w*\s*\)?\s*=>\s*\{(?![\s\S]{0,300}(sender\.(id|origin|url|tab)|\w+\(\s*sender\s*\)))/g,
    fix: 'Check sender.id === chrome.runtime.id (and sender.origin for content scripts) and validate the message schema.' },

  // ---------- Mobile (code) ----------
  { id: 'mobile.webview-js-bridge', severity: 'high', cwe: 'CWE-749', owasp: 'M4', title: 'WebView JavaScript bridge / file access enabled', files: /\.(java|kt|swift|dart|m?[jt]sx?)$/i,
    re: /addJavascriptInterface\(|setAllowFileAccessFromFileURLs\(\s*true|setAllowUniversalAccessFromFileURLs\(\s*true|setJavaScriptEnabled\(\s*true\s*\)(?![\s\S]{0,200}setAllowFileAccess\(\s*false)|originWhitelist=\{\s*\[\s*["']\*["']\s*\]\s*\}|allowUniversalAccessFromFileURLs|mixedContentMode=["']always["']/g,
    fix: 'Load only bundled/https content, restrict originWhitelist, disable file access, never expose native bridges to remote pages.' },
  { id: 'mobile.insecure-storage', severity: 'high', cwe: 'CWE-922', owasp: 'M9', title: 'Secret stored in insecure local storage', files: /\.(java|kt|swift|dart|m?[jt]sx?)$/i,
    re: /(AsyncStorage|localStorage|SharedPreferences|UserDefaults|shared_preferences|MMKV)[\s\S]{0,60}(token|password|secret|jwt|refresh)/gi,
    fix: 'Use Keychain / Android Keystore via expo-secure-store, react-native-keychain, flutter_secure_storage, EncryptedSharedPreferences.' },
  // ---------- C / C++ memory safety (firmware, drivers, native) ----------
  { id: 'c.banned-functions', severity: 'high', cwe: 'CWE-120', owasp: 'A03', title: 'Unbounded string/buffer function (overflow risk)', files: C_SRC,
    re: /\b(gets|strcpy|strcat|sprintf|vsprintf|stpcpy|wcscpy|wcscat|lstrcpy[AW]?|lstrcat[AW]?|_tcscpy|_tcscat|_mbscpy|StrCpy|StrCat)\s*\(|\b(scanf|sscanf|fscanf)\s*\([^)]*"[^"]*%s/g,
    fix: 'Use bounded APIs: snprintf, strlcpy/strscpy (kernel), strncat with explicit remaining size, RtlStringCch* (Windows), and validate lengths before memcpy.' },
  { id: 'c.format-string', severity: 'medium', cwe: 'CWE-134', owasp: 'A03', title: 'Non-literal format string', files: C_SRC,
    re: /\b(printf|printk|DbgPrint|KdPrint|wprintf|Serial\.printf)\s*\(\s*[a-zA-Z_][\w\->.[\]]*\s*\)|\bsyslog\s*\(\s*\w+\s*,\s*[a-zA-Z_][\w\->.[\]]*\s*\)|\b(fprintf|snprintf)\s*\(\s*[^,"]+,\s*(\w+\s*,\s*)?[a-zA-Z_][\w\->.[\]]*\s*\)/g,
    fix: 'Always use a literal format: printf("%s", msg).' },
  { id: 'c.command-exec', severity: 'high', cwe: 'CWE-78', owasp: 'A03', title: 'Shell command from a non-literal string', files: C_SRC,
    re: /\b(system|popen|_wsystem|_popen)\s*\(\s*(?!")[a-zA-Z_]/g, fix: 'Use execve/posix_spawn with an argument vector, or avoid shelling out; allow-list inputs.' },
  { id: 'c.alloc-overflow', severity: 'medium', cwe: 'CWE-190', owasp: 'A03', title: 'Allocation size computed by multiplication (integer overflow)', files: C_SRC,
    re: /\b(malloc|kmalloc|kzalloc|vmalloc|ExAllocatePool\w*|pvPortMalloc|heap_caps_malloc)\s*\(\s*(\w+\s*,\s*)?[\w\->.]+\s*\*\s*[\w\->.]+/g,
    fix: 'Use calloc / kmalloc_array / kcalloc / array_size() or check for overflow before multiplying.' },
  { id: 'c.insecure-temp', severity: 'medium', cwe: 'CWE-377', owasp: 'A05', title: 'Insecure temporary file API', files: C_SRC,
    re: /\b(tmpnam|tempnam|mktemp|_mktemp)\s*\(/g, fix: 'Use mkstemp / tmpfile.' },
  { id: 'c.stack-protector-off', severity: 'medium', cwe: 'CWE-693', owasp: 'A05', title: 'Compiler exploit mitigations explicitly disabled', files: /(^|\/)(CMakeLists\.txt|Makefile|Kbuild|[\w.-]+\.cmake|[\w.-]+\.mk|platformio\.ini|[\w.-]+\.vcxproj)$/i,
    re: /-fno-stack-protector|-z\s*execstack|-U_FORTIFY_SOURCE|-D_FORTIFY_SOURCE=0|<BufferSecurityCheck>false<\/BufferSecurityCheck>|<ControlFlowGuard>false|-no-pie\b/g,
    fix: 'Keep -fstack-protector-strong, -D_FORTIFY_SOURCE=2/3, PIE/RELRO/NX (desktop/Linux targets), /GS and /guard:cf (MSVC).' },

  // ---------- Firmware / IoT ----------
  { id: 'fw.tls-no-verify', severity: 'critical', cwe: 'CWE-295', owasp: 'A02', title: 'Firmware TLS without certificate verification', files: C_SRC,
    re: /MBEDTLS_SSL_VERIFY_(NONE|OPTIONAL)|\.setInsecure\s*\(\s*\)|skip_cert_common_name_check\s*=\s*true|WOLFSSL_VERIFY_NONE|SSL_VERIFY_NONE|esp_tls_cfg_t[^;]*\{[^}]*use_global_ca_store\s*=\s*false[^}]*\}/g,
    fix: 'Pin the server CA (setCACert / esp_crt_bundle_attach / mbedtls_x509_crt_parse) and use MBEDTLS_SSL_VERIFY_REQUIRED.' },
  { id: 'fw.insecure-ota', severity: 'high', cwe: 'CWE-494', owasp: 'A08', title: 'Firmware update over plain HTTP or without signature check', files: C_SRC,
    re: /(httpUpdate|ESPhttpUpdate|HTTPUpdate|esp_https_ota|esp_http_client_config_t)[\s\S]{0,200}["']http:\/\/|Update\.begin\([\s\S]{0,400}Update\.end\(\s*true\s*\)(?![\s\S]{0,400}(verify|signature|sha256|ecdsa))/g,
    fix: 'Serve OTA over TLS with verification, sign images (ESP Secure Boot v2 / MCUboot ECDSA-P256/Ed25519), verify before boot, enable anti-rollback.' },
  { id: 'fw.debug-interfaces', severity: 'medium', cwe: 'CWE-1191', owasp: 'A05', title: 'Debug interface / readout protection left open', files: C_SRC,
    re: /OB_RDP_LEVEL_0\b|HAL_DBGMCU_Enable\w*\s*\(|DBGMCU->CR\s*\|=|NRF_APPROTECT_DISABLE|UICR_APPROTECT_PALL_Disabled/g,
    fix: 'Production: RDP level 1/2 (STM32), APPROTECT enabled (nRF), JTAG disabled via eFuse (ESP32), secure debug with authentication only.' },

  // ---------- Linux kernel ----------
  { id: 'kernel.deprecated-api', severity: 'low', cwe: 'CWE-676', owasp: 'A06', title: 'Deprecated/unsafe kernel string API', files: C_SRC, requires: /#include\s*<linux\//,
    re: /\b(simple_strto(u?l|u?ll)|strlcpy|strncpy)\s*\(/g, fix: 'Use kstrto*() with error checking and strscpy().' },
  { id: 'kernel.ioctl-no-capability', severity: 'medium', cwe: 'CWE-862', owasp: 'A01', title: 'ioctl handler without capability/permission check', files: C_SRC, fileLevel: true,
    requires: /unlocked_ioctl|compat_ioctl/, requiresNot: /\b(capable|ns_capable|file_ns_capable|security_\w+)\s*\(/, re: /\.unlocked_ioctl\s*=/g,
    fix: 'Check capable(CAP_SYS_ADMIN) (or the narrowest capability) for privileged commands; set device node permissions via udev.' },
  { id: 'kernel.infoleak', severity: 'medium', cwe: 'CWE-200', owasp: 'A01', title: 'Stack struct copied to user space (padding may leak kernel memory)', files: C_SRC,
    unless: /memset\s*\(\s*&|=\s*\{\s*(0\s*)?\}\s*;|kzalloc/, re: /copy_to_user\s*\([^,]+,\s*&\w+\s*,\s*sizeof/g, fix: 'memset() the struct (or = {}) before filling it, or copy field-by-field.' },
  { id: 'kernel.user-copy-unchecked', severity: 'high', cwe: 'CWE-252', owasp: 'A04', title: 'copy_from_user/copy_to_user result ignored', files: C_SRC,
    re: /^\s*(copy_from_user|copy_to_user)\s*\(/gm, fix: 'if (copy_from_user(...)) return -EFAULT; — and validate user-supplied lengths against the destination size first.' },

  // ---------- Windows drivers ----------
  { id: 'win.method-neither', severity: 'high', cwe: 'CWE-781', owasp: 'A04', title: 'IOCTL uses METHOD_NEITHER (raw user pointers)', files: C_SRC,
    re: /CTL_CODE\s*\([^)]*METHOD_NEITHER/g, fix: 'Use METHOD_BUFFERED (or DIRECT); if unavoidable, ProbeForRead/Write inside __try/__except and capture values once.' },
  { id: 'win.deprecated-pool', severity: 'medium', cwe: 'CWE-908', owasp: 'A04', title: 'Deprecated pool allocation (uninitialised / executable memory)', files: C_SRC,
    re: /\bExAllocatePool(WithTag|WithQuotaTag|WithTagPriority)?\s*\(|\bNonPagedPool\b(?!Nx)/g, fix: 'Use ExAllocatePool2(POOL_FLAG_NON_PAGED, …) — zero-initialised and non-executable (HVCI compatible).' },
  { id: 'win.insecure-device-acl', severity: 'medium', cwe: 'CWE-732', owasp: 'A01', title: 'Device object created without an explicit security descriptor', files: C_SRC, fileLevel: true,
    requiresNot: /IoCreateDeviceSecure|WdfDeviceInitAssignSDDL|SDDL_DEVOBJ/, re: /\bIoCreateDevice\s*\(/g, fix: 'Use IoCreateDeviceSecure / WdfDeviceInitAssignSDDL with SDDL_DEVOBJ_SYS_ALL_ADM_ALL (or tighter) and FILE_DEVICE_SECURE_OPEN.' },
  { id: 'win.dangerous-primitive', severity: 'high', cwe: 'CWE-269', owasp: 'A01', title: 'Driver exposes physical memory / MSR / port I/O primitives', files: C_SRC,
    re: /\b(MmMapIoSpace(Ex)?|MmCopyMemory|__readmsr|__writemsr|ZwMapViewOfSection\s*\([^)]*PhysicalMemory|READ_PORT_\w+|WRITE_PORT_\w+)\s*\(/g,
    fix: 'Never let IOCTL input choose addresses/MSRs/ports; hard-code the device ranges, restrict the device ACL to admins. (This is the classic "vulnerable driver" pattern used by attackers.)' },

  { id: 'mobile.logging-release', severity: 'low', cwe: 'CWE-532', owasp: 'M9', title: 'Verbose logging likely shipped in release', files: /\.(java|kt|swift|dart)$/i,
    re: /\bLog\.(d|v)\(|\bprint\(|debugPrint\(|NSLog\(/g, fix: 'Strip debug logs in release (R8 rules, #if DEBUG, kReleaseMode).' },
];

// Config-file rules (platform manifests / infra). Matched against specific files.
export const CONFIG_RULES = [
  // Browser extension manifest
  { id: 'ext.broad-host-permissions', severity: 'high', cwe: 'CWE-250', owasp: 'A01', title: 'Extension requests all-sites host access', files: /(^|\/)manifest\.json$/, requires: /"manifest_version"/,
    re: /"<all_urls>"|"\*:\/\/\*\/\*"|"https?:\/\/\*\/\*"/g, fix: 'Use activeTab or list exact hosts; move broad hosts to optional_host_permissions requested at runtime.' },
  { id: 'ext.dangerous-permissions', severity: 'medium', cwe: 'CWE-250', owasp: 'A01', title: 'Extension requests high-risk permissions', files: /(^|\/)manifest\.json$/, requires: /"manifest_version"/,
    re: /"(debugger|webRequestBlocking|nativeMessaging|management|proxy|history|cookies|clipboardRead|downloads\.open|declarativeNetRequestFeedback|tabCapture|desktopCapture)"/g, fix: 'Remove unless essential; justify each in the store listing; prefer optional_permissions.' },
  { id: 'ext.weak-csp', severity: 'high', cwe: 'CWE-693', owasp: 'A05', title: 'Extension CSP allows unsafe-eval/inline or remote scripts', files: /(^|\/)manifest\.json$/, requires: /"manifest_version"/,
    re: /"content_security_policy"\s*:\s*(\{[^}]*|"[^"]*)('unsafe-eval'|'unsafe-inline'|https?:\/\/)/g, fix: "Use the MV3 default or \"script-src 'self'; object-src 'self'\"." },
  { id: 'ext.externally-connectable', severity: 'medium', cwe: 'CWE-346', owasp: 'A01', title: 'externally_connectable matches all sites', files: /(^|\/)manifest\.json$/, requires: /"externally_connectable"/,
    re: /"externally_connectable"[\s\S]{0,200}"(<all_urls>|\*:\/\/\*\/\*|https:\/\/\*\/\*)"/g, fix: 'Restrict matches to your own domains.' },
  { id: 'ext.web-accessible-all', severity: 'medium', cwe: 'CWE-200', owasp: 'A01', title: 'web_accessible_resources exposed to all sites', files: /(^|\/)manifest\.json$/, requires: /"web_accessible_resources"/,
    re: /"web_accessible_resources"[\s\S]{0,400}"matches"\s*:\s*\[\s*"<all_urls>"/g, fix: 'Limit matches and resources; use use_dynamic_url: true.' },
  { id: 'ext.mv2', severity: 'medium', cwe: 'CWE-1104', owasp: 'A06', title: 'Manifest V2 extension (deprecated, unsupported in Chrome)', files: /(^|\/)manifest\.json$/, requires: /"manifest_version"/,
    re: /"manifest_version"\s*:\s*2\b/g, fix: 'Migrate to Manifest V3 (service worker background, declarativeNetRequest).' },

  // Android
  { id: 'android.debuggable', severity: 'high', cwe: 'CWE-489', owasp: 'M8', title: 'android:debuggable="true"', files: /AndroidManifest\.xml$/, re: /android:debuggable\s*=\s*"true"/g, fix: 'Remove; the build type controls debuggability.' },
  { id: 'android.allow-backup', severity: 'medium', cwe: 'CWE-530', owasp: 'M9', title: 'android:allowBackup="true"', files: /AndroidManifest\.xml$/, re: /android:allowBackup\s*=\s*"true"/g, fix: 'Set allowBackup="false" or define dataExtractionRules excluding secrets.' },
  { id: 'android.cleartext', severity: 'high', cwe: 'CWE-319', owasp: 'M5', title: 'Cleartext traffic permitted', files: /(AndroidManifest|network_security_config)\.xml$/, re: /usesCleartextTraffic\s*=\s*"true"|cleartextTrafficPermitted\s*=\s*"true"/g, fix: 'Disable cleartext; add a network_security_config (optionally with certificate pinning).' },
  { id: 'android.exported', severity: 'medium', cwe: 'CWE-926', owasp: 'M8', title: 'Exported component without permission', files: /AndroidManifest\.xml$/, re: /<(activity|service|receiver|provider)[^>]*android:exported\s*=\s*"true"(?![^>]*android:permission)[^>]*>/g, fix: 'Set exported="false" unless required; protect with a signature-level permission.' },
  { id: 'android.minify-off', severity: 'low', cwe: 'CWE-656', owasp: 'M7', title: 'Release build without R8/ProGuard minification', files: /build\.gradle(\.kts)?$/, re: /release\s*\{[^}]*(minifyEnabled|isMinifyEnabled)\s*(=\s*)?false/g, fix: 'Enable minify + shrinkResources for release (code hardening/obfuscation).' },
  // iOS
  { id: 'ios.ats-disabled', severity: 'high', cwe: 'CWE-319', owasp: 'M5', title: 'App Transport Security disabled', files: /Info\.plist$/, re: /<key>NSAllowsArbitraryLoads<\/key>\s*<true\s*\/>/g, fix: 'Remove NSAllowsArbitraryLoads; add narrowly scoped NSExceptionDomains if unavoidable.' },

  // Firmware build configuration (ESP-IDF sdkconfig, Zephyr prj.conf / Kconfig fragments)
  { id: 'fw.secure-boot-off', severity: 'medium', cwe: 'CWE-1326', owasp: 'A08', title: 'Secure boot not enabled', files: /(^|\/)sdkconfig(\.defaults)?(\.[\w-]+)?$/, fileLevel: true,
    requiresNot: /^CONFIG_SECURE_BOOT=y/m, re: /^# CONFIG_SECURE_BOOT is not set|^CONFIG_IDF_TARGET=/gm,
    fix: 'Enable Secure Boot v2 (RSA-3072/ECDSA) for production builds; keep signing keys offline/HSM.' },
  { id: 'fw.flash-encryption-off', severity: 'medium', cwe: 'CWE-311', owasp: 'A02', title: 'Flash encryption not enabled', files: /(^|\/)sdkconfig(\.defaults)?(\.[\w-]+)?$/, fileLevel: true,
    requiresNot: /^CONFIG_(SECURE_FLASH_ENC_ENABLED|FLASH_ENCRYPTION_ENABLED)=y/m, re: /^# CONFIG_(SECURE_FLASH_ENC_ENABLED|FLASH_ENCRYPTION_ENABLED) is not set|^CONFIG_IDF_TARGET=/gm,
    fix: 'Enable flash encryption in Release mode and NVS encryption to protect credentials and firmware at rest.' },
  { id: 'fw.insecure-sdkconfig', severity: 'high', cwe: 'CWE-295', owasp: 'A02', title: 'Insecure TLS/OTA/debug option in firmware config', files: /(^|\/)(sdkconfig(\.defaults)?(\.[\w-]+)?|prj\.conf|[\w-]+\.conf|[\w-]+_defconfig)$/,
    re: /^CONFIG_(ESP_TLS_INSECURE|ESP_TLS_SKIP_SERVER_CERT_VERIFY|OTA_ALLOW_HTTP|ESP_HTTPS_OTA_ALLOW_HTTP|SECURE_BOOT_INSECURE|SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC|SECURE_BOOT_ALLOW_JTAG|BOOT_SIGNATURE_TYPE_NONE|MBEDTLS_SSL_VERIFY_NONE)=y/gm,
    fix: 'Remove insecure options from production configs; keep them only in a separate debug config that is never shipped.' },
  { id: 'fw.debug-shell-enabled', severity: 'low', cwe: 'CWE-489', owasp: 'A05', title: 'Debug shell/console enabled in firmware config', files: /(^|\/)(prj\.conf|[\w-]+_defconfig)$/,
    re: /^CONFIG_(SHELL|DEBUG|ASSERT_VERBOSE|LOG_DEFAULT_LEVEL=4|MCUMGR_CMD_SHELL_MGMT)=y/gm, fix: 'Disable shells/debug in production (use an overlay for debug builds).' },

  // Docker
  { id: 'docker.root-user', severity: 'medium', cwe: 'CWE-250', owasp: 'A05', title: 'Container runs as root (no USER)', files: /(^|\/)(Dockerfile|Containerfile)[^/]*$/, fileLevel: true, requiresNot: /^\s*USER\s+(?!root\b)\S+/m, re: /^\s*FROM\s+/gm, fix: 'Add a non-root user and `USER app` before CMD.' },
  { id: 'docker.latest-tag', severity: 'low', cwe: 'CWE-1104', owasp: 'A06', title: 'Base image not pinned', files: /(^|\/)(Dockerfile|Containerfile)[^/]*$/, re: /^\s*FROM\s+[^\s:@]+(:latest)?\s*($|\s+AS)/gim, fix: 'Pin to a version tag and ideally a digest (@sha256:...).' },
  { id: 'docker.secret-in-env', severity: 'high', cwe: 'CWE-798', owasp: 'A02', title: 'Secret baked into image (ENV/ARG)', files: /(^|\/)(Dockerfile|Containerfile)[^/]*$/, re: /^\s*(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\w*[\s=]+\S+/gim, fix: 'Use BuildKit secrets (--mount=type=secret) and runtime env/secret stores.' },
  { id: 'docker.add-remote', severity: 'low', cwe: 'CWE-494', owasp: 'A08', title: 'ADD from remote URL', files: /(^|\/)(Dockerfile|Containerfile)[^/]*$/, re: /^\s*ADD\s+https?:/gim, fix: 'Use COPY for local files; download with checksum verification.' },
  { id: 'compose.privileged', severity: 'high', cwe: 'CWE-250', owasp: 'A05', title: 'Privileged container / host mounts', files: /(docker-)?compose[^/]*\.ya?ml$/, re: /privileged:\s*true|\/var\/run\/docker\.sock|network_mode:\s*host/g, fix: 'Drop privileged, avoid mounting the Docker socket, use explicit capabilities.' },
  // Kubernetes
  { id: 'k8s.privileged', severity: 'high', cwe: 'CWE-250', owasp: 'A05', title: 'Kubernetes privileged / root / host namespaces', files: /\.ya?ml$/, requires: /^\s*kind:\s*\w+/m, re: /privileged:\s*true|runAsUser:\s*0\b|allowPrivilegeEscalation:\s*true|hostNetwork:\s*true|hostPID:\s*true/g, fix: 'runAsNonRoot: true, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, drop ALL capabilities.' },
  // Terraform
  { id: 'tf.open-ingress', severity: 'high', cwe: 'CWE-284', owasp: 'A05', title: 'Security group open to the internet', files: /\.tf$/, re: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\][\s\S]{0,200}(from_port\s*=\s*(22|3389|3306|5432|6379|27017|9200)\b)|from_port\s*=\s*(22|3389|3306|5432|6379|27017|9200)\b[\s\S]{0,200}cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"/g, fix: 'Restrict admin/database ports to VPN/bastion CIDRs or use SSM Session Manager.' },
  { id: 'tf.public-bucket', severity: 'high', cwe: 'CWE-732', owasp: 'A01', title: 'Public storage bucket', files: /\.tf$/, re: /acl\s*=\s*"public-read(-write)?"|block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|allow_blob_public_access\s*=\s*true|public_access_prevention\s*=\s*"inherited"/g, fix: 'Block public access; serve public assets through a CDN with origin access control.' },
  { id: 'tf.unencrypted', severity: 'medium', cwe: 'CWE-311', owasp: 'A02', title: 'Storage without encryption', files: /\.tf$/, re: /storage_encrypted\s*=\s*false|encrypted\s*=\s*false|enable_encryption\s*=\s*false/g, fix: 'Enable encryption at rest with a managed KMS key.' },
  // CI
  { id: 'ci.pull-request-target', severity: 'high', cwe: 'CWE-829', owasp: 'A08', title: 'GitHub Actions pull_request_target checking out PR code', files: /^\.github\/workflows\/.*\.ya?ml$/, requires: /pull_request_target/, re: /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)/g, fix: 'Do not run untrusted PR code with pull_request_target secrets; use pull_request.' },
  { id: 'ci.script-injection', severity: 'high', cwe: 'CWE-78', owasp: 'A03', title: 'GitHub Actions script injection from event data', files: /^\.github\/workflows\/.*\.ya?ml$/, re: /run:[^\n]*\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit)\.[\w.]*(title|body|message|name|ref|label)/g, fix: 'Pass event data via env: variables and quote them in the script.' },
  { id: 'ci.unpinned-action', severity: 'low', cwe: 'CWE-1104', owasp: 'A08', title: 'Third-party action not pinned to a commit SHA', files: /^\.github\/workflows\/.*\.ya?ml$/, re: /uses:\s*(?!actions\/|github\/|\.\/)[\w.-]+\/[\w.-]+@(?![0-9a-f]{40}\b)[\w.-]+/g, fix: 'Pin third-party actions to a full commit SHA (Dependabot keeps them updated).' },
  { id: 'ci.write-all', severity: 'medium', cwe: 'CWE-250', owasp: 'A01', title: 'Workflow token has write-all permissions', files: /^\.github\/workflows\/.*\.ya?ml$/, re: /permissions:\s*write-all/g, fix: 'Set `permissions: contents: read` at top level and grant more per job.' },
  // Next.js / web config
  { id: 'web.next-powered-by', severity: 'info', cwe: 'CWE-200', owasp: 'A05', title: 'Next.js X-Powered-By header enabled', files: /(^|\/)next\.config\.(js|mjs|ts)$/, fileLevel: true, requiresNot: /poweredByHeader\s*:\s*false/, re: /./g, fix: 'Set poweredByHeader: false.' },
  { id: 'web.source-maps-prod', severity: 'low', cwe: 'CWE-540', owasp: 'A05', title: 'Production browser source maps enabled', files: /(^|\/)(next\.config\.(js|mjs|ts)|vite\.config\.(js|ts|mjs)|webpack\.config\.(js|ts))$/, re: /productionBrowserSourceMaps\s*:\s*true|sourcemap\s*:\s*true|devtool\s*:\s*["']source-map["']/g, fix: 'Upload source maps to your error tracker privately instead of serving them.' },
];

export const CODE_FILES = ANY_SRC;
export const CONFIG_FILES = CONFIG;
