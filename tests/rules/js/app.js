// Rule corpus (JavaScript / Node). Deliberately vulnerable lines are annotated `ruleid`, safe twins `ok`.
const express = require('express');
const crypto = require('crypto');
const app = express();

app.post('/calc', (req, res) => {
  const userCode = req.body.expr;
  // ruleid: inj.eval
  const out = eval(userCode);
  // ok: inj.eval
  model.eval();
  res.json({ out });
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // ruleid: inj.command
  exec(`ping -c 1 ${host}`);
  // ok: inj.command
  execFile('ping', ['-c', '1', host]);
});

app.get('/user', (req, res) => {
  // ruleid: inj.sql-concat
  db.query("SELECT * FROM users WHERE id = '" + req.query.id + "'");
  // ok: inj.sql-concat
  db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);
  // ruleid: inj.nosql
  User.findOne(req.body);
  // ok: inj.nosql
  User.findOne({ email: String(req.body.email) });
});

app.post('/tpl', (req, res) => {
  // ruleid: inj.ssti
  res.send(ejs.render(req.body.template));
  // ok: inj.ssti
  res.send(ejs.renderFile('views/page.ejs', { name: 'x' }));
  // ruleid: inj.ldap-xpath
  ldap.search("(uid=" + req.body.username + ")");
});

function renderBio(el, userBio) {
  // ruleid: xss.dangerous-html
  el.innerHTML = userBio;
  // ok: xss.dangerous-html
  el.innerHTML = '<b>static</b>';
}

app.get('/go', (req, res) => {
  // ruleid: xss.open-redirect
  res.redirect(req.query.next);
  // ok: xss.open-redirect
  res.redirect('/dashboard');
});

function notifyParent(data) {
  // ruleid: xss.postmessage-any-origin
  window.parent.postMessage(data, '*');
  // ok: xss.postmessage-any-origin
  window.parent.postMessage(data, 'https://app.example.com');
}

function cryptoStuff(data, key) {
  // ruleid: crypto.weak-hash
  const h = crypto.createHash('md5').update(data).digest('hex');
  // ok: crypto.weak-hash
  const h2 = crypto.createHash('sha256').update(data).digest('hex');
  // ruleid: crypto.weak-cipher
  const c = crypto.createCipheriv('aes-256-ecb', key, null);
  // ok: crypto.weak-cipher
  const c2 = crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12));
  // ruleid: crypto.insecure-random
  const resetToken = Math.random().toString(36);
  // ok: crypto.insecure-random
  const resetToken2 = crypto.randomBytes(32).toString('hex');
  // ruleid: crypto.hardcoded-iv-salt
  const iv = Buffer.from('0123456789abcdef');
  // ok: crypto.hardcoded-iv-salt
  const iv2 = crypto.randomBytes(12);
  return [h, h2, c, c2, resetToken, resetToken2, iv, iv2];
}

app.post('/login', async (req, res) => {
  const user = await User.byEmail(req.body.email);
  // ruleid: crypto.plaintext-password-compare
  if (user.password === req.body.password) res.json({ ok: true });
  // ok: crypto.plaintext-password-compare
  if (await argon2.verify(user.passwordHash, req.body.password)) res.json({ ok: true });
  // ruleid: auth.jwt-weak-secret
  const t = jwt.sign({ sub: user.id }, 'changeme123');
  // ok: auth.jwt-weak-secret
  const t2 = jwt.sign({ sub: user.id }, process.env.JWT_SECRET);
  // ruleid: auth.jwt-none-or-noverify
  jwt.verify(t, key, { algorithms: ['none'] });
  // ok: auth.jwt-none-or-noverify
  jwt.verify(t2, key, { algorithms: ['RS256'] });
  // ruleid: auth.insecure-cookie
  res.cookie('sid', t, { httpOnly: false });
  // ok: auth.insecure-cookie
  res.cookie('sid', t2, { httpOnly: true, secure: true, sameSite: 'lax' });
});

// ruleid: auth.session-secret-literal
app.use(session({ secret: 'keyboard cat' }));
// ok: auth.session-secret-literal
app.use(session({ secret: process.env.SESSION_SECRET }));

// ruleid: tls.verification-disabled
const agent = new https.Agent({ rejectUnauthorized: false });
// ok: tls.verification-disabled
const agent2 = new https.Agent({ rejectUnauthorized: true });

// ruleid: cors.wildcard-credentials
app.use(cors());
// ok: cors.wildcard-credentials
app.use(cors({ origins: ALLOWED_ORIGINS, credentials: true }));

app.use((err, req, res, next) => {
  // ruleid: config.stack-trace-leak
  res.status(500).json({ error: err.stack });
  // ok: config.stack-trace-leak
  res.status(500).json({ error: 'Internal error', id: req.id });
});

// ruleid: config.http-url
const PARTNER_API = 'http://api.partner.io/v1';
// ok: config.http-url
const LOCAL_API = 'http://localhost:3000';

app.get('/file', (req, res) => {
  // ruleid: file.path-traversal
  res.sendFile(req.query.name);
  // ok: file.path-traversal
  res.sendFile(path.join(PUBLIC_DIR, safeName(req)));
});

app.get('/proxy', async (req, res) => {
  // ruleid: ssrf.user-url
  res.send(await fetch(req.query.url));
  // ok: ssrf.user-url
  res.send(await fetch(ALLOWED_SITES[req.query.site]));
});

// ruleid: upload.unrestricted
const upload = multer();
// ok: upload.unrestricted
const upload2 = multer({ limits: { fileSize: 1e6 }, fileFilter: onlyImages });

app.get('/search', (req, res) => {
  // ruleid: regex.redos
  const re = new RegExp(req.query.q);
  // ok: regex.redos
  const re2 = new RegExp(escapeRegExp(String(req.query.q).slice(0, 100)));
  // ruleid: proto.pollution
  _.merge(config, req.body);
  // ok: proto.pollution
  _.merge(config, Schema.parse(req.body));
});

function audit(userId, password) {
  // ruleid: log.sensitive
  console.log('login', password);
  // ok: log.sensitive
  console.log('login ok', userId);
}

async function agentStep(completion) {
  // ruleid: llm.output-exec
  eval(completion.choices[0].message.content);
  // ok: llm.output-exec
  const action = ActionSchema.parse(JSON.parse(completion.choices[0].message.content));
  return action;
}

app.post('/chat', async (req, res) => {
  const reply = await openai.chat.completions.create({
    // ruleid: llm.prompt-injection
    messages: [{ role: 'system', content: `You are the assistant for ${req.body.company}` }],
  });
  const reply2 = await openai.chat.completions.create({
    // ok: llm.prompt-injection
    messages: [{ role: 'system', content: SYSTEM_PROMPT }, { role: 'user', content: req.body.question }],
  });
  res.json({ reply, reply2 });
});

// ruleid: mobile.insecure-storage
await AsyncStorage.setItem('token', jwtValue);
// ok: mobile.insecure-storage
await SecureStore.setItemAsync('session', jwtValue);

// ruleid: doc.html-to-pdf-input
const pdf = await page.setContent(req.body.html);
// ok: doc.html-to-pdf-input
const pdf2 = await page.setContent(renderInvoice(sanitize(order)));

// ruleid: doc.pdfjs-eval
const viewer = pdfjsLib.getDocument({ url: uploadUrl, isEvalSupported: true });
