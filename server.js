const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { lookup } = require('node:dns').promises;
const nodemailer = require('nodemailer');

// Load local development settings without adding another runtime dependency.
const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (match && process.env[match[1]] === undefined) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
}

const PORT = process.env.PORT || 3030;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'takeoff.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], applications: [], otpLog: [] }, null, 2));
const readDb = () => JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
const writeDb = db => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
const send = (res, code, payload) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(payload)); };
const body = req => new Promise((resolve, reject) => { let raw = ''; req.on('data', c => raw += c); req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('Invalid request')); } }); });
const sessions = new Map();
const OTP_TTL_MS = 10 * 60 * 1000;
const otpHash = code => crypto.createHash('sha256').update(String(code)).digest('hex');
const validDate = value => { const text = String(value || ''); if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) return false; const date = new Date(`${text}T00:00:00Z`); return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === text; };
const today = () => new Date().toISOString().slice(0, 10);
function validateApplication(input) {
  const p = input.personal || {}, i = input.identity || {}, v = input.vehicle || {};
  if (p.dateOfBirth) { if (!validDate(p.dateOfBirth)) throw new Error('Enter a valid date of birth.'); const age = (Date.now() - Date.parse(`${p.dateOfBirth}T00:00:00`)) / 31557600000; if (age < 18 || age > 100) throw new Error('Drivers must be between 18 and 100 years old.'); }
  for (const [value, label] of [[i.licenceExpiry, 'licence'], [v.insuranceExpiry, 'insurance']]) if (value && (!validDate(value) || value < today())) throw new Error(`Your ${label} expiry date must be today or later.`);
  if (v.year && (!/^\d{4}$/.test(String(v.year)) || Number(v.year) < 1900 || Number(v.year) > new Date().getFullYear() + 1)) throw new Error(`Vehicle year must be between 1900 and ${new Date().getFullYear() + 1}.`);
}

async function sendOtpEmail({ to, code }) {
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD?.replace(/\s/g, '');
  if (!user || !pass) throw new Error('Email OTP is not configured. Set GMAIL_USER and GMAIL_APP_PASSWORD on the server.');
  const { address: gmailIpv4 } = await lookup('smtp.gmail.com', { family: 4 });
  const transporter = nodemailer.createTransport({
    host: gmailIpv4,
    port: 465,
    secure: true,
    tls: { servername: 'smtp.gmail.com' },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
    auth: { user, pass },
  });
  return transporter.sendMail({
    from: `TakeOFF <${user}>`,
    to,
    subject: 'Your TakeOFF verification code',
    text: `Your TakeOFF verification code is ${code}. It expires in 10 minutes. Do not share this code with anyone.`,
  });
}

function publicUser(user) { return { id: user.id, name: user.name, email: user.email, phone: user.phone, status: user.status || 'In progress' }; }
async function api(req, res) {
  try {
    const input = await body(req); const db = readDb();
    if (req.url === '/api/auth/request-otp' && req.method === 'POST') {
      if (!input.email || !/^\S+@\S+\.\S+$/.test(input.email)) return send(res, 400, { error: 'Enter a valid email address.' });
      const destination = String(input.email).trim().toLowerCase();
      const phone = String(input.phone || '').trim();
      const existingUser = db.users.find(user => user.email.toLowerCase() === destination || (phone && user.phone === phone));
      if (existingUser) {
        const application = db.applications.find(app => app.userId === existingUser.id);
        return send(res, 409, {
          error: 'An application already exists for that email address or mobile number.',
          registered: true,
          identifier: existingUser.email,
          status: application?.status || existingUser.status || 'In progress',
        });
      }
      const recent = db.otpLog.filter(x => x.destination === destination && Date.now() - Date.parse(x.createdAt) < OTP_TTL_MS);
      if (recent.length >= 3) return send(res, 429, { error: 'Too many code requests. Please wait 10 minutes and try again.' });
      const code = String(crypto.randomInt(100000, 1000000)); const challengeId = crypto.randomUUID();
      let emailResult;
      try { emailResult = await sendOtpEmail({ to: destination, code }); }
      catch (error) {
        console.error('OTP email delivery failed:', error.message);
        return send(res, 503, { error: 'We could not send a verification email right now. Please try again shortly.' });
      }
      db.otpLog.push({ challengeId, destination, codeHash: otpHash(code), messageId: emailResult.messageId || emailResult.id || null, createdAt: new Date().toISOString() }); writeDb(db);
      return send(res, 200, { challengeId, expiresIn: 600 });
    }
    if (req.url === '/api/auth/verify-otp' && req.method === 'POST') {
      const otp = db.otpLog.find(x => x.challengeId === input.challengeId);
      if (!otp || otp.codeHash !== otpHash(input.code) || Date.now() - Date.parse(otp.createdAt) > OTP_TTL_MS) return send(res, 400, { error: 'That verification code is invalid or has expired.' });
      let user = db.users.find(x => x.email === input.email || (input.phone && x.phone === input.phone));
      if (user) return send(res, 409, { error: 'An application already exists for those details. Please view its status instead.', registered: true, identifier: user.email, status: user.status || 'In progress' });
      if (!user) { user = { id: crypto.randomUUID(), name: input.name || '', email: input.email || '', phone: input.phone || '', status: 'In progress', createdAt: new Date().toISOString() }; db.users.push(user); }
      const token = crypto.randomUUID(); sessions.set(token, user.id); writeDb(db); return send(res, 200, { token, user: publicUser(user) });
    }
    if (req.url === '/api/auth/signin' && req.method === 'POST') {
      const user = db.users.find(x => x.email.toLowerCase() === String(input.identifier).toLowerCase() || x.phone === input.identifier);
      if (!user) return send(res, 404, { error: 'No test profile found. Start a new application instead.' });
      const token = crypto.randomUUID(); sessions.set(token, user.id); return send(res, 200, { token, user: publicUser(user) });
    }
    const token = (req.headers.authorization || '').replace('Bearer ', ''); const userId = sessions.get(token);
    if (!userId) return send(res, 401, { error: 'Please sign in again.' });
    if (req.url === '/api/application' && req.method === 'GET') return send(res, 200, { application: db.applications.find(a => a.userId === userId) || null, user: publicUser(db.users.find(u => u.id === userId)) });
    if (req.url === '/api/application' && req.method === 'POST') {
      validateApplication(input);
      let app = db.applications.find(a => a.userId === userId);
      const user = db.users.find(u => u.id === userId);
      const safe = { ...input, userId, id: app ? app.id : crypto.randomUUID(), updatedAt: new Date().toISOString(), submittedAt: input.status === 'Submitted' ? new Date().toISOString() : (app && app.submittedAt) || null };
      if (app) Object.assign(app, safe); else { db.applications.push(safe); app = safe; }
      user.status = safe.status || 'In progress'; if (safe.personal?.fullName) user.name = safe.personal.fullName; writeDb(db); return send(res, 200, { application: app });
    }
    if (req.url === '/api/admin/profiles' && req.method === 'GET') {
      const profiles = db.applications.map(a => ({
        ...a,
        documents: Object.fromEntries(Object.entries(a.documents || {}).map(([key, doc]) => [key, { name: doc.name, type: doc.type, size: doc.size }])),
        user: publicUser(db.users.find(u => u.id === a.userId)),
      }));
      return send(res, 200, { profiles });
    }
    const statusMatch = req.url.match(/^\/api\/admin\/profiles\/([^/]+)\/status$/);
    if (statusMatch && req.method === 'PATCH') {
      const status = String(input.status || '');
      if (!['Approved', 'Changes requested'].includes(status)) return send(res, 400, { error: 'Choose Approved or Changes requested.' });
      const application = db.applications.find(a => a.id === statusMatch[1]);
      if (!application) return send(res, 404, { error: 'Test driver profile not found.' });
      if (application.status !== 'Submitted') return send(res, 409, { error: 'Only submitted applications can be reviewed.' });
      application.status = status; application.reviewedAt = new Date().toISOString();
      const profileUser = db.users.find(u => u.id === application.userId);
      profileUser.status = status;
      writeDb(db);
      return send(res, 200, { application });
    }
    send(res, 404, { error: 'Not found' });
  } catch (e) { send(res, 500, { error: e.message || 'Server error' }); }
}
http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) return api(req, res);
  const file = req.url === '/' ? 'index.html' : req.url.slice(1).split('?')[0];
  // Support local development (assets in /public) and the current GitHub
  // layout (assets at the repository root) without changing app URLs.
  const staticDir = fs.existsSync(path.join(__dirname, 'public'))
    ? path.join(__dirname, 'public')
    : __dirname;
  const target = path.join(staticDir, file);

  if (!target.startsWith(staticDir) || !fs.existsSync(target)) {
    res.writeHead(404);
    return res.end('Not found');
  }

  const type = file.endsWith('.css')
    ? 'text/css'
    : file.endsWith('.js')
      ? 'application/javascript'
      : 'text/html';
  res.writeHead(200, { 'Content-Type': type });
  fs.createReadStream(target).pipe(res);
}).listen(PORT, () => console.log(`TakeOFF running on port ${PORT}`));
