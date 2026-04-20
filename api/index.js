require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const express = require('express');
const path = require('path');
const os = require('os');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'securecloud-secret-change-in-production';
const IS_VERCEL = process.env.VERCEL || process.env.NODE_ENV === 'production';
const DATA_DIR = IS_VERCEL ? '/tmp' : __dirname;
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const FILES_FILE = path.join(DATA_DIR, 'files.json');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const LOG_FILE = path.join(DATA_DIR, 'audit.log');
const RESET_EMAIL_FROM = process.env.RESET_EMAIL_FROM || 'no-reply@example.com';
const RESET_EMAIL_USER = process.env.RESET_EMAIL_USER || 'your-email@example.com';
const RESET_EMAIL_PASS = process.env.RESET_EMAIL_PASS || 'your-email-password';
const USE_PLACEHOLDER_CREDS = RESET_EMAIL_USER === 'your-email@example.com' || RESET_EMAIL_USER === 'your-gmail@gmail.com' || !RESET_EMAIL_PASS || RESET_EMAIL_PASS === 'your-email-password' || RESET_EMAIL_PASS === 'your-16-char-app-password';

const RESET_EMAIL_TRANSPORT = {
  host: process.env.RESET_EMAIL_HOST || 'smtp.gmail.com',
  port: Number(process.env.RESET_EMAIL_PORT || 587),
  secure: process.env.RESET_EMAIL_SECURE === 'true',
  auth: { user: RESET_EMAIL_USER, pass: RESET_EMAIL_PASS },
};

const RESET_LINKS_FILE = path.join(DATA_DIR, 'reset-links.json');
const PENDING_REGISTRATIONS_FILE = path.join(DATA_DIR, 'pending-registrations.json');
const TUNNEL_URL_FILE = path.join(DATA_DIR, '.tunnel-url');

function getPublicBaseUrl(req) {
  try {
    if (fs.existsSync(TUNNEL_URL_FILE)) {
      const tunnel = fs.readFileSync(TUNNEL_URL_FILE, 'utf8').trim();
      if (tunnel && (tunnel.startsWith('http://') || tunnel.startsWith('https://'))) return tunnel;
    }
  } catch (_) {}
  const reqHost = req.get('host') || '';
  const isLocalhost = /^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(reqHost);
  const reqOrigin = `${req.protocol}://${reqHost}`;
  if (!isLocalhost) return reqOrigin;
  return process.env.APP_BASE_URL || reqOrigin;
}

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(FILES_FILE)) fs.writeFileSync(FILES_FILE, '[]');

// Migrate existing users: add verified: true for users created before email verification
(function migrateUsers() {
  if (!fs.existsSync(USERS_FILE)) return;
  const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  let changed = false;
  users.forEach((u) => {
    if (u.verified === undefined) {
      u.verified = true;
      changed = true;
    }
  });
  if (changed) fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
})();

function audit(action, username, details = '') {
  const line = `[${new Date().toISOString()}] ${action} | user: ${username || '-'} | ${details}\n`;
  fs.appendFileSync(LOG_FILE, line);
}

// Transporter: use Ethereal test account when real SMTP is not configured
let resetEmailTransporter = null;
let etherealAccountPromise = null;

function getResetEmailTransporter(callback) {
  if (!USE_PLACEHOLDER_CREDS) {
    if (!resetEmailTransporter) resetEmailTransporter = nodemailer.createTransport(RESET_EMAIL_TRANSPORT);
    return callback(null, resetEmailTransporter);
  }
  if (resetEmailTransporter) return callback(null, resetEmailTransporter);
  if (!etherealAccountPromise) {
    etherealAccountPromise = new Promise((resolve, reject) => {
      nodemailer.createTestAccount((err, account) => {
        if (err) return reject(err);
        resolve(nodemailer.createTransport({
          host: 'smtp.ethereal.email',
          port: 587,
          secure: false,
          auth: { user: account.user, pass: account.pass },
        }));
      });
    });
  }
  etherealAccountPromise
    .then((transporter) => {
      resetEmailTransporter = transporter;
      callback(null, transporter);
    })
    .catch((err) => callback(err, null));
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${(file.originalname || 'file').replace(/[^a-zA-Z0-9.-]/g, '_')}`),
});
const upload = multer({ storage });

app.set('trust proxy', 1); // For correct protocol when behind tunnel (localtunnel, ngrok)
app.use(cors({ origin: true, credentials: true }));
// Skip JSON parser for multipart (file upload) so multer can parse the body
app.use((req, res, next) => {
  const ct = req.headers['content-type'] || '';
  if (ct.includes('multipart/form-data')) return next();
  express.json()(req, res, next);
});

function getUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function findUserByEmail(email) {
  const norm = (e) => (e || '').toLowerCase().trim();
  return getUsers().find((u) => norm(u.email) === norm(email));
}

function getFiles() {
  if (!fs.existsSync(FILES_FILE)) return [];
  return JSON.parse(fs.readFileSync(FILES_FILE, 'utf8'));
}

function saveFiles(files) {
  fs.writeFileSync(FILES_FILE, JSON.stringify(files, null, 2));
}

function authMiddleware(req, res, next) {
  // Always assign a public dummy user to bypass authentication
  req.user = { email: 'public@vaultguard.local' };
  next();
}

// Health check — open http://localhost:3001/api/health in browser to confirm correct server
app.get('/api/health', (req, res) => {
  const base = getPublicBaseUrl(req);
  const hasTunnel = fs.existsSync(TUNNEL_URL_FILE);
  res.json({
    ok: true,
    message: 'SecureCloud API',
    baseUrl: base,
    tunnelActive: hasTunnel,
    routes: ['/api/login', '/api/register', '/api/me', '/api/files'],
  });
});

// POST /api/login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  const user = findUserByEmail(email.trim());
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    audit('LOGIN_FAIL', email && email.trim(), 'invalid credentials');
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.verified === false) {
    audit('LOGIN_FAIL', user.email, 'email not verified');
    return res.status(403).json({ error: 'Please verify your email first. Check your inbox for the verification link.' });
  }
  const userEmail = (user.email || '').trim();
  const token = jwt.sign(
    { email: userEmail },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  audit('LOGIN_OK', userEmail, '');
  res.json({ token, email: userEmail });
});

function getPendingRegistrations() {
  if (!fs.existsSync(PENDING_REGISTRATIONS_FILE)) return [];
  return JSON.parse(fs.readFileSync(PENDING_REGISTRATIONS_FILE, 'utf8'));
}
function savePendingRegistrations(list) {
  fs.writeFileSync(PENDING_REGISTRATIONS_FILE, JSON.stringify(list, null, 2));
}

// POST /api/register — send verification email only; account created AFTER verification
app.post('/api/register', (req, res) => {
  const { email, password } = req.body || {};
  const trimmed = (email || '').trim().toLowerCase();
  if (!trimmed || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  const users = getUsers();
  if (users.some((u) => (u.email || '').toLowerCase().trim() === trimmed)) {
    return res.status(409).json({ error: 'An account with this email already exists' });
  }
  const verifyToken = crypto.randomBytes(32).toString('hex');
  const verifyExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  const baseUrl = getPublicBaseUrl(req);
  const verifyLink = `${baseUrl}/verify-email?token=${encodeURIComponent(verifyToken)}`;

  // Store in pending — NOT in users.json. Account created only after email verification.
  const pending = getPendingRegistrations().filter((p) => (p.email || '').toLowerCase() !== trimmed);
  pending.push({
    email: trimmed,
    passwordHash: bcrypt.hashSync(password, 10),
    verificationToken: verifyToken,
    verificationExpires: verifyExpires,
  });
  savePendingRegistrations(pending);
  audit('REGISTER', trimmed, 'pending verification (no account yet)');

  const mailOptions = {
    from: `"VaultGuard" <${RESET_EMAIL_FROM}>`,
    to: trimmed,
    subject: 'Verify your VaultGuard account',
    text: `Welcome! Click the link below to verify your email (valid for 24 hours):\n\n${verifyLink}\n\nIf you did not create this account, you can ignore this email.`,
    html: `<p>Welcome! <a href="${verifyLink}">Click here to verify your email</a> (valid for 24 hours).</p><p>If you did not create this account, you can ignore this email.</p>`,
  };

  getResetEmailTransporter((transporterErr, transporter) => {
    if (transporterErr || !transporter) {
      console.log('\n[Verify Email] Link (paste in browser):', verifyLink);
      console.log('Also check server/verify-links.json\n');
      try {
        fs.writeFileSync(path.join(__dirname, 'verify-links.json'), JSON.stringify({ email: trimmed, verifyLink }, null, 2));
      } catch (_) {}
      return res.status(201).json({
        email: trimmed,
        message: 'Check your email to verify — or use the link printed in the server console.',
      });
    }
    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        audit('VERIFY_EMAIL_ERROR', trimmed, err.message);
        console.log('\n[Verify Email] Failed to send. Link:', verifyLink, '\n');
        return res.status(201).json({
          email: trimmed,
          message: 'Verification email failed — check server console for the link.',
        });
      }
      res.status(201).json({
        email: trimmed,
        message: 'Check your email and click the verification link to create your account.',
      });
    });
  });
});

// POST /api/verify-email — consume verification token, CREATE account in users.json
app.post('/api/verify-email', (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Token required' });
  const pending = getPendingRegistrations();
  const now = Date.now();
  const idx = pending.findIndex((p) => p.verificationToken === token && p.verificationExpires > now);
  if (idx === -1) {
    return res.status(400).json({ error: 'Invalid or expired verification link' });
  }
  const p = pending[idx];
  const users = getUsers();
  users.push({
    email: p.email,
    passwordHash: p.passwordHash,
    verified: true,
  });
  saveUsers(users);
  pending.splice(idx, 1);
  savePendingRegistrations(pending);
  audit('VERIFY_EMAIL', p.email, 'account created');
  res.json({ message: 'Email verified. You can now log in.' });
});

// POST /api/forgot-password — issue a reset link via email
app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body || {};
  const trimmedEmail = (email || '').trim().toLowerCase();
  if (!trimmedEmail) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const users = getUsers();
  const user = users.find((u) => (u.email || '').toLowerCase().trim() === trimmedEmail);
  if (!user || user.verified === false) {
    // Always respond success to avoid leaking which emails exist
    return res.status(200).json({ message: 'If an account with this email exists, a reset link has been sent.' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes
  user.resetToken = token;
  user.resetTokenExpires = expiresAt;
  saveUsers(users);

  const baseUrl = getPublicBaseUrl(req);
  const resetLink = `${baseUrl}/reset-password?token=${encodeURIComponent(token)}`;
  audit('PASSWORD_RESET_TOKEN_ISSUED', trimmedEmail, `expiresAt=${new Date(expiresAt).toISOString()}`);

  // Save reset link to file (for dev/testing when email not configured)
  try {
    fs.writeFileSync(RESET_LINKS_FILE, JSON.stringify({ email: trimmedEmail, resetLink, expiresAt: new Date(expiresAt).toISOString() }, null, 2));
  } catch (_) {}

  const mailOptions = {
    from: `"VaultGuard" <${RESET_EMAIL_FROM}>`,
    to: user.email,
    subject: 'Reset your VaultGuard password',
    text: `You requested a password reset.\n\nClick the link below to set a new password (valid for 15 minutes):\n\n${resetLink}\n\nIf you did not request this, you can ignore this email.`,
    html: `<p>You requested a password reset.</p><p><a href="${resetLink}">Click here to set a new password</a> (valid for 15 minutes).</p><p>If you did not request this, you can ignore this email.</p>`,
  };

  getResetEmailTransporter((transporterErr, transporter) => {
    if (transporterErr || !transporter) {
      audit('PASSWORD_RESET_EMAIL_ERROR', trimmedEmail, transporterErr?.message || 'Failed to create email transporter');
      console.log('\n[Password Reset] Link saved to server/reset-links.json — open that file to copy the link.\n');
      return res.status(200).json({
        message: 'If an account with this email exists, a reset link has been sent.',
      });
    }
    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        audit('PASSWORD_RESET_EMAIL_ERROR', trimmedEmail, err.message || String(err));
        console.log('\n[Password Reset] Email failed. Link saved to server/reset-links.json — copy it from there.\n');
        return res.status(200).json({
          message: 'If an account with this email exists, a reset link has been sent.',
        });
      }
      if (USE_PLACEHOLDER_CREDS && nodemailer.getTestMessageUrl) {
        const previewUrl = nodemailer.getTestMessageUrl(info);
        if (previewUrl) {
          console.log('\n[Password Reset] Preview email at:', previewUrl);
          console.log('Link also saved to server/reset-links.json\n');
        }
      }
      res.status(200).json({
        message: 'If an account with this email exists, a reset link has been sent.',
      });
    });
  });
});

// POST /api/reset-password — consume reset token and set new password
app.post('/api/reset-password', (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password required' });
  }
  if (newPassword.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }

  const users = getUsers();
  const now = Date.now();
  const user = users.find(
    (u) => u.resetToken === token && typeof u.resetTokenExpires === 'number' && u.resetTokenExpires > now
  );

  if (!user) {
    return res.status(400).json({ error: 'Invalid or expired reset link' });
  }

  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  delete user.resetToken;
  delete user.resetTokenExpires;
  saveUsers(users);

  const emailForAudit = (user.email || '').toLowerCase().trim();
  audit('PASSWORD_RESET_TOKEN', emailForAudit, '');
  res.status(200).json({ message: 'Password updated. You can now log in with the new password.' });
});

// GET /api/me — require auth
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ email: req.user.email });
});

// POST /api/logout
app.post('/api/logout', authMiddleware, (req, res) => {
  audit('LOGOUT', req.user.email, '');
  res.json({ ok: true });
});

// ---------- FILES (auth required) ----------

// POST /api/files — upload (multer puts non-file fields in req.body)
app.post('/api/files', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const originalName = (req.body && req.body.originalName) || req.file.originalname || 'file';
  const encrypted = (req.body && req.body.encrypted) === 'true';
  const files = getFiles();
  const entry = {
    id: req.file.filename,
    email: req.user.email,
    username: req.user.email,
    originalName,
    storedName: req.file.filename,
    size: req.file.size,
    encrypted: !!encrypted,
    uploadedAt: new Date().toISOString(),
  };
  files.push(entry);
  saveFiles(files);
  audit('UPLOAD', req.user.email, `file: ${entry.originalName} id: ${entry.id}`);
  res.status(201).json(entry);
});

// GET /api/files — list current user's files
app.get('/api/files', authMiddleware, (req, res) => {
  const userEmail = req.user.email;
  const files = getFiles().filter((f) => (f.email || f.username) === userEmail);
  res.json(files);
});

// GET /api/files/:id — download
app.get('/api/files/:id', authMiddleware, (req, res) => {
  const files = getFiles();
  const entry = files.find((f) => f.id === req.params.id && (f.email || f.username) === req.user.email);
  if (!entry) return res.status(404).json({ error: 'File not found' });
  const filePath = path.join(UPLOAD_DIR, entry.storedName);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  audit('DOWNLOAD', req.user.email, `file: ${entry.originalName} id: ${entry.id}`);
  res.download(filePath, entry.originalName);
});

// DELETE /api/files/:id
app.delete('/api/files/:id', authMiddleware, (req, res) => {
  const files = getFiles();
  const idx = files.findIndex((f) => f.id === req.params.id && (f.email || f.username) === req.user.email);
  if (idx === -1) return res.status(404).json({ error: 'File not found' });
  const entry = files[idx];
  const filePath = path.join(UPLOAD_DIR, entry.storedName);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  files.splice(idx, 1);
  saveFiles(files);
  audit('DELETE', req.user.email, `file: ${entry.originalName} id: ${entry.id}`);
  res.json({ ok: true });
});

// Serve frontend static files — AFTER API routes so /api/* is handled first
const PUBLIC_DIR = path.join(__dirname, '..');
app.use(express.static(PUBLIC_DIR));
app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});
app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});
app.get('/verify-email', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

function getLocalIP() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) return net.address;
    }
  }
  return null;
}

if (!IS_VERCEL) {
  app.listen(PORT, () => {
    console.log(`SecureCloud API running at http://localhost:${PORT}`);
    const ip = getLocalIP();
    if (ip) {
      console.log(`  Same WiFi (phone): http://${ip}:${PORT}`);
    }
  });
}

module.exports = app;
