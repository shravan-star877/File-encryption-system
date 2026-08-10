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
const mongoose = require('mongoose');

let putBlob = null;
let delBlob = null;
try {
  const blobSdk = require('@vercel/blob');
  putBlob = blobSdk.put;
  delBlob = blobSdk.del;
} catch (_) {}

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

// --- MongoDB Atlas Setup ---
let isMongoConnected = false;
const MONGODB_URI = process.env.MONGODB_URI;

if (MONGODB_URI) {
  mongoose.connect(MONGODB_URI)
    .then(() => {
      isMongoConnected = true;
      console.log('[Database] Successfully connected to MongoDB Atlas');
    })
    .catch((err) => {
      console.error('[Database] MongoDB Atlas connection error:', err.message);
    });
}

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  verified: { type: Boolean, default: true },
  createdAt: { type: String, default: () => new Date().toISOString() }
});
const UserModel = mongoose.models.User || mongoose.model('User', UserSchema);

const FileSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  email: { type: String, required: true, lowercase: true, trim: true },
  username: { type: String },
  originalName: String,
  storedName: String,
  blobUrl: String,
  size: Number,
  encrypted: Boolean,
  uploadedAt: { type: String, default: () => new Date().toISOString() },
  expiresAt: String
});
const FileModel = mongoose.models.File || mongoose.model('File', FileSchema);

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

function audit(action, username, details = '') {
  const line = `[${new Date().toISOString()}] ${action} | user: ${username || '-'} | ${details}\n`;
  try {
    fs.appendFileSync(LOG_FILE, line);
  } catch (_) {}
}

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

// Multer memory storage when using Vercel Blob or buffer mode, otherwise disk storage
const upload = multer({ storage: multer.memoryStorage() });

app.set('trust proxy', 1);
app.use(cors({ origin: true, credentials: true }));
app.use((req, res, next) => {
  const ct = req.headers['content-type'] || '';
  if (ct.includes('multipart/form-data')) return next();
  express.json()(req, res, next);
});

// --- Data Layer Helpers ---
async function getUsers() {
  if (isMongoConnected) {
    const docs = await UserModel.find({}).lean();
    return docs.map((d) => ({ ...d, id: d._id.toString() }));
  }
  if (!fs.existsSync(USERS_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (_) {
    return [];
  }
}

async function findUserByEmail(email) {
  const norm = (e) => (e || '').toLowerCase().trim();
  if (isMongoConnected) {
    const doc = await UserModel.findOne({ email: norm(email) }).lean();
    return doc ? { ...doc, id: doc._id.toString() } : null;
  }
  const users = await getUsers();
  return users.find((u) => norm(u.email) === norm(email));
}

async function saveUser(userObj) {
  if (isMongoConnected) {
    await UserModel.updateOne(
      { email: userObj.email.toLowerCase().trim() },
      { $set: userObj },
      { upsert: true }
    );
    return;
  }
  const users = await getUsers();
  const idx = users.findIndex((u) => (u.email || '').toLowerCase().trim() === userObj.email.toLowerCase().trim());
  if (idx >= 0) users[idx] = userObj;
  else users.push(userObj);
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

async function getFiles() {
  if (isMongoConnected) {
    const docs = await FileModel.find({}).lean();
    return docs.map((d) => ({ ...d, id: d.id || d._id.toString() }));
  }
  if (!fs.existsSync(FILES_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(FILES_FILE, 'utf8'));
  } catch (_) {
    return [];
  }
}

async function saveFileEntry(entry) {
  if (isMongoConnected) {
    await FileModel.updateOne(
      { id: entry.id },
      { $set: entry },
      { upsert: true }
    );
    return;
  }
  const files = await getFiles();
  files.push(entry);
  fs.writeFileSync(FILES_FILE, JSON.stringify(files, null, 2));
}

async function deleteFileEntry(id) {
  if (isMongoConnected) {
    await FileModel.deleteOne({ id });
    return;
  }
  const files = await getFiles();
  const idx = files.findIndex((f) => f.id === id);
  if (idx >= 0) {
    files.splice(idx, 1);
    fs.writeFileSync(FILES_FILE, JSON.stringify(files, null, 2));
  }
}

async function cleanupExpiredFiles() {
  try {
    const files = await getFiles();
    const now = Date.now();
    for (const f of files) {
      if (f && f.expiresAt) {
        const expMs = new Date(f.expiresAt).getTime();
        if (!isNaN(expMs) && expMs <= now) {
          if (f.blobUrl && delBlob && process.env.BLOB_READ_WRITE_TOKEN) {
            try {
              await delBlob(f.blobUrl, { token: process.env.BLOB_READ_WRITE_TOKEN });
            } catch (_) {}
          }
          if (f.storedName) {
            const filePath = path.join(UPLOAD_DIR, f.storedName);
            if (fs.existsSync(filePath)) {
              try { fs.unlinkSync(filePath); } catch (_) {}
            }
          }
          await deleteFileEntry(f.id);
          audit('EXPIRED_AUTO_DELETED', f.email || f.username || 'system', `file: ${f.originalName} id: ${f.id}`);
        }
      }
    }
  } catch (err) {
    console.error('[Cleanup] Error cleaning expired files:', err);
  }
}

// Initial cleanup at server startup
cleanupExpiredFiles();
setInterval(cleanupExpiredFiles, 60000);

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded && decoded.email) {
        req.user = { email: String(decoded.email).trim().toLowerCase() };
        return next();
      }
    } catch (_) {}
  }
  return res.status(401).json({ error: 'Unauthorized. Please log in.' });
}

app.get('/api/health', (req, res) => {
  const base = getPublicBaseUrl(req);
  res.json({
    ok: true,
    message: 'SecureCloud API',
    mongoActive: isMongoConnected,
    blobActive: !!(putBlob && process.env.BLOB_READ_WRITE_TOKEN),
    baseUrl: base,
    routes: ['/api/login', '/api/register', '/api/me', '/api/files'],
  });
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  const user = await findUserByEmail(email.trim());
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

// POST /api/register
app.post('/api/register', async (req, res) => {
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
  const existingUser = await findUserByEmail(trimmed);
  if (existingUser) {
    return res.status(409).json({ error: 'An account with this email already exists' });
  }

  const newUser = {
    id: Date.now().toString(),
    email: trimmed,
    passwordHash: bcrypt.hashSync(password, 10),
    verified: true,
    createdAt: new Date().toISOString(),
  };
  await saveUser(newUser);
  audit('REGISTER', trimmed, 'account created');
  res.status(201).json({ email: trimmed, message: 'Account created successfully. You can now log in.' });
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

// POST /api/files — upload encrypted payload
app.post('/api/files', authMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const originalName = (req.body && req.body.originalName) || req.file.originalname || 'file';
  const encrypted = (req.body && req.body.encrypted) === 'true';

  const expiryStr = (req.body && req.body.expiry) ? String(req.body.expiry).trim().toLowerCase() : 'never';
  const now = Date.now();
  let expiresAt = null;
  if (expiryStr === '1h') {
    expiresAt = new Date(now + 1 * 60 * 60 * 1000).toISOString();
  } else if (expiryStr === '24h') {
    expiresAt = new Date(now + 24 * 60 * 60 * 1000).toISOString();
  } else if (expiryStr === '7d') {
    expiresAt = new Date(now + 7 * 24 * 60 * 60 * 1000).toISOString();
  } else if (/^-?\d+$/.test(expiryStr)) {
    const ms = parseInt(expiryStr, 10);
    if (!isNaN(ms)) {
      expiresAt = new Date(ms > 1e11 ? ms : now + ms).toISOString();
    }
  }

  const fileId = `${Date.now()}-${(originalName || 'file').replace(/[^a-zA-Z0-9.-]/g, '_')}`;
  let blobUrl = null;

  // Upload to Vercel Blob Storage if BLOB_READ_WRITE_TOKEN is set
  if (putBlob && process.env.BLOB_READ_WRITE_TOKEN) {
    try {
      const blob = await putBlob(`uploads/${fileId}`, req.file.buffer, {
        access: 'public',
        addRandomSuffix: false,
        token: process.env.BLOB_READ_WRITE_TOKEN
      });
      blobUrl = blob.url;
    } catch (blobErr) {
      console.error('[VercelBlob] Upload error:', blobErr.message);
      return res.status(500).json({ error: 'Cloud storage upload failed' });
    }
  } else {
    // Local disk fallback
    const filePath = path.join(UPLOAD_DIR, fileId);
    fs.writeFileSync(filePath, req.file.buffer);
  }

  const entry = {
    id: fileId,
    email: req.user.email,
    username: req.user.email,
    originalName,
    storedName: fileId,
    blobUrl,
    size: req.file.size,
    encrypted: !!encrypted,
    uploadedAt: new Date().toISOString(),
    expiresAt: expiresAt,
  };

  await saveFileEntry(entry);
  audit('UPLOAD', req.user.email, `file: ${entry.originalName} id: ${entry.id} expiresAt: ${expiresAt || 'never'}`);
  res.status(201).json(entry);
});

// GET /api/files — list current user's files
app.get('/api/files', authMiddleware, async (req, res) => {
  await cleanupExpiredFiles();
  const userEmail = req.user.email;
  const allFiles = await getFiles();
  const files = allFiles.filter((f) => (f.email || f.username) === userEmail);
  res.json(files);
});

// GET /api/files/:id — download payload
app.get('/api/files/:id', async (req, res) => {
  await cleanupExpiredFiles();
  const files = await getFiles();
  const isShareDownload = req.query && req.query.isShareDownload === 'true';

  let reqUserEmail = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded && decoded.email) {
        reqUserEmail = String(decoded.email).trim().toLowerCase();
      }
    } catch (_) {}
  }

  const entry = files.find((f) => f.id === req.params.id && (isShareDownload || (reqUserEmail && (f.email || f.username) === reqUserEmail)));
  if (!entry) return res.status(404).json({ error: 'File not found' });

  if (entry.expiresAt) {
    const expMs = new Date(entry.expiresAt).getTime();
    if (!isNaN(expMs) && expMs <= Date.now()) {
      audit('DOWNLOAD_BLOCKED_EXPIRED', reqUserEmail || 'unauthenticated_share', `file: ${entry.originalName} id: ${entry.id}`);
      return res.status(410).json({ error: 'This file has expired.' });
    }
  }

  const auditAction = isShareDownload ? 'SHARE_DOWNLOAD' : 'DOWNLOAD';

  if (entry.blobUrl) {
    try {
      const blobRes = await fetch(entry.blobUrl);
      if (!blobRes.ok) return res.status(404).json({ error: 'Cloud blob file not found' });
      const arrayBuf = await blobRes.arrayBuffer();
      const buf = Buffer.from(arrayBuf);
      audit(auditAction, reqUserEmail || 'unauthenticated_share', `file: ${entry.originalName} id: ${entry.id}`);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(entry.originalName)}"`);
      return res.send(buf);
    } catch (err) {
      console.error('[BlobDownload] Error fetching blob:', err.message);
      return res.status(500).json({ error: 'Failed to download cloud file' });
    }
  }

  const filePath = path.join(UPLOAD_DIR, entry.storedName);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  audit(auditAction, reqUserEmail || 'unauthenticated_share', `file: ${entry.originalName} id: ${entry.id}`);
  res.download(filePath, entry.originalName);
});

// DELETE /api/files/:id
app.delete('/api/files/:id', authMiddleware, async (req, res) => {
  const files = await getFiles();
  const idx = files.findIndex((f) => f.id === req.params.id && (f.email || f.username) === req.user.email);
  if (idx === -1) return res.status(404).json({ error: 'File not found' });
  const entry = files[idx];

  if (entry.blobUrl && delBlob && process.env.BLOB_READ_WRITE_TOKEN) {
    try {
      await delBlob(entry.blobUrl, { token: process.env.BLOB_READ_WRITE_TOKEN });
    } catch (_) {}
  }
  if (entry.storedName) {
    const filePath = path.join(UPLOAD_DIR, entry.storedName);
    if (fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch (_) {}
    }
  }

  await deleteFileEntry(entry.id);
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
