if (!process.env.VERCEL) {
  require('dotenv').config({ path: require('path').join(__dirname, '.env') });
}
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
let getBlob = null;
let delBlob = null;
try {
  const blobSdk = require('@vercel/blob');
  putBlob = blobSdk.put;
  getBlob = blobSdk.get;
  delBlob = blobSdk.del;
} catch (_) { }

function getBlobToken() {
  const token = process.env.BLOB_READ_WRITE_TOKEN;
  return token && typeof token === 'string' ? token.trim() : null;
}

async function fetchPrivateBlobBuffer(blobRef) {
  if (!getBlob || !blobRef) return null;
  const token = getBlobToken();
  if (!token) return null;
  const result = await getBlob(blobRef, { access: 'private', token });
  if (!result || result.statusCode !== 200 || !result.stream) return null;
  const arrayBuf = await new Response(result.stream).arrayBuffer();
  return Buffer.from(arrayBuf);
}

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'securecloud-secret-change-in-production';
const IS_VERCEL = !!process.env.VERCEL;
const DATA_DIR = IS_VERCEL ? '/tmp' : __dirname;
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const FILES_FILE = path.join(DATA_DIR, 'files.json');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const MONGO_REQUIRED_IN_PRODUCTION = IS_VERCEL && !resolveMongoUri();
const BLOB_REQUIRED_IN_PRODUCTION = IS_VERCEL && !process.env.BLOB_READ_WRITE_TOKEN;
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

function sanitizeErrorMessage(msg) {
  if (!msg) return 'Unknown error';
  const str = String(msg);
  return str
    .replace(/vercel_blob_rw_[a-zA-Z0-9_-]+/gi, '[REDACTED_BLOB_TOKEN]')
    .replace(/mongodb(?:\+srv)?:\/\/[^\s]+/gi, '[REDACTED_MONGO_URI]')
    .replace(/Bearer\s+[a-zA-Z0-9._-]+/gi, '[REDACTED_TOKEN]')
    .substring(0, 250);
}

function resolveMongoUri() {
  const raw = process.env.MONGODB_URI;
  if (!raw || typeof raw !== 'string') return null;
  let uri = raw.trim();
  if ((uri.startsWith('"') && uri.endsWith('"')) || (uri.startsWith("'") && uri.endsWith("'"))) {
    uri = uri.slice(1, -1).trim();
  }
  return uri || null;
}

function diagnoseMongoUriSafe(uri) {
  if (!uri) return { present: false, valid: false, issues: ['MISSING'] };
  const issues = [];
  if (/<[^>]+>/.test(uri)) issues.push('PLACEHOLDER_TEXT');
  if (!/^mongodb(\+srv)?:\/\//i.test(uri)) issues.push('INVALID_SCHEME');
  if (/\s/.test(uri)) issues.push('EMBEDDED_WHITESPACE');
  const credsMatch = uri.match(/^mongodb\+srv:\/\/([^/?]+)@/i) || uri.match(/^mongodb:\/\/([^/?]+)@/i);
  if (!credsMatch) {
    issues.push('MISSING_CREDENTIALS');
  } else {
    const creds = credsMatch[1];
    const colonIdx = creds.indexOf(':');
    if (colonIdx <= 0) issues.push('MISSING_PASSWORD');
    if (creds.includes('@')) issues.push('MALFORMED_CREDENTIALS');
  }
  return { present: true, valid: issues.length === 0, issues };
}

function getEnvPresence() {
  return {
    MONGODB_URI: resolveMongoUri() ? 'PRESENT' : 'MISSING',
    JWT_SECRET: process.env.JWT_SECRET ? 'PRESENT' : 'MISSING',
    BLOB_READ_WRITE_TOKEN: process.env.BLOB_READ_WRITE_TOKEN ? 'PRESENT' : 'MISSING',
  };
}

// --- MongoDB Atlas Setup (cached connection for serverless) ---
let isMongoConnected = false;

async function ensureMongoReady() {
  const mongoUri = resolveMongoUri();
  if (!mongoUri) {
    if (IS_VERCEL) {
      const err = new Error('Missing MONGODB_URI for production persistence');
      err.code = 'MONGO_NOT_CONFIGURED';
      throw err;
    }
    return false;
  }

  const uriCheck = diagnoseMongoUriSafe(mongoUri);
  if (!uriCheck.valid) {
    const err = new Error(`MONGODB_URI format invalid: ${uriCheck.issues.join(', ')}`);
    err.code = 'MONGO_URI_INVALID';
    throw err;
  }

  if (mongoose.connection.readyState === 1) {
    isMongoConnected = true;
    return true;
  }

  if (!global.__secureCloudMongoPromise) {
    global.__secureCloudMongoPromise = mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 10000,
      maxPoolSize: 10,
      bufferCommands: false,
    }).then(() => {
      isMongoConnected = true;
      console.log('[Database] Connected to MongoDB (database:', mongoose.connection.name + ', collection: users/files)');
      return true;
    }).catch((err) => {
      global.__secureCloudMongoPromise = null;
      isMongoConnected = false;
      console.error('[Database] MongoDB connection error:', sanitizeErrorMessage(err.message));
      throw err;
    });
  }

  await global.__secureCloudMongoPromise;
  return mongoose.connection.readyState === 1;
}

function useMongoStorage() {
  return !!resolveMongoUri();
}

function mongoErrorResponse(err) {
  if (err && err.code === 'MONGO_NOT_CONFIGURED') {
    return { status: 503, error: 'Database is not configured. Missing MONGODB_URI.' };
  }
  if (err && err.code === 'MONGO_URI_INVALID') {
    return {
      status: 503,
      error: 'Database connection string is malformed. Check MONGODB_URI in Vercel Production (no quotes, no placeholders, URL-encode special characters in password).',
    };
  }
  const msg = sanitizeErrorMessage(err && err.message);
  if (/bad auth|authentication failed/i.test(msg)) {
    return {
      status: 503,
      error: 'Database authentication failed. Verify MONGODB_URI in Vercel Production uses the Atlas database username and URL-encoded password (not your Atlas account login).',
    };
  }
  return { status: 503, error: `Database connection failed. ${msg}` };
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
  } catch (_) { }
  const reqHost = req.get('host') || '';
  const isLocalhost = /^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(reqHost);
  const reqOrigin = `${req.protocol}://${reqHost}`;
  if (!isLocalhost) return reqOrigin;
  return process.env.APP_BASE_URL || reqOrigin;
}

function throwIfProductionStorageMissing() {
  if (IS_VERCEL && !resolveMongoUri()) {
    const err = new Error('Missing MONGODB_URI for production user persistence');
    err.statusCode = 503;
    throw err;
  }
}

function throwIfProductionBlobMissing() {
  if (IS_VERCEL && !process.env.BLOB_READ_WRITE_TOKEN) {
    const err = new Error('Missing BLOB_READ_WRITE_TOKEN for production file storage');
    err.statusCode = 503;
    throw err;
  }
}

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(FILES_FILE)) fs.writeFileSync(FILES_FILE, '[]');

function audit(action, username, details = '') {
  const line = `[${new Date().toISOString()}] ${action} | user: ${username || '-'} | ${details}\n`;
  try {
    fs.appendFileSync(LOG_FILE, line);
  } catch (_) { }
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

// Multer memory storage — 4MB limit safe for Vercel serverless body limit
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 4 * 1024 * 1024 },
});

app.set('trust proxy', 1);
app.use(cors({ origin: true, credentials: true }));
app.use((req, res, next) => {
  const ct = req.headers['content-type'] || '';
  if (ct.includes('multipart/form-data')) return next();
  express.json()(req, res, next);
});

// --- Data Layer Helpers ---
function readLocalJson(filePath) {
  if (!fs.existsSync(filePath)) return [];
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return [];
  }
}

async function findUserByEmail(email) {
  const normalized = (email || '').toLowerCase().trim();
  if (useMongoStorage()) {
    await ensureMongoReady();
    const doc = await UserModel.findOne({ email: normalized }).lean();
    return doc ? { ...doc, id: doc._id.toString() } : null;
  }
  if (IS_VERCEL) return null;
  const users = readLocalJson(USERS_FILE);
  return users.find((u) => (u.email || '').toLowerCase().trim() === normalized) || null;
}

async function saveUser(userObj) {
  const email = (userObj.email || '').toLowerCase().trim();
  const record = {
    email,
    passwordHash: userObj.passwordHash,
    verified: userObj.verified !== false,
    createdAt: userObj.createdAt || new Date().toISOString(),
  };
  if (useMongoStorage()) {
    await ensureMongoReady();
    await UserModel.updateOne({ email }, { $set: record }, { upsert: true });
    return;
  }
  if (IS_VERCEL) {
    const err = new Error('Missing MONGODB_URI for production user persistence');
    err.code = 'MONGO_NOT_CONFIGURED';
    throw err;
  }
  const users = readLocalJson(USERS_FILE);
  const idx = users.findIndex((u) => (u.email || '').toLowerCase().trim() === email);
  if (idx >= 0) users[idx] = { ...users[idx], ...record };
  else users.push({ id: Date.now().toString(), ...record });
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

async function getFilesForUser(userEmail) {
  const normalized = (userEmail || '').toLowerCase().trim();
  if (useMongoStorage()) {
    await ensureMongoReady();
    const docs = await FileModel.find({ email: normalized }).lean();
    return docs.map((d) => ({ ...d, id: d.id || d._id.toString() }));
  }
  if (IS_VERCEL) return [];
  const files = readLocalJson(FILES_FILE);
  return files.filter((f) => (f.email || f.username || '').toLowerCase().trim() === normalized);
}

async function getAllFiles() {
  if (useMongoStorage()) {
    await ensureMongoReady();
    const docs = await FileModel.find({}).lean();
    return docs.map((d) => ({ ...d, id: d.id || d._id.toString() }));
  }
  if (IS_VERCEL) return [];
  return readLocalJson(FILES_FILE);
}

async function findFileById(id) {
  if (useMongoStorage()) {
    await ensureMongoReady();
    return FileModel.findOne({ id }).lean();
  }
  if (IS_VERCEL) return null;
  const files = readLocalJson(FILES_FILE);
  return files.find((f) => f.id === id) || null;
}

async function saveFileEntry(entry) {
  if (useMongoStorage()) {
    await ensureMongoReady();
    await FileModel.updateOne({ id: entry.id }, { $set: entry }, { upsert: true });
    return;
  }
  if (IS_VERCEL) {
    const err = new Error('Missing MONGODB_URI for production metadata persistence');
    err.code = 'MONGO_NOT_CONFIGURED';
    throw err;
  }
  const files = readLocalJson(FILES_FILE);
  files.push(entry);
  fs.writeFileSync(FILES_FILE, JSON.stringify(files, null, 2));
}

async function deleteFileEntry(id) {
  if (useMongoStorage()) {
    await ensureMongoReady();
    await FileModel.deleteOne({ id });
    return;
  }
  if (IS_VERCEL) return;
  const files = readLocalJson(FILES_FILE);
  const idx = files.findIndex((f) => f.id === id);
  if (idx >= 0) {
    files.splice(idx, 1);
    fs.writeFileSync(FILES_FILE, JSON.stringify(files, null, 2));
  }
}

function fileOwnerEmail(entry) {
  return (entry && (entry.email || entry.username) || '').toLowerCase().trim();
}

function isFileExpired(entry) {
  if (!entry || !entry.expiresAt) return false;
  const expMs = new Date(entry.expiresAt).getTime();
  return !isNaN(expMs) && expMs <= Date.now();
}

async function removeExpiredFile(entry) {
  if (entry.blobUrl && delBlob && process.env.BLOB_READ_WRITE_TOKEN) {
    try {
      await delBlob(entry.blobUrl, { token: process.env.BLOB_READ_WRITE_TOKEN });
    } catch (_) { }
  }
  if (entry.storedName) {
    const filePath = path.join(UPLOAD_DIR, entry.storedName);
    if (fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch (_) { }
    }
  }
  await deleteFileEntry(entry.id);
  audit('EXPIRED_AUTO_DELETED', entry.email || entry.username || 'system', `file: ${entry.originalName} id: ${entry.id}`);
}

async function cleanupExpiredFiles() {
  try {
    const files = await getAllFiles();
    const now = Date.now();
    for (const f of files) {
      if (f && f.expiresAt) {
        const expMs = new Date(f.expiresAt).getTime();
        if (!isNaN(expMs) && expMs <= now) {
          await removeExpiredFile(f);
        }
      }
    }
  } catch (err) {
    console.error('[Cleanup] Error cleaning expired files:', sanitizeErrorMessage(err.message));
  }
}

// Initial cleanup at server startup
cleanupExpiredFiles();
setInterval(cleanupExpiredFiles, 60000);

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  const token = authHeader.substring(7).trim();
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded && decoded.email) {
      req.user = { email: String(decoded.email).trim().toLowerCase() };
      return next();
    }
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }
    return res.status(401).json({ error: 'Invalid session. Please log in again.' });
  }
  return res.status(401).json({ error: 'Unauthorized. Please log in.' });
}

function getAuthEmailFromRequest(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.substring(7).trim();
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded && decoded.email) {
      return String(decoded.email).trim().toLowerCase();
    }
  } catch (_) { }
  return null;
}

app.get('/api/health', async (req, res) => {
  const base = getPublicBaseUrl(req);
  const mongoUri = resolveMongoUri();
  const uriCheck = diagnoseMongoUriSafe(mongoUri);
  let mongoReady = false;
  let mongoError = null;
  if (mongoUri && uriCheck.valid) {
    try {
      mongoReady = await ensureMongoReady();
    } catch (err) {
      mongoError = mongoErrorResponse(err).error;
    }
  } else if (mongoUri) {
    mongoError = 'MONGODB_URI format invalid: ' + uriCheck.issues.join(', ');
  }
  res.json({
    ok: true,
    message: 'SecureCloud API',
    env: getEnvPresence(),
    mongoConfigured: !!mongoUri,
    mongoUriValid: uriCheck.valid,
    mongoUriIssues: uriCheck.valid ? [] : uriCheck.issues,
    mongoActive: mongoReady,
    mongoDatabase: mongoReady ? mongoose.connection.name : null,
    mongoError: mongoError || null,
    blobConfigured: !!process.env.BLOB_READ_WRITE_TOKEN,
    blobActive: !!(putBlob && process.env.BLOB_READ_WRITE_TOKEN),
    jwtConfigured: !!process.env.JWT_SECRET,
    isVercel: IS_VERCEL,
    baseUrl: base,
    routes: ['/api/login', '/api/register', '/api/me', '/api/files'],
  });
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const normalizedEmail = (email || '').trim().toLowerCase();
  if (!normalizedEmail || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  if (IS_VERCEL && !resolveMongoUri()) {
    audit('LOGIN_FAIL', normalizedEmail, 'MONGODB_URI missing in production');
    return res.status(503).json({ error: 'Authentication storage is not configured. Missing MONGODB_URI.' });
  }
  try {
    const user = await findUserByEmail(normalizedEmail);
    if (!user || !user.passwordHash) {
      audit('LOGIN_FAIL', normalizedEmail, 'user not found');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (!bcrypt.compareSync(password, user.passwordHash)) {
      audit('LOGIN_FAIL', normalizedEmail, 'invalid password');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (user.verified === false) {
      audit('LOGIN_FAIL', user.email, 'email not verified');
      return res.status(403).json({ error: 'Please verify your email first. Check your inbox for the verification link.' });
    }
    const userEmail = (user.email || normalizedEmail).trim().toLowerCase();
    const token = jwt.sign({ email: userEmail }, JWT_SECRET, { expiresIn: '7d' });
    audit('LOGIN_OK', userEmail, '');
    res.json({ token, email: userEmail });
  } catch (err) {
    const mongoErr = mongoErrorResponse(err);
    audit('LOGIN_FAIL', normalizedEmail, 'database unavailable');
    return res.status(mongoErr.status).json({ error: mongoErr.error });
  }
});

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body || {};
  const trimmed = (email || '').trim().toLowerCase();
  if (!trimmed || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  if (IS_VERCEL && !resolveMongoUri()) {
    audit('REGISTER_FAIL', trimmed, 'MONGODB_URI missing in production');
    return res.status(503).json({ error: 'User database is not configured. Missing MONGODB_URI.' });
  }
  try {
    const existingUser = await findUserByEmail(trimmed);
    if (existingUser) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = bcrypt.hashSync(password, 10);
    await saveUser({
      email: trimmed,
      passwordHash,
      verified: true,
      createdAt: new Date().toISOString(),
    });

    const savedUser = await findUserByEmail(trimmed);
    if (!savedUser || !savedUser.passwordHash || !bcrypt.compareSync(password, savedUser.passwordHash)) {
      console.error('[Register] Verification failed: user not readable after save');
      return res.status(503).json({ error: 'Account could not be persisted. Please try again.' });
    }

    audit('REGISTER', trimmed, 'account created');
    res.status(201).json({ email: trimmed, message: 'Account created successfully. You can now log in.' });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }
    const mongoErr = mongoErrorResponse(err);
    console.error('[Register] Save failed:', sanitizeErrorMessage(err.message));
    return res.status(mongoErr.status).json({ error: mongoErr.error });
  }
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
app.post('/api/files', authMiddleware, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File too large. Maximum upload size is 4 MB.' });
      }
      console.error('[Upload Diagnostic] Multipart parse error:', sanitizeErrorMessage(err.message));
      return res.status(400).json({ error: 'Invalid file upload. Could not parse multipart request.' });
    }
    next();
  });
}, async (req, res) => {
  console.log(`[Upload Diagnostic] Method: ${req.method} | Content-Type: ${req.headers['content-type'] || 'none'}`);
  console.log(`[Upload Diagnostic] User: ${req.user ? req.user.email : 'unauthenticated'} | File Attached: ${!!req.file}`);
  
  if (!req.file) {
    console.error('[Upload Diagnostic] Upload failed: No file attached to request');
    return res.status(400).json({ error: 'No file uploaded' });
  }

  console.log(`[Upload Diagnostic] File OriginalName: ${req.file.originalname} | Size: ${req.file.size} bytes | Buffer Length: ${req.file.buffer ? req.file.buffer.length : 0}`);
  console.log(`[Upload Diagnostic] IS_VERCEL: ${!!IS_VERCEL} | BLOB_READ_WRITE_TOKEN present: ${!!process.env.BLOB_READ_WRITE_TOKEN} | putBlob SDK ready: ${!!putBlob}`);

  if (IS_VERCEL && !process.env.BLOB_READ_WRITE_TOKEN) {
    console.error('[Upload Diagnostic] Vercel Blob token missing in environment variables');
    return res.status(503).json({ error: 'Blob storage is not configured. Missing BLOB_READ_WRITE_TOKEN in Vercel.' });
  }

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
      const blobToken = String(process.env.BLOB_READ_WRITE_TOKEN).trim();
      console.log(`[Upload Diagnostic] Initiating Vercel Blob upload for fileId: ${fileId}...`);
      const blob = await putBlob(`uploads/${fileId}`, req.file.buffer, {
        access: 'private',
        addRandomSuffix: false,
        contentType: encrypted ? 'application/octet-stream' : (req.file.mimetype || 'application/octet-stream'),
        token: blobToken,
      });
      blobUrl = blob.url;
      console.log('[Upload Diagnostic] Vercel Blob upload SUCCESS.');
    } catch (blobErr) {
      const safeErr = sanitizeErrorMessage(blobErr.message || String(blobErr));
      console.error('[Upload Diagnostic] Vercel Blob upload EXCEPTION:', safeErr);
      return res.status(500).json({ error: `Blob upload failed: ${safeErr}` });
    }
  } else if (IS_VERCEL) {
    console.error('[Upload Diagnostic] BLOB_READ_WRITE_TOKEN missing in Vercel runtime environment');
    return res.status(503).json({ error: 'Cloud storage is not configured. Missing BLOB_READ_WRITE_TOKEN environment variable in Vercel.' });
  } else {
    // Local disk fallback
    const filePath = path.join(UPLOAD_DIR, fileId);
    fs.writeFileSync(filePath, req.file.buffer);
    console.log('[Upload Diagnostic] Local disk fallback upload SUCCESS');
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

  try {
    await saveFileEntry(entry);
  } catch (err) {
    console.error('[Upload] Metadata save failed:', sanitizeErrorMessage(err.message));
    if (blobUrl && delBlob && process.env.BLOB_READ_WRITE_TOKEN) {
      try {
        await delBlob(blobUrl, { token: String(process.env.BLOB_READ_WRITE_TOKEN).trim() });
      } catch (_) {}
    }
    const mongoErr = mongoErrorResponse(err);
    return res.status(mongoErr.status).json({ error: `Failed to save file metadata: ${mongoErr.error}` });
  }
  audit('UPLOAD', req.user.email, `file: ${entry.originalName} id: ${entry.id} expiresAt: ${expiresAt || 'never'}`);
  const { blobUrl: _omitBlobUrl, ...safeEntry } = entry;
  res.status(201).json(safeEntry);
});

// GET /api/files — list current user's files
app.get('/api/files', authMiddleware, async (req, res) => {
  try {
    await cleanupExpiredFiles();
    const files = await getFilesForUser(req.user.email);
    const safeFiles = files.map(({ blobUrl, ...rest }) => rest);
    res.json(safeFiles);
  } catch (err) {
    const mongoErr = mongoErrorResponse(err);
    return res.status(mongoErr.status).json({ error: mongoErr.error });
  }
});

// GET /api/files/:id — download payload
app.get('/api/files/:id', async (req, res) => {
  try {
    const isShareDownload = req.query && req.query.isShareDownload === 'true';
    const reqUserEmail = getAuthEmailFromRequest(req);

    const entry = await findFileById(req.params.id);
    if (!entry) return res.status(404).json({ error: 'File not found' });

    if (isFileExpired(entry)) {
      await removeExpiredFile(entry);
      audit('DOWNLOAD_BLOCKED_EXPIRED', reqUserEmail || 'unauthenticated_share', `file: ${entry.originalName} id: ${entry.id}`);
      return res.status(410).json({ error: 'This file has expired.' });
    }

    if (!isShareDownload) {
      if (!reqUserEmail) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
      }
      if (fileOwnerEmail(entry) !== reqUserEmail) {
        audit('DOWNLOAD_DENIED', reqUserEmail, `file: ${entry.originalName} id: ${entry.id}`);
        return res.status(403).json({ error: 'You do not have access to this file.' });
      }
    }

    const auditAction = isShareDownload ? 'SHARE_DOWNLOAD' : 'DOWNLOAD';

    if (entry.blobUrl) {
      try {
        const buf = await fetchPrivateBlobBuffer(entry.blobUrl);
        if (!buf) return res.status(404).json({ error: 'Cloud blob file not found' });
        audit(auditAction, reqUserEmail || 'unauthenticated_share', `file: ${entry.originalName} id: ${entry.id}`);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(entry.originalName)}"`);
        return res.send(buf);
      } catch (err) {
        console.error('[BlobDownload] Error fetching private blob:', sanitizeErrorMessage(err.message));
        return res.status(500).json({ error: 'Failed to download cloud file' });
      }
    }

    const filePath = path.join(UPLOAD_DIR, entry.storedName);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
    audit(auditAction, reqUserEmail || 'unauthenticated_share', `file: ${entry.originalName} id: ${entry.id}`);
    res.download(filePath, entry.originalName);
  } catch (err) {
    const mongoErr = mongoErrorResponse(err);
    return res.status(mongoErr.status).json({ error: mongoErr.error });
  }
});

// DELETE /api/files/:id
app.delete('/api/files/:id', authMiddleware, async (req, res) => {
  try {
    const entry = await findFileById(req.params.id);
    if (!entry) return res.status(404).json({ error: 'File not found' });
    if (fileOwnerEmail(entry) !== req.user.email) {
      audit('DELETE_DENIED', req.user.email, `file: ${entry.originalName} id: ${entry.id}`);
      return res.status(403).json({ error: 'You do not have access to this file.' });
    }

    if (entry.blobUrl && delBlob && process.env.BLOB_READ_WRITE_TOKEN) {
      try {
        await delBlob(entry.blobUrl, { token: process.env.BLOB_READ_WRITE_TOKEN });
      } catch (_) { }
    }
    if (entry.storedName) {
      const filePath = path.join(UPLOAD_DIR, entry.storedName);
      if (fs.existsSync(filePath)) {
        try { fs.unlinkSync(filePath); } catch (_) { }
      }
    }

    await deleteFileEntry(entry.id);
    audit('DELETE', req.user.email, `file: ${entry.originalName} id: ${entry.id}`);
    res.json({ ok: true });
  } catch (err) {
    const mongoErr = mongoErrorResponse(err);
    return res.status(mongoErr.status).json({ error: mongoErr.error });
  }
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
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`SecureCloud API running at http://localhost:${PORT}`);
    const ip = getLocalIP();
    if (ip) {
      console.log(`  Same WiFi (phone): http://${ip}:${PORT}`);
    }
  });
}

module.exports = app;
