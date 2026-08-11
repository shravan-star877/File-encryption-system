/**
 * Integration tests for Secure Cloud API.
 * Usage: node scripts/test-api.js [baseUrl]
 * Requires MONGODB_URI (and optionally BLOB_READ_WRITE_TOKEN) in api/.env for full tests.
 */
require('dotenv').config({ path: require('path').join(__dirname, '..', 'api', '.env') });
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const BASE = process.argv[2] || 'http://localhost:3001';
const testEmail = `test-${Date.now()}@securecloud-test.local`;
const testPassword = 'TestPass123!';
const userBEmail = `testb-${Date.now()}@securecloud-test.local`;
const userBPassword = 'TestPass456!';

const results = [];
let tokenA = null;
let tokenB = null;
let uploadedFileId = null;
let encryptionKey = null;

function pass(name, detail) {
  results.push({ name, ok: true, detail: detail || '' });
  console.log(`PASS  ${name}${detail ? ` — ${detail}` : ''}`);
}

function fail(name, detail) {
  results.push({ name, ok: false, detail: detail || '' });
  console.error(`FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
}

async function jsonFetch(url, options = {}) {
  const res = await fetch(url, options);
  let data = {};
  try { data = await res.json(); } catch (_) { }
  return { res, data };
}

async function run() {
  console.log(`\nSecure Cloud API tests → ${BASE}\n`);

  // Health
  try {
    const { res, data } = await jsonFetch(`${BASE}/api/health`);
    if (res.ok && data.ok) {
      pass('Health check', `mongoConfigured=${data.mongoConfigured} blobConfigured=${data.blobConfigured}`);
    } else {
      fail('Health check', `status ${res.status}`);
    }
  } catch (e) {
    fail('Health check', e.message);
  }

  // Register fresh user
  try {
    const { res, data } = await jsonFetch(`${BASE}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: testPassword }),
    });
    if (res.status === 201 && data.email === testEmail) {
      pass('Register fresh user', testEmail);
    } else {
      fail('Register fresh user', `${res.status} ${data.error || JSON.stringify(data)}`);
    }
  } catch (e) {
    fail('Register fresh user', e.message);
  }

  // Immediate login same credentials
  try {
    const { res, data } = await jsonFetch(`${BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: testPassword }),
    });
    if (res.status === 200 && data.token && data.email === testEmail) {
      tokenA = data.token;
      pass('Immediate login same credentials', 'JWT received');
    } else {
      fail('Immediate login same credentials', `${res.status} ${data.error || JSON.stringify(data)}`);
    }
  } catch (e) {
    fail('Immediate login same credentials', e.message);
  }

  // Wrong password
  try {
    const { res, data } = await jsonFetch(`${BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: 'WrongPassword!' }),
    });
    if (res.status === 401 && data.error) {
      pass('Wrong password rejected', data.error);
    } else {
      fail('Wrong password rejected', `expected 401, got ${res.status}`);
    }
  } catch (e) {
    fail('Wrong password rejected', e.message);
  }

  // Unknown email
  try {
    const { res, data } = await jsonFetch(`${BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@securecloud-test.local', password: testPassword }),
    });
    if (res.status === 401) {
      pass('Unknown email rejected');
    } else {
      fail('Unknown email rejected', `expected 401, got ${res.status}`);
    }
  } catch (e) {
    fail('Unknown email rejected', e.message);
  }

  // Session /me
  if (tokenA) {
    try {
      const { res, data } = await jsonFetch(`${BASE}/api/me`, {
        headers: { Authorization: `Bearer ${tokenA}` },
      });
      if (res.status === 200 && data.email === testEmail) {
        pass('Session refresh via /api/me');
      } else {
        fail('Session refresh via /api/me', `${res.status}`);
      }
    } catch (e) {
      fail('Session refresh via /api/me', e.message);
    }
  }

  // Invalid token
  try {
    const { res } = await jsonFetch(`${BASE}/api/me`, {
      headers: { Authorization: 'Bearer invalid.token.here' },
    });
    if (res.status === 401) {
      pass('Invalid token rejected');
    } else {
      fail('Invalid token rejected', `expected 401, got ${res.status}`);
    }
  } catch (e) {
    fail('Invalid token rejected', e.message);
  }

  // Upload encrypted file (if token available)
  if (tokenA) {
    try {
      const plainText = 'Secure Cloud integration test payload ' + Date.now();
      const plainBuf = Buffer.from(plainText, 'utf8');
      encryptionKey = crypto.randomUUID().replace(/-/g, '');

      // Simulate client-side AES-GCM encryption (same format as app.js)
      const salt = crypto.randomBytes(16);
      const iv = crypto.randomBytes(12);
      const key = crypto.pbkdf2Sync(encryptionKey, salt, 100000, 32, 'sha256');
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([cipher.update(plainBuf), cipher.final(), cipher.getAuthTag()]);
      const payload = Buffer.concat([salt, iv, encrypted]);

      const form = new FormData();
      form.append('file', new Blob([payload]), 'test-file.txt');
      form.append('originalName', 'test-file.txt');
      form.append('encrypted', 'true');
      form.append('expiry', 'never');

      const res = await fetch(`${BASE}/api/files`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokenA}` },
        body: form,
      });
      const data = await res.json().catch(() => ({}));
      if (res.status === 201 && data.id) {
        uploadedFileId = data.id;
        pass('Encrypted file upload', `id=${uploadedFileId}`);
      } else {
        fail('Encrypted file upload', `${res.status} ${data.error || JSON.stringify(data)}`);
      }
    } catch (e) {
      fail('Encrypted file upload', e.message);
    }
  }

  // File list
  if (tokenA) {
    try {
      const { res, data } = await jsonFetch(`${BASE}/api/files`, {
        headers: { Authorization: `Bearer ${tokenA}` },
      });
      const found = Array.isArray(data) && data.some((f) => f.id === uploadedFileId);
      if (res.status === 200 && found) {
        pass('File appears in list');
      } else if (res.status === 200 && !uploadedFileId) {
        fail('File appears in list', 'no upload id');
      } else if (res.status === 200) {
        fail('File appears in list', 'uploaded file not in list');
      } else {
        fail('File appears in list', `${res.status}`);
      }
    } catch (e) {
      fail('File appears in list', e.message);
    }
  }

  // User B isolation
  try {
    await jsonFetch(`${BASE}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userBEmail, password: userBPassword }),
    });
    const loginB = await jsonFetch(`${BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: userBEmail, password: userBPassword }),
    });
    tokenB = loginB.data.token;
  } catch (_) { }

  if (tokenB && uploadedFileId) {
    try {
      const { res, data } = await jsonFetch(`${BASE}/api/files/${encodeURIComponent(uploadedFileId)}`, {
        headers: { Authorization: `Bearer ${tokenB}` },
      });
      if (res.status === 403 || res.status === 404) {
        pass('User B cannot access User A file', `status ${res.status}`);
      } else {
        fail('User B cannot access User A file', `expected 403/404, got ${res.status}`);
      }
    } catch (e) {
      fail('User B cannot access User A file', e.message);
    }
  }

  // Download + decrypt
  if (tokenA && uploadedFileId && encryptionKey) {
    try {
      const res = await fetch(`${BASE}/api/files/${encodeURIComponent(uploadedFileId)}`, {
        headers: { Authorization: `Bearer ${tokenA}` },
      });
      if (!res.ok) {
        fail('Download encrypted file', `status ${res.status}`);
      } else {
        const buf = Buffer.from(await res.arrayBuffer());
        const salt = buf.slice(0, 16);
        const iv = buf.slice(16, 28);
        const ciphertext = buf.slice(28);
        const tag = ciphertext.slice(ciphertext.length - 16);
        const encData = ciphertext.slice(0, ciphertext.length - 16);
        const key = crypto.pbkdf2Sync(encryptionKey, salt, 100000, 32, 'sha256');
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const decrypted = Buffer.concat([decipher.update(encData), decipher.final()]);
        pass('Download + client-side decrypt', decrypted.toString('utf8').slice(0, 40) + '...');
      }
    } catch (e) {
      fail('Download + client-side decrypt', e.message);
    }
  }

  console.log('\n--- Summary ---');
  const passed = results.filter((r) => r.ok).length;
  const failed = results.filter((r) => !r.ok).length;
  console.log(`${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch((err) => {
  console.error('Test runner error:', err.message);
  process.exit(1);
});
