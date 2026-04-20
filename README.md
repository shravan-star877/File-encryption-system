# [VAULT]GUARD — Secure Cloud File Protection

**Client-side encrypted cloud storage.** Upload files under a secret key; only with that key can files be decrypted and opened. The server never sees your plain data or key.

---

## What It Does

1. **Protect a file** — Choose a file, generate (or paste) an encryption key, then upload. The file is encrypted in your browser with **AES-256-GCM** and only the ciphertext is sent to the server.
2. **Access a file** — From your file list, choose “Decrypt & open,” enter the same key you used when protecting the file. The file is decrypted in the browser and can open in a new tab (images, PDFs, etc.) or download.

Your encryption key is never sent to the server. Without the key, stored files remain unreadable ciphertext.

---

## Features

- **Client-side encryption** — AES-256-GCM; keys derived from your passphrase via PBKDF2 (SHA-256, 100k iterations).
- **Key-per-file** — Generate a unique key per file (e.g. UUID-style) and store it safely; required to decrypt.
- **User accounts** — Register and log in with email and password. Files are scoped to your account.
- **Protect & Access workflow** — Tabbed UI: “Protect file” (upload + encrypt) and “Access file” (list, decrypt, open or download).
- **View encrypted payload** — Inspect the raw encrypted bytes (hex) before decrypting.
- **Open after decrypt** — For images, PDFs, and other viewable types, optionally open in a new browser tab with correct MIME types.
- **Audit log** — Server logs login, registration, upload, download, and delete events to `server/audit.log`.

---

## Tech Stack

| Layer      | Technology |
|-----------|------------|
| Frontend  | HTML5, CSS3, JavaScript (vanilla) |
| Crypto    | Web Crypto API (AES-GCM, PBKDF2) |
| Backend   | Node.js, Express |
| Auth      | JWT (Bearer), bcrypt for password hashing |
| Storage   | Local filesystem (`server/uploads/`), metadata in `server/files.json` |

---

## Project Structure

```
Secure cloud/
├── README.md           # This file
├── package.json        # Scripts: start, dev, seed
├── index.html          # Single-page app (login, Protect file, Access file)
├── style.css           # [VAULT]GUARD theme and layout
├── app.js              # Frontend: auth, crypto, upload, decrypt, UI
└── server/
    ├── README.md       # API reference
    ├── server.js       # Express API (auth, files, static)
    ├── seed-users.js   # One-time: create users.json
    ├── users.json      # User accounts (created by seed or register)
    ├── files.json      # File metadata (id, owner, originalName, encrypted, etc.)
    ├── audit.log       # Audit trail (append-only)
    └── uploads/        # Stored files (encrypted or plain)
```

---

## Prerequisites

- **Node.js** (v14 or later)
- **npm** (comes with Node)

---

## Quick Start

### 1. Install dependencies

From the project root:

```bash
npm install
```

### 2. (Optional) Seed a test user

Creates `server/users.json` with one user:

```bash
npm run seed
```

- **Email:** `admin@securecloud.com`  
- **Password:** `1234`

You can also register a new account from the app.

### 3. Start the server

```bash
npm start
```

Or, for development:

```bash
npm run dev
```

The API runs at **http://localhost:3001**. A public URL is also shown — use it on your phone (works on same or different network).

**One command works everywhere.** Just run `npm start` — open the Cloudflare URL on your phone for access from any network.

### 4. Use the app

1. **Log in** (or register) with your email and password.
2. **Protect file:** In “Protect file,” select a file → “Generate key” → copy the key somewhere safe → “Encrypt & upload.” Your file is encrypted in the browser and uploaded.
3. **Access file:** In “Access file,” find your file → “Decrypt & open” → paste the key → confirm. Check “Open file after download” to view images/PDFs in a new tab, or leave unchecked to download.

**Important:** If you lose the encryption key, the file cannot be recovered.

### 5. (Optional) Password reset emails to real inbox

By default, reset links go to a test inbox. To send them to the user's actual email (e.g. on mobile):

1. Copy `server/.env.example` → `server/.env`
2. Add your Gmail address and [App Password](https://myaccount.google.com/apppasswords)
3. Restart the server

See **`server/EMAIL-SETUP.md`** for detailed steps.

---

## API Overview

All file endpoints require authentication: `Authorization: Bearer <token>`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST   | `/api/register` | Create account (email + password) |
| POST   | `/api/login`   | Log in → returns JWT and email |
| GET    | `/api/me`      | Current user (requires auth) |
| POST   | `/api/logout`  | Log out (optional) |
| GET    | `/api/health`  | Health check |
| POST   | `/api/files`   | Upload file (multipart: `file`, optional `originalName`, optional `encrypted`) |
| GET    | `/api/files`   | List current user’s files |
| GET    | `/api/files/:id` | Download file by id |
| DELETE | `/api/files/:id` | Delete file |

See **`server/README.md`** for request/response details.

---

## Security Notes

- **Encryption** happens in the browser. The server only stores ciphertext (and metadata). Keys never leave the client.
- **JWT secret:** Default is for development only. Set `JWT_SECRET` in production.
- **HTTPS:** Use HTTPS in production so tokens and data are not sent in the clear.
- **Key storage:** Users must store their encryption keys securely (e.g. password manager). The app does not store keys.

---

## Audit Log

Events are appended to `server/audit.log`:

- `LOGIN_OK` / `LOGIN_FAIL`
- `REGISTER`
- `LOGOUT`
- `UPLOAD` (with filename and id)
- `DOWNLOAD` (with filename and id)
- `DELETE` (with filename and id)

---

## License

Use and modify as needed for your environment.
# File-encryption-system
