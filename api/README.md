# Secure Cloud — API Reference

Backend for **[VAULT]GUARD** (Secure Cloud). Serves auth, file upload/download, and the static frontend. Full project docs: see root **README.md**.

---

## Run

From project root:

```bash
npm install
npm run seed   # optional: create admin@securecloud.com / 1234
npm start      # http://localhost:3001
```

Environment:

- `PORT` — default `3001`
- `JWT_SECRET` — set in production (default is dev-only)

---

## Auth

| Method | Endpoint | Body / Headers | Response |
|--------|----------|----------------|----------|
| POST   | `/api/register` | `{ "email", "password" }` | `201` `{ "email", "message" }` or `4xx` `{ "error" }` |
| POST   | `/api/login`    | `{ "email", "password" }` | `200` `{ "token", "email" }` or `401` `{ "error" }` |
| GET    | `/api/me`       | `Authorization: Bearer <token>` | `200` `{ "email" }` or `401` |
| POST   | `/api/logout`   | `Authorization: Bearer <token>` | `200` `{ "ok": true }` |

Registration: email required, password min 4 characters, valid email format. Logins use email (case-insensitive).

---

## Files

All file routes require: **`Authorization: Bearer <token>`**.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST   | `/api/files`     | Upload. Multipart: `file` (required), `originalName` (optional), `encrypted` (`"true"` for client-encrypted uploads). Returns file entry. |
| GET    | `/api/files`     | List current user’s files. Returns array of `{ id, originalName, storedName, size, encrypted, uploadedAt, ... }`. |
| GET    | `/api/files/:id` | Download file. `id` is the stored filename (e.g. `1234567890-filename.ext`). |
| DELETE | `/api/files/:id` | Delete file and metadata. Returns `{ "ok": true }`. |

File metadata is in **`server/files.json`**; file bodies in **`server/uploads/`**.

---

## Other

- **GET /api/health** — `{ "ok": true, "message": "SecureCloud API", "routes": [...] }` — no auth.

---

## Audit

All auth and file actions are appended to **`server/audit.log`** with timestamp, action, user, and details (e.g. filename, id).
