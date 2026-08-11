const loginOverlay = document.getElementById("loginOverlay");
const loginForm = document.getElementById("loginForm");
const loginError = document.getElementById("loginError");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const regEmailInput = document.getElementById("regEmail");
const regPasswordInput = document.getElementById("regPassword");

const userDisplay = document.getElementById("userDisplay");
const userAvatar = document.getElementById("userAvatar");
const logoutBtn = document.getElementById("logoutBtn");

const fileInput = document.getElementById("fileInput");
const uploadArea = document.getElementById("uploadArea");
const fileInfo = document.getElementById("fileInfo");
const fileName = document.getElementById("fileName");
const fileSize = document.getElementById("fileSize");
const removeFile = document.getElementById("removeFile");

const encryptionKey = document.getElementById("encryptionKey");
const generateKey = document.getElementById("generateKey");
const keyToggle = document.getElementById("keyToggle");

const statusArea = document.getElementById("statusArea");
const statusMessage = document.getElementById("statusMessage");

/* ---------- API & AUTH ---------- */
const API_BASE = ""; // Same origin when served by backend
const AUTH_STORAGE_KEYS = ["securecloud_token", "securecloud_session", "securecloud_user"];

function clearAuthState() {
    AUTH_STORAGE_KEYS.forEach((key) => {
        localStorage.removeItem(key);
        sessionStorage.removeItem(key);
    });
    if (typeof document !== "undefined") {
        document.cookie = "securecloud_token=; Max-Age=0; path=/; SameSite=Lax";
        document.cookie = "securecloud_session=; Max-Age=0; path=/; SameSite=Lax";
    }
}

function getToken() {
    const token = localStorage.getItem("securecloud_token");
    if (!token || typeof token !== "string") return null;
    const trimmed = token.trim();
    return trimmed ? trimmed : null;
}

function setToken(token) {
    if (token && typeof token === "string" && token.trim()) {
        localStorage.setItem("securecloud_token", token.trim());
        sessionStorage.setItem("securecloud_session", "active");
        return;
    }
    clearAuthState();
}

function showLoginScreen() {
    if (loginOverlay) loginOverlay.style.display = "flex";
    const userInfo = document.getElementById("userInfo");
    if (userInfo) userInfo.style.display = "none";
    if (userDisplay) userDisplay.textContent = "";
    if (userAvatar) userAvatar.textContent = "?";
}

function showLoggedIn(email) {
    if (!email || typeof email !== "string") {
        clearAuthState();
        showLoginScreen();
        return;
    }
    if (loginOverlay) loginOverlay.style.display = "none";
    const userInfo = document.getElementById("userInfo");
    if (userInfo) userInfo.style.display = "flex";
    if (userDisplay) userDisplay.textContent = email;
    if (userAvatar) userAvatar.textContent = (email[0] || "?").toUpperCase();
    localStorage.setItem("securecloud_user", email);
    loadMyFiles();
}

function logout() {
    clearAuthState();
    const userInfo = document.getElementById("userInfo");
    if (userInfo) userInfo.style.display = "none";
    if (userDisplay) userDisplay.textContent = "";
    if (userAvatar) userAvatar.textContent = "?";
    const filesList = document.getElementById("filesList");
    if (filesList) filesList.innerHTML = `<li class="files-empty"><div class="empty-icon">📂</div><div>Log in to view your files</div></li>`;
    showLoginScreen();
}

function authHeaders() {
    const token = getToken();
    return token ? { "Authorization": `Bearer ${token}` } : {};
}

async function restoreAuthSession() {
    const token = getToken();
    if (!token) {
        clearAuthState();
        showLoginScreen();
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/api/me`, { headers: { Authorization: `Bearer ${token}` } });
        if (!res.ok) {
            clearAuthState();
            showLoginScreen();
            return;
        }

        const data = await res.json().catch(() => ({}));
        if (!data || !data.email) {
            clearAuthState();
            showLoginScreen();
            return;
        }

        showLoggedIn(data.email);
    } catch (_) {
        clearAuthState();
        showLoginScreen();
    }
}

/* ---------- CRYPTO (AES-256-GCM, key from passphrase) ---------- */
const SALT_LEN = 16;
const IV_LEN = 12;
const PBKDF2_ITERATIONS = 100000;

/** Normalize key: remove invisible chars, extra whitespace. Fixes copy-paste issues. */
function normalizeKey(str) {
    if (typeof str !== "string") return "";
    return str
        .replace(/[\s\u00A0\u200B-\u200D\uFEFF]/g, "")  // spaces, nbsp, zero-width, BOM
        .trim();
}

async function deriveKey(passphrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptFile(plainBuffer) {
    const keyStr = normalizeKey(encryptionKey.value || "");
    if (!keyStr) throw new Error("Enter an encryption key");
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const key = await deriveKey(keyStr, salt);
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, tagLength: 128 },
        key,
        plainBuffer
    );
    const out = new Uint8Array(SALT_LEN + IV_LEN + ciphertext.byteLength);
    out.set(salt, 0);
    out.set(iv, SALT_LEN);
    out.set(new Uint8Array(ciphertext), SALT_LEN + IV_LEN);
    return out.buffer;
}

async function decryptFile(encryptedBuffer, passphrase) {
    if (!passphrase || !encryptedBuffer || encryptedBuffer.byteLength < SALT_LEN + IV_LEN) throw new Error("Invalid data or key");
    const arr = new Uint8Array(encryptedBuffer);
    const salt = arr.slice(0, SALT_LEN);
    const iv = arr.slice(SALT_LEN, SALT_LEN + IV_LEN);
    const ciphertext = arr.slice(SALT_LEN + IV_LEN);
    const key = await deriveKey(passphrase, salt);
    return crypto.subtle.decrypt(
        { name: "AES-GCM", iv, tagLength: 128 },
        key,
        ciphertext
    );
}

window.addEventListener("hashchange", checkShareUrlOnLoad);

/* ---------- FILE UPLOAD ---------- */
if (uploadArea) uploadArea.addEventListener("click", () => fileInput && fileInput.click());

if (fileInput) {
    fileInput.addEventListener("change", () => {
        const file = fileInput.files[0];
        if (!file) return;

        if (fileInfo) fileInfo.style.display = "flex";
        if (fileName) fileName.textContent = file.name;
        if (fileSize) fileSize.textContent = formatFileSize(file.size);
    });
}

if (removeFile) {
    removeFile.addEventListener("click", () => {
        if (fileInput) fileInput.value = "";
        if (fileInfo) fileInfo.style.display = "none";
    });
}

/* ---------- MY FILES (cloud) ---------- */
const filesList = document.getElementById("filesList");
const filesEmpty = document.getElementById("filesEmpty");
const refreshFilesBtn = document.getElementById("refreshFiles");

async function loadMyFiles() {
    try {
        const res = await fetch(`${API_BASE}/api/files`, { headers: authHeaders() });
        if (!res.ok) return;
        const files = await res.json();
        const countEl = document.getElementById("filesCount");
        if (countEl) countEl.textContent = files.length === 0 ? "0 files" : files.length === 1 ? "1 file" : files.length + " files";
        filesList.innerHTML = "";
        if (files.length === 0) {
            filesEmpty.style.display = "block";
        } else {
            filesEmpty.style.display = "none";
            files.forEach((f) => {
                const li = document.createElement("li");
                const sizeStr = formatFileSize(f.size);
                const isEnc = !!f.encrypted;
                const isExpired = !!(f.expiresAt && !isNaN(new Date(f.expiresAt).getTime()) && new Date(f.expiresAt).getTime() <= Date.now());
                const encTag = isEnc ? ' <span class="file-enc-tag">encrypted</span>' : '';
                const expTag = isExpired ? ' <span class="file-expired-tag">expired</span>' : '';
                const encId = escapeHtml(String(f.id));
                const encName = escapeHtml(String(f.originalName || 'file'));
                const expiryMeta = f.expiresAt ? ` · Expires: ${new Date(f.expiresAt).toLocaleString()}` : '';
                li.innerHTML = `
                    <div class="file-main">
                        <div class="file-name" title="${encName}">${encName}${encTag}${expTag}</div>
                        <div class="file-meta">${sizeStr} · Uploaded: ${new Date(f.uploadedAt).toLocaleDateString()}${expiryMeta}</div>
                    </div>
                    <div class="file-actions">
                        ${isEnc && !isExpired ? `<button type="button" class="btn btn-view-enc" data-id="${encId}" data-name="${encName}" title="View encrypted payload">View encrypted</button>` : ''}
                        ${!isExpired ? `<button type="button" class="btn btn-share" data-id="${encId}" data-name="${encName}" data-encrypted="${isEnc ? '1' : '0'}" title="Share zero-knowledge link">Share</button>` : ''}
                        <button type="button" class="btn ${isExpired ? 'btn-expired' : 'btn-download'}" data-id="${encId}" data-name="${encName}" data-encrypted="${isEnc ? '1' : '0'}" data-expired="${isExpired ? '1' : '0'}" ${isExpired ? 'disabled' : ''}>${isExpired ? 'Expired' : (isEnc ? 'Decrypt & open' : 'Download')}</button>
                        <button type="button" class="btn btn-delete" data-id="${encId}" data-encrypted="${isEnc ? '1' : '0'}">Delete</button>
                    </div>
                `;
                filesList.appendChild(li);
            });
            filesList.querySelectorAll(".btn-download").forEach((btn) => btn.addEventListener("click", () => downloadFile(btn.dataset.id, btn.dataset.name, btn.dataset.encrypted === '1')));
            filesList.querySelectorAll(".btn-view-enc").forEach((btn) => btn.addEventListener("click", () => viewEncryptedFile(btn.dataset.id, btn.dataset.name)));
            filesList.querySelectorAll(".btn-share").forEach((btn) => btn.addEventListener("click", () => showShareModal(btn.dataset.id, btn.dataset.name, btn.dataset.encrypted === '1')));
            filesList.querySelectorAll(".btn-delete").forEach((btn) => btn.addEventListener("click", () => deleteFile(btn.dataset.id, btn.dataset.encrypted === '1')));
        }
    } catch (err) {
        filesEmpty.innerHTML = '<div class="empty-icon">⚠️</div><p>Could not load files. Check your connection and try again.</p>';
        filesEmpty.style.display = "block";
        filesList.innerHTML = "";
    }
}

function escapeHtml(s) {
    const div = document.createElement("div");
    div.textContent = s;
    return div.innerHTML;
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1024 / 1024).toFixed(2) + " MB";
}

let _encPreviewFileId = null;
let _encPreviewFileName = null;

async function viewEncryptedFile(id, name) {
    try {
        const res = await fetch(`${API_BASE}/api/files/${encodeURIComponent(id)}`, { headers: authHeaders() });
        if (res.status === 410) {
            showStatus("This file has expired.");
            loadMyFiles();
            return;
        }
        if (!res.ok) throw new Error("Failed to load");
        const blob = await res.blob();
        const buf = await blob.arrayBuffer();
        const arr = new Uint8Array(buf);
        const hex = Array.from(arr.slice(0, 512)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        const preview = document.getElementById("encPreviewContent");
        const overlay = document.getElementById("encPreviewOverlay");
        if (!preview || !overlay) return;
        preview.textContent = hex + (arr.length > 512 ? '\n... (truncated)' : '');
        _encPreviewFileId = id;
        _encPreviewFileName = name;
        overlay.style.display = 'flex';
    } catch {
        showStatus("Failed to load encrypted file");
    }
}

const encPreviewOverlayEl = document.getElementById("encPreviewOverlay");
if (encPreviewOverlayEl) {
    encPreviewOverlayEl.addEventListener("click", (e) => {
        if (e.target.id === "encPreviewOverlay") encPreviewOverlayEl.style.display = "none";
    });
}
const encPreviewCloseEl = document.getElementById("encPreviewClose");
if (encPreviewCloseEl) {
    encPreviewCloseEl.addEventListener("click", () => {
        if (encPreviewOverlayEl) encPreviewOverlayEl.style.display = "none";
    });
}

let _sharedPayloadBuf = null;
let _sharedFilename = null;
let _sharedObjectUrl = null;

async function showShareModal(id, name, isEncrypted) {
    const baseUrl = window.location.origin + window.location.pathname;
    const shareUrl = `${baseUrl}#share=${encodeURIComponent(id)}`;

    const input = document.getElementById("shareUrlInput");
    const msg = document.getElementById("shareModalMsg");
    if (input) input.value = shareUrl;
    if (msg) msg.style.display = "none";
    const overlay = document.getElementById("shareModalOverlay");
    if (overlay) overlay.style.display = "flex";
    showStatus("Zero-Knowledge Share Link generated.");
}

const copyShareUrlBtnEl = document.getElementById("copyShareUrlBtn");
if (copyShareUrlBtnEl) {
    copyShareUrlBtnEl.addEventListener("click", async () => {
        const input = document.getElementById("shareUrlInput");
        if (!input || !input.value) return;
        try {
            await navigator.clipboard.writeText(input.value);
        } catch {
            input.select();
            document.execCommand("copy");
        }
        const msg = document.getElementById("shareModalMsg");
        if (msg) msg.style.display = "block";
    });
}

const shareModalCancelEl = document.getElementById("shareModalCancel");
if (shareModalCancelEl) {
    shareModalCancelEl.addEventListener("click", () => {
        const overlay = document.getElementById("shareModalOverlay");
        if (overlay) overlay.style.display = "none";
    });
}

const shareModalOverlayEl = document.getElementById("shareModalOverlay");
if (shareModalOverlayEl) {
    shareModalOverlayEl.addEventListener("click", (e) => {
        if (e.target.id === "shareModalOverlay") shareModalOverlayEl.style.display = "none";
    });
}

function closeShareView() {
    const overlay = document.getElementById("sharedFileOverlay");
    if (overlay) overlay.style.display = "none";

    if (_sharedObjectUrl) {
        URL.revokeObjectURL(_sharedObjectUrl);
        _sharedObjectUrl = null;
    }
    _sharedPayloadBuf = null;
    _sharedFilename = null;

    const keyInput = document.getElementById("sharedKeyInput");
    const keyErr = document.getElementById("sharedKeyError");
    if (keyInput) keyInput.value = "";
    if (keyErr) keyErr.textContent = "";

    if (window.location.hash) {
        history.replaceState(null, "", window.location.pathname);
    }

    const token = getToken();
    if (token) {
        if (loginOverlay) loginOverlay.style.display = "none";
        loadMyFiles();
    } else {
        setToken(null);
        if (loginOverlay) loginOverlay.style.display = "flex";
    }
}

const sharedFileCloseEl = document.getElementById("sharedFileClose");
if (sharedFileCloseEl) {
    sharedFileCloseEl.addEventListener("click", closeShareView);
}

const sharedFileOverlayEl = document.getElementById("sharedFileOverlay");
if (sharedFileOverlayEl) {
    sharedFileOverlayEl.addEventListener("click", (e) => {
        if (e.target.id === "sharedFileOverlay") closeShareView();
    });
}

const sharedKeyToggleEl = document.getElementById("sharedKeyToggle");
if (sharedKeyToggleEl) {
    sharedKeyToggleEl.addEventListener("click", () => {
        const input = document.getElementById("sharedKeyInput");
        if (input) {
            input.type = input.type === "password" ? "text" : "password";
        }
    });
}

const sharedKeyDecryptBtnEl = document.getElementById("sharedKeyDecryptBtn");
if (sharedKeyDecryptBtnEl) {
    sharedKeyDecryptBtnEl.addEventListener("click", async () => {
        const keyInput = document.getElementById("sharedKeyInput");
        const keyErr = document.getElementById("sharedKeyError");
        if (keyErr) keyErr.textContent = "";
        const keyStr = normalizeKey(keyInput ? keyInput.value || "" : "");

        if (!keyStr) {
            if (keyErr) keyErr.textContent = "Please enter the decryption key.";
            return;
        }
        if (!_sharedPayloadBuf) {
            if (keyErr) keyErr.textContent = "Shared payload not available. Please reopen share link.";
            return;
        }

        showStatus("Decrypting shared file client-side...");
        try {
            const decryptedBuf = await decryptFile(_sharedPayloadBuf, keyStr);
            const filename = _sharedFilename || "shared_file";
            const ext = (filename.split(".").pop() || "").toLowerCase();
            const mimeByExt = {
                jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", gif: "image/gif",
                webp: "image/webp", bmp: "image/bmp", svg: "image/svg+xml", ico: "image/x-icon",
                pdf: "application/pdf", webm: "video/webm", mp4: "video/mp4", ogg: "video/ogg",
                mp3: "audio/mpeg", wav: "audio/wav", txt: "text/plain", html: "text/html",
                htm: "text/html", json: "application/json", xml: "application/xml"
            };
            const mimeType = mimeByExt[ext] || "application/octet-stream";
            const dataBlob = new Blob([decryptedBuf], { type: mimeType });

            if (_sharedObjectUrl) URL.revokeObjectURL(_sharedObjectUrl);
            _sharedObjectUrl = URL.createObjectURL(dataBlob);

            const titleEl = document.querySelector("#sharedFileOverlay h3");
            const hintEl = document.querySelector("#sharedFileOverlay .modal-hint");
            const nameEl = document.getElementById("sharedFileName");
            const sizeEl = document.getElementById("sharedFileSize");
            const iconEl = document.getElementById("sharedFileIcon");
            const downloadBtn = document.getElementById("sharedFileDownloadBtn");
            const previewArea = document.getElementById("sharedFilePreviewArea");
            const imgPreview = document.getElementById("sharedImagePreview");
            const keySection = document.getElementById("sharedKeySection");

            if (titleEl) titleEl.textContent = "🎁 Shared File Decrypted";
            if (hintEl) hintEl.textContent = "Decrypted client-side with your key. File preview ready.";
            if (nameEl) nameEl.textContent = filename;
            if (sizeEl) sizeEl.textContent = formatFileSize(decryptedBuf.byteLength);

            const isImage = ["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp"].includes(ext);
            if (isImage && previewArea && imgPreview) {
                imgPreview.src = _sharedObjectUrl;
                previewArea.style.display = "block";
                if (iconEl) iconEl.textContent = "🖼️";
            } else {
                if (previewArea) previewArea.style.display = "none";
                if (iconEl) iconEl.textContent = "📄";
            }

            if (keySection) keySection.style.display = "none";
            if (downloadBtn) {
                downloadBtn.href = _sharedObjectUrl;
                downloadBtn.download = filename;
                downloadBtn.style.display = "inline-flex";
            }

            showStatus("File decrypted successfully.");

        } catch (err) {
            console.error("[ShareLink] Decryption failed:", err);
            if (keyErr) keyErr.textContent = "Invalid Decryption Key";
            showStatus("Invalid Decryption Key.");
        }
    });
}

async function checkShareUrlOnLoad() {
    console.log("[ShareLink] Checking URL hash on page load:", window.location.hash);
    const hash = String(window.location.hash || "");
    if (!hash || !hash.includes("share=")) return;

    if (loginOverlay) loginOverlay.style.display = "none";

    const params = new URLSearchParams(hash.replace(/^#/, ""));
    const shareId = params.get("share");
    console.log("[ShareLink] Extracted shareId:", shareId);
    if (!shareId) {
        showStatus("Invalid Share Link.");
        renderInvalidShareUI("⚠️ Invalid Share Link", "The share link fragment is missing a valid file ID.", "❌");
        return;
    }

    showStatus("Shared file link detected. Fetching payload from server...");
    try {
        const res = await fetch(`${API_BASE}/api/files/${encodeURIComponent(shareId)}?isShareDownload=true`);
        console.log("[ShareLink] API fetch HTTP status:", res.status);

        if (res.status === 410) {
            showStatus("This shared file link has expired.");
            renderInvalidShareUI("⌛ Expired Share Link", "This shared file link has expired and is no longer accessible.", "⌛");
            return;
        }
        if (!res.ok) {
            showStatus("Invalid Share Link.");
            renderInvalidShareUI("⚠️ Invalid Share Link", "Unable to locate shared file. The link may be invalid or removed.", "❌");
            return;
        }

        let filename = "shared_file";
        const cd = res.headers.get("content-disposition");
        if (cd && cd.includes("filename=")) {
            const match = cd.match(/filename="?([^";]+)"?/);
            if (match && match[1]) filename = match[1];
        }
        if (filename === "shared_file" && shareId.includes("-")) {
            filename = shareId.substring(shareId.indexOf("-") + 1);
        }

        const blob = await res.blob();
        _sharedPayloadBuf = await blob.arrayBuffer();
        _sharedFilename = filename;

        const titleEl = document.querySelector("#sharedFileOverlay h3");
        const hintEl = document.querySelector("#sharedFileOverlay .modal-hint");
        const nameEl = document.getElementById("sharedFileName");
        const sizeEl = document.getElementById("sharedFileSize");
        const iconEl = document.getElementById("sharedFileIcon");
        const downloadBtn = document.getElementById("sharedFileDownloadBtn");
        const previewArea = document.getElementById("sharedFilePreviewArea");
        const keySection = document.getElementById("sharedKeySection");
        const keyInput = document.getElementById("sharedKeyInput");
        const keyErr = document.getElementById("sharedKeyError");
        const overlayEl = document.getElementById("sharedFileOverlay");

        if (titleEl) titleEl.textContent = "🔒 Shared Encrypted File";
        if (hintEl) hintEl.textContent = "Enter the decryption key provided by the sender to unlock this file.";
        if (nameEl) nameEl.textContent = filename;
        if (sizeEl) sizeEl.textContent = formatFileSize(blob.size);
        if (iconEl) iconEl.textContent = "🔒";
        if (keySection) keySection.style.display = "block";
        if (keyInput) keyInput.value = "";
        if (keyErr) keyErr.textContent = "";
        if (previewArea) previewArea.style.display = "none";
        if (downloadBtn) downloadBtn.style.display = "none";

        if (overlayEl) overlayEl.style.display = "flex";
        if (keyInput) keyInput.focus();

    } catch (err) {
        console.error("[ShareLink] Error processing share link:", err);
        showStatus("Invalid Share Link.");
        renderInvalidShareUI("⚠️ Invalid Share Link", "Unable to fetch shared file payload. Check network connection.", "❌");
    }
}

function renderInvalidShareUI(title, hint, icon = "⚠️") {
    const titleEl = document.querySelector("#sharedFileOverlay h3");
    const hintEl = document.querySelector("#sharedFileOverlay .modal-hint");
    const nameEl = document.getElementById("sharedFileName");
    const sizeEl = document.getElementById("sharedFileSize");
    const downloadBtn = document.getElementById("sharedFileDownloadBtn");
    const previewArea = document.getElementById("sharedFilePreviewArea");
    const iconEl = document.getElementById("sharedFileIcon");
    const keySection = document.getElementById("sharedKeySection");
    const overlayEl = document.getElementById("sharedFileOverlay");

    if (titleEl) titleEl.textContent = title;
    if (hintEl) hintEl.textContent = hint;
    if (nameEl) nameEl.textContent = "Access Blocked";
    if (sizeEl) sizeEl.textContent = "";
    if (iconEl) iconEl.textContent = icon;
    if (keySection) keySection.style.display = "none";
    if (previewArea) previewArea.style.display = "none";
    if (downloadBtn) downloadBtn.style.display = "none";
    if (overlayEl) overlayEl.style.display = "flex";
}

/* Decrypt modal — shown when user clicks Decrypt & Download on encrypted file */
let _decryptFileId = null;
let _decryptFileName = null;

function showDecryptModal(id, name) {
    _decryptFileId = id;
    _decryptFileName = name;
    document.getElementById("decryptKeyInput").value = "";
    document.getElementById("decryptModalError").textContent = "";
    document.getElementById("decryptModalOverlay").style.display = "flex";
    document.getElementById("decryptKeyInput").focus();
}

function hideDecryptModal() {
    document.getElementById("decryptModalOverlay").style.display = "none";
    _decryptFileId = null;
    _decryptFileName = null;
}

const decryptModalOverlayEl = document.getElementById("decryptModalOverlay");
if (decryptModalOverlayEl) {
    decryptModalOverlayEl.addEventListener("click", (e) => {
        if (e.target.id === "decryptModalOverlay") hideDecryptModal();
    });
}
const decryptModalCancelEl = document.getElementById("decryptModalCancel");
if (decryptModalCancelEl) {
    decryptModalCancelEl.addEventListener("click", hideDecryptModal);
}
const decryptKeyToggleEl = document.getElementById("decryptKeyToggle");
if (decryptKeyToggleEl) {
    decryptKeyToggleEl.addEventListener("click", () => {
        const input = document.getElementById("decryptKeyInput");
        const btn = document.getElementById("decryptKeyToggle");
        if (input && btn) {
            if (input.type === "password") {
                input.type = "text";
                btn.textContent = "🙈";
                btn.title = "Click to hide key";
            } else {
                input.type = "password";
                btn.textContent = "👁";
                btn.title = "Click to show key";
            }
        }
    });
}
const decryptModalConfirmEl = document.getElementById("decryptModalConfirm");
if (decryptModalConfirmEl) {
    decryptModalConfirmEl.addEventListener("click", async () => {
        const keyInput = document.getElementById("decryptKeyInput");
        const keyStr = normalizeKey(keyInput.value || "");
        const errEl = document.getElementById("decryptModalError");
        const openAfter = document.getElementById("openAfterDownload");
        const confirmBtn = document.getElementById("decryptModalConfirm");
        if (!keyStr) {
            errEl.textContent = "Please paste your decryption key first.";
            return;
        }
        if (!_decryptFileId || !_decryptFileName) return;
        errEl.textContent = "";
        confirmBtn.disabled = true;
        confirmBtn.textContent = "Decrypting…";
        try {
            const res = await fetch(`${API_BASE}/api/files/${encodeURIComponent(_decryptFileId)}`, { headers: authHeaders() });
            if (res.status === 410) {
                errEl.textContent = "This file has expired.";
                showStatus("This file has expired.");
                loadMyFiles();
                return;
            }
            if (!res.ok) throw new Error("Download failed");
            const blob = await res.blob();
            const buf = await blob.arrayBuffer();
            const decrypted = await decryptFile(buf, keyStr);
            const name = _decryptFileName || "download";
            const ext = (name.split(".").pop() || "").toLowerCase();
            const mimeByExt = {
                jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", gif: "image/gif",
                webp: "image/webp", bmp: "image/bmp", svg: "image/svg+xml", ico: "image/x-icon",
                pdf: "application/pdf", webm: "video/webm", mp4: "video/mp4", ogg: "video/ogg",
                mp3: "audio/mpeg", wav: "audio/wav", txt: "text/plain", html: "text/html",
                htm: "text/html", json: "application/json", xml: "application/xml"
            };
            const mimeType = mimeByExt[ext] || "application/octet-stream";
            const data = new Blob([decrypted], { type: mimeType });
            const url = URL.createObjectURL(data);
            const viewableTypes = ["pdf", "jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "webm", "mp4", "ogg", "mp3", "wav", "txt", "html", "htm", "json", "xml"];
            const shouldOpen = openAfter && openAfter.checked && viewableTypes.includes(ext);
            if (shouldOpen) {
                window.open(url, "_blank", "noopener");
                setTimeout(() => URL.revokeObjectURL(url), 30000);
            } else {
                const a = document.createElement("a");
                a.href = url;
                a.download = name;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(() => URL.revokeObjectURL(url), 1000);
            }

            try {
                await fetch(`${API_BASE}/api/files/${encodeURIComponent(_decryptFileId)}`, { method: "DELETE", headers: authHeaders() });
            } catch (e) { }

            hideDecryptModal();
            showStatus(shouldOpen ? "File decrypted and opened. Removed from cloud." : "File decrypted and downloaded. Removed from cloud.");
            loadMyFiles();
        } catch (e) {
            if (e.message && (e.message.includes("key") || e.message.includes("decrypt") || e.message.includes("Invalid"))) {
                errEl.textContent = "Invalid key. Use the key you received when you protected this file.";
            } else {
                errEl.textContent = "Decryption failed.";
            }
        } finally {
            confirmBtn.disabled = false;
            confirmBtn.textContent = "Decrypt & open";
        }
    });
}

async function downloadFile(id, name, isEncrypted) {
    if (isEncrypted) {
        showDecryptModal(id, name);
        return;
    }
    try {
        const res = await fetch(`${API_BASE}/api/files/${encodeURIComponent(id)}`, { headers: authHeaders() });
        if (res.status === 410) {
            showStatus("This file has expired.");
            loadMyFiles();
            return;
        }
        if (!res.ok) throw new Error("Download failed");
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = name || "download";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 1000);

        try {
            await fetch(`${API_BASE}/api/files/${encodeURIComponent(id)}`, { method: "DELETE", headers: authHeaders() });
        } catch (e) { }

        showStatus("File downloaded and removed from cloud.");
        loadMyFiles();
    } catch {
        showStatus("Download failed");
    }
}

/* ---------- Delete file (with special key for encrypted) ---------- */
let _deleteFileId = null;

function showDeleteModal(id, isEncrypted) {
    _deleteFileId = { id, isEncrypted };
    document.getElementById("deleteKeyInput").value = "";
    document.getElementById("deleteModalError").textContent = "";
    document.getElementById("deleteConfirmOverlay").style.display = "flex";
    document.getElementById("deleteKeyInput").focus();
}

function hideDeleteModal() {
    document.getElementById("deleteConfirmOverlay").style.display = "none";
    _deleteFileId = null;
}

const deleteConfirmOverlayEl = document.getElementById("deleteConfirmOverlay");
if (deleteConfirmOverlayEl) {
    deleteConfirmOverlayEl.addEventListener("click", (e) => {
        if (e.target.id === "deleteConfirmOverlay") hideDeleteModal();
    });
}
const deleteModalCancelEl = document.getElementById("deleteModalCancel");
if (deleteModalCancelEl) {
    deleteModalCancelEl.addEventListener("click", hideDeleteModal);
}
const deleteKeyToggleEl = document.getElementById("deleteKeyToggle");
if (deleteKeyToggleEl) {
    deleteKeyToggleEl.addEventListener("click", () => {
        const input = document.getElementById("deleteKeyInput");
        const btn = document.getElementById("deleteKeyToggle");
        if (input && btn) {
            if (input.type === "password") {
                input.type = "text";
                btn.textContent = "🙈";
                btn.title = "Click to hide key";
            } else {
                input.type = "password";
                btn.textContent = "👁";
                btn.title = "Click to show key";
            }
        }
    });
}
const deleteModalConfirmEl = document.getElementById("deleteModalConfirm");
if (deleteModalConfirmEl) {
    deleteModalConfirmEl.addEventListener("click", async () => {
        const keyInput = document.getElementById("deleteKeyInput");
        const keyStr = normalizeKey(keyInput.value || "");
        const errEl = document.getElementById("deleteModalError");
        if (!_deleteFileId) return;
        const { id, isEncrypted } = _deleteFileId;
        if (isEncrypted) {
            if (!keyStr) {
                errEl.textContent = "Please enter the file's decryption key (special key) to confirm deletion.";
                return;
            }
            errEl.textContent = "";
            try {
                const res = await fetch(`${API_BASE}/api/files/${encodeURIComponent(id)}`, { headers: authHeaders() });
                if (!res.ok) throw new Error("Could not load file");
                const blob = await res.blob();
                const buf = await blob.arrayBuffer();
                await decryptFile(buf, keyStr);
            } catch (e) {
                if (e.message && (e.message.includes("key") || e.message.includes("decrypt") || e.message.includes("Invalid"))) {
                    errEl.textContent = "Invalid key. Enter the correct decryption key for this file.";
                } else {
                    errEl.textContent = "Invalid key. Cannot delete without the correct special key.";
                }
                return;
            }
        }
        try {
            const res = await fetch(`${API_BASE}/api/files/${encodeURIComponent(id)}`, { method: "DELETE", headers: authHeaders() });
            if (!res.ok) throw new Error("Delete failed");
            hideDeleteModal();
            loadMyFiles();
            showStatus("File deleted");
        } catch {
            errEl.textContent = errEl.textContent || "Delete failed.";
        }
    });
}

async function deleteFile(id, isEncrypted) {
    if (isEncrypted) {
        showDeleteModal(id, true);
        return;
    }
    if (!confirm("Delete this file?")) return;
    try {
        const res = await fetch(`${API_BASE}/api/files/${encodeURIComponent(id)}`, { method: "DELETE", headers: authHeaders() });
        if (!res.ok) throw new Error("Delete failed");
        loadMyFiles();
        showStatus("File deleted");
    } catch {
        showStatus("Delete failed");
    }
}

if (refreshFilesBtn) refreshFilesBtn.addEventListener("click", () => loadMyFiles());

/* ---------- Tabs (Protect / Access) ---------- */
document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
        const target = tab.dataset.tab;
        document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
        document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
        tab.classList.add("active");
        const panel = document.getElementById("panel-" + target);
        if (panel) panel.classList.add("active");
        if (target === "access") loadMyFiles();
    });
});

/* ---------- KEY ---------- */
if (generateKey) {
    generateKey.addEventListener("click", () => {
        if (!fileInput || !fileInput.files[0]) {
            showStatus("Select a file first, then generate the key.");
            return;
        }
        if (encryptionKey) encryptionKey.value = crypto.randomUUID().replace(/-/g, "");
        showStatus("Key generated. Copy and store it securely — required to decrypt this file.");
    });
}

const copyKeyBtnEl = document.getElementById("copyKeyBtn");
if (copyKeyBtnEl) {
    copyKeyBtnEl.addEventListener("click", async () => {
        const key = normalizeKey(encryptionKey ? encryptionKey.value || "" : "");
        if (!key) {
            showStatus("Generate or paste a key first.");
            return;
        }
        try {
            await navigator.clipboard.writeText(key);
            showStatus("Key copied to clipboard.");
        } catch {
            if (encryptionKey) {
                encryptionKey.select();
                document.execCommand("copy");
            }
            showStatus("Key selected — press Ctrl+C to copy.");
        }
    });
}

if (keyToggle) {
    keyToggle.addEventListener("click", () => {
        if (encryptionKey) {
            encryptionKey.type = encryptionKey.type === "password" ? "text" : "password";
        }
    });
}

/* ---------- ACTION BUTTONS ---------- */
const encryptBtnEl = document.getElementById("encryptBtn");
if (encryptBtnEl) {
    encryptBtnEl.onclick = async () => {
        const file = fileInput.files[0];
        if (!file) {
            showStatus("Select a file first.");
            return;
        }
        const keyStr = normalizeKey(encryptionKey.value || "");
        if (!keyStr) {
            showStatus("Generate an encryption key, then try again.");
            return;
        }
        const btn = document.getElementById("encryptBtn");
        const origText = btn.textContent;
        btn.disabled = true;
        btn.textContent = "Encrypting…";
        showStatus("Encrypting in browser…");
        try {
            const expiryEl = document.getElementById("fileExpiry");
            const expiryVal = expiryEl ? expiryEl.value : "never";
            const buf = await file.arrayBuffer();
            const encryptedBuf = await encryptFile(buf);
            const blob = new Blob([encryptedBuf]);
            const form = new FormData();
            form.append("file", blob, file.name);
            form.append("originalName", file.name);
            form.append("encrypted", "true");
            form.append("expiry", expiryVal);
            showStatus("Uploading…");
            const res = await fetch(`${API_BASE || ""}/api/files`, {
                method: "POST",
                headers: authHeaders(),
                body: form,
            });
            const data = await res.json().catch(async () => {
                const text = await res.text().catch(() => "");
                return { error: text || `Upload failed (${res.status})` };
            });
            if (!res.ok) {
                showStatus(data.error || `Upload failed (${res.status})`);
                btn.disabled = false;
                btn.textContent = origText;
                return;
            }
            showStatus("File protected. Stored encrypted in cloud — only your key can decrypt it.");
            fileInput.value = "";
            fileInfo.style.display = "none";
            encryptionKey.value = "";
            if (expiryEl) expiryEl.value = "never";
            await loadMyFiles();
        } catch (e) {
            showStatus("Upload failed: " + (e.message || "Check your connection. On mobile, use the tunnel URL."));
        }
        btn.disabled = false;
        btn.textContent = origText;
    };
}

function showStatus(msg) {
    if (statusArea) statusArea.style.display = "flex";
    if (statusMessage) statusMessage.textContent = msg;
}

/* ---------- AUTH UI LISTENERS & SESSION PERSISTENCE ---------- */

const loginFormEl = document.getElementById("loginForm");
if (loginFormEl) {
    loginFormEl.addEventListener("submit", async (e) => {
        e.preventDefault();
        const email = (document.getElementById("loginEmail").value || "").trim();
        const password = document.getElementById("loginPassword").value || "";
        const errorEl = document.getElementById("loginError");
        if (errorEl) errorEl.textContent = "";

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            if (errorEl) errorEl.textContent = "Please enter a valid email address.";
            return;
        }

        try {
            const res = await fetch(`${API_BASE}/api/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                if (errorEl) errorEl.textContent = data.error || "Invalid email or password";
                return;
            }
            setToken(data.token);
            showLoggedIn(data.email);
        } catch (err) {
            if (errorEl) errorEl.textContent = "Login failed. Please check network connection.";
        }
    });
}

const registerFormEl = document.getElementById("registerForm");
if (registerFormEl) {
    registerFormEl.addEventListener("submit", async (e) => {
        e.preventDefault();
        const email = (document.getElementById("regEmail").value || "").trim();
        const password = document.getElementById("regPassword").value || "";
        const confirmPassword = document.getElementById("regConfirmPassword").value || "";
        const errorEl = document.getElementById("regError");
        const successEl = document.getElementById("regSuccess");

        if (errorEl) errorEl.textContent = "";
        if (successEl) { successEl.textContent = ""; successEl.style.display = "none"; }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            if (errorEl) errorEl.textContent = "Please enter a valid email address.";
            return;
        }
        if (password.length < 6) {
            if (errorEl) errorEl.textContent = "Password must be at least 6 characters long.";
            return;
        }
        if (password !== confirmPassword) {
            if (errorEl) errorEl.textContent = "Confirm Password does not match Password.";
            return;
        }

        try {
            const res = await fetch(`${API_BASE}/api/register`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                if (errorEl) errorEl.textContent = data.error || "Registration failed";
                return;
            }
            if (successEl) {
                successEl.textContent = "Account created successfully! Switching to login...";
                successEl.style.display = "block";
            }
            setTimeout(() => {
                if (registerFormEl) registerFormEl.style.display = "none";
                if (loginFormEl) loginFormEl.style.display = "block";
                document.getElementById("loginEmail").value = email;
                document.getElementById("loginPassword").focus();
            }, 1200);
        } catch (err) {
            if (errorEl) errorEl.textContent = "Registration failed. Please check network connection.";
        }
    });
}

const showRegisterBtn = document.getElementById("showRegisterBtn");
if (showRegisterBtn) {
    showRegisterBtn.addEventListener("click", () => {
        if (loginFormEl) loginFormEl.style.display = "none";
        if (registerFormEl) registerFormEl.style.display = "block";
        const regErr = document.getElementById("regError");
        if (regErr) regErr.textContent = "";
    });
}

const showLoginBtn = document.getElementById("showLoginBtn");
if (showLoginBtn) {
    showLoginBtn.addEventListener("click", () => {
        if (registerFormEl) registerFormEl.style.display = "none";
        if (loginFormEl) loginFormEl.style.display = "block";
        const loginErr = document.getElementById("loginError");
        if (loginErr) loginErr.textContent = "";
    });
}

/* ---------- LOGOUT CONFIRMATION MODAL (UI/UX ONLY) ---------- */
const logoutModalOverlayEl = document.getElementById("logoutModalOverlay");
const logoutModalCancelEl = document.getElementById("logoutModalCancel");
const logoutModalConfirmEl = document.getElementById("logoutModalConfirm");

if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
        if (logoutModalOverlayEl) logoutModalOverlayEl.style.display = "flex";
    });
}

if (logoutModalCancelEl) {
    logoutModalCancelEl.addEventListener("click", () => {
        if (logoutModalOverlayEl) logoutModalOverlayEl.style.display = "none";
    });
}

if (logoutModalConfirmEl) {
    logoutModalConfirmEl.addEventListener("click", () => {
        if (logoutModalOverlayEl) logoutModalOverlayEl.style.display = "none";
        logout();
    });
}

if (logoutModalOverlayEl) {
    logoutModalOverlayEl.addEventListener("click", (e) => {
        if (e.target.id === "logoutModalOverlay") {
            logoutModalOverlayEl.style.display = "none";
        }
    });
}

window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        if (logoutModalOverlayEl && logoutModalOverlayEl.style.display === "flex") {
            logoutModalOverlayEl.style.display = "none";
        }
    }
});

/* ---------- PASSWORD SHOW/HIDE TOGGLE (UI ONLY) ---------- */
function setupPasswordToggle(inputId, toggleBtnId) {
    const input = document.getElementById(inputId);
    const btn = document.getElementById(toggleBtnId);
    if (input && btn) {
        btn.addEventListener("click", (e) => {
            e.preventDefault();
            const isPassword = input.type === "password";
            input.type = isPassword ? "text" : "password";
            btn.textContent = isPassword ? "🙈" : "👁️";
            btn.setAttribute("title", isPassword ? "Hide password" : "Show password");
        });
    }
}

setupPasswordToggle("loginPassword", "loginPasswordToggle");
setupPasswordToggle("regPassword", "regPasswordToggle");
setupPasswordToggle("regConfirmPassword", "regConfirmPasswordToggle");

/* ---------- STARTUP SESSION PERSISTENCE ---------- */
(async () => {
    // Check for Share Link hash fragment first
    if (window.location.hash && window.location.hash.includes("share=")) {
        await checkShareUrlOnLoad();
        return;
    }

    await restoreAuthSession();
})();
// Keep the background fixed while any overlay is active.
function updateBodyScrollLock() {
    const overlays = document.querySelectorAll(".login-overlay, .modal-overlay");
    const hasVisibleOverlay = Array.from(overlays).some((overlay) => {
        if (!overlay || !overlay.isConnected) return false;
        const style = window.getComputedStyle(overlay);
        return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
    });

    document.body.classList.toggle("modal-open", hasVisibleOverlay);
    document.documentElement.classList.toggle("modal-open", hasVisibleOverlay);
}

const scrollLockObserver = new MutationObserver(updateBodyScrollLock);

if (loginOverlay) {
    scrollLockObserver.observe(loginOverlay, {
        attributes: true,
        attributeFilter: ["class", "style"]
    });
}

document.querySelectorAll(".modal-overlay").forEach((overlay) => {
    scrollLockObserver.observe(overlay, {
        attributes: true,
        attributeFilter: ["class", "style"]
    });
});

updateBodyScrollLock();