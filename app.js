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

function getToken() {
    return localStorage.getItem("securecloud_token");
}

function setToken(token) {
    if (token) localStorage.setItem("securecloud_token", token);
    else localStorage.removeItem("securecloud_token");
}

function showLoggedIn(email) {
    loginOverlay.style.display = "none";
    userDisplay.textContent = email;
    userAvatar.textContent = (email[0] || "?").toUpperCase();
    loadMyFiles();
}

function authHeaders() {
    return {};
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

/* Splash screen / Share URL detector on load */
(async () => {
    const hasShareHash = String(window.location.hash || "").includes("share=");
    if (hasShareHash) {
        loginOverlay.style.display = "none";
        loadMyFiles();
        checkShareUrlOnLoad();
    } else {
        setTimeout(() => {
            loginOverlay.style.display = "none";
            loadMyFiles();
        }, 2000);
    }
})();

window.addEventListener("hashchange", checkShareUrlOnLoad);

/* ---------- FILE UPLOAD ---------- */
uploadArea.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (!file) return;

    fileInfo.style.display = "flex";
    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
});

removeFile.addEventListener("click", () => {
    fileInput.value = "";
    fileInfo.style.display = "none";
});

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

document.getElementById("encPreviewOverlay").addEventListener("click", (e) => {
    if (e.target.id === "encPreviewOverlay") document.getElementById("encPreviewOverlay").style.display = "none";
});
document.getElementById("encPreviewClose").addEventListener("click", () => {
    document.getElementById("encPreviewOverlay").style.display = "none";
});

/* ---------- SECURE FILE SHARING (Zero-Knowledge) ---------- */
function showShareModal(id, name, isEncrypted) {
    let keyStr = "";
    if (isEncrypted) {
        const inputKey = prompt("Enter the encryption key for '" + name + "' to generate zero-knowledge share link:");
        if (inputKey === null) return;
        keyStr = normalizeKey(inputKey || "");
        if (!keyStr) {
            showStatus("Key required to generate share link.");
            return;
        }
    }
    const baseUrl = window.location.origin + window.location.pathname;
    const shareUrl = isEncrypted 
        ? `${baseUrl}#share=${encodeURIComponent(id)}&key=${encodeURIComponent(keyStr)}`
        : `${baseUrl}#share=${encodeURIComponent(id)}`;
    
    const input = document.getElementById("shareUrlInput");
    const msg = document.getElementById("shareModalMsg");
    if (input) input.value = shareUrl;
    if (msg) msg.style.display = "none";
    const overlay = document.getElementById("shareModalOverlay");
    if (overlay) overlay.style.display = "flex";
}

document.getElementById("copyShareUrlBtn").addEventListener("click", async () => {
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

document.getElementById("shareModalCancel").addEventListener("click", () => {
    document.getElementById("shareModalOverlay").style.display = "none";
});

document.getElementById("shareModalOverlay").addEventListener("click", (e) => {
    if (e.target.id === "shareModalOverlay") document.getElementById("shareModalOverlay").style.display = "none";
});

document.getElementById("sharedFileClose").addEventListener("click", () => {
    document.getElementById("sharedFileOverlay").style.display = "none";
});

document.getElementById("sharedFileOverlay").addEventListener("click", (e) => {
    if (e.target.id === "sharedFileOverlay") document.getElementById("sharedFileOverlay").style.display = "none";
});

async function checkShareUrlOnLoad() {
    console.log("[ShareLink] Checking URL hash on page load:", window.location.hash);
    const hash = String(window.location.hash || "");
    if (!hash || !hash.includes("share=")) return;
    
    // Hide login overlay immediately when a share hash is detected
    if (loginOverlay) loginOverlay.style.display = "none";

    const params = new URLSearchParams(hash.replace(/^#/, ""));
    const shareId = params.get("share");
    const shareKey = normalizeKey(params.get("key") || "");
    console.log("[ShareLink] Extracted shareId:", shareId, "| shareKey present:", !!shareKey);
    if (!shareId) return;

    showStatus("Shared file link detected. Fetching payload from server...");
    try {
        const res = await fetch(`${API_BASE}/api/files/${encodeURIComponent(shareId)}?isShareDownload=true`, { headers: authHeaders() });
        console.log("[ShareLink] API fetch HTTP status:", res.status);
        if (res.status === 410) {
            showStatus("This shared file link has expired.");
            alert("This shared file link has expired.");
            return;
        }
        if (!res.ok) {
            if (res.status === 404) throw new Error("Shared file not found or removed.");
            throw new Error(`Download failed (${res.status})`);
        }

        // Determine original filename from response header or file ID
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
        const buf = await blob.arrayBuffer();
        console.log("[ShareLink] Payload downloaded. Size:", blob.size, "bytes");

        let dataBlob;
        if (shareKey) {
            showStatus("Decrypting shared file client-side using URL key...");
            console.log("[ShareLink] Decrypting ciphertext with AES-256-GCM + PBKDF2...");
            const decrypted = await decryptFile(buf, shareKey);
            console.log("[ShareLink] Decryption SUCCESS! Decrypted byte length:", decrypted.byteLength);
            
            const ext = (filename.split(".").pop() || "").toLowerCase();
            const mimeByExt = {
                jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", gif: "image/gif",
                webp: "image/webp", bmp: "image/bmp", svg: "image/svg+xml", ico: "image/x-icon",
                pdf: "application/pdf", webm: "video/webm", mp4: "video/mp4", ogg: "video/ogg",
                mp3: "audio/mpeg", wav: "audio/wav", txt: "text/plain", html: "text/html",
                htm: "text/html", json: "application/json", xml: "application/xml"
            };
            const mimeType = mimeByExt[ext] || "application/octet-stream";
            dataBlob = new Blob([decrypted], { type: mimeType });
        } else {
            dataBlob = blob;
        }

        const objectUrl = URL.createObjectURL(dataBlob);
        const ext = (filename.split(".").pop() || "").toLowerCase();
        
        // Populate Shared File Modal
        const nameEl = document.getElementById("sharedFileName");
        const sizeEl = document.getElementById("sharedFileSize");
        const downloadBtn = document.getElementById("sharedFileDownloadBtn");
        const overlayEl = document.getElementById("sharedFileOverlay");
        const previewArea = document.getElementById("sharedFilePreviewArea");
        const imgPreview = document.getElementById("sharedImagePreview");
        const iconEl = document.getElementById("sharedFileIcon");

        if (nameEl) nameEl.textContent = filename;
        if (sizeEl) sizeEl.textContent = formatFileSize(dataBlob.size);
        if (downloadBtn) {
            downloadBtn.href = objectUrl;
            downloadBtn.download = filename;
        }

        const isImage = ["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp"].includes(ext);
        if (isImage && previewArea && imgPreview) {
            imgPreview.src = objectUrl;
            previewArea.style.display = "block";
            if (iconEl) iconEl.textContent = "🖼️";
        } else {
            if (previewArea) previewArea.style.display = "none";
            if (iconEl) iconEl.textContent = "📄";
        }

        if (overlayEl) overlayEl.style.display = "flex";
        showStatus(`Shared file '${filename}' decrypted and ready!`);

    } catch (err) {
        console.error("[ShareLink] Error processing share link:", err);
        showStatus("Failed to process share link: " + (err.message || "Invalid key or payload."));
        alert("Share Link Error: " + (err.message || "Invalid key or file data."));
    }
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

document.getElementById("decryptModalOverlay").addEventListener("click", (e) => {
    if (e.target.id === "decryptModalOverlay") hideDecryptModal();
});
document.getElementById("decryptModalCancel").addEventListener("click", hideDecryptModal);
document.getElementById("decryptKeyToggle").addEventListener("click", () => {
    const input = document.getElementById("decryptKeyInput");
    const btn = document.getElementById("decryptKeyToggle");
    if (input.type === "password") {
        input.type = "text";
        btn.textContent = "🙈";
        btn.title = "Click to hide key";
    } else {
        input.type = "password";
        btn.textContent = "👁";
        btn.title = "Click to show key";
    }
});
document.getElementById("decryptModalConfirm").addEventListener("click", async () => {
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
        } catch (e) {}

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
        } catch (e) {}

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

document.getElementById("deleteConfirmOverlay").addEventListener("click", (e) => {
    if (e.target.id === "deleteConfirmOverlay") hideDeleteModal();
});
document.getElementById("deleteModalCancel").addEventListener("click", hideDeleteModal);
document.getElementById("deleteKeyToggle").addEventListener("click", () => {
    const input = document.getElementById("deleteKeyInput");
    const btn = document.getElementById("deleteKeyToggle");
    if (input.type === "password") {
        input.type = "text";
        btn.textContent = "🙈";
        btn.title = "Click to hide key";
    } else {
        input.type = "password";
        btn.textContent = "👁";
        btn.title = "Click to show key";
    }
});
document.getElementById("deleteModalConfirm").addEventListener("click", async () => {
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

refreshFilesBtn.addEventListener("click", () => loadMyFiles());

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
generateKey.addEventListener("click", () => {
    if (!fileInput.files[0]) {
        showStatus("Select a file first, then generate the key.");
        return;
    }
    encryptionKey.value = crypto.randomUUID().replace(/-/g, "");
    showStatus("Key generated. Copy and store it securely — required to decrypt this file.");
});

document.getElementById("copyKeyBtn").addEventListener("click", async () => {
    const key = normalizeKey(encryptionKey.value || "");
    if (!key) {
        showStatus("Generate or paste a key first.");
        return;
    }
    try {
        await navigator.clipboard.writeText(key);
        showStatus("Key copied to clipboard.");
    } catch {
        encryptionKey.select();
        document.execCommand("copy");
        showStatus("Key selected — press Ctrl+C to copy.");
    }
});

keyToggle.addEventListener("click", () => {
    encryptionKey.type =
        encryptionKey.type === "password" ? "text" : "password";
});

/* ---------- ACTION BUTTONS ---------- */
document.getElementById("encryptBtn").onclick = async () => {
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
        const data = await res.json().catch(() => ({}));
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

function showStatus(msg) {
    if (statusArea) statusArea.style.display = "flex";
    if (statusMessage) statusMessage.textContent = msg;
}