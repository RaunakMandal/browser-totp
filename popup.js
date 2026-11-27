const VAULT_KEY = "totpVault";
const LEGACY_STORAGE_KEY = "totpAccounts";
const SESSION_KEY = "sessionKey";
const AUTO_LOCK_ALARM = "autoLock";
const AUTO_LOCK_MINUTES = 10;
const PBKDF2_ITERATIONS = 600_000;
const TOTP_PERIOD_SECONDS = 30;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Derive an AES-256-GCM key from a master password and salt via PBKDF2.
 */
async function deriveMasterKey(password, saltBytes) {
  const passwordBytes = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault(accounts, key, saltBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(accounts));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );

  return {
    version: 1,
    salt: bytesToBase64(saltBytes),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

async function decryptVault(vault, key) {
  const iv = base64ToBytes(vault.iv);
  const ciphertext = base64ToBytes(vault.ciphertext);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );
  const parsed = JSON.parse(new TextDecoder().decode(decrypted));
  return Array.isArray(parsed) ? parsed : [];
}

async function saveSessionKey(key) {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  await chrome.storage.session.set({ [SESSION_KEY]: jwk });
  await chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: AUTO_LOCK_MINUTES });
}

async function loadSessionKey() {
  const result = await chrome.storage.session.get(SESSION_KEY);
  const jwk = result[SESSION_KEY];
  if (!jwk) return null;

  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function clearSession() {
  await chrome.storage.session.remove(SESSION_KEY);
  await chrome.alarms.clear(AUTO_LOCK_ALARM);
}

/**
 * Normalize and decode a Base32 secret into a Uint8Array.
 * Throws if the secret is empty or contains invalid characters.
 */
function decodeBase32(input) {
  const cleaned = input.toUpperCase().replace(/[\s=-]+/g, "");
  if (!cleaned) {
    throw new Error("Secret key is required.");
  }

  let bits = 0;
  let value = 0;
  const bytes = [];

  for (const char of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) {
      throw new Error("Secret must be valid Base32 (A-Z, 2-7).");
    }
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  if (bytes.length === 0) {
    throw new Error("Secret key is too short.");
  }

  return new Uint8Array(bytes);
}

/**
 * Generate a 6-digit RFC 6238 TOTP code using HMAC-SHA1.
 */
async function generateTotp(secret) {
  const keyBytes = decodeBase32(secret);
  const counter = Math.floor(Date.now() / 1000 / TOTP_PERIOD_SECONDS);

  const counterBytes = new Uint8Array(8);
  let remaining = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = remaining & 0xff;
    remaining = Math.floor(remaining / 256);
  }

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBytes));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = (binary % 1_000_000).toString().padStart(6, "0");
  return `${otp.slice(0, 3)} ${otp.slice(3)}`;
}

document.addEventListener("DOMContentLoaded", () => {
  const setupView = document.getElementById("setup-view");
  const unlockView = document.getElementById("unlock-view");
  const vaultView = document.getElementById("vault-view");
  const headerActions = document.getElementById("header-actions");
  const countdownBadge = document.getElementById("countdown-badge");

  const setupForm = document.getElementById("setup-form");
  const setupPasswordInput = document.getElementById("setup-password");
  const setupConfirmInput = document.getElementById("setup-confirm");
  const setupError = document.getElementById("setup-error");

  const unlockForm = document.getElementById("unlock-form");
  const unlockPasswordInput = document.getElementById("unlock-password");
  const unlockError = document.getElementById("unlock-error");

  const lockBtn = document.getElementById("lock-btn");
  const toggleFormBtn = document.getElementById("toggle-form-btn");
  const cancelFormBtn = document.getElementById("cancel-form-btn");
  const addForm = document.getElementById("add-form");
  const issuerInput = document.getElementById("issuer-input");
  const accountInput = document.getElementById("account-input");
  const secretInput = document.getElementById("secret-input");
  const formError = document.getElementById("form-error");
  const totpListEl = document.getElementById("totp-list");
  const emptyStateEl = document.getElementById("empty-state");

  let accounts = [];
  let vaultKey = null;
  let vaultSaltBytes = null;
  let lastWindow = -1;
  let tickTimer = null;

  function setError(el, message) {
    if (!message) {
      el.textContent = "";
      el.classList.add("hidden");
    } else {
      el.textContent = message;
      el.classList.remove("hidden");
    }
  }

  function showView(viewName) {
    setupView.classList.toggle("hidden", viewName !== "setup");
    unlockView.classList.toggle("hidden", viewName !== "unlock");
    vaultView.classList.toggle("hidden", viewName !== "vault");
    headerActions.classList.toggle("hidden", viewName !== "vault");
    countdownBadge.classList.toggle("hidden", viewName !== "vault");

    if (viewName === "setup") {
      setupPasswordInput.focus();
    } else if (viewName === "unlock") {
      unlockPasswordInput.focus();
    }
  }

  function setFormOpen(isOpen) {
    addForm.classList.toggle("hidden", !isOpen);
    toggleFormBtn.textContent = isOpen ? "Close" : "+ Add";
    if (!isOpen) {
      addForm.reset();
      setError(formError, "");
    } else {
      issuerInput.focus();
    }
  }

  async function persistVault() {
    const encrypted = await encryptVault(accounts, vaultKey, vaultSaltBytes);
    await chrome.storage.local.set({ [VAULT_KEY]: encrypted });
    await chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: AUTO_LOCK_MINUTES });
  }

  async function renderList() {
    totpListEl.innerHTML = "";
    emptyStateEl.classList.toggle("hidden", accounts.length > 0);

    for (const entry of accounts) {
      const li = document.createElement("li");
      li.className = "totp-item";

      const meta = document.createElement("div");
      meta.className = "totp-meta";

      const issuerEl = document.createElement("div");
      issuerEl.className = "totp-issuer";
      issuerEl.textContent = entry.issuer || entry.account || "Unnamed";
      meta.appendChild(issuerEl);

      if (entry.issuer && entry.account) {
        const accountEl = document.createElement("div");
        accountEl.className = "totp-account";
        accountEl.textContent = entry.account;
        meta.appendChild(accountEl);
      }

      const controls = document.createElement("div");
      controls.className = "totp-controls";

      const codeEl = document.createElement("span");
      codeEl.className = "totp-code";
      try {
        codeEl.textContent = await generateTotp(entry.secret);
      } catch {
        codeEl.textContent = "------";
      }

      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "copy-btn";
      copyBtn.title = "Copy code without spaces";
      copyBtn.textContent = "Copy";
      copyBtn.addEventListener("click", async () => {
        const rawCode = codeEl.textContent.replace(/\s+/g, "");
        if (!/^\d{6}$/.test(rawCode)) return;
        await navigator.clipboard.writeText(rawCode);
        copyBtn.textContent = "Copied";
        copyBtn.classList.add("copied");
        setTimeout(() => {
          copyBtn.textContent = "Copy";
          copyBtn.classList.remove("copied");
        }, 900);
      });

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "delete-btn";
      deleteBtn.title = "Remove TOTP";
      deleteBtn.setAttribute("aria-label", `Remove ${issuerEl.textContent}`);
      deleteBtn.textContent = "✕";
      deleteBtn.addEventListener("click", async () => {
        accounts = accounts.filter((item) => item.id !== entry.id);
        await persistVault();
        await renderList();
      });

      controls.append(codeEl, copyBtn, deleteBtn);
      li.append(meta, controls);
      totpListEl.appendChild(li);
    }
  }

  async function tick() {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const currentWindow = Math.floor(nowSeconds / TOTP_PERIOD_SECONDS);
    const remaining = TOTP_PERIOD_SECONDS - (nowSeconds % TOTP_PERIOD_SECONDS);
    countdownBadge.textContent = `${remaining}s`;

    if (currentWindow !== lastWindow) {
      lastWindow = currentWindow;
      await renderList();
    }
  }

  async function enterVault(decryptedAccounts, key, saltBytes) {
    accounts = decryptedAccounts;
    vaultKey = key;
    vaultSaltBytes = saltBytes;
    lastWindow = -1;
    setFormOpen(false);
    showView("vault");
    await tick();
    if (tickTimer) clearInterval(tickTimer);
    tickTimer = setInterval(tick, 1000);
  }

  setupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setError(setupError, "");

    const password = setupPasswordInput.value;
    const confirm = setupConfirmInput.value;
    if (password.length < 6) {
      setError(setupError, "Master password must be at least 6 characters.");
      return;
    }
    if (password !== confirm) {
      setError(setupError, "Passwords do not match.");
      return;
    }

    const submitBtn = setupForm.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    try {
      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const key = await deriveMasterKey(password, saltBytes);

      const legacy = await chrome.storage.local.get(LEGACY_STORAGE_KEY);
      const initialAccounts = Array.isArray(legacy[LEGACY_STORAGE_KEY])
        ? legacy[LEGACY_STORAGE_KEY]
        : [];

      const encrypted = await encryptVault(initialAccounts, key, saltBytes);
      await chrome.storage.local.set({ [VAULT_KEY]: encrypted });
      await chrome.storage.local.remove(LEGACY_STORAGE_KEY);
      await saveSessionKey(key);

      setupForm.reset();
      await enterVault(initialAccounts, key, saltBytes);
    } finally {
      submitBtn.disabled = false;
    }
  });

  unlockForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setError(unlockError, "");

    const password = unlockPasswordInput.value;
    if (!password) {
      setError(unlockError, "Enter your master password.");
      return;
    }

    const submitBtn = unlockForm.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    try {
      const stored = await chrome.storage.local.get(VAULT_KEY);
      const vault = stored[VAULT_KEY];
      if (!vault) {
        showView("setup");
        return;
      }

      const saltBytes = base64ToBytes(vault.salt);
      const key = await deriveMasterKey(password, saltBytes);
      const decrypted = await decryptVault(vault, key);

      await saveSessionKey(key);
      unlockForm.reset();
      await enterVault(decrypted, key, saltBytes);
    } catch {
      setError(unlockError, "Incorrect master password.");
    } finally {
      submitBtn.disabled = false;
    }
  });

  lockBtn.addEventListener("click", async () => {
    if (tickTimer) {
      clearInterval(tickTimer);
      tickTimer = null;
    }
    accounts = [];
    vaultKey = null;
    vaultSaltBytes = null;
    totpListEl.innerHTML = "";
    await clearSession();
    showView("unlock");
  });

  toggleFormBtn.addEventListener("click", () => {
    setFormOpen(addForm.classList.contains("hidden"));
  });

  cancelFormBtn.addEventListener("click", () => {
    setFormOpen(false);
  });

  addForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setError(formError, "");

    const issuer = issuerInput.value.trim();
    const account = accountInput.value.trim();
    const secret = secretInput.value.trim().toUpperCase().replace(/\s+/g, "");

    if (!issuer && !account) {
      setError(formError, "Enter at least an issuer or account name.");
      return;
    }

    try {
      decodeBase32(secret);
    } catch (err) {
      setError(formError, err.message);
      return;
    }

    const newEntry = {
      id: crypto.randomUUID(),
      issuer,
      account,
      secret,
      createdAt: Date.now(),
    };

    accounts = [...accounts, newEntry];
    await persistVault();
    setFormOpen(false);
    await renderList();
  });

  (async () => {
    const stored = await chrome.storage.local.get(VAULT_KEY);
    const vault = stored[VAULT_KEY];
    if (!vault) {
      showView("setup");
      return;
    }

    try {
      const sessionKey = await loadSessionKey();
      if (sessionKey) {
        const decrypted = await decryptVault(vault, sessionKey);
        await chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: AUTO_LOCK_MINUTES });
        await enterVault(decrypted, sessionKey, base64ToBytes(vault.salt));
        return;
      }
    } catch {
      await clearSession();
    }

    showView("unlock");
  })();
});
