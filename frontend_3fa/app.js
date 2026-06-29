// ═══════════════════════════════════════════════════════════════
// State
// ═══════════════════════════════════════════════════════════════
const API = "http://localhost:8000";

const state = {
  username: "",
  sessionToken: "",
  cryptoKeyPair: null,  // loaded from localStorage on demand
  pendingChallenge: null // stores the challenge between request and sign steps
};

// ═══════════════════════════════════════════════════════════════
// Key store — localStorage + JWK export/import
// ═══════════════════════════════════════════════════════════════

function lsKey(username) {
  return `3fa_keypair:${username}`;
}

async function saveKeyPair(username, keyPair) {
  const [pubJwk, privJwk] = await Promise.all([
    crypto.subtle.exportKey("jwk", keyPair.publicKey),
    crypto.subtle.exportKey("jwk", keyPair.privateKey),
  ]);
  localStorage.setItem(lsKey(username), JSON.stringify({ pub: pubJwk, priv: privJwk }));
}

async function loadKeyPair(username) {
  const raw = localStorage.getItem(lsKey(username));
  if (!raw) return null;
  try {
    const { pub, priv } = JSON.parse(raw);
    const [publicKey, privateKey] = await Promise.all([
      crypto.subtle.importKey("jwk", pub,  { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]),
      crypto.subtle.importKey("jwk", priv, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]),
    ]);
    return { publicKey, privateKey };
  } catch (e) {
    console.warn("Failed to re-import keypair:", e);
    return null;
  }
}

function deleteKeyPair(username) {
  localStorage.removeItem(lsKey(username));
}

// ═══════════════════════════════════════════════════════════════
// Navigation helpers
// ═══════════════════════════════════════════════════════════════
const panels = ["register", "f1", "f2", "f3", "done"];

function showPanel(name) {
  panels.forEach(p => {
    document.getElementById(`panel-${p}`).classList.remove("active");
    const nav = document.getElementById(`nav-${p}`);
    if (nav) { nav.classList.remove("active"); nav.classList.remove("done"); }
  });
  document.getElementById(`panel-${name}`).classList.add("active");

  const order   = ["register", "f1", "f2", "f3", "done"];
  const current = order.indexOf(name);
  order.forEach((step, i) => {
    const nav = document.getElementById(`nav-${step}`);
    if (!nav) return;
    if (i < current)      nav.classList.add("done");
    else if (i === current) nav.classList.add("active");
  });
}

function setStatus(id, type, msg) {
  const el = document.getElementById(id);
  el.className = `status-msg ${type}`;
  el.textContent = msg;
}

function clearStatus(id) {
  const el = document.getElementById(id);
  el.className = "status-msg";
  el.textContent = "";
}

function switchTab(tab) {
  document.getElementById("tab-register").style.display = tab === "register" ? "block" : "none";
  document.getElementById("tab-login").style.display    = tab === "login"    ? "block" : "none";
  document.querySelectorAll(".tab-btn").forEach((b, i) => {
    b.classList.toggle("active", (i === 0) === (tab === "register"));
  });
}

async function jumpToLogin() {
  const u = document.getElementById("login-jump-username").value.trim();
  if (!u) { alert("Enter your username."); return; }
  state.username = u;

  const kp = await loadKeyPair(u);
  if (kp) {
    state.cryptoKeyPair = kp;
  }

  document.getElementById("f1-username").value = u;
  showPanel("f1");
}

// ═══════════════════════════════════════════════════════════════
// Web Crypto helpers
// ═══════════════════════════════════════════════════════════════

async function generateKeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
}

async function exportPublicKeyAsJWK(keyPair) {
  return await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
}

async function signChallenge(privateKey, challengeHex) {
  const data = new TextEncoder().encode(challengeHex);
  const sig  = await window.crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    privateKey,
    data
  );
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

// ═══════════════════════════════════════════════════════════════
// Step 0A — Register account
// ═══════════════════════════════════════════════════════════════
async function doRegister() {
  const username = document.getElementById("reg-username").value.trim();
  const password = document.getElementById("reg-password").value;

  if (!username || !password) {
    setStatus("reg-status", "error", "Username and password are required.");
    return;
  }

  setStatus("reg-status", "loading", "Creating account...");

  try {
    const res  = await fetch(`${API}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (!res.ok) {
      setStatus("reg-status", "error", data.detail || "Registration failed.");
      return;
    }

    state.username = username;
    document.getElementById("qr-img").src              = data.qr_code;
    document.getElementById("qr-section").style.display = "block";
    setStatus("reg-status", "ok", `Account '${username}' created! Scan the QR code below.`);

  } catch (e) {
    setStatus("reg-status", "error", `Network error: ${e.message}. Is the API running on port 8000?`);
  }
}

// ═══════════════════════════════════════════════════════════════
// Step 0B — Register device
// ═══════════════════════════════════════════════════════════════
async function doRegisterDevice() {
  setStatus("device-status", "loading", "Generating ECDSA P-256 keypair in your browser...");

  try {
    const keyPair      = await generateKeyPair();
    const publicKeyJwk = await exportPublicKeyAsJWK(keyPair);

    setStatus("device-status", "loading", "Saving private key to browser localStorage (as JWK)...");

    await saveKeyPair(state.username, keyPair);
    state.cryptoKeyPair = keyPair;

    setStatus("device-status", "loading", "Sending public key to server...");

    const res  = await fetch(`${API}/auth/register-device`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: state.username, public_key_jwk: publicKeyJwk }),
    });
    const data = await res.json();

    if (!res.ok) {
      setStatus("device-status", "error", data.detail || "Device registration failed.");
      return;
    }

    setStatus("device-status", "ok", "Trusted device registered. Private key stored in this browser only.");

    setTimeout(() => {
      document.getElementById("f1-username").value = state.username;
      showPanel("f1");
    }, 1800);

  } catch (e) {
    setStatus("device-status", "error", `Crypto error: ${e.message}`);
  }
}

// ═══════════════════════════════════════════════════════════════
// Factor 1 — Password
// ═══════════════════════════════════════════════════════════════
async function doF1() {
  const username = document.getElementById("f1-username").value.trim();
  const password = document.getElementById("f1-password").value;

  if (!username || !password) {
    setStatus("f1-status", "error", "Both fields are required.");
    return;
  }

  setStatus("f1-status", "loading", "Verifying password (Argon2ID)...");

  try {
    const res  = await fetch(`${API}/auth/login-f1`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (!res.ok) {
      setStatus("f1-status", "error", data.detail || "Invalid credentials.");
      return;
    }

    state.username     = username;
    state.sessionToken = data.session_token;

    if (!state.cryptoKeyPair) {
      state.cryptoKeyPair = await loadKeyPair(username);
    }

    setStatus("f1-status", "ok", "Factor 1 passed ✓ — JWT issued with status: pending_f2");
    document.getElementById("f2-username-label").textContent = username;
    setTimeout(() => showPanel("f2"), 1200);

  } catch (e) {
    setStatus("f1-status", "error", `Network error: ${e.message}`);
  }
}

// ═══════════════════════════════════════════════════════════════
// Factor 2 — TOTP
// ═══════════════════════════════════════════════════════════════
async function doF2() {
  const code = document.getElementById("f2-code").value.trim();
  if (!code || code.length !== 6) {
    setStatus("f2-status", "error", "Enter the 6-digit code from your authenticator app.");
    return;
  }

  setStatus("f2-status", "loading", "Verifying TOTP code (RFC 6238)...");

  try {
    const res  = await fetch(`${API}/auth/verify-f2`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_token: state.sessionToken, totp_code: code }),
    });
    const data = await res.json();

    if (!res.ok) {
      setStatus("f2-status", "error", data.detail || "Invalid TOTP code.");
      return;
    }

    state.sessionToken = data.session_token;
    setStatus("f2-status", "ok", "Factor 2 passed ✓ — JWT upgraded to status: pending_f3");
    setTimeout(() => showPanel("f3"), 1200);

  } catch (e) {
    setStatus("f2-status", "error", `Network error: ${e.message}`);
  }
}

// ═══════════════════════════════════════════════════════════════
// Factor 3 — Web Crypto ECDSA challenge-response (SPLIT LOGIC)
// ═══════════════════════════════════════════════════════════════

// Step 3a: Request the Challenge (This is where you pause for the presentation!)
async function requestF3Challenge() {
  if (!state.cryptoKeyPair && state.username) {
    state.cryptoKeyPair = await loadKeyPair(state.username);
  }

  if (!state.cryptoKeyPair) {
    setStatus("f3-status", "error",
      "No device key found for this account in this browser. " +
      "You need to register this device first — go back to Registration and click 'Register This Device as Trusted'."
    );
    return;
  }

  document.getElementById("f3-request-btn").disabled = true;
  setStatus("f3-status", "loading", "Requesting challenge from server...");

  try {
    const challengeRes = await fetch(`${API}/auth/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_token: state.sessionToken }),
    });
    const { challenge } = await challengeRes.json();
    
    // Store challenge globally to use in the next step
    state.pendingChallenge = challenge;
    document.getElementById("challenge-display").textContent = challenge;

    setStatus("f3-status", "ok", "Challenge received! The database now holds this challenge. You can pause and check it.");
    
    // Hide request button, show sign button
    document.getElementById("f3-request-btn").style.display = "none";
    document.getElementById("f3-sign-btn").style.display = "inline-flex";

  } catch (e) {
    setStatus("f3-status", "error", `Error: ${e.message}`);
    document.getElementById("f3-request-btn").disabled = false;
  }
}

// Step 3b: Sign and Verify the Challenge
async function signAndVerifyF3() {
  document.getElementById("f3-sign-btn").disabled = true;
  setStatus("f3-status", "loading", "Signing challenge with device private key (ECDSA P-256 / SHA-256)...");

  try {
    const signature = await signChallenge(state.cryptoKeyPair.privateKey, state.pendingChallenge);
    document.getElementById("sig-display").textContent = signature.substring(0, 40) + "...";

    setStatus("f3-status", "loading", "Submitting signature for server verification...");

    const verifyRes = await fetch(`${API}/auth/verify-f3`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_token: state.sessionToken, signature }),
    });
    const data = await verifyRes.json();

    if (!verifyRes.ok) {
      setStatus("f3-status", "error", data.detail || "Device verification failed.");
      document.getElementById("f3-sign-btn").disabled = false;
      return;
    }

    state.sessionToken = data.access_token;
    setStatus("f3-status", "ok", "Factor 3 passed ✓ — Signature verified. All factors complete.");
    
    // Show manual proceed button to prevent auto-redirect
    document.getElementById("f3-sign-btn").style.display = "none";
    document.getElementById("f3-proceed-btn").style.display = "inline-flex";

  } catch (e) {
    setStatus("f3-status", "error", `Error: ${e.message}`);
    document.getElementById("f3-sign-btn").disabled = false;
  }
}

// ═══════════════════════════════════════════════════════════════
// Manually trigger the Success Panel transition
// ═══════════════════════════════════════════════════════════════
function goToSuccess() {
  loadSuccessPanel(state.sessionToken);
}

// ═══════════════════════════════════════════════════════════════
// Success + Feed
// ═══════════════════════════════════════════════════════════════
async function loadSuccessPanel(token) {
  showPanel("done");
  document.getElementById("jwt-display").textContent = token;

  try {
    const res  = await fetch(`${API}/feed?token=${encodeURIComponent(token)}`);
    const data = await res.json();
    const container = document.getElementById("feed-container");

    if (!res.ok) {
      container.innerHTML = `<p style="color:var(--danger)">${data.detail}</p>`;
      return;
    }

    container.innerHTML = data.feed.map(post => `
      <div class="feed-post">
        <div class="feed-author">@${post.author}</div>
        <div class="feed-content">${post.content}</div>
      </div>
    `).join("");

  } catch (e) {
    document.getElementById("feed-container").innerHTML =
      `<p style="color:var(--muted)">Could not load feed: ${e.message}</p>`;
  }
}

// ═══════════════════════════════════════════════════════════════
// Reset — clears session state but NOT the IndexedDB keypair
// ═══════════════════════════════════════════════════════════════
function resetAll() {
  state.username     = "";
  state.sessionToken = "";
  state.cryptoKeyPair = null;
  state.pendingChallenge = null;

  ["reg-username","reg-password","f1-username","f1-password","f2-code"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });

  document.getElementById("qr-section").style.display = "none";
  document.getElementById("challenge-display").textContent = "Requesting...";
  document.getElementById("sig-display").textContent       = "Pending...";
  
  // Reset F3 Buttons
  const reqBtn = document.getElementById("f3-request-btn");
  if(reqBtn) {
      reqBtn.disabled = false;
      reqBtn.style.display = "inline-flex";
  }
  const signBtn = document.getElementById("f3-sign-btn");
  if(signBtn) {
      signBtn.disabled = false;
      signBtn.style.display = "none";
  }
  const proceedBtn = document.getElementById("f3-proceed-btn");
  if(proceedBtn) {
      proceedBtn.style.display = "none";
  }

  ["reg-status","device-status","f1-status","f2-status","f3-status"].forEach(clearStatus);

  switchTab("register");
  showPanel("register");
}

// ── Init
showPanel("register");
document.getElementById("nav-register").classList.add("active");