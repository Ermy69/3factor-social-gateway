# 3FA Security Gateway
**SEC-PRJ-7F_25 — Triple Factor Authentication for Social Media**  
UNIME · System Security · 2025

---

## What it demonstrates

Three **independent** authentication factors — each from a different category — before a JWT is issued:

| Factor | Category | Technology |
|--------|----------|------------|
| 1 — Password | Knowledge | Argon2ID (memory-hard hashing) |
| 2 — TOTP | Possession | RFC 6238 / Google Authenticator |
| 3 — Trusted Device | Inherence / Cryptotools | ECDSA P-256 via Web Crypto API |
| Reward | — | JWT (HS256), grants access to protected feed |

---

## Architecture

```
frontend_3fa/index.html     ← Single-page demo UI (plain HTML/JS)
gateway_api/
  ├── main.py               ← FastAPI endpoints
  ├── auth.py               ← Argon2ID · TOTP · JWT · ECDSA verification
  ├── database.py           ← SQLite (users + challenges)
  ├── requirements.txt
  └── Dockerfile
docker-compose.yml
.env.example
```

---

## Quick start

### Option A — Docker (recommended)
```bash
cp .env.example .env
docker compose up --build
```

### Option B — Local Python
```bash
cd gateway_api
pip install -r requirements.txt
cp ../.env.example ../.env
uvicorn main:app --reload --port 8000
```

Then open `frontend_3fa/index.html` directly in your browser.  
API docs: http://localhost:8000/docs

---

## Demo flow

1. **Register** — create a username + password; scan the QR code with Google Authenticator
2. **Register Device** — browser generates an ECDSA keypair; public key is sent to the server; private key stays in the browser
3. **Factor 1** — enter password → server verifies Argon2ID hash → issues `pending_f2` JWT
4. **Factor 2** — enter 6-digit TOTP from authenticator app → server verifies RFC 6238 → upgrades JWT to `pending_f3`
5. **Factor 3** — browser signs a server challenge with the device private key → server verifies ECDSA signature → issues `fully_authenticated` JWT
6. **Feed** — JWT is used to access the protected `/feed` endpoint

---

## Key security properties

- **Argon2ID** is resistant to GPU/ASIC brute-force (memory-hard, time-hard)
- **TOTP codes** expire every 30 seconds; no code can be reused
- **JWT state machine** — each factor upgrades the token status; skipping a factor is cryptographically impossible
- **ECDSA private key** never leaves the browser; the server only stores the public key
- **Single-use challenges** — each cryptographic challenge is deleted immediately after use
- **No server-side sessions** — all auth state is carried in short-lived signed JWTs

---

## Notes

- `USER_DB` is SQLite (file `3fa.db` inside `gateway_api/`) — persists across restarts  
- CORS is open (`*`) for local demo; restrict to your frontend origin in production  
- The `/feed` endpoint uses a query param for the token for demo simplicity; production would use `Authorization: Bearer`
