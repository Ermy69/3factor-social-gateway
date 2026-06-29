"""
main.py — 3FA Security Gateway API
====================================
Three independent authentication factors, one JWT reward.

Factor 1 — Knowledge     : Argon2ID-hashed password  →  /auth/login-f1
Factor 2 — Possession    : TOTP (RFC 6238 / Google Authenticator)  →  /auth/verify-f2
Factor 3 — Trusted Device: ECDSA signature via browser Web Crypto API  →  /auth/verify-f3
Reward    — JWT           : Issued only when all three factors pass
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()

from database import init_db, create_user, get_user, user_exists, save_public_key, store_challenge, get_and_clear_challenge
from auth import (
    hash_password, verify_password,
    generate_totp_secret, get_totp_qr_base64, verify_totp_code,
    create_session_token, decode_session_token,
    generate_challenge, verify_ecdsa_signature,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="3FA Security Gateway",
    description="Triple Factor Authentication: Password + TOTP + Web Crypto trusted device",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    # NOTE: In production this would be locked to the specific frontend origin.
    # Permissive here for local demo purposes only.
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    init_db()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str
    password: str

class RegisterDeviceRequest(BaseModel):
    username: str
    public_key_jwk: dict   # The P-256 public key from the browser's Web Crypto API

class LoginF1Request(BaseModel):
    username: str
    password: str

class VerifyF2Request(BaseModel):
    session_token: str
    totp_code: str

class ChallengeRequest(BaseModel):
    session_token: str     # Must be in 'pending_f3' state

class VerifyF3Request(BaseModel):
    session_token: str
    signature: str         # base64-encoded ECDSA signature from the browser


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
def root():
    return {"status": "3FA Gateway is running", "version": "2.0.0"}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@app.post("/auth/register", status_code=status.HTTP_201_CREATED, tags=["Registration"])
def register(req: RegisterRequest):
    """
    Step 0A — Create a new account.

    Stores the Argon2ID password hash and generates a TOTP secret.
    Returns a QR code image (base64) for the user to scan with Google Authenticator.
    The TOTP secret is never sent again after this — treat the QR code as the secret.
    """
    if user_exists(req.username):
        raise HTTPException(status_code=400, detail="Username already taken.")

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    hashed = hash_password(req.password)
    totp_secret = generate_totp_secret()
    create_user(req.username, hashed, totp_secret)

    qr_data_uri = get_totp_qr_base64(req.username, totp_secret)

    return {
        "message": f"Account '{req.username}' created. Scan the QR code with Google Authenticator.",
        "qr_code": qr_data_uri,
        # Exposed for demo/debug purposes only — in production this would NOT be returned
        "totp_secret_debug": totp_secret,
    }


@app.post("/auth/register-device", tags=["Registration"])
def register_device(req: RegisterDeviceRequest):
    """
    Step 0B — Register this browser as the trusted device (Factor 3 setup).

    The browser's Web Crypto API generates an ECDSA P-256 keypair.
    The PUBLIC key is sent here and stored against the account.
    The PRIVATE key never leaves the browser — it stays in the device's secure key store.
    """
    user = get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Validate it looks like a P-256 JWK
    required_fields = {"kty", "crv", "x", "y"}
    if not required_fields.issubset(req.public_key_jwk.keys()):
        raise HTTPException(status_code=400, detail="Invalid public key format. Expected P-256 JWK.")

    if req.public_key_jwk.get("crv") != "P-256":
        raise HTTPException(status_code=400, detail="Only P-256 (ECDSA) keys are accepted.")

    save_public_key(req.username, req.public_key_jwk)
    return {"message": "Trusted device registered. Your private key stays on this device."}


# ---------------------------------------------------------------------------
# Authentication — Factor 1: Password
# ---------------------------------------------------------------------------

@app.post("/auth/login-f1", tags=["Authentication"])
def login_factor1(req: LoginF1Request):
    """
    Factor 1 — Knowledge: Password

    Verifies username + Argon2ID-hashed password.
    On success, issues a short-lived JWT with status='pending_f2'.
    This token is required for Factor 2 — it proves F1 was passed without
    needing the server to store session state.
    """
    user = get_user(req.username)
    if not user or not verify_password(user["hashed_password"], req.password):
        # Deliberately vague — don't reveal whether username or password was wrong
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    session_token = create_session_token(req.username, "pending_f2")
    return {
        "message": "Factor 1 passed. Proceed to TOTP verification.",
        "session_token": session_token,
        "factor": 1,
    }


# ---------------------------------------------------------------------------
# Authentication — Factor 2: TOTP
# ---------------------------------------------------------------------------

@app.post("/auth/verify-f2", tags=["Authentication"])
def verify_factor2(req: VerifyF2Request):
    """
    Factor 2 — Possession: TOTP (Time-based One-Time Password)

    Validates the 6-digit code from Google Authenticator / Apple Passwords.
    The session_token from F1 must be present and in 'pending_f2' state.
    On success, upgrades the token to 'pending_f3'.

    RFC 6238 compliance: 30-second window with ±1 step clock-skew tolerance.
    """
    session = decode_session_token(req.session_token)
    if not session or session.get("status") != "pending_f2":
        raise HTTPException(status_code=401, detail="Invalid or expired session. Please restart login.")

    username = session["sub"]
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if not verify_totp_code(user["totp_secret"], req.totp_code):
        raise HTTPException(status_code=401, detail="Invalid or expired TOTP code.")

    # Check that a trusted device is registered before proceeding
    if not user.get("public_key_jwk"):
        raise HTTPException(
            status_code=400,
            detail="No trusted device registered for this account. Complete device registration first."
        )

    session_token = create_session_token(username, "pending_f3")
    return {
        "message": "Factor 2 passed. Proceed to trusted device verification.",
        "session_token": session_token,
        "factor": 2,
    }


# ---------------------------------------------------------------------------
# Authentication — Factor 3: Trusted Device (Web Crypto ECDSA)
# ---------------------------------------------------------------------------

@app.post("/auth/challenge", tags=["Authentication"])
def get_challenge(req: ChallengeRequest):
    """
    Factor 3 setup — Issue a cryptographic challenge.

    The session must be in 'pending_f3' state.
    Returns a random 32-byte hex string. The client must sign this with their
    ECDSA private key (stored in the browser's secure key store) and send the
    signature back to /auth/verify-f3.

    Each challenge is single-use and expires in 5 minutes.
    """
    session = decode_session_token(req.session_token)
    if not session or session.get("status") != "pending_f3":
        raise HTTPException(status_code=401, detail="Invalid or expired session. Please restart login.")

    username = session["sub"]
    challenge = generate_challenge()
    store_challenge(username, challenge)

    return {
        "challenge": challenge,
        "info": "Sign this string with your device's private key and submit the signature to /auth/verify-f3."
    }


@app.post("/auth/verify-f3", tags=["Authentication"])
def verify_factor3(req: VerifyF3Request):
    """
    Factor 3 — Inherence: Trusted Device (ECDSA signature)

    The client signs the challenge string with the private key that was generated
    on their device at registration. We verify the signature against the stored
    public key using ECDSA P-256 / SHA-256.

    If valid: the user is proven to be on their registered device.
    Reward: a fully_authenticated JWT is issued. This is the final access token.
    """
    session = decode_session_token(req.session_token)
    if not session or session.get("status") != "pending_f3":
        raise HTTPException(status_code=401, detail="Invalid or expired session. Please restart login.")

    username = session["sub"]
    user = get_user(username)
    if not user or not user.get("public_key_jwk"):
        raise HTTPException(status_code=400, detail="No trusted device registered.")

    challenge = get_and_clear_challenge(username)
    if not challenge:
        raise HTTPException(status_code=400, detail="Challenge expired or not found. Request a new challenge.")

    if not verify_ecdsa_signature(user["public_key_jwk"], challenge, req.signature):
        raise HTTPException(status_code=401, detail="Device signature verification failed.")

    # All three factors passed — issue the final JWT
    final_token = create_session_token(username, "fully_authenticated")

    return {
        "message": f"All 3 factors verified. Access granted to '{username}'.",
        "access_token": final_token,
        "token_type": "Bearer",
        "factor": 3,
        "authentication_complete": True,
    }


# ---------------------------------------------------------------------------
# Protected resource — demo endpoint
# ---------------------------------------------------------------------------

@app.get("/feed", tags=["Protected"])
def social_feed(token: str):
    """
    Protected resource: Social Media Feed.
    Only accessible with a fully_authenticated JWT.
    In a real app this would use an Authorization: Bearer header.
    """
    session = decode_session_token(token)
    if not session or session.get("status") != "fully_authenticated":
        raise HTTPException(status_code=403, detail="Access denied. Valid authenticated token required.")

    username = session["sub"]
    return {
        "feed": [
            {
                "author": "GlobalNews24", 
                "content": "🚨 BREAKING: Europe is currently experiencing a severe, record-breaking heatwave sweeping across western and central regions. Temperatures have officially exceeded 40°C (104°F). Stay hydrated and indoors!"
            },
            {
                "author": "WorldCup2026", 
                "content": "⚽ The 2026 FIFA World Cup is officially in the Knockout Stage! The tension is incredible. Who are you rooting for to take home the trophy?"
            },
            {
                "author": "CyberSecInsider", 
                "content": "Privacy update: Tech giants announce transition to Web Crypto API and Triple Factor Authentication (3FA) to combat next-generation phishing attacks."
            }
        ]
    }