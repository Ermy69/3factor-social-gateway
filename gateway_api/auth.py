"""
auth.py — Cryptographic core of the 3FA Gateway
Handles: Argon2ID hashing, TOTP generation/QR, JWT signing, WebCrypto challenge/verify
"""

import os
import io
import base64
import json
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

import pyotp
import qrcode

import jwt
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Argon2ID — Factor 1
# ---------------------------------------------------------------------------

ph = PasswordHasher()

def hash_password(password: str) -> str:
    """Hash a plaintext password with Argon2ID (salted automatically)."""
    return ph.hash(password)

def verify_password(hash_str: str, password: str) -> bool:
    """Return True if password matches the Argon2ID hash."""
    try:
        return ph.verify(hash_str, password)
    except VerifyMismatchError:
        return False


# ---------------------------------------------------------------------------
# TOTP — Factor 2
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Generate a random base32 TOTP secret for the user's authenticator app."""
    return pyotp.random_base32()

def get_totp_qr_base64(username: str, secret: str) -> str:
    """
    Build the otpauth:// URI and render it as a QR code PNG.
    Returns the image as a base64 data URI ready to drop into an <img> tag.
    """
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="3FA Security Gateway")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"

def verify_totp_code(secret: str, code: str) -> bool:
    """
    RFC 6238 TOTP verification with a 1-step (30 s) window to absorb clock skew.
    No master keys, no backdoors.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


# ---------------------------------------------------------------------------
# JWT — session state carrier & final reward token
# ---------------------------------------------------------------------------

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fallback_dev_key_change_in_prod")
ALGORITHM = "HS256"

def create_session_token(username: str, status: str, extra: dict = None) -> str:
    """
    Issue a short-lived (5 min) signed JWT carrying the user's auth progress.
    The 'status' field acts as a state machine:
      pending_f2 → pending_f3 → fully_authenticated
    """
    payload = {
        "sub": username,
        "status": status,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        **(extra or {}),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_session_token(token: str) -> dict | None:
    """
    Verify the JWT signature and expiry. Returns the decoded payload or None.
    Any tampering with the token will raise an exception that we catch here.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None


# ---------------------------------------------------------------------------
# Web Crypto / ECDSA — Factor 3 (Trusted Device)
# ---------------------------------------------------------------------------

def generate_challenge() -> str:
    """
    Generate a cryptographically random 32-byte challenge string.
    The client must sign this with their private key to prove device possession.
    """
    return secrets.token_hex(32)

def verify_ecdsa_signature(public_key_jwk: dict, challenge: str, signature_b64: str) -> bool:
    """
    Verify an ECDSA P-256 signature produced by the browser's Web Crypto API.

    The browser signs SHA-256(challenge) with the user's private key.
    We verify with the stored public key. If the signature is valid, the user
    is mathematically proven to be on the same device that registered.

    Args:
        public_key_jwk: The public key as a JWK dict (stored at registration).
        challenge:      The random hex string we sent to the client.
        signature_b64:  The base64-encoded ECDSA signature from the browser.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        # Reconstruct the EC public key from the stored JWK
        x = base64.urlsafe_b64decode(public_key_jwk["x"] + "==")
        y = base64.urlsafe_b64decode(public_key_jwk["y"] + "==")

        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, "big"),
            y=int.from_bytes(y, "big"),
            curve=ec.SECP256R1(),
        )
        public_key = public_numbers.public_key(default_backend())

        # The browser's WebCrypto produces a raw 64-byte signature (r||s)
        # cryptography expects DER format, so we convert
        raw_sig = base64.b64decode(signature_b64)
        if len(raw_sig) != 64:
            return False

        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")

        # Encode as DER
        def encode_asn1_int(n):
            b = n.to_bytes((n.bit_length() + 7) // 8, "big")
            if b[0] & 0x80:
                b = b"\x00" + b
            return bytes([0x02, len(b)]) + b

        r_enc = encode_asn1_int(r)
        s_enc = encode_asn1_int(s)
        der_sig = bytes([0x30, len(r_enc) + len(s_enc)]) + r_enc + s_enc

        public_key.verify(der_sig, challenge.encode(), ec.ECDSA(hashes.SHA256()))
        return True

    except (InvalidSignature, Exception):
        return False
