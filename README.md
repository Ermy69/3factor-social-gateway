# 3factor-social-gateway
UNIME Data Analysis | System Security Project


# Triple Factor Authentication (3FA) Gateway with Out-of-Band Social Media Integration

A hardened system security authentication gateway implementing a 3FA protocol using conventional cryptotools, time-based OTP, and out-of-band automated validation channels.

##  Academic Alignment
- **Course:** System Security
- **Project Code:** PROF. ASS.SEC-PRJ-7F_25
- **Title:** Triple Factor Authentication for Social Media

## The 3FA Cryptographic Architecture
The gateway strictly enforces three independent validation layers before granting access to protected system resources:

1. **Factor 1 (Knowledge):** Password verification utilizing cryptographically salted hashing (Argon2ID) against a local datastore.
2. **Factor 2 (Possession):** Time-Based One-Time Password (TOTP / RFC 6238) validated via a state-encoded JSON Web Token (JWT).
3. **Factor 3 (Out-of-Band Social Integration):** Automated transaction approval loop operating via an asynchronous webhook integration (Telegram/Discord Bot API). If the out-of-band token handshake fails, the session token is instantly blacklisted.

##  Repository 
- `/gateway_api`: Core authentication engine, cryptographic hashing, and JWT signing routines.
- `/oob_worker`: The social media API integration service running independent loop listeners.
- `/docker`: Containerized environment configuration for microservice isolation.

