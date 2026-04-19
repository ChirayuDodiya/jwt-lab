# JWT Vulnerability Labs

A hands-on collection of JWT (JSON Web Token) vulnerability labs built with Node.js and Express. Inspired by PortSwigger's JWT labs, this project demonstrates common JWT security flaws and their mitigations.

Each lab contains a **vulnerable endpoint** (exploitable) Fand a **secure endpoint** (properly protected) so you can compare the difference.

---

## Table of Contents

- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Labs](#running-the-labs)
- [Lab 1: JWT Unverified Signature](#lab-1-jwt-unverified-signature)
- [Lab 2: JWT alg:none Attack](#lab-2-jwt-algnone-attack)
- [Lab 7: JWT Algorithm Confusion (HS256 / RSA)](#lab-7-jwt-algorithm-confusion-hs256--rsa)
- [Lab 8: Algorithm Confusion (No Exposed Key)](#lab-8-algorithm-confusion-no-exposed-key)
- [Tech Stack](#tech-stack)

---

## Project Structure

```
jwt_lab/
├── .env                          # Shared credentials & config
├── package.json                  # Dependencies & scripts
├── lab1-unverified-signature/    # Lab 1
│   ├── server.js                 # Express server (vulnerable + secure endpoints)
│   └── public/
│       ├── index.html            # Login page
│       ├── dashboard.html        # Dashboard with attack instructions
│       ├── vulnerable-admin.html # Vulnerable admin panel (jwt.decode)
│       └── secure-admin.html     # Secure admin panel (jwt.verify)
├── lab2-alg-none/                # Lab 2
│   ├── server.js                 # Express server (alg:none vulnerability)
│   └── public/
│       ├── index.html            # Login page
│       ├── dashboard.html        # Dashboard with attack instructions
│       ├── vulnerable-admin.html # Vulnerable admin panel (accepts alg:none)
│       └── secure-admin.html     # Secure admin panel (HS256 only)
├── lab7-algorithm-confusion/     # Lab 7
│   ├── server.js                 # Express server (algorithm confusion vulnerability)
│   └── public/
│       ├── dashboard.html        # Dashboard with attack instructions
│       ├── vulnerable-admin.html # Vulnerable admin (accepts public key as HMAC secret)
│       └── secure-admin.html     # Secure admin panel (enforces RS256)
├── lab8-alg-confusion-no-key/    # Lab 8
│   ├── server.js                 # Express server (key derivation algorithm confusion)
│   └── public/
│       ├── dashboard.html        # Dashboard with attack instructions
│       ├── vulnerable-admin.html # Vulnerable admin (same algorithm confusion)
│       └── secure-admin.html     # Secure admin (enforces RS256)
└── node_modules/
```

---

## Prerequisites

- [Node.js](https://nodejs.org/) (v14 or higher)
- [npm](https://www.npmjs.com/)
- [Burp Suite](https://portswigger.net/burp) (Community Edition is sufficient) — for intercepting and modifying requests

---

## Installation

1. Clone or download this project.

2. Install dependencies:
   ```bash
   cd jwt_lab
   npm install
   ```

3. The `.env` file is pre-configured with default credentials:
   ```env
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=admin123
   USER_USERNAME=chirayu
   USER_PASSWORD=chirayu123
   JWT_SECRET=super-secret-jwt-key-2024
   LAB1_PORT=3001
   LAB2_PORT=3002
   LAB7_PORT=3007
   LAB8_PORT=3008
   ```

---

## Running the Labs

**Run a single lab:**

```bash
npm run lab1    # Starts Lab 1 on http://localhost:3001
npm run lab2    # Starts Lab 2 on http://localhost:3002
npm run lab7    # Starts Lab 7 on http://localhost:3007
npm run lab8    # Starts Lab 8 on http://localhost:3008
```

**Run all labs simultaneously:**

```bash
npm run all     # Starts both labs concurrently
```

---

## Lab 1: JWT Unverified Signature

**Port:** `3001`
**Vulnerability:** The vulnerable endpoint uses `jwt.decode()` instead of `jwt.verify()`, so the JWT signature is **never checked**.

### How the Attack Works

1. **Login** with `chirayu` / `chirayu123` to receive a valid JWT token.
2. **Intercept** the request to `/api/vulnerable-admin` using Burp Suite.
3. **Decode** the JWT token (at [jwt.io](https://jwt.io) or Burp's decoder). The payload looks like:
   ```json
   {
     "sub": "chirayu",
     "role": "user",
     "iat": 1234567890,
     "exp": 1234571490
   }
   ```
4. **Modify** the payload — change `"sub"` to `"admin"` and `"role"` to `"admin"`.
5. **Base64url-encode** the modified payload, replace it in the token, and forward the request.
6. The server accepts it because `jwt.decode()` **does not verify the signature**.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate and receive JWT |
| `/api/vulnerable-admin` | GET | Uses `jwt.decode()` — signature NOT verified |
| `/api/secure-admin` | GET | Uses `jwt.verify()` — signature IS verified |
| `/api/me` | GET | Returns current user info from token |
| `/logout` | POST | Clears the token cookie |

### Why the Secure Endpoint Works

The secure endpoint uses `jwt.verify(token, secret, { algorithms: ['HS256'] })` which:
- Validates the JWT signature against the server's secret key
- Rejects any modified/tampered tokens
- Only accepts HS256-signed tokens

---

## Lab 2: JWT alg:none Attack

**Port:** `3002`
**Vulnerability:** The vulnerable endpoint accepts JWTs with `alg: "none"`, allowing completely **unsigned tokens**.

### How the Attack Works

1. **Login** with `chirayu` / `chirayu123` to receive a valid JWT token.
2. **Intercept** the request to `/api/vulnerable-admin` using Burp Suite.
3. **Create a forged token** with `alg: "none"`:
   - Header: `{"alg":"none","typ":"JWT"}`
   - Payload: `{"sub":"admin","role":"admin","iat":1234567890,"exp":9999999999}`
4. **Base64url-encode** both header and payload.
5. **Concatenate** with a dot and add a trailing dot (empty signature):
   ```
   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTIzNDU2Nzg5MCwiZXhwIjo5OTk5OTk5OTk5fQ.
   ```
6. **Replace** the cookie value with the forged token and send the request.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate and receive JWT |
| `/api/vulnerable-admin` | GET | Accepts `alg: "none"` — unsigned tokens work |
| `/api/secure-admin` | GET | Only accepts `HS256` — unsigned tokens rejected |
| `/api/me` | GET | Returns current user info from token |
| `/logout` | POST | Clears the token cookie |

### Why the Secure Endpoint Works

The secure endpoint uses a strict algorithm whitelist:
```js
jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })
```
- Tokens with `alg: "none"` are automatically rejected
- Only tokens signed with HS256 and the correct secret are accepted

---

## Lab 7: JWT Algorithm Confusion (HS256 / RSA)

**Port:** `3007`
**Vulnerability:** The vulnerable endpoint trusts the `alg` field from the JWT header and uses the same RSA public key for verification regardless of the algorithm type.

### How the Attack Works

1. **Login** with `chirayu` / `chirayu123` to receive a valid RS256-signed JWT token.
2. **Obtain the public key** exposed by the server at `/jwks.json` or `/api/public-key`.
3. **Intercept** the request to `/api/vulnerable-admin` using Burp Suite.
4. **Modify** the JWT header — change the algorithm `alg` from `RS256` to `HS256`.
5. **Modify** the JWT payload — change `"sub"` to `"admin"`.
6. **Sign the token** using the obtained server's **public key** (PEM format) as the symmetric HMAC secret.
7. The server accepts it because it dynamically switches to `HS256` verification and incorrectly uses the asymmetric public key as a symmetric shared secret.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate and receive JWT |
| `/api/vulnerable-admin` | GET | Trusts `alg` header — allows algorithm switching (uses public key as HMAC secret) |
| `/api/secure-admin` | GET | Enforces `RS256` only — rejects algorithm switching |
| `/jwks.json` / `/api/public-key` | GET | Exposes the server's RSA public key |
| `/api/me` | GET | Returns current user info from token |
| `/logout` | POST | Clears the token cookie |

### Why the Secure Endpoint Works

The secure endpoint strictly enforces the `RS256` algorithm via configuration:
```js
jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] })
```
Even if an attacker provides an `HS256` token signed with the public key, the underlying verification will reject it because the algorithm does not match the explicitly allowed list (only `RS256`).

---

## Lab 8: Algorithm Confusion (No Exposed Key)

**Port:** `3008`
**Vulnerability:** This lab features the same algorithm confusion vulnerability as Lab 7, but the server **does not expose its public key**. The attacker must derive the RSA public key mathematically from two valid JWT signatures.

### How the Attack Works

1. **Login** to obtain two different valid JWT tokens signed by the same RSA key (e.g., login twice or use the `/api/collect-tokens` endpoint).
2. **Derive the public key** using a tool like PortSwigger's `sig2n` (`rsa_sign2n` docker container) with the two collected tokens.
3. Once the key is derived, the attack proceeds exactly like Lab 7.
4. **Modify** the JWT header from `RS256` to `HS256` and the payload to impersonate `"admin"`.
5. **Sign** the modified token using the **derived public key** as the HMAC secret.
6. The server accepts the forged token because it trusts the `alg` header and uses the derived public key for HS256 HMAC verification.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate and receive JWT |
| `/api/vulnerable-admin` | GET | Trusts `alg` header — allows algorithm switching |
| `/api/secure-admin` | GET | Enforces `RS256` only — rejects algorithm switching |
| `/api/collect-tokens` | POST | Helper endpoint to easily get two valid token signatures |
| `/api/me` | GET | Returns current user info from token |
| `/logout` | POST | Clears the token cookie |

### Why the Secure Endpoint Works

Hidden public keys are **not** a security mitigation against algorithm confusion. The secure endpoint strictly enforces the algorithm during verification `manualVerifyRS256(token)`, successfully rejecting any `HS256` forged tokens regardless of whether the attacker derived the public key.

---

## Tech Stack

| Technology | Purpose |
|---|---|
| **Node.js** | Runtime environment |
| **Express.js** | Web framework |
| **jsonwebtoken** | JWT signing, decoding, and verification |
| **cookie-parser** | Cookie handling middleware |
| **dotenv** | Environment variable management |
| **concurrently** | Run multiple labs simultaneously |

---

## Key Takeaways

| Vulnerability | Root Cause | Fix |
|---|---|---|
| Unverified Signature | Using `jwt.decode()` instead of `jwt.verify()` | Always use `jwt.verify()` with a secret key |
| alg:none Attack | Accepting unsigned tokens | Explicitly whitelist allowed algorithms (e.g., `['HS256']`) |
| Algorithm Confusion | Trusting the `alg` header and reusing asymmetric keys for symmetric verification | Enforce allowed algorithms; do not use PEM keys for HMAC secrets |

### General JWT Security Best Practices

1. **Always verify signatures** — use `jwt.verify()`, never `jwt.decode()` for auth.
2. **Whitelist algorithms** — explicitly specify allowed algorithms.
3. **Use strong secrets** — generate cryptographically random secret keys.
4. **Set expiration** — always include `exp` claims in your tokens.
5. **Validate claims** — check `sub`, `role`, `iss`, `aud` on the server side.
6. **Use HTTPS** — prevent token interception in transit.
