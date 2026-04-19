# JWT Vulnerability Labs

A hands-on collection of JWT (JSON Web Token) vulnerability labs built with Node.js and Express. Inspired by PortSwigger's JWT labs, this project demonstrates common JWT security flaws and their mitigations.

<<<<<<< HEAD
Each lab contains a **vulnerable endpoint** (exploitable) and a **secure endpoint** (properly protected) so you can compare the difference.
=======
Each lab contains a **vulnerable endpoint** (exploitable) Fand a **secure endpoint** (properly protected) so you can compare the difference.
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5

---

## Table of Contents

- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Labs](#running-the-labs)
- [Lab 1: JWT Unverified Signature](#lab-1-jwt-unverified-signature)
- [Lab 2: JWT alg:none Attack](#lab-2-jwt-algnone-attack)
<<<<<<< HEAD
- [Lab 3: JWT Weak Signing Key](#lab-3-jwt-weak-signing-key)
- [Lab 4: JWT JWK Header Injection](#lab-4-jwt-jwk-header-injection)
- [Lab 5: JWT jku Header Injection](#lab-5-jwt-jku-header-injection)
- [Lab 6: JWT kid Path Traversal](#lab-6-jwt-kid-path-traversal)
=======
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5
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
<<<<<<< HEAD
│   └── public/                   # Client-side UI
├── lab2-alg-none/                # Lab 2
│   ├── server.js                 # Express server (alg:none vulnerability)
│   └── public/
├── lab3-weak-signing-key/        # Lab 3
│   ├── server.js                 # Express server (weak secret vulnerability)
│   └── public/
├── lab4-jwk-header-injection/    # Lab 4
│   ├── server.js                 # Express server (JWK header injection)
│   └── public/
├── lab5-jku-header-injection/    # Lab 5
│   ├── server.js                 # Express server (jku header injection)
│   └── public/
├── lab6-kid-path-traversal/      # Lab 6
│   ├── server.js                 # Express server (kid path traversal)
│   ├── keys/                     # Directory storing server keys
│   ├── dev/                      # Simulated system directory (for dev/null)
│   └── public/
=======
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
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5
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
<<<<<<< HEAD
   USER_USERNAME=wiener
   USER_PASSWORD=peter
   JWT_SECRET=super-secret-jwt-key-2024
   LAB1_PORT=3001
   LAB2_PORT=3002
   LAB3_PORT=3003
   LAB4_PORT=3004
   LAB5_PORT=3005
   LAB6_PORT=3006
=======
   USER_USERNAME=chirayu
   USER_PASSWORD=chirayu123
   JWT_SECRET=super-secret-jwt-key-2024
   LAB1_PORT=3001
   LAB2_PORT=3002
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5
   LAB7_PORT=3007
   LAB8_PORT=3008
   ```

---

## Running the Labs

**Run a single lab:**

```bash
npm run lab1    # Starts Lab 1 on http://localhost:3001
npm run lab2    # Starts Lab 2 on http://localhost:3002
<<<<<<< HEAD
npm run lab3    # Starts Lab 3 on http://localhost:3003
npm run lab4    # Starts Lab 4 on http://localhost:3004
npm run lab5    # Starts Lab 5 on http://localhost:3005
npm run lab6    # Starts Lab 6 on http://localhost:3006
=======
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5
npm run lab7    # Starts Lab 7 on http://localhost:3007
npm run lab8    # Starts Lab 8 on http://localhost:3008
```

**Run all labs simultaneously:**

```bash
<<<<<<< HEAD
npm run all     # Starts all labs concurrently
=======
npm run all     # Starts both labs concurrently
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5
```

---

## Lab 1: JWT Unverified Signature

**Port:** `3001`
**Vulnerability:** The vulnerable endpoint uses `jwt.decode()` instead of `jwt.verify()`, so the JWT signature is **never checked**.

### How the Attack Works

<<<<<<< HEAD
1. **Login** to receive a valid JWT token.
2. **Intercept** the request to `/api/vulnerable-admin` using Burp Suite.
3. **Decode** the JWT token.
4. **Modify** the payload — change `"sub"` to `"admin"`.
=======
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
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5
5. **Base64url-encode** the modified payload, replace it in the token, and forward the request.
6. The server accepts it because `jwt.decode()` **does not verify the signature**.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate and receive JWT |
| `/api/vulnerable-admin` | GET | Uses `jwt.decode()` — signature NOT verified |
| `/api/secure-admin` | GET | Uses `jwt.verify()` — signature IS verified |
<<<<<<< HEAD
=======
| `/api/me` | GET | Returns current user info from token |
| `/logout` | POST | Clears the token cookie |

### Why the Secure Endpoint Works

The secure endpoint uses `jwt.verify(token, secret, { algorithms: ['HS256'] })` which:
- Validates the JWT signature against the server's secret key
- Rejects any modified/tampered tokens
- Only accepts HS256-signed tokens
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5

---

## Lab 2: JWT alg:none Attack

**Port:** `3002`
**Vulnerability:** The vulnerable endpoint accepts JWTs with `alg: "none"`, allowing completely **unsigned tokens**.

### How the Attack Works

<<<<<<< HEAD
1. **Login** to receive a valid JWT token.
2. **Intercept** the request to `/api/vulnerable-admin` using Burp Suite.
3. **Create a forged token** with `alg: "none"`:
   - Header: `{"alg":"none","typ":"JWT"}`
   - Payload: `{"sub":"admin",...}`
4. **Base64url-encode** both header and payload.
5. **Concatenate** with a dot and add a trailing dot (empty signature).
=======
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
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5
6. **Replace** the cookie value with the forged token and send the request.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate and receive JWT |
| `/api/vulnerable-admin` | GET | Accepts `alg: "none"` — unsigned tokens work |
| `/api/secure-admin` | GET | Only accepts `HS256` — unsigned tokens rejected |
<<<<<<< HEAD

---

## Lab 3: JWT Weak Signing Key

**Port:** `3003`
**Vulnerability:** The server uses an extremely weak secret key (`secret1`) to sign JWTs. This can be brute-forced using hashcat with a common secrets wordlist.

### How the Attack Works

1. **Login** to receive a valid JWT.
2. **Copy the JWT** from your browser cookies.
3. **Brute-force the secret** using hashcat:
   ```bash
   hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list
   ```
   This reveals the weak secret: `secret1`.
4. **Base64-encode the secret:** `echo -n 'secret1' | base64` → `c2VjcmV0MQ==`
5. **Create a JWK symmetric key** in Burp Suite's JWT Editor with the Base64-encoded secret as the `k` value.
6. **Forge a token** — change `sub` to `admin`, sign it with your key.
7. **Access the vulnerable admin panel** `/api/vulnerable-admin` to solve the lab.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate and receive JWT (signed with weak secret) |
| `/api/vulnerable-admin` | GET | Verifies with weak secret — brute-forceable |
| `/api/secure-admin` | GET | Verifies with strong secret — brute-force infeasible |

---

## Lab 4: JWT JWK Header Injection

**Port:** `3004`
**Vulnerability:** The server supports the `jwk` parameter in the JWT header and uses the embedded key for verification without checking if it came from a trusted source.

### How the Attack Works

1. **Login** to receive a valid JWT (signed with RS256).
2. **Generate your own RSA key pair** in Burp Suite's JWT Editor Keys tab.
3. **Modify the JWT payload** — change `sub` to `admin`.
4. **Use the Embedded JWK attack** in Burp: click Attack → Embedded JWK → select your key.
5. This embeds your public key in the JWT header's `jwk` parameter and signs with your private key.
6. **Send the request** to `/api/vulnerable-admin`. The server uses your embedded key to verify, granting access.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate and receive JWT (RS256) |
| `/api/vulnerable-admin` | GET | Trusts embedded `jwk` in header — injectable |
| `/api/secure-admin` | GET | Uses only server's own public key — ignores embedded JWK |

---

## Lab 5: JWT jku Header Injection

**Port:** `3005`
**Vulnerability:** The server supports the `jku` parameter in the JWT header and fetches the JWK Set from that URL for verification, **without validating if the URL belongs to a trusted domain.**

### How the Attack Works

1. **Login** to receive a valid JWT.
2. **Generate your own RSA key pair** in Burp Suite and copy the public key as a JWK.
3. **Upload the JWK** to the provided exploit server endpoint (`/exploit/jwks.json`).
4. **Modify the JWT header** — change `kid` to match your key, and add `"jku": "http://localhost:3005/exploit/jwks.json"`.
5. **Modify the payload** — change `sub` to `admin`.
6. **Sign the token** using your RSA private key (choosing "Don't modify header" in Burp).
7. **Send the request** to `/api/vulnerable-admin`. The server fetches your key from the untrusted URL, granting access.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate and receive JWT |
| `/api/vulnerable-admin` | GET | Fetches keys from ANY untrusted `jku` URL |
| `/api/secure-admin` | GET | Strict domain validation against a whitelist for the `jku` URL |
| `/exploit/jwks.json` | GET/PUT | A built-in exploit server space for hosting your malicious JWK Set |

---

## Lab 6: JWT kid Path Traversal

**Port:** `3006`
**Vulnerability:** The server retrieves the signing key from the filesystem dynamically using the `kid` parameter without sanitizing path traversal sequences (`../`), allowing an attacker to point it to an empty file.

### How the Attack Works

1. **Login** to receive a valid JWT.
2. **Generate a Symmetric Key** in Burp Suite, modifying the `k` value to `AA==` (which represents a base64 encoded null-byte).
3. **Modify the JWT header** — change `kid` to `../dev/null` (which points to an empty file).
4. **Modify the payload** — change `sub` to `admin`.
5. **Sign the token** using your newly created null-byte key.
6. **Send the request** to `/api/vulnerable-admin`. The server reads the empty file, generates a block of zero-padding, which mathematically perfectly matches the null-byte key signature. Access is granted.

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate and receive JWT |
| `/api/vulnerable-admin` | GET | Path traversal vulnerability — no sanitization on `kid` |
| `/api/secure-admin` | GET | Uses `path.basename()` to neutralize path traversal sequences |
=======
| `/api/me` | GET | Returns current user info from token |
| `/logout` | POST | Clears the token cookie |

### Why the Secure Endpoint Works

The secure endpoint uses a strict algorithm whitelist:
```js
jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })
```
- Tokens with `alg: "none"` are automatically rejected
- Only tokens signed with HS256 and the correct secret are accepted
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5

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
<<<<<<< HEAD
| Weak Signing Key | Using a guessable/common secret | Use a cryptographically strong, random key (256+ bits) |
| JWK Header Injection | Trusting `jwk` parameter from JWT header | Never verify tokens using keys embedded in the token itself |
| JKU Header Injection | Trusting `jku` URL blindly | Validate `jku` URLs against a strict whitelist of internal/trusted domains |
| kid Path Traversal | Building filesystem paths with `kid` directly | Sanitize the `kid` claim (e.g. `path.basename()`) and explicitly verify file bounds |
=======
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5
| Algorithm Confusion | Trusting the `alg` header and reusing asymmetric keys for symmetric verification | Enforce allowed algorithms; do not use PEM keys for HMAC secrets |

### General JWT Security Best Practices

1. **Always verify signatures** — use `jwt.verify()`, never `jwt.decode()` for auth.
2. **Whitelist algorithms** — explicitly specify allowed algorithms.
3. **Use strong secrets** — generate cryptographically random secret keys.
4. **Set expiration** — always include `exp` claims in your tokens.
5. **Validate claims** — check `sub`, `role`, `iss`, `aud` on the server side.
6. **Use HTTPS** — prevent token interception in transit.
