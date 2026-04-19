/**
 * Lab 5: JWT Authentication Bypass via jku Header Injection
 *
 * VULNERABILITY: The vulnerable endpoint reads the "jku" parameter from the
 * JWT header and fetches the JWK Set from that URL without checking whether
 * the URL belongs to a trusted domain. An attacker can:
 *   1. Generate their own RSA key pair
 *   2. Host a malicious JWK Set on the built-in exploit server (/exploit/jwks.json)
 *   3. Craft a JWT whose header points jku → exploit JWKS URL
 *   4. Sign the JWT with their own private key
 *   5. The server fetches the attacker's public key and accepts the forged token
 *
 * Port: 3005
 * Exploit server: http://localhost:3005/exploit/jwks.json  (store your JWK Set here)
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const express = require('express');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const https   = require('https');
const http    = require('http');
const url     = require('url');
const cookieParser = require('cookie-parser');
const path    = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.LAB5_PORT || 3005;

// ==================== SERVER RSA KEY PAIR ====================
// The server generates its own RSA key pair at startup
const { publicKey: serverPublicKey, privateKey: serverPrivateKey } =
    crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding:  { type: 'spki',  format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

const serverJwk = crypto.createPublicKey(serverPublicKey).export({ format: 'jwk' });
const SERVER_KID = 'server-key-lab5';

// Trusted JWKS URL (the server's own endpoint)
const TRUSTED_JWKS_URL = `http://localhost:${PORT}/.well-known/jwks.json`;
const TRUSTED_DOMAIN   = `localhost:${PORT}`;

// ==================== EXPLOIT SERVER STORAGE ====================
// Students upload their malicious JWK Set here via PUT /exploit/jwks.json
let exploitJwksBody = { keys: [] };



// ==================== HELPER: fetch JWK Set from URL ====================
function fetchJwks(jwksUrl) {
    return new Promise((resolve, reject) => {
        const parsedUrl = url.parse(jwksUrl);
        const transport = parsedUrl.protocol === 'https:' ? https : http;
        const req = transport.get(jwksUrl, { timeout: 3000 }, (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch (e) { reject(new Error('Invalid JSON in JWKS response')); }
            });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('JWKS fetch timed out')); });
    });
}

// ==================== SERVER'S OWN JWKS ENDPOINT ====================
app.get('/.well-known/jwks.json', (req, res) => {
    res.json({
        keys: [{ ...serverJwk, kid: SERVER_KID, use: 'sig', alg: 'RS256' }]
    });
});

// ==================== EXPLOIT SERVER ENDPOINTS ====================
// GET  – retrieve whatever is stored in the exploit JWKS
app.get('/exploit/jwks.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.json(exploitJwksBody);
});

// PUT – store the attacker's JWK Set (simulates "Store" on the exploit server)
app.put('/exploit/jwks.json', (req, res) => {
    exploitJwksBody = req.body;
    res.json({ success: true, message: 'Exploit JWKS stored successfully.' });
});

// ==================== LOGIN ====================
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const validUsers = {
        [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD,
        [process.env.USER_USERNAME]: process.env.USER_PASSWORD
    };

    if (validUsers[username] && validUsers[username] === password) {
        const token = jwt.sign(
            { sub: username, role: username === 'admin' ? 'admin' : 'user' },
            serverPrivateKey,
            {
                algorithm: 'RS256',
                expiresIn: '1h',
                header: {
                    typ: 'JWT',
                    alg: 'RS256',
                    kid: SERVER_KID,
                    jku: TRUSTED_JWKS_URL   // server sets its own trusted jku
                }
            }
        );

        res.cookie('token', token, { httpOnly: false });
        return res.json({ success: true, token, redirect: '/dashboard.html' });
    }

    return res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// ==================== VULNERABLE ADMIN ENDPOINT ====================
// BUG: Fetches the public key from whatever jku URL is in the JWT header —
//      no domain validation is performed!
app.get('/api/vulnerable-admin', async (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        // Decode header — do NOT verify yet
        const headerB64 = token.split('.')[0];
        const header    = JSON.parse(Buffer.from(headerB64, 'base64url').toString());

        if (!header.jku) {
            return res.status(400).json({
                error: 'No jku parameter found in JWT header.',
                hint: 'Add a jku parameter pointing to your exploit JWKS URL.'
            });
        }

        // VULNERABLE: fetches the JWKS from whatever URL the attacker provides — no domain check!
        let jwks;
        try {
            jwks = await fetchJwks(header.jku);
        } catch (fetchErr) {
            return res.status(400).json({
                error: `Failed to fetch JWKS from jku URL: ${header.jku}`,
                details: fetchErr.message
            });
        }

        // Find the key matching the kid in the header
        const kid      = header.kid;
        const jwkEntry = jwks.keys?.find(k => k.kid === kid) || jwks.keys?.[0];

        if (!jwkEntry) {
            return res.status(400).json({ error: 'No matching key found in JWKS.' });
        }

        const pubKey = crypto.createPublicKey({ key: jwkEntry, format: 'jwk' })
                             .export({ type: 'spki', format: 'pem' });

        // Verify with the fetched (potentially attacker-controlled) key
        const decoded = jwt.verify(token, pubKey, { algorithms: ['RS256'] });

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: '🎉 Congratulations! You accessed the admin panel via jku Header Injection!',
                user: decoded,
                vulnerability_explanation:
                    'This server reads the "jku" parameter from the JWT header and fetches the JWK Set ' +
                    'from that URL without verifying that the URL belongs to a trusted domain. ' +
                    'An attacker can host their own JWKS, point jku to it, sign the token with their ' +
                    'private key, and the server will accept it as valid.',
                prevention: [
                    '1. Validate that the jku URL belongs to a trusted domain before fetching.',
                    '2. Maintain a server-side allowlist of approved JWKS URLs.',
                    '3. Ignore jku/jwk parameters in JWT headers — use only your own JWKS endpoint.',
                    '4. Never let clients dictate where the server should fetch signing keys from.',
                    '5. Use a signed or pinned JWKS with key rotation managed internally.',
                    '6. Apply strict URL parsing: check scheme, host, and port explicitly.'
                ]
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_identity: decoded.sub,
            hint: 'Try changing the "sub" claim to "administrator" and point jku to your exploit JWKS.'
        });

    } catch (err) {
        return res.status(401).json({
            error: 'Token verification failed.',
            details: err.message
        });
    }
});



// ==================== SECURE ADMIN ENDPOINT ====================
// SECURE: Validates that jku URL belongs to the trusted domain before fetching.
app.get('/api/secure-admin', async (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        const headerB64 = token.split('.')[0];
        const header    = JSON.parse(Buffer.from(headerB64, 'base64url').toString());

        let pubKey = serverPublicKey; // default: use server's own key

        if (header.jku) {
            // SECURE: Check that the jku URL's host matches the trusted domain
            const parsedJku = url.parse(header.jku);
            const jkuHost   = parsedJku.host; // includes port

            if (jkuHost !== TRUSTED_DOMAIN) {
                return res.status(401).json({
                    error: 'jku URL host is not trusted!',
                    provided_host: jkuHost,
                    trusted_host: TRUSTED_DOMAIN,
                    security_note: 'This endpoint validates the jku URL against a trusted domain allowlist. ' +
                                   'Pointing jku to an external or attacker-controlled host is rejected.'
                });
            }

            // Host is trusted — fetch from allowed URL
            const jwks     = await fetchJwks(header.jku);
            const kid      = header.kid;
            const jwkEntry = jwks.keys?.find(k => k.kid === kid) || jwks.keys?.[0];

            if (!jwkEntry) return res.status(400).json({ error: 'No matching key found in JWKS.' });

            pubKey = crypto.createPublicKey({ key: jwkEntry, format: 'jwk' })
                           .export({ type: 'spki', format: 'pem' });
        }

        const decoded = jwt.verify(token, pubKey, { algorithms: ['RS256'] });

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Welcome Admin! This is the secure admin panel.',
                user: decoded,
                security_note: 'This endpoint validates the jku URL against a trusted domain allowlist. ' +
                               'Your external JWKS was rejected because it does not belong to the trusted domain.'
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            note: 'This endpoint validates the jku URL. Pointing to an external host is blocked.'
        });

    } catch (err) {
        return res.status(401).json({
            error: 'Invalid or tampered token detected!',
            details: err.message,
            note: 'The server validated the jku URL domain and rejected an untrusted key source.'
        });
    }
});

// ==================== USER INFO ====================
app.get('/api/me', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Not logged in' });

    const decoded = jwt.decode(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid token' });

    return res.json({ user: decoded });
});

// ==================== SERVER PUBLIC KEY (reference) ====================
app.get('/api/server-key', (req, res) => {
    return res.json({
        info: "This is the server's public key used to verify legitimate tokens.",
        jwks_url: TRUSTED_JWKS_URL,
        jwk: { ...serverJwk, kid: SERVER_KID, use: 'sig', alg: 'RS256' }
    });
});

// ==================== LOGOUT ====================
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ success: true });
});

// ==================== START ====================
app.listen(PORT, () => {
    console.log(`\nLab 5: JWT jku Header Injection`);
    console.log(`   Running on       http://localhost:${PORT}`);
    console.log(`   Server JWKS:     http://localhost:${PORT}/.well-known/jwks.json`);
    console.log(`   Exploit JWKS:    http://localhost:${PORT}/exploit/jwks.json`);
    console.log(`   Login with:      ${process.env.USER_USERNAME} / ${process.env.USER_PASSWORD}`);
    console.log(`   Admin creds:     ${process.env.ADMIN_USERNAME} / ${process.env.ADMIN_PASSWORD}\n`);
});
