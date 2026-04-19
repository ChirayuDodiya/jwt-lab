/**
 * Lab 4: JWT Authentication Bypass via JWK Header Injection
 * 
 * VULNERABILITY: The vulnerable endpoint trusts the "jwk" parameter embedded
 * in the JWT header to verify the token. An attacker can generate their own
 * RSA key pair, embed their public key in the JWT header, sign the token with
 * their private key, and the server will accept it as valid.
 * 
 * Port: 3004
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.LAB4_PORT || 3004;

// Generate the server's RSA key pair on startup
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Export public key as JWK for reference
const serverJwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
const SERVER_KID = 'server-key-1';

// ==================== LOGIN ====================
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const validUsers = {
        [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD,
        [process.env.USER_USERNAME]: process.env.USER_PASSWORD
    };

    if (validUsers[username] && validUsers[username] === password) {
        // Sign with the server's RSA private key (RS256)
        const token = jwt.sign(
            { sub: username, role: username === 'admin' ? 'admin' : 'user' },
            privateKey,
            {
                algorithm: 'RS256',
                expiresIn: '1h',
                keyid: SERVER_KID,
                header: {
                    typ: 'JWT',
                    alg: 'RS256',
                    kid: SERVER_KID
                }
            }
        );

        res.cookie('token', token, { httpOnly: false });
        return res.json({ success: true, token, redirect: '/dashboard.html' });
    }

    return res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// ==================== VULNERABLE ADMIN ENDPOINT ====================
// BUG: Trusts the "jwk" parameter from the JWT header to verify the token!
app.get('/api/vulnerable-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        // Decode header to check for embedded JWK
        const headerB64 = token.split('.')[0];
        const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());

        let decoded;

        if (header.jwk) {
            // VULNERABLE: Trusts the JWK embedded in the token header!
            // The server uses the attacker-supplied public key to verify the token.
            // Since the attacker signed it with the matching private key, verification passes.
            const embeddedKey = crypto.createPublicKey({ key: header.jwk, format: 'jwk' });
            const embeddedPem = embeddedKey.export({ type: 'spki', format: 'pem' });
            decoded = jwt.verify(token, embeddedPem, { algorithms: ['RS256'] });
        } else {
            // Normal verification with server's public key
            decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        }

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Congratulations! You accessed the admin panel via JWK header injection!',
                user: decoded,
                vulnerability_explanation: 'This server trusts the "jwk" parameter embedded in the JWT header. An attacker can generate their own RSA key pair, embed the public key in the header, and sign the token with their private key — the server will accept it.',
                prevention: [
                    '1. Never trust JWK keys embedded in the JWT header for verification.',
                    '2. Always verify tokens against a server-side key store or JWKS endpoint.',
                    '3. Maintain a whitelist of trusted public keys on the server.',
                    '4. If using "kid", validate it against a known set of key IDs.',
                    '5. Use a well-configured JWKS endpoint with key rotation.',
                    '6. Strip or ignore "jwk" and "jku" parameters from incoming JWT headers.'
                ]
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            hint: 'Try embedding your own JWK public key in the JWT header and signing with your private key...'
        });
    } catch (err) {
        return res.status(401).json({
            error: 'Token verification failed.',
            details: err.message
        });
    }
});



// ==================== SECURE ADMIN ENDPOINT ====================
// SECURE: Only uses the server's own public key — ignores embedded JWK
app.get('/api/secure-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        // SECURE: Always uses the server's public key — ignores any embedded JWK
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Welcome Admin! This is the secure admin panel.',
                user: decoded,
                security_note: 'This endpoint ignores any JWK embedded in the token header. It only uses the server\'s own public key for verification.'
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            note: 'This endpoint uses only the server\'s public key. JWK header injection will not work here.'
        });
    } catch (err) {
        return res.status(401).json({
            error: 'Invalid or tampered token detected!',
            details: err.message,
            note: 'This endpoint only trusts the server\'s public key. Embedded JWK keys in the header are ignored.'
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

// ==================== SERVER PUBLIC KEY (for reference) ====================
app.get('/api/server-key', (req, res) => {
    return res.json({
        info: 'This is the server\'s public key. The vulnerable endpoint also accepts keys embedded in the JWT header.',
        jwk: { ...serverJwk, kid: SERVER_KID, use: 'sig', alg: 'RS256' }
    });
});

// ==================== LOGOUT ====================
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`\nLab 4: JWT JWK Header Injection`);
    console.log(`   Running on http://localhost:${PORT}`);
    console.log(`   Login with: ${process.env.USER_USERNAME} / ${process.env.USER_PASSWORD}`);
    console.log(`   Admin creds: ${process.env.ADMIN_USERNAME} / ${process.env.ADMIN_PASSWORD}\n`);
});
