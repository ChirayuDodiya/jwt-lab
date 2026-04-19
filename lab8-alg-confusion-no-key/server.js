/**
 * Lab 8: JWT Authentication Bypass via Algorithm Confusion (No Exposed Key)
 * 
 * VULNERABILITY: Same algorithm confusion as Lab 7, but the server does NOT
 * expose its public key via JWKS or any endpoint. The attacker must derive
 * the RSA public key mathematically from two valid JWT signatures using
 * tools like sig2n / rsa_sign2n.
 * 
 * NOTE: Uses 512-bit RSA keys and manual crypto signing (bypassing jsonwebtoken's
 * 2048-bit minimum) so that sig2n can reliably derive the key in a lab setting.
 * 
 * Port: 3008
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const express = require('express');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.LAB8_PORT || 3008;

// ==================== RSA KEY GENERATION ====================
// Uses 512-bit RSA keys so sig2n can derive the public key reliably.
// We bypass jsonwebtoken entirely (it enforces 2048-bit minimum for RS256)
// and use Node's crypto module directly for signing/verification.
const KEY_DIR = path.join(__dirname, 'keys');
const PRIVATE_KEY_PATH = path.join(KEY_DIR, 'private.pem');
const PUBLIC_KEY_PATH = path.join(KEY_DIR, 'public.pem');

let PRIVATE_KEY, PUBLIC_KEY;

if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
    PRIVATE_KEY = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
    PUBLIC_KEY = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
    console.log('   Loaded existing RSA key pair from keys/ directory');
} else {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 512,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    PRIVATE_KEY = privateKey;
    PUBLIC_KEY = publicKey;

    if (!fs.existsSync(KEY_DIR)) {
        fs.mkdirSync(KEY_DIR, { recursive: true });
    }
    fs.writeFileSync(PRIVATE_KEY_PATH, PRIVATE_KEY);
    fs.writeFileSync(PUBLIC_KEY_PATH, PUBLIC_KEY);
    console.log('   Generated new 512-bit RSA key pair to keys/ directory');
}

// NOTE: No JWKS endpoint, no public key endpoint!
// The public key is NOT exposed — attacker must derive it from JWT signatures.

// ==================== MANUAL JWT HELPERS ====================
// We bypass jsonwebtoken entirely to use 512-bit RSA keys.

function manualSignRS256(payload) {
    const header = { alg: 'RS256', typ: 'JWT' };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), PRIVATE_KEY);
    return `${signingInput}.${signature.toString('base64url')}`;
}

function manualVerifyRS256(token) {
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = Buffer.from(signatureB64, 'base64url');
    const isValid = crypto.verify('RSA-SHA256', Buffer.from(signingInput), PUBLIC_KEY, signature);
    if (!isValid) throw new Error('Invalid RS256 signature');
    return JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
}

// ==================== CREDENTIALS ====================
app.get('/api/credentials', (req, res) => {
    res.json({
        username: process.env.USER_USERNAME,
        password: process.env.USER_PASSWORD
    });
});

// ==================== LOGIN ====================
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const validUsers = {
        [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD,
        [process.env.USER_USERNAME]: process.env.USER_PASSWORD
    };

    if (validUsers[username] && validUsers[username] === password) {
        const now = Math.floor(Date.now() / 1000);
        const token = manualSignRS256({
            sub: username,
            role: username === 'admin' ? 'admin' : 'user',
            iat: now,
            exp: now + 3600
        });

        res.cookie('token', token, { httpOnly: false });
        return res.json({ success: true, token, redirect: '/dashboard.html' });
    }

    return res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// ==================== TOKEN COLLECTOR ENDPOINT ====================
// Helper: returns two distinct valid JWTs for the attacker to use with sig2n
app.post('/api/collect-tokens', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Not logged in' });

    try {
        const parts = token.split('.');
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

        // Generate a second token with different payload (different iat)
        const now = Math.floor(Date.now() / 1000);
        const token2 = manualSignRS256({
            sub: payload.sub,
            role: payload.role,
            session: 2,
            iat: now,
            exp: now + 3600
        });

        return res.json({
            message: 'Two valid RS256-signed JWTs for key derivation',
            token1: token,
            token2: token2,
            hint: 'Use these two tokens with: docker run --rm -it portswigger/sig2n <token1> <token2>'
        });
    } catch (err) {
        return res.status(400).json({ error: 'Failed to generate tokens', details: err.message });
    }
});

// ==================== VULNERABLE ADMIN ENDPOINT ====================
// BUG: Trusts the "alg" field from the JWT header and uses the public key
// for both RS256 verification AND as an HS256 HMAC secret!
app.get('/api/vulnerable-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        const headerB64 = token.split('.')[0];
        const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());

        let decoded;

        if (header.alg === 'HS256') {
            // VULNERABLE: Uses the PUBLIC KEY as HMAC secret!
            // The server blindly trusts the "alg" field and uses the public key
            // as a symmetric secret for HS256 verification.
            const [hdrB64, payB64, sigB64] = token.split('.');
            const hmac = crypto.createHmac('sha256', PUBLIC_KEY);
            hmac.update(`${hdrB64}.${payB64}`);
            const expectedSig = hmac.digest('base64url');

            if (sigB64 !== expectedSig) {
                return res.status(401).json({
                    error: 'Token verification failed.',
                    details: 'Invalid HMAC signature'
                });
            }

            decoded = JSON.parse(Buffer.from(payB64, 'base64url').toString());
        } else if (header.alg === 'RS256') {
            // Normal RS256 verification with public key (manual)
            decoded = manualVerifyRS256(token);
        } else {
            return res.status(401).json({ error: `Unsupported algorithm: ${header.alg}` });
        }

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Congratulations! You accessed the admin panel via algorithm confusion with a derived key!',
                user: decoded,
                algorithm_used: header.alg,
                vulnerability_explanation: 'Even though the public key was NOT exposed, you derived it from JWT signatures and used it for an algorithm confusion attack. The server trusted the "alg" header and used the public key as an HMAC secret for HS256 verification.',
                prevention: [
                    '1. Never trust the "alg" field from the JWT header — enforce a fixed algorithm on the server side.',
                    '2. Use separate keys for different algorithm types (symmetric vs asymmetric).',
                    '3. Reject tokens that use an algorithm different from what the server expects.',
                    '4. Use JWT libraries that enforce algorithm validation and prevent key misuse.',
                    '5. Public keys must only be used for verification in asymmetric schemes, never as HMAC secrets.',
                    '6. Hiding the public key is NOT a mitigation — it can be derived from signed tokens.',
                    '7. Implement server-side authorization — validate roles from database, not just JWT payload.'
                ]
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            hint: 'Derive the public key from two JWTs, then use it for algorithm confusion...'
        });
    } catch (err) {
        return res.status(401).json({
            error: 'Token verification failed.',
            details: err.message
        });
    }
});

// ==================== SECURE ADMIN ENDPOINT ====================
// SECURE: Enforces RS256 only — rejects algorithm switching
app.get('/api/secure-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        // SECURE: Always verifies with RS256 regardless of the header
        const decoded = manualVerifyRS256(token);

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Welcome Admin! This is the secure admin panel.',
                user: decoded,
                security_note: 'This endpoint enforces RS256 algorithm only. Even if the attacker derives the public key, algorithm switching is rejected.'
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            note: 'This endpoint enforces RS256 only. Algorithm confusion attacks will not work here.'
        });
    } catch (err) {
        return res.status(401).json({
            error: 'Invalid or tampered token detected!',
            details: err.message,
            note: 'The server enforces RS256 algorithm only. HS256 tokens signed with a derived key are rejected.'
        });
    }
});

// ==================== USER INFO ====================
app.get('/api/me', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Not logged in' });

    try {
        const parts = token.split('.');
        const decoded = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        return res.json({ user: decoded });
    } catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
});

// ==================== LOGOUT ====================
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`\nLab 8: JWT Algorithm Confusion (No Exposed Key)`);
    console.log(`   Running on http://localhost:${PORT}`);
    console.log(`   Login with: ${process.env.USER_USERNAME} / ${process.env.USER_PASSWORD}`);
    console.log(`   Admin creds: ${process.env.ADMIN_USERNAME} / ${process.env.ADMIN_PASSWORD}`);
    console.log(`   NOTE: No JWKS or public key endpoint — key must be derived!`);
    console.log(`   Uses 512-bit RSA key (manual crypto) for reliable sig2n derivation\n`);
});
