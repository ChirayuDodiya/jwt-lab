/**
 * Lab 7: JWT Authentication Bypass via Algorithm Confusion (HS256 <-> RSA)
 * 
 * VULNERABILITY: The vulnerable endpoint trusts the "alg" field from the JWT header
 * and uses the same RSA public key for verification regardless of algorithm type.
 * An attacker can change the algorithm from RS256 to HS256 and use the server's
 * public key (PEM) as the HMAC secret to forge a valid token.
 * 
 * Port: 3007
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.LAB7_PORT || 3007;

// ==================== RSA KEY GENERATION ====================
// Generate RSA key pair on startup (or load from file if exists)
const KEY_DIR = path.join(__dirname, 'keys');
const PRIVATE_KEY_PATH = path.join(KEY_DIR, 'private.pem');
const PUBLIC_KEY_PATH = path.join(KEY_DIR, 'public.pem');

let PRIVATE_KEY, PUBLIC_KEY;

if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
    PRIVATE_KEY = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
    PUBLIC_KEY = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
    console.log('   Loaded existing RSA key pair from keys/ directory');
} else {
    // Generate new RSA key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    PRIVATE_KEY = privateKey;
    PUBLIC_KEY = publicKey;

    // Save keys to disk
    if (!fs.existsSync(KEY_DIR)) {
        fs.mkdirSync(KEY_DIR, { recursive: true });
    }
    fs.writeFileSync(PRIVATE_KEY_PATH, PRIVATE_KEY);
    fs.writeFileSync(PUBLIC_KEY_PATH, PUBLIC_KEY);
    console.log('   Generated and saved new RSA key pair to keys/ directory');
}

// Generate a kid (key ID) for the JWKS
const KID = crypto.createHash('sha256').update(PUBLIC_KEY).digest('hex').substring(0, 16);

// ==================== HELPER: PEM to JWK ====================
function pemToJwk(pem) {
    const keyObject = crypto.createPublicKey(pem);
    const jwk = keyObject.export({ format: 'jwk' });
    return {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        kid: KID,
        alg: 'RS256',
        use: 'sig'
    };
}

// ==================== JWKS ENDPOINT ====================
// Exposes the server's public key in JWK format
app.get('/jwks.json', (req, res) => {
    const jwk = pemToJwk(PUBLIC_KEY);
    res.json({ keys: [jwk] });
});

app.get('/.well-known/jwks.json', (req, res) => {
    const jwk = pemToJwk(PUBLIC_KEY);
    res.json({ keys: [jwk] });
});

// ==================== PUBLIC KEY ENDPOINT (PEM) ====================
// Directly exposes the PEM-encoded public key
app.get('/api/public-key', (req, res) => {
    res.type('text/plain').send(PUBLIC_KEY);
});

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
        // Sign with RS256 using the RSA private key
        const token = jwt.sign(
            { sub: username, role: username === 'admin' ? 'admin' : 'user' },
            PRIVATE_KEY,
            { algorithm: 'RS256', expiresIn: '1h', keyid: KID }
        );

        res.cookie('token', token, { httpOnly: false });
        return res.json({ success: true, token, redirect: '/dashboard.html' });
    }

    return res.status(401).json({ success: false, message: 'Invalid credentials' });
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
        // VULNERABLE: Parse the header to get the algorithm
        const headerB64 = token.split('.')[0];
        const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());

        let decoded;

        if (header.alg === 'HS256') {
            // VULNERABLE: Uses the PUBLIC KEY as HMAC secret!
            // This is the core of the algorithm confusion attack.
            // The server blindly trusts the "alg" field and uses the public key
            // as a symmetric secret for HS256 verification.
            //
            // NOTE: Modern jsonwebtoken (v9+) blocks PEM keys for HS256 — that IS
            // the real-world fix. We use raw crypto.createHmac here to simulate
            // what older/vulnerable JWT libraries would do.
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
            // Normal RS256 verification with public key
            decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
        } else {
            return res.status(401).json({ error: `Unsupported algorithm: ${header.alg}` });
        }

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Congratulations! You accessed the admin panel via algorithm confusion!',
                user: decoded,
                algorithm_used: header.alg,
                vulnerability_explanation: 'This endpoint trusts the "alg" field from the JWT header. When you switched from RS256 to HS256 and signed the token using the server\'s public key as the HMAC secret, the server accepted it because it used the same public key for both asymmetric (RS256) and symmetric (HS256) verification.',
                prevention: [
                    '1. Never trust the "alg" field from the JWT header — enforce a fixed algorithm on the server side.',
                    '2. Use separate keys for different algorithm types (symmetric vs asymmetric).',
                    '3. Reject tokens that use an algorithm different from what the server expects.',
                    '4. Use JWT libraries that enforce algorithm validation and prevent key misuse.',
                    '5. Public keys must only be used for verification in asymmetric schemes, never as HMAC secrets.',
                    '6. Implement server-side authorization — validate roles from database, not just JWT payload.'
                ]
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            hint: 'Try changing the algorithm from RS256 to HS256 and signing with the public key...'
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
        // SECURE: Only allows RS256 — ignores the "alg" claim in the token header!
        // The server enforces a fixed algorithm regardless of what the token says.
        const decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Welcome Admin! This is the secure admin panel.',
                user: decoded,
                security_note: 'This endpoint enforces RS256 algorithm only. It ignores the "alg" field from the token header and only accepts RS256-signed tokens verified with the RSA public key.'
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
            note: 'The server enforces RS256 algorithm only. HS256 tokens signed with the public key are rejected.'
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

// ==================== LOGOUT ====================
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`\nLab 7: JWT Algorithm Confusion (HS256 <-> RSA)`);
    console.log(`   Running on http://localhost:${PORT}`);
    console.log(`   Login with: ${process.env.USER_USERNAME} / ${process.env.USER_PASSWORD}`);
    console.log(`   Admin creds: ${process.env.ADMIN_USERNAME} / ${process.env.ADMIN_PASSWORD}`);
    console.log(`   JWKS endpoint: http://localhost:${PORT}/jwks.json`);
    console.log(`   Public key: http://localhost:${PORT}/api/public-key\n`);
});
