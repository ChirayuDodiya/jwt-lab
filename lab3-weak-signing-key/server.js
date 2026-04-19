/**
 * Lab 3: JWT Authentication Bypass via Weak Signing Key
 * 
 * VULNERABILITY: The server uses an extremely weak secret key ("secret1")
 * to sign and verify JWTs. This can be easily brute-forced using hashcat
 * with a wordlist of common secrets, allowing an attacker to forge tokens.
 * 
 * Port: 3003
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.LAB3_PORT || 3003;

// VULNERABLE: Extremely weak secret — easily brute-forced with hashcat
const WEAK_SECRET = 'secret1';

// SECURE: A strong, random secret key
const STRONG_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-2024';

// ==================== LOGIN ====================
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const validUsers = {
        [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD,
        [process.env.USER_USERNAME]: process.env.USER_PASSWORD
    };

    if (validUsers[username] && validUsers[username] === password) {
        // Sign with the WEAK secret — this is the vulnerability!
        const token = jwt.sign(
            { sub: username, role: username === 'admin' ? 'admin' : 'user' },
            WEAK_SECRET,
            { algorithm: 'HS256', expiresIn: '1h' }
        );

        res.cookie('token', token, { httpOnly: false });
        return res.json({ success: true, token, redirect: '/dashboard.html' });
    }

    return res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// ==================== VULNERABLE ADMIN ENDPOINT ====================
// BUG: Uses a weak secret key that can be brute-forced with hashcat
app.get('/api/vulnerable-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        // VULNERABLE: Verifies with a weak secret that can be cracked
        const decoded = jwt.verify(token, WEAK_SECRET, { algorithms: ['HS256'] });

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Congratulations! You accessed the admin panel by forging a token with the cracked secret!',
                user: decoded,
                vulnerability_explanation: 'This server uses an extremely weak signing key ("secret1") that can be brute-forced using hashcat with a common secrets wordlist. Once cracked, an attacker can sign any token they want.',
                prevention: [
                    '1. Use a cryptographically strong, random secret key (at least 256 bits).',
                    '2. Never use common words, passwords, or predictable strings as JWT secrets.',
                    '3. Store secrets securely using environment variables or a secrets manager.',
                    '4. Consider using asymmetric algorithms (RS256/ES256) where the private key never leaves the server.',
                    '5. Rotate signing keys periodically.',
                    '6. Use a key derivation function (KDF) if deriving keys from passwords.'
                ]
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            hint: 'Try brute-forcing the JWT secret key using hashcat: hashcat -a 0 -m 16500 <jwt> /path/to/jwt.secrets.list'
        });
    } catch (err) {
        return res.status(401).json({
            error: 'Token verification failed.',
            details: err.message
        });
    }
});



// ==================== SECURE ADMIN ENDPOINT ====================
// SECURE: Uses a strong secret key that cannot be easily brute-forced
app.get('/api/secure-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        // First try with strong secret (properly signed tokens)
        // Note: Tokens from this lab's login are signed with the WEAK secret,
        // so this will reject them — demonstrating why strong secrets matter
        const decoded = jwt.verify(token, STRONG_SECRET, { algorithms: ['HS256'] });

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Welcome Admin! This is the secure admin panel.',
                user: decoded,
                security_note: 'This endpoint uses a strong, random secret key. Brute-forcing it is computationally infeasible.'
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            note: 'This endpoint uses a strong signing key. The brute-force attack will not work here.'
        });
    } catch (err) {
        return res.status(401).json({
            error: 'Invalid or tampered token detected!',
            details: err.message,
            note: 'This endpoint uses a strong secret key. Tokens signed with weak secrets are rejected, and brute-forcing the strong key is infeasible.'
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
    console.log(`\nLab 3: JWT Weak Signing Key`);
    console.log(`   Running on http://localhost:${PORT}`);
    console.log(`   Weak secret: "${WEAK_SECRET}" (brute-forceable!)`);
    console.log(`   Login with: ${process.env.USER_USERNAME} / ${process.env.USER_PASSWORD}`);
    console.log(`   Admin creds: ${process.env.ADMIN_USERNAME} / ${process.env.ADMIN_PASSWORD}\n`);
});
