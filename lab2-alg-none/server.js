/**
 * Lab 2: JWT Authentication Bypass via Accepting Unsigned Tokens (alg: "none")
 * 
 * VULNERABILITY: The vulnerable endpoint accepts JWTs with algorithm "none",
 * which means no signature is required. An attacker can forge tokens by setting
 * the algorithm to "none" and removing the signature.
 * 
 * Port: 3002
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

const PORT = process.env.LAB2_PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-2024';

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
            JWT_SECRET,
            { algorithm: 'HS256', expiresIn: '1h' }
        );

        res.cookie('token', token, { httpOnly: false });
        return res.json({ success: true, token, redirect: '/dashboard.html' });
    }

    return res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// ==================== VULNERABLE ADMIN ENDPOINT ====================
// BUG: Accepts tokens with alg: "none" — no signature verification!
app.get('/api/vulnerable-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        // VULNERABLE: allows algorithm "none" which requires no signature
        // First, check if the token uses alg: "none" — if so, accept it without signature check
        const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
        let decoded;

        if (header.alg && header.alg.toLowerCase() === 'none') {
            // Simulate vulnerable behavior: accept unsigned tokens
            decoded = jwt.decode(token);
            if (!decoded) throw new Error('Invalid token payload');
        } else {
            // For other algorithms, verify normally
            decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        }

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Congratulations! You accessed the admin panel using alg:none attack!',
                user: decoded,
                vulnerability_explanation: 'This endpoint accepted tokens with algorithm "none". The server was configured to allow unsigned tokens, meaning anyone can forge a valid token.',
                prevention: [
                    '1. Never include "none" in the list of allowed algorithms.',
                    '2. Always explicitly specify allowed algorithms: { algorithms: ["HS256"] }',
                    '3. Use jwt.verify() with a strict algorithm whitelist.',
                    '4. Some JWT libraries accept "none" by default — always check your library\'s configuration.',
                    '5. Validate the "alg" header claim on the server side before processing.',
                    '6. Consider using asymmetric algorithms (RS256) for better security.'
                ]
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            hint: 'Try creating a token with algorithm "none" and no signature...'
        });
    } catch (err) {
        return res.status(401).json({
            error: 'Token verification failed.',
            details: err.message
        });
    }
});

// ==================== SECURE ADMIN ENDPOINT ====================
// SECURE: Only accepts HS256 — rejects "none" algorithm
app.get('/api/secure-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        // SECURE: Only allows HS256 — "none" algorithm is rejected!
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Welcome Admin! This is the secure admin panel.',
                user: decoded,
                security_note: 'This endpoint only accepts HS256 algorithm. Tokens with alg:"none" are rejected.'
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            note: 'This endpoint only accepts HS256 tokens. The alg:none attack will not work here.'
        });
    } catch (err) {
        return res.status(401).json({
            error: 'Invalid or tampered token detected!',
            details: err.message,
            note: 'The server only accepts HS256 signed tokens. alg:none tokens are rejected.'
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
    console.log(`\nLab 2: JWT alg:none Attack`);
    console.log(`   Running on http://localhost:${PORT}`);
    console.log(`   Login with: ${process.env.USER_USERNAME} / ${process.env.USER_PASSWORD}`);
    console.log(`   Admin creds: ${process.env.ADMIN_USERNAME} / ${process.env.ADMIN_PASSWORD}\n`);
});
