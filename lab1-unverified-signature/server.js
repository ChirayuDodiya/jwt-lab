/**
 * Lab 1: JWT Authentication Bypass via Unverified Signature
 * 
 * VULNERABILITY: The vulnerable endpoint decodes the JWT without verifying
 * the signature. An attacker can modify the payload (e.g., change "sub" to "admin")
 * and the server will trust it.
 * 
 * Port: 3001
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

const PORT = process.env.LAB1_PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-2024';

// ==================== LOGIN ====================
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Check credentials against .env
    const validUsers = {
        [process.env.ADMIN_USERNAME]: process.env.ADMIN_PASSWORD,
        [process.env.USER_USERNAME]: process.env.USER_PASSWORD
    };

    if (validUsers[username] && validUsers[username] === password) {
        // Create JWT with user info
        const token = jwt.sign(
            { sub: username, role: username === 'admin' ? 'admin' : 'user' },
            JWT_SECRET,
            { algorithm: 'HS256', expiresIn: '1h' }
        );

        res.cookie('token', token, { httpOnly: false }); // httpOnly false so JS can read it for demo
        return res.json({ success: true, token, redirect: '/dashboard.html' });
    }

    return res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// ==================== VULNERABLE ADMIN ENDPOINT ====================
// BUG: Uses jwt.decode() instead of jwt.verify() — does NOT check signature!
app.get('/api/vulnerable-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    // VULNERABLE: jwt.decode() does NOT verify the signature!
    const decoded = jwt.decode(token);

    if (!decoded) {
        return res.status(401).json({ error: 'Invalid token format.' });
    }

    if (decoded.sub === 'admin') {
        return res.json({
            success: true,
            message: 'Congratulations! You accessed the admin panel!',
            user: decoded,
            vulnerability_explanation: 'This endpoint used jwt.decode() instead of jwt.verify(). The signature was NEVER checked, so you could modify the payload freely.',
            prevention: [
                '1. Always use jwt.verify() instead of jwt.decode() to validate tokens.',
                '2. jwt.decode() only decodes the payload — it does NOT verify the signature.',
                '3. Never trust data from a JWT without verifying its signature first.',
                '4. Use a strong, random secret key for signing tokens.',
                '5. Implement proper role-based access control on the server side.'
            ]
        });
    }

    return res.status(403).json({
        error: 'Access denied. Admin privileges required.',
        your_role: decoded.sub,
        hint: 'Try modifying the JWT payload to change your identity...'
    });
});

// ==================== SECURE ADMIN ENDPOINT ====================
// SECURE: Uses jwt.verify() which checks the signature
app.get('/api/secure-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        // SECURE: jwt.verify() checks the signature!
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Welcome Admin! This is the secure admin panel.',
                user: decoded,
                security_note: 'This endpoint uses jwt.verify() which validates the signature. Modified tokens will be rejected.'
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            note: 'This endpoint properly verifies the JWT signature. You cannot bypass this by modifying the token.'
        });
    } catch (err) {
        return res.status(401).json({
            error: 'Invalid or tampered token detected!',
            details: err.message,
            note: 'The server verified the JWT signature and detected tampering.'
        });
    }
});

// ==================== USER INFO (for dashboard) ====================
app.get('/api/me', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Not logged in' });

    const decoded = jwt.decode(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid token' });

    return res.json({ user: decoded });
});

<<<<<<< HEAD
// ==================== CREDENTIALS (for index.html) ====================
app.get('/api/credentials', (req, res) => {
    res.json({
        username: process.env.USER_USERNAME || 'wiener',
        password: process.env.USER_PASSWORD || 'peter'
    });
});

=======
>>>>>>> eb2aa1a73d0a937a559764f7cd2d99ba1491b0f5
// ==================== LOGOUT ====================
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`\nLab 1: JWT Unverified Signature`);
    console.log(`   Running on http://localhost:${PORT}`);
    console.log(`   Login with: ${process.env.USER_USERNAME} / ${process.env.USER_PASSWORD}`);
    console.log(`   Admin creds: ${process.env.ADMIN_USERNAME} / ${process.env.ADMIN_PASSWORD}\n`);
});
