/**
 * Lab 6: JWT Authentication Bypass via kid Header Path Traversal
 *
 * VULNERABILITY: The server uses the "kid" (Key ID) parameter from the JWT
 * header to locate a signing key on the filesystem. It constructs a file path
 * by concatenating the keys directory with the kid value — WITHOUT sanitizing
 * path traversal sequences like "../".
 *
 * An attacker can:
 *   1. Set kid to a path traversal sequence pointing to a known empty file
 *      (e.g., ../../../../../../../dev/null on Linux, or ../dev/null in this lab)
 *   2. Sign the JWT with an empty string (or a null byte AA==)
 *   3. The server reads the empty file, gets an empty secret, and the forged
 *      signature matches → access granted.
 *
 * Port: 3006
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const express      = require('express');
const jwt          = require('jsonwebtoken');
const fs           = require('fs');
const cookieParser = require('cookie-parser');
const path         = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const PORT     = process.env.LAB6_PORT || 3006;
const KEYS_DIR = path.join(__dirname, 'keys');
const SERVER_KID = 'secret.key';  // kid used in legitimate tokens

// Read the actual server secret from the filesystem
const SERVER_SECRET = fs.readFileSync(path.join(KEYS_DIR, SERVER_KID));



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
            SERVER_SECRET,
            {
                algorithm: 'HS256',
                expiresIn: '1h',
                header: {
                    typ: 'JWT',
                    alg: 'HS256',
                    kid: SERVER_KID   // legitimate kid pointing to keys/secret.key
                }
            }
        );

        res.cookie('token', token, { httpOnly: false });
        return res.json({ success: true, token, redirect: '/dashboard.html' });
    }

    return res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// ==================== HELPER: read key from filesystem by kid ====================
function readKeyFromFile(kid) {
    const keyPath = path.join(KEYS_DIR, kid);
    return fs.readFileSync(keyPath);
}

function readKeyFromFileSafe(kid) {
    // Sanitize: strip path traversal sequences
    const sanitized = path.basename(kid);
    const keyPath   = path.join(KEYS_DIR, sanitized);
    return fs.readFileSync(keyPath);
}

// ==================== VULNERABLE ADMIN ENDPOINT ====================
// BUG: Uses the kid parameter to build a file path WITHOUT sanitization!
// Path traversal allows reading any file on the filesystem.
app.get('/api/vulnerable-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        // Decode header to read kid
        const headerB64 = token.split('.')[0];
        const header    = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
        const kid       = header.kid;

        if (!kid) {
            return res.status(400).json({
                error: 'No kid parameter in JWT header.',
                hint: 'The server expects a kid parameter to locate the signing key.'
            });
        }

        // VULNERABLE: No path traversal sanitization!
        // e.g., kid = "../dev/null" → reads lab6-kid-path-traversal/dev/null (empty file)
        let secret;
        try {
            secret = readKeyFromFile(kid);
        } catch (fileErr) {
            return res.status(400).json({
                error: `Could not read key file for kid "${kid}".`,
                details: fileErr.message,
                hint: 'Try using path traversal to point to a file with known (empty) contents.'
            });
        }

        // Verify with the key read from the filesystem
        const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: '🎉 Congratulations! You accessed the admin panel via kid Path Traversal!',
                user: decoded,
                kid_used: kid,
                vulnerability_explanation:
                    'The server used the "kid" parameter to construct a file path without sanitizing ' +
                    'path traversal sequences (../). By pointing kid to an empty file (like /dev/null ' +
                    'or dev/null), the signing secret becomes an empty string. The attacker signs the ' +
                    'token with an empty/null-byte key and the server accepts it.',
                prevention: [
                    '1. Never use the kid parameter directly in file paths without sanitization.',
                    '2. Use path.basename() to strip directory traversal sequences.',
                    '3. Maintain a whitelist or lookup table mapping kid values to keys.',
                    '4. Store keys in a database rather than the filesystem.',
                    '5. Validate that the resolved path stays within the expected keys directory.',
                    '6. Use a dedicated key management service (KMS) for production.'
                ]
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_identity: decoded.sub,
            hint: 'Try changing "sub" to "administrator" and using path traversal in kid to point to an empty file.'
        });

    } catch (err) {
        return res.status(401).json({
            error: 'Token verification failed.',
            details: err.message
        });
    }
});



// ==================== SECURE ADMIN ENDPOINT ====================
// SECURE: Uses path.basename() to strip traversal sequences from kid
app.get('/api/secure-admin', (req, res) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided. Please login first.' });
    }

    try {
        const headerB64 = token.split('.')[0];
        const header    = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
        const kid       = header.kid || SERVER_KID;

        let secret;
        try {
            // SECURE: sanitizes kid using path.basename()
            secret = readKeyFromFileSafe(kid);
        } catch (fileErr) {
            return res.status(400).json({
                error: `Key "${path.basename(kid)}" not found in authorized keys directory.`,
                security_note: 'Path traversal sequences were stripped using path.basename(). ' +
                               'Only filenames within the keys/ directory are allowed.'
            });
        }

        const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });

        if (decoded.sub === 'admin') {
            return res.json({
                success: true,
                message: 'Welcome Admin! This is the secure admin panel.',
                user: decoded,
                security_note: 'This endpoint uses path.basename() to sanitize the kid parameter. ' +
                               'Path traversal attacks are neutralized.'
            });
        }

        return res.status(403).json({
            error: 'Access denied. Admin privileges required.',
            your_role: decoded.sub,
            note: 'This endpoint sanitizes the kid parameter. Path traversal will not work here.'
        });

    } catch (err) {
        return res.status(401).json({
            error: 'Invalid or tampered token detected!',
            details: err.message,
            note: 'The server sanitized the kid parameter and used the correct key for verification.'
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

// ==================== START ====================
app.listen(PORT, () => {
    console.log(`\nLab 6: JWT kid Header Path Traversal`);
    console.log(`   Running on http://localhost:${PORT}`);
    console.log(`   Keys dir:   ${KEYS_DIR}`);
    console.log(`   Server kid: ${SERVER_KID}`);
    console.log(`   Login with: ${process.env.USER_USERNAME} / ${process.env.USER_PASSWORD}`);
    console.log(`   Admin creds: ${process.env.ADMIN_USERNAME} / ${process.env.ADMIN_PASSWORD}\n`);
});
