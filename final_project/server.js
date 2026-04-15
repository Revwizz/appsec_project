/**
 * FILE: server.js
 * PROJECT: SECU2000 - Secure Student Portal
 * PROGRAMMER: Ritik Vyas
 * DESCRIPTION:
 *   Main application server for the Secure Student Portal.
 *   Implements layered architecture:
 *     - Presentation Layer: EJS views
 *     - Application Layer: Express routes
 *     - Security Layer: Middleware (auth, RBAC, rate limiting, validation)
 *     - Data Layer: SQLite database
 * 
 * OWASP TOP 10 COVERAGE:
 *   - A01: Broken Access Control (RBAC middleware)
 *   - A03: Injection (parameterized queries in secure routes)
 *   - A05: Security Misconfiguration (Helmet, secure headers, error handling)
 *   - A07: Authentication Failures (bcrypt, rate limiting, strong session)
 *   - A09: Logging & Monitoring (Winston, audit_log table)
 * 
 * THREAT SURFACE:
 *   - Login form (authentication)
 *   - Search form (query parameters)
 *   - File upload (profile/document upload)
 *   - Admin panel (role-based access)
 *   - REST APIs (Express routes)
 */

// ============================================
// DEPENDENCIES
// ============================================
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const db = require('./database');
const multer = require('multer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// CREATE REQUIRED DIRECTORIES
// ============================================
// Ensure logs and uploads directories exist
if (!fs.existsSync('logs')) fs.mkdirSync('logs');
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

// ============================================
// SECURITY MIDDLEWARE
// ============================================

/**
 * Helmet.js sets various HTTP headers to prevent common attacks:
 * - XSS Protection
 * - Clickjacking prevention (X-Frame-Options)
 * - MIME type sniffing prevention
 * OWASP A05: Security Misconfiguration
 */
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts for EJS simplicity
            styleSrc: ["'self'", "'unsafe-inline'"],
        },
    },
}));

// Parse URL-encoded bodies (form submissions)
app.use(express.urlencoded({ extended: true }));

// Serve static files from /public
app.use(express.static('public'));

/**
 * Session configuration
 * Uses secure defaults:
 * - HttpOnly cookies (prevent XSS access)
 * - Secure flag in production (requires HTTPS)
 * OWASP A07: Authentication Failures
 */
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_development_secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, // Set to true if using HTTPS
        maxAge: 60 * 60 * 1000 // 1 hour
    }
}));

// Set EJS as the view engine
app.set('view engine', 'ejs');

// ============================================
// LOGGING CONFIGURATION
// ============================================
/**
 * Winston structured logger
 * Writes to console and files for audit trail
 * OWASP A09: Security Logging & Monitoring
 */
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        // Write errors to error.log
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error' 
        }),
        // Write all logs to combined.log
        new winston.transports.File({ 
            filename: 'logs/combined.log' 
        }),
        // Also log to console during development
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

/**
 * FUNCTION: auditLog(action, user)
 * DESCRIPTION:
 *   Logs security-relevant events to both database and Winston.
 *   Provides non-repudiation for admin actions.
 * PARAMETERS:
 *   action - Description of the event
 *   user   - Username associated with the event
 */
function auditLog(action, user = 'system') {
    const timestamp = new Date().toISOString();
    db.run('INSERT INTO audit_log (action, user) VALUES (?, ?)', 
        [action, user],
        (err) => {
            if (err) logger.error(`Audit log DB error: ${err.message}`);
        }
    );
    logger.info(`${action} - User: ${user}`);
}

// ============================================
// RATE LIMITING
// ============================================
/**
 * Rate limiter for login endpoint
 * Prevents brute-force attacks
 * OWASP A07: Authentication Failures
 */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: 'Too many login attempts. Please try again after 15 minutes.',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        auditLog('Rate limit exceeded on login', req.body.username || 'unknown');
        res.status(429).send('Too many login attempts. Please try again later.');
    }
});

// ============================================
// FILE UPLOAD CONFIGURATIONS
// ============================================

/**
 * VULNERABLE UPLOAD CONFIGURATION
 * No restrictions - accepts any file type and size
 * FOR DEMONSTRATION PURPOSES ONLY
 */
const vulnerableUpload = multer({ 
    dest: 'uploads/' 
});

/**
 * SECURE UPLOAD CONFIGURATION
 * Implements file type and size restrictions
 * OWASP A05: Security Misconfiguration
 * OWASP A01: Prevents malicious file uploads
 */
const secureUpload = multer({
    dest: 'uploads/',
    limits: { 
        fileSize: 1 * 1024 * 1024 // 1MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedMimes = ['image/png', 'image/jpeg', 'application/pdf'];
        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only PNG, JPEG, and PDF are allowed.'));
        }
    }
});

// ============================================
// AUTHENTICATION & AUTHORIZATION MIDDLEWARE
// ============================================

/**
 * FUNCTION: isAuthenticated(req, res, next)
 * DESCRIPTION:
 *   Middleware to ensure user is logged in.
 *   Redirects to login page if not authenticated.
 * PARAMETERS:
 *   req, res, next - Express middleware parameters
 */
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.redirect('/login');
}

/**
 * FUNCTION: isAdmin(req, res, next)
 * DESCRIPTION:
 *   Middleware to enforce Role-Based Access Control (RBAC).
 *   Only users with 'admin' role can proceed.
 *   Returns 403 Forbidden for unauthorized access.
 * OWASP A01: Broken Access Control
 * PARAMETERS:
 *   req, res, next - Express middleware parameters
 */
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') {
        return next();
    }
    auditLog(`UNAUTHORIZED ACCESS ATTEMPT to admin area`, 
        req.session.user?.username || 'unauthenticated');
    res.status(403).render('error', { 
        message: 'Access Denied: Administrators Only',
        user: req.session.user
    });
}

console.log('Server initialized with security middleware.');

// ============================================
// ROUTES: AUTHENTICATION
// ============================================

/**
 * GET /
 * Redirects root to login page
 */
app.get('/', (req, res) => {
    res.redirect('/login');
});

/**
 * GET /login
 * Renders the login form
 */
app.get('/login', (req, res) => {
    // If already logged in, redirect to dashboard
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.render('login', { error: null });
});

/**
 * POST /login
 * Processes login form submission
 * - Validates credentials against database
 * - Uses bcrypt for password verification (A07)
 * - Rate limited to prevent brute force (A07)
 * - Logs all attempts (A09)
 * 
 * SECURITY NOTES:
 * - Generic error message prevents user enumeration
 * - Password is never stored in plain text
 */
app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    
    // Input validation
    if (!username || !password) {
        auditLog('Login attempt with missing credentials', username || 'unknown');
        return res.render('login', { error: 'Username and password are required.' });
    }
    
    // Query database for user
    // Parameterized query prevents SQL injection (A03)
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            logger.error(`Database error during login: ${err.message}`);
            return res.render('login', { error: 'An error occurred. Please try again.' });
        }
        
        // User not found - generic error prevents enumeration
        if (!user) {
            auditLog(`Failed login - user not found: ${username}`, username);
            return res.render('login', { error: 'Invalid username or password.' });
        }
        
        // Verify password using bcrypt
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            // Successful login - create session
            req.session.user = { 
                id: user.id, 
                username: user.username, 
                role: user.role 
            };
            auditLog(`Successful login`, username);
            return res.redirect('/dashboard');
        } else {
            // Wrong password
            auditLog(`Failed login - wrong password: ${username}`, username);
            return res.render('login', { error: 'Invalid username or password.' });
        }
    });
});

/**
 * GET /logout
 * Destroys session and redirects to login
 */
app.get('/logout', (req, res) => {
    const username = req.session.user?.username;
    req.session.destroy((err) => {
        if (err) {
            logger.error(`Logout error: ${err.message}`);
        }
        auditLog(`User logged out`, username);
        res.redirect('/login');
    });
});

/**
 * GET /dashboard
 * Main dashboard after login - displays available features
 */
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', { user: req.session.user });
});

// ============================================
// ROUTES: SEARCH FUNCTIONALITY
// ============================================

/**
 * GET /search-vulnerable
 * INTENTIONALLY VULNERABLE SEARCH - SQL INJECTION
 * FOR DEMONSTRATION PURPOSES ONLY
 * 
 * VULNERABILITY: String concatenation in SQL query
 * RISK: Attacker can extract all data or modify database
 * OWASP A03: Injection
 * 
 * Try entering: ' OR '1'='1
 * This will return ALL records in the grades table.
 */
app.get('/search-vulnerable', isAuthenticated, (req, res) => {
    const query = req.query.q || '';
    
    // VULNERABLE: String concatenation - DO NOT USE IN PRODUCTION
    const sql = `SELECT * FROM grades WHERE student_name LIKE '%${query}%' OR course LIKE '%${query}%'`;
    
    logger.warn(`VULNERABLE search executed with query: ${query} by ${req.session.user.username}`);
    
    db.all(sql, [], (err, rows) => {
        if (err) {
            logger.error(`SQL Error in vulnerable search: ${err.message}`);
            return res.send('Database error occurred.');
        }
        res.render('search', { 
            results: rows, 
            query: query, 
            mode: 'VULNERABLE (SQL Injection Possible)',
            user: req.session.user 
        });
    });
});

/**
 * GET /search
 * SECURE SEARCH - PARAMETERIZED QUERY
 * 
 * SECURITY: Uses parameterized queries to prevent SQL injection
 * OWASP A03: Injection (Mitigated)
 * 
 * The same payload ' OR '1'='1 will return no results
 * because it's treated as a literal string, not SQL code.
 */
app.get('/search', isAuthenticated, (req, res) => {
    const query = req.query.q || '';
    
    // SECURE: Parameterized query using placeholders
    const sql = `SELECT * FROM grades WHERE student_name LIKE ? OR course LIKE ?`;
    const searchPattern = `%${query}%`;
    
    auditLog(`Secure search executed`, req.session.user.username);
    
    db.all(sql, [searchPattern, searchPattern], (err, rows) => {
        if (err) {
            logger.error(`SQL Error in secure search: ${err.message}`);
            return res.send('Database error occurred.');
        }
        res.render('search', { 
            results: rows, 
            query: query, 
            mode: 'SECURE (Parameterized Query)',
            user: req.session.user 
        });
    });
});

// ============================================
// ROUTES: FILE UPLOAD
// ============================================

/**
 * GET /upload
 * Renders the file upload form
 */
app.get('/upload', isAuthenticated, (req, res) => {
    res.render('upload', { user: req.session.user });
});

/**
 * POST /upload-vulnerable
 * VULNERABLE FILE UPLOAD - No restrictions
 * Accepts any file type, any size
 * FOR DEMONSTRATION PURPOSES ONLY
 * 
 * RISKS:
 * - Malicious file upload (web shells)
 * - Denial of Service (large files)
 * - Information disclosure
 */
app.post('/upload-vulnerable', isAuthenticated, vulnerableUpload.single('file'), (req, res) => {
    if (!req.file) {
        return res.send('No file uploaded.');
    }
    
    // Store file metadata
    db.run('INSERT INTO files (filename, path, uploaded_by) VALUES (?, ?, ?)',
        [req.file.originalname, req.file.path, req.session.user.id],
        (err) => {
            if (err) {
                logger.error(`Database error on vulnerable upload: ${err.message}`);
                return res.send('Database error.');
            }
            auditLog(`File uploaded (VULNERABLE): ${req.file.originalname}`, 
                req.session.user.username);
            
            res.send(`
                <h2>File Uploaded (VULNERABLE)</h2>
                <p><strong>Warning:</strong> No file type or size restrictions were enforced.</p>
                <p>Filename: ${req.file.originalname}</p>
                <p>Size: ${req.file.size} bytes</p>
                <p>Path: ${req.file.path}</p>
                <a href="/dashboard">Back to Dashboard</a>
            `);
        }
    );
});

/**
 * POST /upload
 * SECURE FILE UPLOAD - With validation
 * 
 * SECURITY CONTROLS:
 * - File size limit: 1MB
 * - MIME type validation: only PNG, JPEG, PDF
 * - Files stored with random names to prevent path traversal
 * OWASP A05: Security Misconfiguration (Mitigated)
 */
app.post('/upload', isAuthenticated, (req, res, next) => {
    secureUpload.single('file')(req, res, (err) => {
        if (err) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                auditLog(`Upload rejected - file too large`, req.session.user.username);
                return res.status(400).send('File too large. Maximum size is 1MB.');
            }
            if (err.message.includes('Invalid file type')) {
                auditLog(`Upload rejected - invalid file type`, req.session.user.username);
                return res.status(400).send('Invalid file type. Only PNG, JPEG, and PDF are allowed.');
            }
            return res.status(500).send('Upload error.');
        }
        
        if (!req.file) {
            return res.send('No file uploaded.');
        }
        
        // Store file metadata in database
        db.run('INSERT INTO files (filename, path, uploaded_by) VALUES (?, ?, ?)',
            [req.file.originalname, req.file.path, req.session.user.id],
            (dbErr) => {
                if (dbErr) {
                    logger.error(`Database error on secure upload: ${dbErr.message}`);
                    return res.send('Database error.');
                }
                auditLog(`File uploaded (SECURE): ${req.file.originalname}`, 
                    req.session.user.username);
                
                res.send(`
                    <h2>File Uploaded (SECURE)</h2>
                    <p>Validation: File type and size checked</p>
                    <p>Filename: ${req.file.originalname}</p>
                    <p>Size: ${req.file.size} bytes</p>
                    <a href="/dashboard">Back to Dashboard</a>
                `);
            }
        );
    });
});
// ============================================
// ROUTES: ADMIN PANEL
// ============================================

/**
 * GET /admin-vulnerable
 * VULNERABLE ADMIN PANEL - No role check
 * Any authenticated user can access
 * FOR DEMONSTRATION PURPOSES ONLY
 * 
 * VULNERABILITY: Missing authorization check
 * OWASP A01: Broken Access Control
 */
app.get('/admin-vulnerable', isAuthenticated, (req, res) => {
    // WARNING: No role check - any logged-in user can see this
    auditLog(`Accessed VULNERABLE admin panel`, req.session.user.username);
    
    db.all('SELECT * FROM grades ORDER BY id', [], (err, rows) => {
        if (err) {
            logger.error(`Database error in admin-vulnerable: ${err.message}`);
            return res.send('Database error.');
        }
        res.render('admin', { 
            grades: rows, 
            mode: 'VULNERABLE (No Role Check)',
            user: req.session.user 
        });
    });
});

/**
 * GET /admin
 * SECURE ADMIN PANEL - RBAC enforced
 * Only users with 'admin' role can access
 * 
 * SECURITY: isAdmin middleware checks user.role
 * OWASP A01: Broken Access Control (Mitigated)
 */
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    auditLog(`Accessed SECURE admin panel`, req.session.user.username);
    
    db.all('SELECT * FROM grades ORDER BY id', [], (err, rows) => {
        if (err) {
            logger.error(`Database error in admin: ${err.message}`);
            return res.send('Database error.');
        }
        res.render('admin', { 
            grades: rows, 
            mode: 'SECURE (RBAC Enforced)',
            user: req.session.user 
        });
    });
});