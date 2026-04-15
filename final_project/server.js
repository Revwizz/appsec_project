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