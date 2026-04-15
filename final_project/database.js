/**
 * FILE: database.js
 * PROJECT: SECU2000 - Secure Student Portal
 * PROGRAMMER: [Your Name]
 * DESCRIPTION:
 *   Database configuration and schema definition using SQLite.
 *   Creates four tables with meaningful relationships:
 *   - users: stores credentials and roles
 *   - grades: student grade records (for search demo)
 *   - files: uploaded file metadata with foreign key to users
 *   - audit_log: security event logging for repudiation prevention
 * 
 * OWASP COVERAGE:
 *   - A09: Security Logging & Monitoring (audit_log table)
 * 
 * RELATIONSHIPS:
 *   files.uploaded_by -> users.id (FOREIGN KEY)
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Initialize database connection
const db = new sqlite3.Database(path.join(__dirname, 'student.db'), (err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
    } else {
        console.log('Connected to SQLite database.');
    }
});

/**
 * FUNCTION: db.serialize()
 * DESCRIPTION:
 *   Creates all required tables if they don't exist.
 *   Enforces data integrity with CHECK constraints and FOREIGN KEYs.
 */
db.serialize(() => {
    // ============================================
    // TABLE: users
    // PURPOSE: Store user credentials and roles for authentication
    // ============================================
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
    )`);

    // ============================================
    // TABLE: grades
    // PURPOSE: Store student grade records for search functionality
    // ============================================
    db.run(`CREATE TABLE IF NOT EXISTS grades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_name TEXT NOT NULL,
        course TEXT NOT NULL,
        grade TEXT NOT NULL
    )`);

    // ============================================
    // TABLE: files
    // PURPOSE: Track uploaded files with user association
    // RELATIONSHIP: uploaded_by -> users.id
    // ============================================
    db.run(`CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        path TEXT NOT NULL,
        uploaded_by INTEGER,
        FOREIGN KEY(uploaded_by) REFERENCES users(id)
    )`);

    // ============================================
    // TABLE: audit_log
    // PURPOSE: Store security-relevant events for monitoring
    // OWASP A09: Security Logging & Monitoring
    // ============================================
    db.run(`CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        action TEXT NOT NULL,
        user TEXT
    )`);

    console.log('Database tables created/verified.');
});

module.exports = db;