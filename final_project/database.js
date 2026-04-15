const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, 'student.db'));

db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
    )`);

    // Grades table (for search demo)
    db.run(`CREATE TABLE IF NOT EXISTS grades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_name TEXT NOT NULL,
        course TEXT NOT NULL,
        grade TEXT NOT NULL
    )`);

    // Files table (for upload demo)
    db.run(`CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        path TEXT NOT NULL,
        uploaded_by INTEGER,
        FOREIGN KEY(uploaded_by) REFERENCES users(id)
    )`);

    // Audit log table (for logging requirement)
    db.run(`CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        action TEXT NOT NULL,
        user TEXT
    )`);
});

module.exports = db;