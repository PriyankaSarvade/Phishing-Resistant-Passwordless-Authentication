const Database = require("better-sqlite3");
const db = new Database("cybernova.db");

// Initialize tables
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('student', 'staff'))
    );

    CREATE TABLE IF NOT EXISTS credentials (
        credential_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        public_key TEXT NOT NULL,
        counter INTEGER NOT NULL DEFAULT 0,
        device_name TEXT DEFAULT 'Security Authenticator',
        transports TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        email TEXT,
        ip_address TEXT,
        details TEXT,
        severity TEXT CHECK(severity IN ('INFO', 'WARNING', 'CRITICAL')),
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`);

// Insert default demo accounts if not already present
const addUser = db.prepare(`
    INSERT OR IGNORE INTO users (email, display_name, role)
    VALUES (?, ?, ?)
`);

addUser.run("student@nkocet.edu", "Demo Student", "student");
addUser.run("staff@nkocet.edu", "Demo Staff", "staff");

console.log("✓ Database initialized with Users, Credentials, and Security Audit tables.");

module.exports = db;