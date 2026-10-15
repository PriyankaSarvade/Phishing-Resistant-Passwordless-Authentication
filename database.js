
const Database = require("better-sqlite3");
const db = new Database("cybernova.db");

// Store registered users
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL
            CHECK(role IN ('student', 'staff'))
    );

    CREATE TABLE IF NOT EXISTS credentials (
        credential_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        public_key TEXT NOT NULL,
        counter INTEGER NOT NULL DEFAULT 0,
        transports TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
`);

// Demo accounts for local development
const addUser = db.prepare(`
    INSERT OR IGNORE INTO users (email, display_name, role)
    VALUES (?, ?, ?)
`);

addUser.run("student@nkocet.edu", "Demo Student", "student");
addUser.run("staff@nkocet.edu", "Demo Staff", "staff");

console.log("Database and tables created successfully!");

module.exports = db;
