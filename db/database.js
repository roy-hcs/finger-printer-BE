const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Create a database connection
const dbPath = path.resolve(__dirname, 'users.db');
const db = new sqlite3.Database(dbPath);

function initDb() {
  db.serialize(() => {
    // Create users table if it doesn't exist
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err) {
        console.error('Error creating users table:', err.message);
      } else {
        console.log('Users table initialized');
      }
    });

    // Create authenticators table for WebAuthn
    db.run(`
      CREATE TABLE IF NOT EXISTS authenticators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        credential_id TEXT NOT NULL UNIQUE,
        public_key TEXT NOT NULL,
        counter INTEGER NOT NULL,
        transports TEXT,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `, (err) => {
      if (err) {
        console.error('Error creating authenticators table:', err.message);
      } else {
        console.log('Authenticators table initialized');
      }
    });

    // Create challenges table for WebAuthn
    db.run(`
      CREATE TABLE IF NOT EXISTS challenges (
        user_id INTEGER PRIMARY KEY,
        challenge TEXT NOT NULL,
        expires INTEGER NOT NULL
      )
    `, (err) => {
      if (err) {
        console.error('Error creating challenges table:', err.message);
      } else {
        console.log('Challenges table initialized');
      }
    });
  });
}

module.exports = {
  db,
  initDb
};
