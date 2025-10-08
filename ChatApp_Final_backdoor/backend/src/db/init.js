// src/db/init.js
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

export async function initDB() {
  const db = await open({
    filename: 'socp.db',
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,       -- UUID
      pubkey TEXT NOT NULL,           -- RSA-4096 (base64url)
      privkey_store TEXT NOT NULL,    -- Encrypted private key blob
      pake_password TEXT NOT NULL,    -- PAKE verifier / salted hash
      meta TEXT,                      -- Optional decorative fields, JSON string
      version INT NOT NULL            -- Bumps on deco/security changes
    );
  `);

  console.log('[DB] users table ready');
  return db;
}
