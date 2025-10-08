import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

let database;

export async function getDB() {
  if (!database) {
    database = await open({
      filename: 'socp.db',
      driver: sqlite3.Database
    });
  }
  return database;
}

export async function getUser(userId) {
  const database = await getDB();
  return database.get('SELECT * FROM users WHERE user_id = ?', [userId]);
}

export async function getAllUsers() {
  const database = await getDB();
  return database.all('SELECT user_id, pubkey, meta, version FROM users');
}

export async function insertUser({ user_id, pubkey, privkey_store, pake_password, meta, version }) {
  const database = await getDB();
  await database.run(
    `INSERT INTO users (user_id, pubkey, privkey_store, pake_password, meta, version)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [user_id, pubkey, privkey_store, pake_password, meta || null, version]
  );
}