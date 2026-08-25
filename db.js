// ===== ND CONNECTION — PERSISTENTE OPSLAG (SQLite) =====
const path = require("path");
const Database = require("better-sqlite3");

const db = new Database(path.join(__dirname, "nd-connection.db"));
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    alias TEXT NOT NULL,
    energie TEXT,
    geluid INTEGER NOT NULL DEFAULT 0,
    drukte INTEGER NOT NULL DEFAULT 0,
    communicatie TEXT,
    open_voor_romantiek INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL,
    from_alias TEXT NOT NULL,
    text TEXT NOT NULL,
    time TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id);

  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS community_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alias TEXT NOT NULL,
    text TEXT NOT NULL,
    time TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

/* ---- USERS ---- */
function createUser(id, { alias, energie, geluid, drukte, communicatie, openVoorRomantiek }) {
  db.prepare(`
    INSERT INTO users (id, alias, energie, geluid, drukte, communicatie, open_voor_romantiek)
    VALUES (@id, @alias, @energie, @geluid, @drukte, @communicatie, @openVoorRomantiek)
  `).run({
    id,
    alias,
    energie,
    geluid: geluid ? 1 : 0,
    drukte: drukte ? 1 : 0,
    communicatie,
    openVoorRomantiek: openVoorRomantiek ? 1 : 0,
  });
  return getUser(id);
}

function getUser(id) {
  const row = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  return row ? rowToUser(row) : null;
}

function getOtherUsers(id) {
  return db.prepare("SELECT * FROM users WHERE id != ?").all(id).map(rowToUser);
}

function rowToUser(row) {
  return {
    id: row.id,
    alias: row.alias,
    energie: row.energie,
    geluid: !!row.geluid,
    drukte: !!row.drukte,
    communicatie: row.communicatie,
    openVoorRomantiek: !!row.open_voor_romantiek,
  };
}

/* ---- MESSAGES ---- */
function addMessage(roomId, from, text, time) {
  db.prepare(`
    INSERT INTO messages (room_id, from_alias, text, time) VALUES (?, ?, ?, ?)
  `).run(roomId, from, text, time);
}

function getMessages(roomId) {
  return db.prepare(`
    SELECT from_alias AS "from", text, time FROM messages WHERE room_id = ? ORDER BY id ASC
  `).all(roomId);
}

/* ---- REPORTS ---- */
function addReport(payload) {
  db.prepare("INSERT INTO reports (payload) VALUES (?)").run(JSON.stringify(payload));
}

/* ---- COMMUNITY POSTS ---- */
function addCommunityPost(alias, text, time) {
  db.prepare(`
    INSERT INTO community_posts (alias, text, time) VALUES (?, ?, ?)
  `).run(alias, text, time);
}

function getCommunityPosts(limit = 100) {
  return db.prepare(`
    SELECT alias, text, time FROM community_posts ORDER BY id DESC LIMIT ?
  `).all(limit);
}

module.exports = {
  createUser,
  getUser,
  getOtherUsers,
  addMessage,
  getMessages,
  addReport,
  addCommunityPost,
  getCommunityPosts,
};
