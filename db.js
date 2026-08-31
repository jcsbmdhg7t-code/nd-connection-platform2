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
    user_id TEXT NOT NULL,
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

  CREATE TABLE IF NOT EXISTS quiz_questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    options TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS quiz_answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    question_id INTEGER NOT NULL,
    round_date TEXT NOT NULL,
    choice_index INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, question_id, round_date)
  );
  CREATE INDEX IF NOT EXISTS idx_quiz_answers_round ON quiz_answers(round_date);
`);

/* ---- QUIZ VRAGENBANK (eenmalig seeden) ---- */
const QUIZ_SEED = [
  { text: "Iemand appt je 5x kort achter elkaar met losse gedachtes. Hoe voelt dat voor jou?", options: ["Fijn, zo hou ik het gesprek levendig", "Prima, maar ik reageer liever in één keer terug", "Overweldigend, ik wil het liever in één bericht"] },
  { text: "Je hebt een afspraak, maar voelt je die dag opeens te moe. Wat doe je het liefst?", options: ["Gewoon gaan, ik trek het wel", "Vragen om te verzetten, zonder uitleg nodig te hebben", "Afzeggen en er niet meer op terugkomen"] },
  { text: "Een gesprek gaat opeens over jouw specifieke interesse. Wat gebeurt er?", options: ["Ik vertel honderduit, ook als het lang duurt", "Ik vertel kort en check of de ander nog mee wil", "Ik hou het liever kort, bang dat het teveel is"] },
  { text: "Iemand stuurt een kort antwoord zonder uitleg. Wat denk je het eerst?", options: ["Waarschijnlijk gewoon druk, niks aan de hand", "Ik weet het niet zeker en vraag het gewoon", "Ik ga ervan uit dat er iets mis is"] },
  { text: "Wat helpt jou het meest om een gesprek prettig te laten voelen?", options: ["Ruimte om te reageren wanneer het uitkomt", "Duidelijke, letterlijke taal zonder subtekst", "Gewoon lekker kunnen kletsen, geen regels nodig"] },
  { text: "Een eerste ontmoeting — wat spreekt je het meest aan?", options: ["Iets rustigs, 1-op-1, weinig prikkels", "Samen iets doen rond een gedeelde interesse", "Een korte kennismaking, zonder verplichting om door te praten"] },
  { text: "Je merkt dat je overprikkeld raakt tijdens contact. Wat wil je dat er gebeurt?", options: ["Dat ik het zelf mag aangeven en de ander dat serieus neemt", "Dat de ander het al aanvoelt zonder dat ik het hoef te zeggen", "Ik zeg het liever niet en probeer het uit te zitten"] },
  { text: "Hoe ga je het liefst om met stiltes in een gesprek?", options: ["Stilte is prima, hoeft niet opgevuld", "Ik vul het liever aan met een nieuw onderwerp", "Stilte voelt ongemakkelijk, ik wil weten wat de ander denkt"] },
  { text: "Wat is voor jou een teken dat een connectie klopt?", options: ["We kunnen gewoon onszelf zijn, zonder te maskeren", "We delen dezelfde interesses of special interest", "Er is duidelijkheid — we weten waar we aan toe zijn"] },
  { text: "Als iemand een grens aangeeft, wat doe jij daarmee?", options: ["Ik pas me meteen aan, zonder verdere vragen", "Ik vraag door zodat ik het goed begrijp", "Ik neem het serieus en laat het rusten"] },
  { text: "Wat is voor jou de fijnste manier om een dag te plannen?", options: ["Losjes, ik hou van spontaniteit", "Vast, ik weet graag van tevoren wat er gaat gebeuren", "Een globaal plan met ruimte om af te wijken"] },
  { text: "Bij een meningsverschil, wat heb je het meest nodig?", options: ["Tijd om er alleen over na te denken voor ik reageer", "Meteen uitpraten, liefst niet laten liggen", "Concreet benoemen wat er precies gebeurde, geen aannames"] },
  { text: "Wat zou jij het fijnst vinden aan een dagelijks contactmoment zoals dit?", options: ["Dat het voorspelbaar en begrensd is", "Dat het spannend blijft en niet te vaak is", "Dat ik zelf kan kiezen of ik meedoe, zonder druk"] },
];

function seedQuizQuestions() {
  const count = db.prepare("SELECT COUNT(*) AS n FROM quiz_questions").get().n;
  if (count > 0) return;
  const insert = db.prepare("INSERT INTO quiz_questions (text, options) VALUES (?, ?)");
  const insertMany = db.transaction((questions) => {
    for (const q of questions) insert.run(q.text, JSON.stringify(q.options));
  });
  insertMany(QUIZ_SEED);
}
seedQuizQuestions();

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
function addMessage(roomId, userId, from, text, time) {
  db.prepare(`
    INSERT INTO messages (room_id, user_id, from_alias, text, time) VALUES (?, ?, ?, ?, ?)
  `).run(roomId, userId, from, text, time);
}

function getMessages(roomId) {
  return db.prepare(`
    SELECT user_id AS "userId", from_alias AS "from", text, time FROM messages WHERE room_id = ? ORDER BY id ASC
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

/* ---- DAGELIJKSE QUIZ ---- */
function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash * 31 + str.charCodeAt(i)) >>> 0;
  }
  return hash;
}

// Iedereen krijgt dezelfde vragen op dezelfde datum — een gedeeld, dagelijks ritueel
// i.p.v. willekeurige vragen per gebruiker.
function getQuizQuestionsForDate(dateStr, count = 5) {
  const all = db.prepare("SELECT id, text, options FROM quiz_questions ORDER BY id ASC").all();
  if (all.length === 0) return [];
  const offset = hashString(dateStr) % all.length;
  const picked = [];
  for (let i = 0; i < Math.min(count, all.length); i++) {
    const q = all[(offset + i) % all.length];
    picked.push({ id: q.id, text: q.text, options: JSON.parse(q.options) });
  }
  return picked;
}

function saveQuizAnswer(userId, questionId, roundDate, choiceIndex) {
  db.prepare(`
    INSERT INTO quiz_answers (user_id, question_id, round_date, choice_index)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, question_id, round_date) DO UPDATE SET choice_index = excluded.choice_index
  `).run(userId, questionId, roundDate, choiceIndex);
}

function getUserAnswersForRound(userId, roundDate) {
  return db.prepare(`
    SELECT question_id AS questionId, choice_index AS choiceIndex
    FROM quiz_answers WHERE user_id = ? AND round_date = ?
  `).all(userId, roundDate);
}

function getOtherAnswersForRound(userId, roundDate) {
  return db.prepare(`
    SELECT user_id AS userId, question_id AS questionId, choice_index AS choiceIndex
    FROM quiz_answers WHERE user_id != ? AND round_date = ?
  `).all(userId, roundDate);
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
  getQuizQuestionsForDate,
  saveQuizAnswer,
  getUserAnswersForRound,
  getOtherAnswersForRound,
};
