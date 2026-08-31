// ===== ND CONNECTION — FULL MVP =====
const express = require("express");
const http = require("http");
const path = require("path");
const { Server } = require("socket.io");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const db = require("./db");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 5000;

app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: true, limit: "50kb" }));

/* ---- RATE LIMITING ---- */
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Te veel verzoeken, probeer het over een minuutje opnieuw." },
});
app.use("/api/", apiLimiter);

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Te veel accounts aangemaakt vanaf dit adres, probeer het later opnieuw." },
});

function genId() { return crypto.randomBytes(6).toString("hex"); }
function roomIdFor(a, b) { return [a, b].sort().join("_"); }

const ENERGIE_OPTIONS = ["laag", "gemiddeld", "hoog"];

function cleanString(value, maxLength) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function matchScore(a, b) {
  let score = 0;
  if (a.energie === b.energie) score += 3;
  if (a.geluid === b.geluid) score += 2;
  if (a.drukte === b.drukte) score += 2;
  return score;
}

async function getMatches(userId) {
  const me = await db.getUser(userId);
  if (!me) return [];
  // Geen ruwe account-ID's van anderen teruggeven — dat is sinds de herstelcode-login
  // hun volledige accounttoegang. Een roomId is voldoende om te kunnen chatten.
  const others = await db.getOtherUsers(userId);
  return others
    .map((u) => ({ roomId: roomIdFor(userId, u.id), alias: u.alias, energie: u.energie, score: matchScore(me, u) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);
}

function nvcCheck(text) {
  const triggers = ["jij altijd", "nooit", "dom", "stom", "irritant", "idiot", "waardeloos"];
  const found = triggers.filter(w => text.toLowerCase().includes(w));
  if (found.length > 0) {
    return "NVC-tip: Probeer je gevoel te benoemen in plaats van een oordeel. Bijv. 'Ik voel me gefrustreerd omdat...'";
  }
  return null;
}

/* ---- API ROUTES ---- */
app.post("/api/register", registerLimiter, async (req, res, next) => {
  try {
    const { alias, energie, geluid, drukte, communicatie, openVoorRomantiek } = req.body;

    const cleanAlias = cleanString(alias, 40);
    if (!cleanAlias) {
      return res.status(400).json({ error: "Naam is verplicht" });
    }

    if (energie !== undefined && !ENERGIE_OPTIONS.includes(energie)) {
      return res.status(400).json({ error: "Ongeldige waarde voor energie" });
    }

    const id = genId();
    const user = await db.createUser(id, {
      alias: cleanAlias,
      energie,
      geluid: geluid === "true",
      drukte: drukte === "true",
      communicatie: cleanString(communicatie, 1000),
      openVoorRomantiek: openVoorRomantiek === "true",
    });
    res.json({ id, alias: user.alias });
  } catch (err) { next(err); }
});

app.get("/api/matches/:userId", async (req, res, next) => {
  try {
    res.json(await getMatches(req.params.userId));
  } catch (err) { next(err); }
});

// Herstel-login: je account-ID is je enige toegangscode (geen e-mail/wachtwoord nodig).
app.get("/api/users/:id", async (req, res, next) => {
  try {
    const user = await db.getUser(req.params.id);
    if (!user) return res.status(404).json({ error: "Onbekende code" });
    res.json(user);
  } catch (err) { next(err); }
});

app.get("/api/messages/:roomId", async (req, res, next) => {
  try {
    res.json(await db.getMessages(req.params.roomId));
  } catch (err) { next(err); }
});

app.post("/api/report", async (req, res, next) => {
  try {
    const payload = JSON.stringify(req.body || {});
    if (payload.length > 5000) return res.status(400).json({ error: "Melding is te lang" });
    await db.addReport(req.body);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.get("/api/community", async (req, res, next) => {
  try {
    res.json(await db.getCommunityPosts());
  } catch (err) { next(err); }
});

app.post("/api/community", async (req, res, next) => {
  try {
    const { alias, text } = req.body;
    const trimmed = cleanString(text, 500);
    if (!trimmed) return res.status(400).json({ error: "text is verplicht (max 500 tekens)" });
    const cleanAlias = cleanString(alias, 40);
    if (!cleanAlias) return res.status(400).json({ error: "Naam is verplicht" });
    const time = new Date().toLocaleTimeString("nl-NL", { hour: "2-digit", minute: "2-digit" });
    await db.addCommunityPost(cleanAlias, trimmed, time);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

/* ---- DAGELIJKSE QUIZ (matching, geen swipen) ---- */
function today() { return new Date().toISOString().slice(0, 10); }

app.get("/api/quiz/today", async (req, res, next) => {
  try {
    const { userId } = req.query;
    const date = today();
    const questions = await db.getQuizQuestionsForDate(date, 5);
    const answered = userId
      ? new Set((await db.getUserAnswersForRound(userId, date)).map((a) => a.questionId))
      : new Set();
    res.json({
      date,
      questions: questions.map((q) => ({ ...q, answered: answered.has(q.id) })),
    });
  } catch (err) { next(err); }
});

app.post("/api/quiz/answer", async (req, res, next) => {
  try {
    const { userId, questionId, choiceIndex } = req.body;
    if (!userId || questionId === undefined || choiceIndex === undefined) {
      return res.status(400).json({ error: "userId, questionId en choiceIndex zijn verplicht" });
    }
    if (!(await db.getUser(userId))) {
      return res.status(404).json({ error: "Onbekend account" });
    }

    const date = today();
    const todaysQuestion = (await db.getQuizQuestionsForDate(date, 5)).find((q) => q.id === questionId);
    if (!todaysQuestion) {
      return res.status(400).json({ error: "Deze vraag hoort niet bij de quiz van vandaag" });
    }
    if (!Number.isInteger(choiceIndex) || choiceIndex < 0 || choiceIndex >= todaysQuestion.options.length) {
      return res.status(400).json({ error: "Ongeldige keuze" });
    }

    await db.saveQuizAnswer(userId, questionId, date, choiceIndex);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.get("/api/quiz/matches/:userId", async (req, res, next) => {
  try {
    const date = today();
    const userId = req.params.userId;
    const myAnswers = await db.getUserAnswersForRound(userId, date);
    if (myAnswers.length === 0) return res.json({ date, matches: [], reason: "nog niet meegedaan vandaag" });

    const myMap = new Map(myAnswers.map((a) => [a.questionId, a.choiceIndex]));
    const others = await db.getOtherAnswersForRound(userId, date);

    const perUser = new Map();
    for (const a of others) {
      if (!myMap.has(a.questionId)) continue;
      if (!perUser.has(a.userId)) perUser.set(a.userId, { shared: 0, overlap: 0, questionIds: [] });
      const entry = perUser.get(a.userId);
      entry.shared += 1;
      if (myMap.get(a.questionId) === a.choiceIndex) {
        entry.overlap += 1;
        entry.questionIds.push(a.questionId);
      }
    }

    const questionsById = new Map(
      (await db.getQuizQuestionsForDate(date, 5)).map((q) => [q.id, q])
    );

    const matches = (await Promise.all(
      [...perUser.entries()]
        .filter(([, v]) => v.shared > 0)
        .map(async ([otherId, v]) => {
          const user = await db.getUser(otherId);
          return {
            roomId: roomIdFor(userId, otherId),
            alias: user ? user.alias : "Onbekend",
            overlap: v.overlap,
            shared: v.shared,
            matchedOn: v.questionIds.map((qid) => questionsById.get(qid)?.text).filter(Boolean),
          };
        })
    ))
      .sort((a, b) => b.overlap - a.overlap)
      .slice(0, 10);

    res.json({ date, matches });
  } catch (err) { next(err); }
});

/* ---- SOCKET.IO CHAT ---- */
const MESSAGE_WINDOW_MS = 10 * 1000;
const MESSAGE_MAX_PER_WINDOW = 15;

// Een roomId is altijd "kleinsteId_grootsteId" (zie roomIdFor) — zo kunnen we
// controleren of een userId daadwerkelijk bij die room hoort, zonder een aparte
// sessielaag te bouwen.
function isParticipant(roomId, userId) {
  if (typeof roomId !== "string" || typeof userId !== "string") return false;
  return roomId.split("_").includes(userId);
}

io.on("connection", (socket) => {
  let messageTimestamps = [];

  socket.on("join", async ({ roomId, userId } = {}) => {
    if (!isParticipant(roomId, userId) || !(await db.getUser(userId))) return;
    socket.data.userId = userId;
    socket.join(roomId);
  });

  socket.on("message", async ({ roomId, text }) => {
    const userId = socket.data.userId;
    if (!isParticipant(roomId, userId)) return;
    if (typeof text !== "string" || !text.trim()) return;

    const now = Date.now();
    messageTimestamps = messageTimestamps.filter((t) => now - t < MESSAGE_WINDOW_MS);
    if (messageTimestamps.length >= MESSAGE_MAX_PER_WINDOW) return;
    messageTimestamps.push(now);

    const cleanText = text.trim().slice(0, 2000);
    // De afzendernaam komt van de server (via het geverifieerde userId), nooit
    // van de client — anders kan iemand zich voordoen als de ander in de room.
    const sender = await db.getUser(userId);
    if (!sender) return;
    const fromAlias = sender.alias;

    const msg = { userId, from: fromAlias, text: cleanText, time: new Date().toLocaleTimeString("nl-NL", { hour: "2-digit", minute: "2-digit" }) };
    await db.addMessage(roomId, userId, msg.from, msg.text, msg.time);

    const tip = nvcCheck(cleanText);
    io.to(roomId).emit("message", msg);
    if (tip) socket.emit("nvc-tip", tip);
  });
});

/* ---- FRONTEND ---- */
app.use(express.static(path.join(__dirname, "public")));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Serverfout" });
});

db.ready
  .then(() => {
    server.listen(PORT, "0.0.0.0", () => console.log("ND Connection draait op poort", PORT));
  })
  .catch((err) => {
    console.error("Kon database niet initialiseren:", err);
    process.exit(1);
  });
