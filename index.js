// ===== ND CONNECTION — FULL MVP =====
const express = require("express");
const http = require("http");
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
    return "💛 NVC-tip: Probeer je gevoel te benoemen in plaats van een oordeel. Bijv. 'Ik voel me gefrustreerd omdat...'";
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
app.get("/", (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover"/>
<title>ND Connection</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<script src="/socket.io/socket.io.js"><\/script>
<style>
:root{
--blue:#16225c;--green:#3355e8;--sea:#7a93e0;
  --naples:#f2d98d; --orange:#c96b3c; --ochre:#c9a24d;
  --glass:rgba(255,255,255,.08); --border:rgba(255,255,255,.16);
  --text:#eef7f5; --muted:#b9d6cf;
  --danger:#ef4444;
}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;height:100%;font-family:Inter,system-ui,sans-serif;color:var(--text)}
body{
  background:linear-gradient(160deg,var(--blue),var(--green));
  display:flex; flex-direction:column;
}

/* ---- SCREENS ---- */
.screen{
  display:none; flex-direction:column;
  min-height:100vh; padding:24px 20px 100px;
  max-width:480px; margin:0 auto; width:100%;
}
.screen.active{display:flex}
.screen.chat-screen{padding-bottom:0}

/* ---- CARD ---- */
.card{
  background:var(--glass); border:1px solid var(--border);
  backdrop-filter:blur(18px); border-radius:24px; padding:28px;
  box-shadow:0 30px 80px rgba(0,0,0,.4);
  animation:pop .3s ease-out;
}
@keyframes pop{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}

h1{margin:0 0 8px;font-size:26px;font-weight:600}
h2{margin:0 0 12px;font-size:20px;font-weight:600}
p,.small{margin:0 0 16px;line-height:1.7;color:var(--muted);font-size:14px}

/* ---- INPUTS ---- */
input,select,textarea{
  width:100%; padding:13px 16px; margin-top:8px; margin-bottom:4px;
  border-radius:14px; border:1px solid var(--border);
  background:rgba(255,255,255,.11); color:var(--text);
  font-size:15px; outline:none; font-family:inherit;
}
input:focus,select:focus,textarea:focus{border-color:var(--naples)}
textarea{min-height:90px;resize:vertical}
label{display:block;margin-top:14px;font-size:14px;font-weight:500}
.checkbox{display:flex;gap:10px;align-items:center;margin-top:12px;font-size:14px}
.checkbox input{width:18px;height:18px;margin:0;accent-color:var(--naples)}

/* ---- BUTTONS ---- */
button{
  width:100%; padding:14px; margin-top:14px;
  border:none; border-radius:18px; font-size:15px; font-weight:600;
  cursor:pointer; font-family:inherit;
  background:linear-gradient(135deg,var(--naples),var(--orange));
  color:#2a1a0f; transition:opacity .15s, transform .1s;
}
button:active{transform:scale(.98)}
button:hover{opacity:.92}
button.sec{background:linear-gradient(135deg,var(--green),var(--blue));color:var(--text)}
button.sm{padding:9px 14px;font-size:13px;margin-top:8px}
button.danger{background:var(--danger);color:white}

/* ---- BOTTOM NAV ---- */
.bottom-nav{
  position:fixed; bottom:0; left:0; right:0;
  background:rgba(11,40,49,.92); backdrop-filter:blur(14px);
  border-top:1px solid var(--border);
  display:none; justify-content:space-around; align-items:center;
  padding:10px 0 max(10px, env(safe-area-inset-bottom));
  z-index:100;
}
.bottom-nav.visible{display:flex}
.nav-btn{
  display:flex;flex-direction:column;align-items:center;gap:4px;
  cursor:pointer; padding:6px 16px; border-radius:14px;
  color:var(--muted); font-size:11px; border:none;
  background:transparent; font-family:inherit;
  transition:color .15s;
}
.nav-btn.active,.nav-btn:hover{color:var(--naples)}
.nav-btn span{font-size:22px}

/* ---- TILES ---- */
.tile{
  padding:16px; border-radius:16px;
  background:rgba(255,255,255,.07); border:1px solid var(--border);
  margin-bottom:12px;
}
.match-tile{cursor:pointer;transition:background .15s}
.match-tile:hover{background:rgba(255,255,255,.13)}
.badge{
  display:inline-block; padding:4px 10px; border-radius:999px;
  background:rgba(255,255,255,.12); font-size:12px; margin-top:6px;
}
.score-bar{
  height:4px; border-radius:99px; background:rgba(255,255,255,.1);
  margin-top:10px; overflow:hidden;
}
.score-fill{height:100%;background:linear-gradient(90deg,var(--sea),var(--naples));border-radius:99px}

/* ---- CHAT ---- */
.chat-wrap{display:flex;flex-direction:column;height:100vh;max-width:480px;margin:0 auto;width:100%}
.chat-header{
  padding:16px 20px; background:rgba(11,40,49,.9); border-bottom:1px solid var(--border);
  display:flex; align-items:center; gap:12px;
}
.chat-messages{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:10px}
.msg{max-width:80%;padding:11px 15px;border-radius:18px;font-size:14px;line-height:1.5}
.msg.mine{background:linear-gradient(135deg,var(--naples),var(--orange));color:#2a1a0f;align-self:flex-end;border-bottom-right-radius:6px}
.msg.theirs{background:rgba(255,255,255,.1);color:var(--text);align-self:flex-start;border-bottom-left-radius:6px}
.msg-time{font-size:11px;opacity:.6;margin-top:4px}
.nvc-banner{
  background:rgba(242,217,141,.15); border:1px solid var(--naples);
  border-radius:14px; padding:12px 14px; margin:8px 16px;
  font-size:13px; color:var(--naples);
}
.chat-input-area{
  padding:12px 16px max(16px, env(safe-area-inset-bottom));
  background:rgba(11,40,49,.9); border-top:1px solid var(--border);
  display:flex; gap:10px;
}
.chat-input-area input{margin:0;border-radius:999px;padding:12px 18px}
.chat-input-area button{width:auto;margin:0;padding:12px 18px;border-radius:999px}

/* ---- MISC ---- */
.section-label{font-size:12px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;color:var(--muted);margin-bottom:10px}
.rule{padding:10px 14px;border-radius:12px;background:rgba(255,255,255,.07);margin-bottom:8px;font-size:14px}
:root{--gold:#f0b429;--cream:#f7f2ea;--ink:#182238;--ink-soft:#5b6472;--card-border:#e6ddce;--accent:#3355e8}.brand{display:flex;align-items:center;gap:8px;color:var(--naples);font-weight:700;letter-spacing:.12em;text-transform:uppercase;font-size:12px;margin-bottom:22px}.brand .dot{width:16px;height:16px;border-radius:50%;border:2px solid var(--naples);display:inline-block}.hero-card{background:rgba(3,10,20,.55);border-radius:22px;padding:26px 24px;margin-bottom:22px}.hero-card h1{font-size:30px;line-height:1.25;margin:0}.hero-card h1 .accent{color:var(--naples)}#s-welcome .card{background:transparent;border:none;backdrop-filter:none;box-shadow:none;padding:0}#s-welcome input{background:transparent;border:none;border-bottom:1px solid var(--border);border-radius:0;padding:10px 2px}#s-matching,#s-community,#s-profile,#s-chat{background:var(--cream);color:var(--ink)}#s-matching h1,#s-matching h2,#s-community h1,#s-community h2,#s-profile h1,#s-profile h2{color:var(--ink);font-weight:700}#s-matching p,#s-matching .small,#s-community p,#s-community .small,#s-profile p,#s-profile .small{color:var(--ink-soft)}#s-matching .card,#s-community .card,#s-profile .card,#s-matching .tile,#s-community .tile,#s-profile .tile{background:#fff;border:1.5px solid var(--card-border);backdrop-filter:none;box-shadow:none;color:var(--ink)}#s-matching .badge{background:#f1eee6;color:var(--ink-soft)}#s-matching .match-tile:hover{background:#faf7f0}#s-profile .badge{background:var(--gold);color:var(--blue);font-weight:700}#s-community input{background:#fff;border:1.5px solid var(--card-border);color:var(--ink)}#s-community button.sm{background:var(--sea);color:#fff;width:auto;display:inline-block}.badge-gold{display:inline-block;background:var(--gold);color:var(--blue);font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:7px 16px;border-radius:999px;font-size:12px;margin-bottom:14px}.quiz-options{display:flex;flex-direction:column;gap:10px;margin-top:16px}.quiz-opt{text-align:left;background:#fff;border:1.5px solid var(--card-border);color:var(--ink);font-weight:500;padding:14px 16px}.quiz-opt.picked{border-color:var(--accent);background:rgba(51,85,232,.06)}.notice-box{background:#eceafc;border:1px solid #d7d3f5;border-radius:14px;padding:14px 16px;font-size:13px;color:var(--ink-soft);margin-top:14px}.avatar{width:40px;height:40px;border-radius:50%;background:var(--accent);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:16px;flex-shrink:0}.avatar-lg{width:56px;height:56px;font-size:22px}#s-profile .rule{background:#fff;border:1px solid var(--card-border);color:var(--ink);display:flex;align-items:center;gap:10px}#s-profile .rule .check{color:var(--gold);font-weight:700}#s-chat .chat-wrap{background:var(--cream)}#s-chat .chat-header{background:#fff;border-bottom:1px solid var(--card-border);color:var(--ink)}#s-chat .msg.theirs{background:#fff;border:1px solid var(--card-border);color:var(--ink)}#s-chat .msg.mine{background:var(--accent);color:#fff}#s-chat .chat-input-area{background:#fff;border-top:1px solid var(--card-border)}#s-chat .chat-input-area input{background:var(--cream);color:var(--ink);border:1px solid var(--card-border)}.bottom-nav{background:#fff;border-top:1px solid var(--card-border)}.nav-btn{color:#9aa3ae}.nav-btn.active,.nav-btn:hover{color:var(--accent)}.match-reason{font-size:12px;color:var(--ink-soft);margin:2px 0 0}</style>
</head>
<body>

<!-- ONBOARDING -->
<div class="screen active" id="s-welcome">
  <div class="card" style="margin-top:auto;margin-bottom:auto">
    <div class="brand"><span class="dot"></span>ND CONNECTION</div><div class="hero-card"><h1>Eindelijk ergens waar je jezelf niet hoeft te <span class="accent">vertalen.</span></h1></div>
    <p>Een veilige plek voor neurodivergente verbinding. Rustig, vrijwillig, op jouw tempo.</p>
    <label>Je naam</label>
    <input id="alias" placeholder="Voer je naam in">
    <p class="small" style="margin:6px 0 0">We werken met echte namen. Dat houdt dit platform veilig en betrouwbaar — geen anonieme accounts.</p>
    <button onclick="tryNextToEnergy()">Verder →</button>
    <button class="sec sm" onclick="nextTo('s-login')">Ik heb al een account</button>
  </div>
</div>

<div class="screen" id="s-login">
  <div class="card" style="margin-top:auto;margin-bottom:auto">
    <h1>Terug op ND Connection</h1>
    <p>Vul je herstelcode in — die heb je gekregen toen je je account maakte.</p>
    <input id="loginCode" placeholder="Jouw herstelcode">
    <p class="small" id="loginError" style="display:none;color:var(--danger);margin:6px 0 0">Deze code kennen we niet. Check op typefouten.</p>
    <button onclick="loginWithCode()">Inloggen</button>
    <button class="sec" onclick="nextTo('s-welcome')">← Terug</button>
  </div>
</div>

<div class="screen" id="s-savecode">
  <div class="card" style="margin-top:auto;margin-bottom:auto">
    <h1>Bewaar je herstelcode</h1>
    <p>Dit is je enige toegang tot je account — er is geen e-mail of wachtwoord. Bewaar 'm ergens veilig, dan kun je altijd terug, ook op een ander apparaat.</p>
    <input id="savecodeValue" readonly>
    <button class="sec" onclick="copySavecode()">Kopieer code</button>
    <button onclick="showScreen('s-matching')">Ik heb 'm bewaard, verder →</button>
  </div>
</div>

<div class="screen" id="s-energy">
  <div class="card" style="margin-top:auto;margin-bottom:auto">
    <h1>Energie & prikkels</h1>
    <p>Dit helpt ons om je de juiste matches te tonen.</p>
    <label>Energietempo</label>
    <select id="energie">
      <option value="laag">🌊 Laag & rustig</option>
      <option value="gemiddeld" selected>🌿 Gemiddeld</option>
      <option value="hoog">✨ Hoog</option>
    </select>
    <div class="checkbox"><input type="checkbox" id="geluid"><label for="geluid">Gevoelig voor veel geluid</label></div>
    <div class="checkbox"><input type="checkbox" id="drukte"><label for="drukte">Gevoelig voor drukte</label></div>
    <button onclick="nextTo('s-comm')">Verder →</button>
    <button class="sec" onclick="nextTo('s-welcome')">← Terug</button>
  </div>
</div>

<div class="screen" id="s-comm">
  <div class="card" style="margin-top:auto;margin-bottom:auto">
    <h1>Veilige communicatie</h1>
    <p>Wat helpt jou om je veilig te voelen in contact?</p>
    <textarea id="communicatie" placeholder="Bijv. rustig taalgebruik, geen plotselinge vragen, duidelijke structuur..."></textarea>
    <div class="checkbox"><input type="checkbox" id="openVoorRomantiek"><label for="openVoorRomantiek">Ik sta ook open voor romantische verbinding via de community</label></div>
    <button onclick="register()">Afronden & verder</button>
    <button class="sec" onclick="nextTo('s-energy')">← Terug</button>
  </div>
</div>

<!-- MAIN APP -->
<div class="screen" id="s-matching"><div class="badge-gold">VANDAAG</div><h2 style="margin-bottom:0">Eén goed moment per dag, geen <span style="color:var(--accent)">eindeloze feed</span>.</h2><div class="card" style="margin-top:16px"><p id="quizQuestion" style="margin-bottom:0">Vraag laden…</p><div class="quiz-options" id="quizOptions"></div></div><p class="small" style="margin-top:14px" id="quizHelper">Beantwoord de vraag om je matches van vandaag te zien.</p><h2 style="margin-top:28px">Zachte matching</h2><p>Op basis van jouw profiel — klik om te chatten.</p><div id="matchList"></div></div>

<div class="screen" id="s-community"><h2>Community</h2><p class="small">Een rustgevende ruimte. Alles is vrijwillig.</p><div class="card" style="margin-bottom:4px"><input id="postInput" placeholder="Deel een moment van rust…"><button class="sm" onclick="addCommunityPost()">Delen</button></div><div id="communityPosts"></div><div class="notice-box">Staat je profiel op “open voor romantiek”? Dan mag je hier zelf iemand aanspreken — de community blijft verder altijd niet-daten.</div></div>

<div class="screen" id="s-profile">
  <h2>Mijn profiel</h2>
  <div class="card" id="profileCard"></div>
  <div class="card" style="margin-top:16px">
    <div class="section-label">Veiligheidsregels</div>
    <div class="rule"><span class="check">✓</span> Altijd vrijwillig — je kunt altijd stoppen</div><div class="rule"><span class="check">✓</span> Geen druk of tijdsdruk</div><div class="rule"><span class="check">✓</span> Respect voor prikkelgevoeligheid</div><div class="rule"><span class="check">✓</span> Geweldloze communicatie (NVC)</div>
    <p class="small" style="margin:12px 0 0">Je account blijft bestaan — bewaar je herstelcode om later weer in te loggen.</p>
    <button class="sec sm" onclick="resetApp()">Uitloggen op dit apparaat</button>
  </div>
</div>

<!-- CHAT SCREEN -->
<div class="screen chat-screen" id="s-chat">
  <div class="chat-wrap">
    <div class="chat-header">
      <button onclick="showScreen('s-matching')" style="width:auto;margin:0;padding:8px 14px;font-size:13px;border-radius:12px">← Terug</button>
      <div class="avatar" id="chatAvatar">?</div><div><strong id="chatPartnerName">Chat</strong><div class="match-reason" id="chatReason"></div></div>
    </div>
    <div class="chat-messages" id="chatMessages"></div>
    <div id="nvcBanner" class="nvc-banner" style="display:none"></div>
    <div class="chat-input-area">
      <input id="chatInput" placeholder="Typ een bericht…" onkeydown="if(event.key==='Enter')sendMsg()">
      <button onclick="sendMsg()">→</button>
    </div>
  </div>
</div>

<!-- BOTTOM NAV -->
<div class="bottom-nav" id="bottomNav">
  <button class="nav-btn active" id="nav-matching" onclick="showScreen('s-matching')"><span>🌊</span>Matches</button>
  <button class="nav-btn" id="nav-community" onclick="showScreen('s-community')"><span>🌿</span>Community</button>
  <button class="nav-btn" id="nav-profile" onclick="showScreen('s-profile')"><span>👤</span>Profiel</button>
</div>

<script>
const socket = io();
let myId = null;
let currentRoom = null;

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// ---- NAVIGATION ----
function nextTo(screenId) {
  document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
  document.getElementById(screenId).classList.add("active");
}

function tryNextToEnergy() {
  const aliasInput = document.getElementById("alias");
  if (!aliasInput.value.trim()) {
    aliasInput.style.borderColor = "var(--danger)";
    aliasInput.focus();
    return;
  }
  aliasInput.style.borderColor = "";
  nextTo("s-energy");
}

function showScreen(screenId) {
  document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
  document.getElementById(screenId).classList.add("active");

  const navScreens = ["s-matching", "s-community", "s-profile"];
  document.getElementById("bottomNav").classList.toggle("visible", navScreens.includes(screenId));

  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  const navMap = {"s-matching":"nav-matching","s-community":"nav-community","s-profile":"nav-profile"};
  if(navMap[screenId]) document.getElementById(navMap[screenId]).classList.add("active");

  if(screenId === "s-matching") loadMatches(); loadQuiz();
  if(screenId === "s-community") renderCommunity();
  if(screenId === "s-profile") renderProfile();
}

// ---- REGISTER ----
async function register() {
  const alias = document.getElementById("alias").value.trim();
  if (!alias) { nextTo("s-welcome"); return; }
  const energie = document.getElementById("energie").value;
  const geluid = document.getElementById("geluid").checked;
  const drukte = document.getElementById("drukte").checked;
  const communicatie = document.getElementById("communicatie").value;
  const openVoorRomantiek = document.getElementById("openVoorRomantiek").checked;

  const res = await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ alias, energie, geluid: String(geluid), drukte: String(drukte), communicatie, openVoorRomantiek: String(openVoorRomantiek) })
  });
  const data = await res.json();
  myId = data.id;
  localStorage.setItem("nd_id", myId);
  localStorage.setItem("nd_profile", JSON.stringify({ alias, energie, geluid, drukte, communicatie, openVoorRomantiek }));

  document.getElementById("savecodeValue").value = myId;
  showScreen("s-savecode");
}

function copySavecode() {
  const input = document.getElementById("savecodeValue");
  input.select();
  navigator.clipboard?.writeText(input.value).catch(() => {});
}

async function loginWithCode() {
  const code = document.getElementById("loginCode").value.trim();
  const errorEl = document.getElementById("loginError");
  errorEl.style.display = "none";
  if (!code) return;

  const res = await fetch("/api/users/" + encodeURIComponent(code));
  if (!res.ok) {
    errorEl.style.display = "block";
    return;
  }
  const user = await res.json();
  myId = code;
  localStorage.setItem("nd_id", myId);
  localStorage.setItem("nd_profile", JSON.stringify({
    alias: user.alias,
    energie: user.energie,
    geluid: user.geluid,
    drukte: user.drukte,
    communicatie: user.communicatie,
    openVoorRomantiek: user.openVoorRomantiek,
  }));
  showScreen("s-matching");
}

// ---- MATCHES ----
async function loadQuiz() {
    if (!myId) return;
      const res = await fetch("/api/quiz/today?userId=" + myId);
        const data = await res.json();
          const q = (data.questions || []).find(x => !x.answered) || (data.questions || [])[0];
            const qEl = document.getElementById("quizQuestion");
              const optsEl = document.getElementById("quizOptions");
                if (!q) {
                  qEl.innerText = "Geen vraag beschikbaar vandaag.";
                    optsEl.innerHTML = "";
                      return;
                        }
                          qEl.innerText = q.text;
                            optsEl.innerHTML = q.options.map((opt, i) => '<button class="quiz-opt" data-i="' + i + '">' + escapeHtml(opt) + '</button>').join("");
                              optsEl.querySelectorAll(".quiz-opt").forEach(btn => {
                                btn.addEventListener("click", async () => {
                                  optsEl.querySelectorAll(".quiz-opt").forEach(b => b.classList.remove("picked"));
                                    btn.classList.add("picked");
                                      await fetch("/api/quiz/answer", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ userId: myId, questionId: q.id, choiceIndex: Number(btn.dataset.i) }) });
                                        document.getElementById("quizHelper").innerText = "Bedankt! Kom morgen terug voor een nieuwe vraag.";
                                          });
                                            });
                                            }
                                            
                                            async function loadMatches() {
  if (!myId) return;
  const res = await fetch("/api/matches/" + myId);
  const matches = await res.json();
  const el = document.getElementById("matchList");

  if (matches.length === 0) {
    el.innerHTML = '<div class="tile"><p class="small" style="margin:0">Nog geen andere gebruikers. Deel de app!</p></div>';
    return;
  }

  el.innerHTML = matches.map(m => {
    const pct = Math.round((m.score / 7) * 100);
    return \`<div class="tile match-tile" data-room="\${escapeHtml(m.roomId)}" data-alias="\${escapeHtml(m.alias)}">
      <strong>\${escapeHtml(m.alias)}</strong>
      <div class="badge">\${escapeHtml(m.energie)}</div>
      <div class="score-bar"><div class="score-fill" style="width:\${pct}%"></div></div>
      <div class="small" style="margin:6px 0 0">\${pct}% compatibiliteit</div>
    </div>\`;
  }).join("");

  el.querySelectorAll(".match-tile").forEach((tile) => {
    tile.addEventListener("click", () => openChat(tile.dataset.room, tile.dataset.alias));
  });
}

// ---- CHAT ----
function openChat(roomId, partnerAlias, reason) {
    currentRoom = roomId;
      document.getElementById("chatPartnerName").innerText = partnerAlias;
        document.getElementById("chatAvatar").innerText = (partnerAlias || "?").charAt(0).toUpperCase();
          document.getElementById("chatReason").innerText = reason || "";
document.getElementById("chatMessages").innerHTML = "";
  document.getElementById("nvcBanner").style.display = "none";
  showScreen("s-chat");
  socket.emit("join", { roomId: currentRoom, userId: myId });
  loadHistory();
}

async function loadHistory() {
  const res = await fetch("/api/messages/" + currentRoom);
  const msgs = await res.json();
  msgs.forEach(m => renderMsg(m));
  scrollChat();
}

function sendMsg() {
  const input = document.getElementById("chatInput");
  const text = input.value.trim();
  if (!text || !currentRoom) return;
  socket.emit("message", { roomId: currentRoom, userId: myId, text });
  input.value = "";
}

socket.on("message", (msg) => {
  renderMsg(msg);
  scrollChat();
});

socket.on("nvc-tip", (tip) => {
  const banner = document.getElementById("nvcBanner");
  banner.style.display = "block";
  banner.innerText = tip;
  setTimeout(() => banner.style.display = "none", 8000);
});

function renderMsg(msg) {
  const isMine = msg.userId === myId;
  const wrap = document.getElementById("chatMessages");
  const div = document.createElement("div");
  div.className = "msg " + (isMine ? "mine" : "theirs");
  div.innerHTML = \`<div>\${escapeHtml(msg.text)}</div><div class="msg-time">\${escapeHtml(msg.from)} · \${escapeHtml(msg.time)}</div>\`;
  wrap.appendChild(div);
}

function scrollChat() {
  const el = document.getElementById("chatMessages");
  el.scrollTop = el.scrollHeight;
}

// ---- COMMUNITY ----
async function addCommunityPost() {
  const input = document.getElementById("postInput");
  const txt = input.value.trim();
  if (!txt) return;
  const profile = JSON.parse(localStorage.getItem("nd_profile") || "{}");
  await fetch("/api/community", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ alias: profile.alias, text: txt })
  });
  input.value = "";
  renderCommunity();
}

async function renderCommunity() {
  const el = document.getElementById("communityPosts");
  const res = await fetch("/api/community");
  const posts = await res.json();

  if (posts.length === 0) {
    el.innerHTML = '<p class="small" style="font-style:italic">Nog geen berichten...</p>';
    return;
  }
  el.innerHTML = posts.map((p) => \`
    <div class="tile">
      <strong style="font-size:13px">\${escapeHtml(p.alias)}</strong>
      <span class="small" style="float:right">\${escapeHtml(p.time)}</span>
      <p style="margin:8px 0 0">\${escapeHtml(p.text)}</p>
    </div>\`).join("");
}

// ---- PROFILE ----
function renderProfile() {
  const p = JSON.parse(localStorage.getItem("nd_profile") || "{}");
  document.getElementById("profileCard").innerHTML = \`
    <div style="display:flex;align-items:center;gap:14px"><div class="avatar avatar-lg">\${escapeHtml((p.alias||"?").charAt(0).toUpperCase())}</div><div><strong style="font-size:19px">\${escapeHtml(p.alias || "Anoniem")}</strong>\${p.openVoorRomantiek ? '<div class="badge" style="margin-top:6px;display:inline-block">Open voor romantiek</div>' : ""}</div></div><div style="border-top:1px solid var(--card-border);margin:18px 0"></div><div style="display:flex;justify-content:space-between;padding:6px 0"><span>Energietempo</span><strong>\${escapeHtml(p.energie || "—")}</strong></div><div style="display:flex;justify-content:space-between;padding:6px 0"><span>Geluidsgevoelig</span><strong>\${p.geluid ? "Ja" : "Nee"}</strong></div><div style="display:flex;justify-content:space-between;padding:6px 0"><span>Druktegevoel</span><strong>\${p.drukte ? "Ja" : "Nee"}</strong></div>\${p.communicatie ? '<div style="border-top:1px solid var(--card-border);margin:14px 0"></div><div class="section-label" style="margin-bottom:6px">Communicatie</div><p style="margin:0">' + escapeHtml(p.communicatie) + '</p>' : ""}
  \`;
}

function resetApp() {
  if (confirm("Je wordt uitgelogd op dit apparaat. Je account en gegevens blijven bestaan — log met je herstelcode weer in.")) {
    localStorage.clear();
    location.reload();
  }
}

// ---- INIT ----
const savedId = localStorage.getItem("nd_id");
const savedProfile = localStorage.getItem("nd_profile");
if (savedId && savedProfile) {
  myId = savedId;
  showScreen("s-matching");
}
</script>
</body>
</html>`);
});

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
