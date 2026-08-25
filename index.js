// ===== ND CONNECTION — FULL MVP =====
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const crypto = require("crypto");
const db = require("./db");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function genId() { return crypto.randomBytes(6).toString("hex"); }

function matchScore(a, b) {
  let score = 0;
  if (a.energie === b.energie) score += 3;
  if (a.geluid === b.geluid) score += 2;
  if (a.drukte === b.drukte) score += 2;
  return score;
}

function getMatches(userId) {
  const me = db.getUser(userId);
  if (!me) return [];
  return db.getOtherUsers(userId)
    .map((u) => ({ id: u.id, alias: u.alias, energie: u.energie, score: matchScore(me, u) }))
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
app.post("/api/register", (req, res) => {
  const { alias, energie, geluid, drukte, communicatie, openVoorRomantiek } = req.body;
  const id = genId();
  const user = db.createUser(id, {
    alias: alias || "Anoniem",
    energie,
    geluid: geluid === "true",
    drukte: drukte === "true",
    communicatie,
    openVoorRomantiek: openVoorRomantiek === "true",
  });
  res.json({ id, alias: user.alias });
});

app.get("/api/matches/:userId", (req, res) => {
  res.json(getMatches(req.params.userId));
});

app.get("/api/messages/:roomId", (req, res) => {
  res.json(db.getMessages(req.params.roomId));
});

app.post("/api/report", (req, res) => {
  db.addReport(req.body);
  res.json({ ok: true });
});

app.get("/api/community", (req, res) => {
  res.json(db.getCommunityPosts());
});

app.post("/api/community", (req, res) => {
  const { alias, text } = req.body;
  const trimmed = (text || "").trim();
  if (!trimmed) return res.status(400).json({ error: "text is verplicht" });
  const time = new Date().toLocaleTimeString("nl-NL", { hour: "2-digit", minute: "2-digit" });
  db.addCommunityPost(alias || "Anoniem", trimmed, time);
  res.json({ ok: true });
});

/* ---- SOCKET.IO CHAT ---- */
io.on("connection", (socket) => {
  socket.on("join", (roomId) => socket.join(roomId));

  socket.on("message", ({ roomId, from, text }) => {
    const msg = { from, text, time: new Date().toLocaleTimeString("nl-NL", { hour: "2-digit", minute: "2-digit" }) };
    db.addMessage(roomId, msg.from, msg.text, msg.time);

    const tip = nvcCheck(text);
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
  --blue:#0b3c49; --green:#0f5c4b; --sea:#6fc3b2;
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
</style>
</head>
<body>

<!-- ONBOARDING -->
<div class="screen active" id="s-welcome">
  <div class="card" style="margin-top:auto;margin-bottom:auto">
    <h1>ND Connection</h1>
    <p>Een veilige plek voor neurodivergente verbinding. Rustig, vrijwillig, op jouw tempo.</p>
    <label>Kies een alias (optioneel)</label>
    <input id="alias" placeholder="Anoniem">
    <button onclick="nextTo('s-energy')">Verder →</button>
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
<div class="screen" id="s-matching">
  <h2 style="margin-bottom:0">Zachte matching</h2>
  <p>Op basis van jouw profiel — klik om te chatten.</p>
  <div id="matchList"></div>
</div>

<div class="screen" id="s-community">
  <h2>Community</h2>
  <p class="small">Een rustgevende ruimte. Alles is vrijwillig.</p>
  <div id="communityPosts"></div>
  <div class="card" style="margin-top:4px">
    <input id="postInput" placeholder="Deel een moment van rust…">
    <button onclick="addCommunityPost()">Delen</button>
  </div>
</div>

<div class="screen" id="s-profile">
  <h2>Mijn profiel</h2>
  <div class="card" id="profileCard"></div>
  <div class="card" style="margin-top:16px">
    <div class="section-label">Veiligheidsregels</div>
    <div class="rule">✔ Altijd vrijwillig — je kunt altijd stoppen</div>
    <div class="rule">✔ Geen druk of tijdsdruk</div>
    <div class="rule">✔ Respect voor prikkelgevoeligheid</div>
    <div class="rule">✔ Geweldloze communicatie (NVC)</div>
    <button class="danger sm" onclick="resetApp()">Alles wissen & opnieuw</button>
  </div>
</div>

<!-- CHAT SCREEN -->
<div class="screen chat-screen" id="s-chat">
  <div class="chat-wrap">
    <div class="chat-header">
      <button onclick="showScreen('s-matching')" style="width:auto;margin:0;padding:8px 14px;font-size:13px;border-radius:12px">← Terug</button>
      <strong id="chatPartnerName">Chat</strong>
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

// ---- NAVIGATION ----
function nextTo(screenId) {
  document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
  document.getElementById(screenId).classList.add("active");
}

function showScreen(screenId) {
  document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
  document.getElementById(screenId).classList.add("active");

  const navScreens = ["s-matching", "s-community", "s-profile"];
  document.getElementById("bottomNav").classList.toggle("visible", navScreens.includes(screenId));

  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  const navMap = {"s-matching":"nav-matching","s-community":"nav-community","s-profile":"nav-profile"};
  if(navMap[screenId]) document.getElementById(navMap[screenId]).classList.add("active");

  if(screenId === "s-matching") loadMatches();
  if(screenId === "s-community") renderCommunity();
  if(screenId === "s-profile") renderProfile();
}

// ---- REGISTER ----
async function register() {
  const alias = document.getElementById("alias").value.trim() || "Anoniem";
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

  showScreen("s-matching");
}

// ---- MATCHES ----
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
    return \`<div class="tile match-tile" onclick="openChat('\${m.id}', '\${m.alias}')">
      <strong>\${m.alias}</strong>
      <div class="badge">\${m.energie}</div>
      <div class="score-bar"><div class="score-fill" style="width:\${pct}%"></div></div>
      <div class="small" style="margin:6px 0 0">\${pct}% compatibiliteit</div>
    </div>\`;
  }).join("");
}

// ---- CHAT ----
function openChat(partnerId, partnerAlias) {
  const ids = [myId, partnerId].sort();
  currentRoom = ids.join("_");
  document.getElementById("chatPartnerName").innerText = partnerAlias;
  document.getElementById("chatMessages").innerHTML = "";
  document.getElementById("nvcBanner").style.display = "none";
  showScreen("s-chat");
  socket.emit("join", currentRoom);
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
  const profile = JSON.parse(localStorage.getItem("nd_profile") || "{}");
  socket.emit("message", { roomId: currentRoom, from: profile.alias || "Jij", text });
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
  const profile = JSON.parse(localStorage.getItem("nd_profile") || "{}");
  const isMine = msg.from === (profile.alias || "Jij");
  const wrap = document.getElementById("chatMessages");
  const div = document.createElement("div");
  div.className = "msg " + (isMine ? "mine" : "theirs");
  div.innerHTML = \`<div>\${msg.text}</div><div class="msg-time">\${msg.from} · \${msg.time}</div>\`;
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
    body: JSON.stringify({ alias: profile.alias || "Anoniem", text: txt })
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
      <strong style="font-size:13px">\${p.alias}</strong>
      <span class="small" style="float:right">\${p.time}</span>
      <p style="margin:8px 0 0">\${p.text}</p>
    </div>\`).join("");
}

// ---- PROFILE ----
function renderProfile() {
  const p = JSON.parse(localStorage.getItem("nd_profile") || "{}");
  document.getElementById("profileCard").innerHTML = \`
    <div class="section-label">Jouw gegevens</div>
    <div class="tile"><strong>Alias:</strong> \${p.alias || "Anoniem"}</div>
    <div class="tile"><strong>Energie:</strong> \${p.energie || "—"}</div>
    <div class="tile"><strong>Geluidsgevoelig:</strong> \${p.geluid ? "Ja" : "Nee"}</div>
    <div class="tile"><strong>Druktegevoel:</strong> \${p.drukte ? "Ja" : "Nee"}</div>
    \${p.communicatie ? \`<div class="tile"><strong>Communicatie:</strong><br>\${p.communicatie}</div>\` : ""}
    <div class="tile"><strong>Open voor romantiek via community:</strong> \${p.openVoorRomantiek ? "Ja" : "Nee"}</div>
  \`;
}

function resetApp() {
  if (confirm("Weet je het zeker? Alle gegevens worden gewist.")) {
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

server.listen(PORT, "0.0.0.0", () => console.log("ND Connection draait op poort", PORT));
