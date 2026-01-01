import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import crypto from 'crypto'

// Simulated backend state
let usersByToken = {};
const users = [
  {
    id: 1,
    name: "Alex",
    intentions: ["vriendschap", "diepe gesprekken"],
    communication: "direct",
    energyLevel: "laag"
  },
  {
    id: 2,
    name: "Sam",
    intentions: ["romantisch", "community"],
    communication: "reflectief",
    energyLevel: "neutraal"
  }
];

let consent = {}; // { userId: "open" | "later" | "no" }
let messages = {}; // { userId: [{ from, text, ts }] }
let reports = []; // { from, against, reason, ts }
let blocks = {};  // { userId: [blockedUserId] }
let stats = { onboarded: 0, chatsOpened: 0 };

function isCompatible(u1, u2) {
  if (!u1 || !u2) return false;
  const sameEnergy = u1.energyLevel === u2.energyLevel;
  const overlappingIntentions = (u1.intentions || []).some(i => (u2.intentions || []).includes(i));
  return sameEnergy || overlappingIntentions;
}

function getMatchesForCurrentUser(currentUser, allUsers, blocks = {}) {
  const userBlocks = blocks[currentUser.id] || [];
  return allUsers.filter(u => u.id !== currentUser.id && !userBlocks.includes(u.id) && isCompatible(currentUser, u));
}

function apiPlugin() {
  return {
    name: 'api-simulator',
    configureServer(server) {
      server.middlewares.use(require('body-parser').json());
      server.middlewares.use((req, res, next) => {
        const token = req.headers["x-token"];

        // Auth routes
        if (req.url === '/api/auth/anon' && req.method === 'POST') {
          const newToken = crypto.randomBytes(16).toString("hex");
          usersByToken[newToken] = { 
            id: newToken,
            name: "Jij",
            intentions: [],
            energyLevel: null,
            communication: null,
            sensoryTriggers: [],
            wantsNvcHelp: false
          };
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ token: newToken }));
          return;
        }

        // Current user routes
        if (req.url === '/api/me' && req.method === 'GET') {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify(usersByToken[token] || null));
          return;
        }
        if (req.url === '/api/me' && req.method === 'POST') {
          if (usersByToken[token]) {
            usersByToken[token] = { ...usersByToken[token], ...req.body };
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ ok: true, currentUser: usersByToken[token] }));
          } else {
            res.statusCode = 401;
            res.end('Unauthorized');
          }
          return;
        }

        // Matches routes
        if (req.url === '/matches' && req.method === 'GET') {
          const currentUser = usersByToken[token];
          if (currentUser) {
            const matches = getMatchesForCurrentUser(currentUser, users, blocks);
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(matches));
          } else {
            res.statusCode = 401;
            res.end('Unauthorized');
          }
          return;
        }

        // Safety routes
        if (req.url === '/api/report' && req.method === 'POST') {
          const { from, against, reason } = req.body;
          reports.push({ from, against, reason, ts: Date.now() });
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ ok: true }));
          return;
        }

        const blockMatch = req.url.match(/^\/api\/block\/(.+)$/);
        if (blockMatch && req.method === 'POST') {
          const userId = blockMatch[1];
          const { target } = req.body;
          blocks[userId] = blocks[userId] || [];
          blocks[userId].push(target);
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ ok: true }));
          return;
        }

        // Consent routes
        const consentMatch = req.url.match(/^\/api\/consent\/(.+)$/);
        if (consentMatch) {
          const userId = consentMatch[1];
          if (req.method === 'POST') {
            consent[userId] = req.body.choice;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ ok: true }));
            return;
          }
          if (req.method === 'GET') {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ choice: consent[userId] || null }));
            return;
          }
        }

        // Chat routes
        const chatMatch = req.url.match(/^\/api\/chat\/(.+)$/);
        if (chatMatch) {
          const userId = chatMatch[1];
          if (req.method === 'POST') {
            const { from, text } = req.body;
            messages[userId] = messages[userId] || [];
            messages[userId].push({ from, text, ts: Date.now() });
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ ok: true }));
            return;
          }
          if (req.method === 'GET') {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(messages[userId] || []));
            return;
          }
        }

        const statsMatch = req.url.match(/^\/api\/stats\/(.+)$/);
        if (statsMatch && req.method === 'POST') {
          const key = statsMatch[1];
          if (stats.hasOwnProperty(key)) {
            stats[key]++;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ ok: true }));
          } else {
            res.statusCode = 400;
            res.end('Invalid stats key');
          }
          return;
        }

        next();
      });
    }
  }
}

export default defineConfig({
  plugins: [react(), apiPlugin()],
  server: {
    host: '0.0.0.0',
    port: 5000,
    allowedHosts: true
  }
})
