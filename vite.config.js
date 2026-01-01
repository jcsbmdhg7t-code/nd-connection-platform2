import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Simulated backend state
let currentUser = {
  id: "me",
  name: "Jij",
  intentions: [],
  energyLevel: null,
  communication: null,
  sensoryTriggers: [],
  wantsNvcHelp: false
};

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

function isCompatible(u1, u2) {
  const sameEnergy = u1.energyLevel === u2.energyLevel;
  const overlappingIntentions = u1.intentions.some(i => u2.intentions.includes(i));
  return sameEnergy || overlappingIntentions;
}

function getMatchesForCurrentUser(me, allUsers) {
  return allUsers.filter(u => u.id !== me.id && isCompatible(me, u));
}

function apiPlugin() {
  return {
    name: 'api-simulator',
    configureServer(server) {
      server.middlewares.use(require('body-parser').json());
      server.middlewares.use((req, res, next) => {
        // Current user routes
        if (req.url === '/api/me' && req.method === 'GET') {
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify(currentUser));
          return;
        }
        if (req.url === '/api/me' && req.method === 'POST') {
          currentUser = { ...currentUser, ...req.body };
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ ok: true, currentUser }));
          return;
        }

        // Matches routes
        if (req.url === '/matches' && req.method === 'GET') {
          const matches = getMatchesForCurrentUser(currentUser, users);
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify(matches));
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
