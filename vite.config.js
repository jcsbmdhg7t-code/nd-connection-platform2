import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

function mockApiPlugin() {
  return {
    name: 'mock-api',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url === '/api/matches') {
          const matches = [
            {
              id: 1,
              name: "Alex",
              intentions: ["Vriendschap", "Diepe gesprekken"],
              communication: "Direct en open",
              energyLevel: "Rustig / Introvert"
            },
            {
              id: 2,
              name: "Sam",
              intentions: ["Lange termijn", "Samen groeien"],
              communication: "Reflectief",
              energyLevel: "Gebalanceerd"
            }
          ];
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify(matches));
          return;
        }
        next();
      });
    }
  }
}

export default defineConfig({
  plugins: [react(), mockApiPlugin()],
  server: {
    host: '0.0.0.0',
    port: 5000,
    allowedHosts: true
  }
})
