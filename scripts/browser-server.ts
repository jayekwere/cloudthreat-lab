import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { demoAuth } from '../src/security.js';
import { Store } from '../src/store.js';
import { createApp } from '../src/app.js';
const { auth, tokens } = await demoAuth('cloudthreat-lab'),
  store = new Store(':memory:', 'k'.repeat(32));
const rules = JSON.parse(readFileSync('rules/detections.json', 'utf8')),
  scenarios = JSON.parse(readFileSync('fixtures/scenarios.json', 'utf8'));
const { app } = createApp({ auth, store, baseUrl: 'http://127.0.0.1:4320', rules, scenarios });
mkdirSync('test-results', { recursive: true });
writeFileSync('test-results/tokens.json', JSON.stringify(tokens), { mode: 0o600 });
await app.listen({ port: 4320, host: '127.0.0.1' });
