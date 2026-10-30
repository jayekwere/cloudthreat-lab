import { readFileSync } from 'node:fs';
import { config } from './config.js';
import { Store } from './store.js';
import { createApp } from './app.js';
const c = await config('cloudthreat-lab', 4320),
  store = new Store(c.db, c.key);
const rules = JSON.parse(readFileSync('rules/detections.json', 'utf8'));
const scenarios = JSON.parse(readFileSync('fixtures/scenarios.json', 'utf8'));
const { app } = createApp({ auth: c.auth, store, baseUrl: c.baseUrl, rules, scenarios });
await app.listen({ port: Number(process.env.PORT ?? 4320), host: c.host });
console.log(`CloudThreat Lab listening at ${c.baseUrl}`);
if (c.demo)
  console.log('Ephemeral demo tokens (15 minutes):\n' + JSON.stringify(c.tokens, null, 2));
for (const signal of ['SIGINT', 'SIGTERM'] as const)
  process.on(signal, () => {
    void app.close().then(() => {
      store.close();
      process.exit(0);
    });
  });
