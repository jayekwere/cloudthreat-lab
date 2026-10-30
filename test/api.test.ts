import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { demoAuth } from '../src/security.js';
import { Store } from '../src/store.js';
import { createApp } from '../src/app.js';
const rules = JSON.parse(readFileSync('rules/detections.json', 'utf8')),
  scenarios = JSON.parse(readFileSync('fixtures/scenarios.json', 'utf8'));
async function setup() {
  const demo = await demoAuth('cloudthreat-lab'),
    store = new Store(':memory:', 'k'.repeat(32));
  const { app } = createApp({
    auth: demo.auth,
    store,
    baseUrl: 'http://127.0.0.1:4320',
    rules,
    scenarios,
  });
  const headers = (role: string) => ({
    host: '127.0.0.1:4320',
    authorization: 'Bearer ' + demo.tokens[role],
  });
  return { ...demo, store, app, headers };
}
test('authenticated analyst replay persists evidence, enforces tenant isolation, and restricts deletion', async () => {
  const { app, store, headers } = await setup();
  try {
    assert.equal(
      (await app.inject({ url: '/api/runs', headers: { host: '127.0.0.1:4320' } })).statusCode,
      401,
    );
    assert.equal(
      (await app.inject({ url: '/api/rules', headers: headers('agent') })).statusCode,
      403,
    );
    const response = await app.inject({
      method: 'POST',
      url: '/api/replay',
      headers: headers('analyst'),
      payload: { name: 'test', events: scenarios[0].events },
    });
    assert.equal(response.statusCode, 201);
    const run = response.json();
    assert.equal(run.findings.length, 4);
    assert.equal(
      (await app.inject({ url: '/api/runs/' + run.id, headers: headers('outsider') })).statusCode,
      404,
    );
    assert.deepEqual(
      (await app.inject({ url: '/api/runs', headers: headers('outsider') })).json(),
      { runs: [] },
    );
    assert.equal(
      (await app.inject({ url: '/api/runs/' + run.id, headers: headers('analyst') })).json()
        .inputDigest,
      run.inputDigest,
    );
    assert.equal(
      (
        await app.inject({
          method: 'DELETE',
          url: '/api/runs/' + run.id,
          headers: headers('analyst'),
        })
      ).statusCode,
      403,
    );
    assert.equal(
      (
        await app.inject({
          method: 'DELETE',
          url: '/api/runs/' + run.id,
          headers: headers('operator'),
        })
      ).statusCode,
      204,
    );
    assert.equal(
      (await app.inject({ url: '/api/runs/' + run.id, headers: headers('operator') })).statusCode,
      404,
    );
    assert.equal(store.verify(), true);
  } finally {
    await app.close();
    store.close();
  }
});
test('malformed batches are atomic, foreign origins are denied, and no raw record is persisted', async () => {
  const { app, store, headers } = await setup();
  try {
    const bad = await app.inject({
      method: 'POST',
      url: '/api/replay',
      headers: headers('analyst'),
      payload: { name: 'bad', events: [scenarios[0].events[0], { provider: 'aws', record: {} }] },
    });
    assert.equal(bad.statusCode, 400);
    assert.equal(
      (await app.inject({ url: '/api/runs', headers: headers('analyst') })).json().runs.length,
      0,
    );
    assert.equal(
      (
        await app.inject({
          url: '/api/rules',
          headers: { ...headers('analyst'), origin: 'https://evil.invalid' },
        })
      ).statusCode,
      403,
    );
    const event = structuredClone(scenarios[0].events[0]);
    event.record.secret = 'untrusted-secret-value';
    await app.inject({
      method: 'POST',
      url: '/api/replay',
      headers: headers('analyst'),
      payload: { name: 'safe', events: [event] },
    });
    const row = store.db.prepare('SELECT body FROM runs').get() as { body: string };
    assert.equal(row.body.includes('untrusted-secret-value'), false);
    assert.equal(JSON.stringify(store.audits('sandbox')).includes('untrusted-secret-value'), false);
  } finally {
    await app.close();
    store.close();
  }
});
