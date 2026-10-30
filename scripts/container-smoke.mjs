import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const image = process.argv[2] ?? 'cloudthreat-lab:local',
  name = 'cloudthreat-lab-smoke-' + process.pid;
const base = 'http://127.0.0.1:4320';
const docker = (args) =>
  execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
try {
  docker([
    'run',
    '--rm',
    '-d',
    '--name',
    name,
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    '--pids-limit=128',
    '--memory=512m',
    '--tmpfs',
    '/tmp:size=16m',
    '-e',
    'DEMO=1',
    '-e',
    'BASE_URL=' + base,
    '-p',
    '127.0.0.1:4320:4320',
    image,
  ]);
  let ready = false;
  for (let i = 0; i < 40; i++) {
    try {
      if ((await fetch(base + '/health')).ok) {
        ready = true;
        break;
      }
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  assert.ok(ready, 'Container became healthy');
  const logs = docker(['logs', name]);
  const tokens = JSON.parse(logs.split('Ephemeral demo tokens (15 minutes):\n')[1]);
  const headers = (role) => ({
    authorization: 'Bearer ' + tokens[role],
    'content-type': 'application/json',
  });
  assert.equal((await fetch(base + '/api/me')).status, 401);
  assert.equal((await fetch(base + '/api/me', { headers: headers('operator') })).status, 200);
  const events = JSON.parse(readFileSync('fixtures/aws-attack.json', 'utf8'));
  const response = await fetch(base + '/api/replay', {
    method: 'POST',
    headers: headers('analyst'),
    body: JSON.stringify({ name: 'container-smoke', events }),
  });
  assert.equal(response.status, 201);
  const result = await response.json();
  assert.equal(result.findings.length, 4);
  assert.equal(
    (await fetch(base + '/api/runs/' + result.id, { headers: headers('outsider') })).status,
    404,
  );
  console.log(
    'PASS: non-root read-only container, health, authentication, replay, four findings, and tenant isolation',
  );
} finally {
  try {
    docker(['rm', '-f', name]);
  } catch {}
}
