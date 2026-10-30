import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { normalize, normalizeBatch } from '../src/normalize.js';
import { detect, RuleSchema } from '../src/engine.js';
import { replay, evaluate } from '../src/replay.js';
const rules = JSON.parse(readFileSync('rules/detections.json', 'utf8')),
  scenarios = JSON.parse(readFileSync('fixtures/scenarios.json', 'utf8'));
const clone = <T>(v: T): T => structuredClone(v);
test('all labeled attack and benign scenarios meet their rule expectations', () => {
  const report = evaluate(scenarios, rules);
  assert.equal(report.scenarios, 18);
  assert.equal(report.fp, 0);
  assert.equal(report.fn, 0);
  assert.equal(report.precision, 1);
  assert.equal(report.recall, 1);
  assert.ok(report.rows.every((r) => r.passed));
});
for (const s of scenarios)
  test('scenario: ' + s.id, () => {
    const result = replay(s.events, rules);
    assert.deepEqual(
      [...new Set(result.findings.map((f) => f.ruleId))].sort(),
      [...s.expected].sort(),
    );
    for (const f of result.findings) {
      assert.ok(f.evidence.length > 0);
      assert.ok(
        f.evidence.every(
          (e) => e.actor === f.actor && e.account === f.account && e.provider === f.provider,
        ),
      );
    }
  });
test('out-of-order delivery and duplicate batches produce stable results', () => {
  const events = scenarios[0].events,
    result = replay(events, rules);
  assert.deepEqual(replay([...events].reverse(), rules), result);
  assert.deepEqual(replay([...events, ...events], rules), result);
});
test('conflicting IDs reject the whole batch', () => {
  const e = clone(scenarios[0].events[0]);
  e.record.eventName = 'ListUsers';
  assert.throws(() => normalizeBatch([scenarios[0].events[0], e]), {
    code: 'conflicting_event_id',
  });
});
test('same source IDs in distinct accounts remain separate', () => {
  const e = clone(scenarios[0].events[0]);
  e.record.recipientAccountId = '111111111111';
  assert.equal(normalizeBatch([scenarios[0].events[0], e]).length, 2);
});
for (const kind of ['timestamp', 'principal', 'account', 'provider', 'oversized'])
  test('normalization rejects ' + kind, () => {
    const e = clone(scenarios[0].events[0]);
    if (kind === 'timestamp') e.record.eventTime = 'yesterday';
    if (kind === 'principal') delete e.record.userIdentity;
    if (kind === 'account') e.record.recipientAccountId = 'not-an-account';
    if (kind === 'provider') e.provider = 'unknown';
    if (kind === 'oversized') e.record.eventName = 'x'.repeat(1000);
    assert.throws(() => normalize(e));
  });
test('AWS event source must match the mutation service', () => {
  const e = clone(scenarios[0].events[2]);
  e.record.eventSource = 'unrelated.invalid';
  assert.equal(normalize(e).action, 'other');
});
test('empty batches, oversized batches, unknown fields in envelopes, and invalid rule logic fail closed', () => {
  assert.throws(() => normalizeBatch([]));
  assert.throws(() => normalizeBatch(Array(2001).fill(scenarios[0].events[0])));
  assert.throws(() => normalize({ ...scenarios[0].events[0], tenant: 'spoof' }));
  assert.throws(() => RuleSchema.parse({ ...rules[0], eval: 'process.exit()' }));
  assert.throws(() => RuleSchema.parse({ ...rules[0], kind: 'sequence' }));
  assert.throws(() => RuleSchema.parse({ ...rules[0], windowSeconds: 999999 }));
  assert.throws(() => detect([], [rules[0], rules[0]]));
});
test('sequence window is inclusive at boundary and exclusive one millisecond later', () => {
  const first = clone(scenarios[0].events[0]),
    second = clone(scenarios[0].events[1]);
  second.record.eventTime = '2026-01-01T00:10:00Z';
  assert.ok(
    replay([first, second], rules).findings.some((f) => f.ruleId === 'credential-after-privilege'),
  );
  second.record.eventTime = '2026-01-01T00:10:00.001Z';
  assert.equal(
    replay([first, second], rules).findings.some((f) => f.ruleId === 'credential-after-privilege'),
    false,
  );
});
test('threshold does not count duplicate events and suppresses repeated overlapping alerts', () => {
  const events = scenarios.find((s: any) => s.id === 'agent-policy-probing').events;
  assert.equal(
    replay([...events, ...events], rules).findings.filter((f) => f.ruleId === 'agent-denial-burst')
      .length,
    1,
  );
  assert.equal(replay(Array(10).fill(events[0]), rules).findings.length, 0);
});
test('cross-provider strings never join and failed first step cannot start a sequence', () => {
  const a = clone(scenarios[0].events[0]),
    b = clone(scenarios[2].events[1]);
  b.record.protoPayload.authenticationInfo.principalEmail = a.record.userIdentity.principalId;
  assert.equal(
    replay([a, b], rules).findings.some((f) => f.ruleId === 'credential-after-privilege'),
    false,
  );
  a.record.errorCode = 'AccessDenied';
  assert.equal(replay([a, scenarios[0].events[1]], rules).findings.length, 0);
});
test('metrics expose injected false positives and misses instead of masking them', () => {
  const wrong = clone(scenarios.slice(0, 1));
  wrong[0].expected = [];
  assert.equal(evaluate(wrong, rules).fp, 4);
  const benign = clone(scenarios.filter((s: any) => s.id === 'aws-benign-read'));
  benign[0].expected = ['logging-disruption'];
  assert.equal(evaluate(benign, rules).fn, 1);
});
test('GCP operations require the correct service and simultaneous events do not prove sequence', () => {
  const e = clone(scenarios[2].events[2]);
  e.record.protoPayload.serviceName = 'unrelated.invalid';
  assert.equal(normalize(e).action, 'other');
  const a = clone(scenarios[0].events[0]),
    b = clone(scenarios[0].events[1]);
  b.record.eventTime = a.record.eventTime;
  assert.equal(
    replay([a, b], rules).findings.some((f) => f.ruleId === 'credential-after-privilege'),
    false,
  );
});
test('actual synthetic Sentinel audit export replays through the agent adapter', () => {
  const exported = JSON.parse(readFileSync('fixtures/sentinel-export.json', 'utf8'));
  const findings = replay(exported, rules).findings;
  assert.ok(findings.some((f) => f.ruleId === 'agent-denial-burst'));
  assert.equal(findings.filter((f) => f.ruleId === 'invalid-approval-use').length, 2);
});
test('maximum-size no-completion sequence remains bounded', () => {
  const template = scenarios[0].events[0];
  const events = Array.from({ length: 2000 }, (_, i) => ({
    ...template,
    record: {
      ...template.record,
      eventID: 'bounded-' + i,
      eventTime: new Date(Date.parse('2026-01-01T00:00:00Z') + i * 1000).toISOString(),
    },
  }));
  const output = replay(events, rules);
  assert.equal(output.eventCount, 2000);
  assert.equal(output.findings.length, 2000);
});
