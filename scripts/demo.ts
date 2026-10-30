import { readFileSync, writeFileSync } from 'node:fs';
import { evaluate, replay } from '../src/replay.js';
const rules = JSON.parse(readFileSync('rules/detections.json', 'utf8')),
  scenarios = JSON.parse(readFileSync('fixtures/scenarios.json', 'utf8'));
const evaluation = evaluate(scenarios, rules);
const sample = replay(scenarios[0].events, rules);
const output = {
  evaluation,
  sample: {
    eventCount: sample.eventCount,
    findings: sample.findings.map((f) => ({
      rule: f.ruleId,
      severity: f.severity,
      evidence: f.evidence.map((e) => e.id),
    })),
  },
};
if (process.argv.includes('--write'))
  writeFileSync('evidence/demo.json', JSON.stringify(output, null, 2) + '\n');
console.log(JSON.stringify(output, null, 2));
if (evaluation.fp || evaluation.fn) process.exitCode = 1;
