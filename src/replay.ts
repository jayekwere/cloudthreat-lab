import { z } from 'zod';
import { normalizeBatch, Envelope } from './normalize.js';
import { detect, type Rule } from './engine.js';
import { digest } from './security.js';
export const ScenarioSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9-]+$/),
    description: z.string(),
    expected: z.array(z.string()),
    events: z.array(Envelope).min(1).max(2000),
  })
  .strict();
export function replay(events: unknown, rules: Rule[]) {
  const normalized = normalizeBatch(events),
    findings = detect(normalized, rules);
  return {
    schemaVersion: 1,
    rulesDigest: digest(rules),
    inputDigest: digest(normalized),
    eventCount: normalized.length,
    findings,
    events: normalized,
  };
}
export function evaluate(input: unknown, rules: Rule[]) {
  const scenarios = z.array(ScenarioSchema).min(1).parse(input);
  if (new Set(scenarios.map((s) => s.id)).size !== scenarios.length)
    throw new Error('Duplicate scenario');
  const ruleIds = new Set(rules.map((r) => r.id));
  let tp = 0,
    fp = 0,
    fn = 0,
    tn = 0;
  const rows = scenarios.map((s) => {
    if (s.expected.some((id) => !ruleIds.has(id))) throw new Error('Unknown expected rule');
    const result = replay(s.events, rules),
      actual = new Set(result.findings.map((f) => f.ruleId)),
      expected = new Set(s.expected);
    for (const id of ruleIds) {
      if (actual.has(id) && expected.has(id)) tp++;
      else if (actual.has(id)) fp++;
      else if (expected.has(id)) fn++;
      else tn++;
    }
    return {
      id: s.id,
      eventCount: result.eventCount,
      expected: [...expected].sort(),
      actual: [...actual].sort(),
      passed:
        [...expected].every((id) => actual.has(id)) && [...actual].every((id) => expected.has(id)),
    };
  });
  return {
    scope: 'synthetic scenario-rule pairs only',
    scenarios: rows.length,
    rules: rules.length,
    tp,
    fp,
    fn,
    tn,
    precision: tp + fp ? tp / (tp + fp) : null,
    recall: tp + fn ? tp / (tp + fn) : null,
    falsePositiveRate: fp + tn ? fp / (fp + tn) : null,
    rows,
  };
}
