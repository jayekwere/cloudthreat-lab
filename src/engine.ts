import { z } from 'zod';
import { digest } from './security.js';
import type { Event } from './normalize.js';
const Filter = z
  .object({
    action: z.enum([
      'privilege.grant',
      'credential.create',
      'logging.disable',
      'agent.denied',
      'approval.invalid',
      'other',
    ]),
    outcome: z.enum(['success', 'failure']).optional(),
    privileged: z.boolean().optional(),
  })
  .strict();
export const RuleSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9-]{1,80}$/),
    version: z.number().int().positive(),
    title: z.string().min(1).max(160),
    description: z.string().min(1).max(500),
    severity: z.enum(['medium', 'high', 'critical']),
    technique: z.string().regex(/^T\d{4}(\.\d{3})?$/),
    windowSeconds: z.number().int().min(1).max(86400),
    kind: z.enum(['match', 'sequence', 'threshold']),
    steps: z.array(Filter).min(1).max(5),
    threshold: z.number().int().min(1).max(100).optional(),
  })
  .strict()
  .superRefine((r, c) => {
    if (r.kind === 'sequence' && r.steps.length < 2)
      c.addIssue({ code: 'custom', message: 'Sequence requires at least two steps' });
    if (r.kind !== 'sequence' && r.steps.length !== 1)
      c.addIssue({ code: 'custom', message: 'Match and threshold require one step' });
    if (r.kind === 'threshold' && !r.threshold)
      c.addIssue({ code: 'custom', message: 'Threshold is required' });
  });
export type Rule = z.infer<typeof RuleSchema>;
export interface Finding {
  id: string;
  ruleId: string;
  ruleVersion: number;
  title: string;
  description: string;
  severity: Rule['severity'];
  technique: string;
  provider: Event['provider'];
  account: string;
  actor: string;
  start: string;
  end: string;
  evidence: Event[];
}
const match = (e: Event, f: z.infer<typeof Filter>) =>
  e.action === f.action &&
  (f.outcome === undefined || e.outcome === f.outcome) &&
  (f.privileged === undefined || e.privileged === f.privileged);
export function detect(events: Event[], input: unknown): Finding[] {
  const rules = z.array(RuleSchema).min(1).max(100).parse(input);
  if (new Set(rules.map((r) => r.id)).size !== rules.length) throw new Error('Duplicate rule id');
  const groups = Map.groupBy(
    [...events].sort((a, b) => Date.parse(a.time) - Date.parse(b.time) || a.id.localeCompare(b.id)),
    (e) => JSON.stringify([e.provider, e.account, e.actor]),
  );
  const findings: Finding[] = [];
  for (const rule of rules)
    for (const group of groups.values()) {
      const emitted = new Set<string>();
      const emit = (evidence: Event[]) => {
        const first = evidence[0]!,
          last = evidence.at(-1)!;
        const id = digest({
          rule: rule.id,
          version: rule.version,
          evidence: evidence.map((e) => [e.provider, e.account, e.id, e.fingerprint]),
        });
        if (emitted.has(id)) return;
        emitted.add(id);
        findings.push({
          id,
          ruleId: rule.id,
          ruleVersion: rule.version,
          title: rule.title,
          description: rule.description,
          severity: rule.severity,
          technique: rule.technique,
          provider: first.provider,
          account: first.account,
          actor: first.actor,
          start: first.time,
          end: last.time,
          evidence,
        });
      };
      if (rule.kind === 'match') {
        for (const e of group) if (match(e, rule.steps[0]!)) emit([e]);
        continue;
      }
      if (rule.kind === 'threshold') {
        const matched = group.filter((e) => match(e, rule.steps[0]!));
        let left = 0,
          lastEnd = -Infinity;
        for (let right = 0; right < matched.length; right++) {
          while (
            Date.parse(matched[right]!.time) - Date.parse(matched[left]!.time) >
            rule.windowSeconds * 1000
          )
            left++;
          if (
            right - left + 1 >= rule.threshold! &&
            Date.parse(matched[right]!.time) - lastEnd > rule.windowSeconds * 1000
          ) {
            emit(matched.slice(left, right + 1));
            lastEnd = Date.parse(matched[right]!.time);
          }
        }
        continue;
      }
      // Index each step and binary-search the earliest strictly later match.
      const candidates = rule.steps.map((filter) => group.filter((e) => match(e, filter)));
      for (const first of candidates[0]!) {
        const evidence = [first];
        for (let step = 1; step < candidates.length; step++) {
          const options = candidates[step]!,
            previous = Date.parse(evidence.at(-1)!.time);
          let low = 0,
            high = options.length;
          while (low < high) {
            const mid = (low + high) >>> 1;
            if (Date.parse(options[mid]!.time) <= previous) low = mid + 1;
            else high = mid;
          }
          const next = options[low];
          if (!next || Date.parse(next.time) - Date.parse(first.time) > rule.windowSeconds * 1000)
            break;
          evidence.push(next);
        }
        if (evidence.length === rule.steps.length) emit(evidence);
      }
    }
  return findings.sort(
    (a, b) => Date.parse(a.start) - Date.parse(b.start) || a.id.localeCompare(b.id),
  );
}
