import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { Auth, Fault } from './security.js';
import { Store } from './store.js';
import { secureApp, requireRole } from './http.js';
import { replay, evaluate } from './replay.js';
import { RuleSchema, type Rule } from './engine.js';
export function createApp(options: {
  auth: Auth;
  store: Store;
  baseUrl: string;
  rules: Rule[];
  scenarios: unknown;
  webRoot?: string;
  limit?: number;
}) {
  const app = secureApp(
    options.auth,
    options.store,
    options.baseUrl,
    options.webRoot,
    options.limit,
  );
  const rules = z.array(RuleSchema).parse(options.rules);
  app.get('/api/rules', async (req) => {
    requireRole(req, ['analyst', 'operator']);
    return { rules };
  });
  app.get('/api/scenarios', async (req) => {
    requireRole(req, ['analyst', 'operator']);
    return options.scenarios;
  });
  app.get('/api/evaluation', async (req) => {
    requireRole(req, ['analyst', 'operator']);
    return evaluate(options.scenarios, rules);
  });
  app.get('/api/runs', async (req) => {
    requireRole(req, ['analyst', 'operator']);
    return {
      runs: (
        options.store.db
          .prepare('SELECT id,body FROM runs WHERE tenant=? ORDER BY rowid DESC LIMIT 50')
          .all(req.identity.tenant) as { id: string; body: string }[]
      ).map((r) => {
        const b = JSON.parse(r.body);
        return {
          id: r.id,
          name: b.name,
          at: b.at,
          eventCount: b.eventCount,
          findings: b.findings.length,
        };
      }),
    };
  });
  app.post('/api/replay', async (req, reply) => {
    requireRole(req, ['analyst', 'operator']);
    const body = z
      .object({ name: z.string().min(1).max(80), events: z.unknown() })
      .strict()
      .parse(req.body);
    const result = replay(body.events, rules),
      id = randomUUID(),
      at = new Date().toISOString();
    options.store.transaction(() => {
      const n = options.store.db
        .prepare('SELECT count(*) AS n FROM runs WHERE tenant=?')
        .get(req.identity.tenant) as { n: number };
      if (n.n >= 100) throw new Fault(409, 'run_limit_reached');
      options.store.db
        .prepare('INSERT INTO runs VALUES(?,?,?)')
        .run(id, req.identity.tenant, JSON.stringify({ ...result, name: body.name, at }));
      options.store.audit(
        req.identity.tenant,
        req.identity.subject,
        'replay.completed',
        'allowed',
        {
          id,
          eventCount: result.eventCount,
          findingCount: result.findings.length,
          inputDigest: result.inputDigest,
          rulesDigest: result.rulesDigest,
        },
      );
    });
    return reply.status(201).send({ id, name: body.name, at, ...result });
  });
  app.get('/api/runs/:id', async (req) => {
    requireRole(req, ['analyst', 'operator']);
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const row = options.store.db
      .prepare('SELECT body FROM runs WHERE id=? AND tenant=?')
      .get(id, req.identity.tenant) as { body: string } | undefined;
    if (!row) throw new Fault(404, 'run_not_found');
    return { id, ...JSON.parse(row.body) };
  });
  app.delete('/api/runs/:id', async (req, reply) => {
    requireRole(req, ['operator']);
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    options.store.transaction(() => {
      const change = options.store.db
        .prepare('DELETE FROM runs WHERE id=? AND tenant=?')
        .run(id, req.identity.tenant);
      if (!change.changes) throw new Fault(404, 'run_not_found');
      options.store.audit(req.identity.tenant, req.identity.subject, 'replay.deleted', 'allowed', {
        id,
      });
    });
    return reply.status(204).send();
  });
  return { app };
}
