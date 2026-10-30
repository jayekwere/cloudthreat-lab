import { z } from 'zod';
import { digest, Fault } from './security.js';
const string = z.string().min(1).max(512);
const time = z.iso.datetime({ offset: true });
export const Envelope = z
  .object({
    provider: z.enum(['aws', 'azure', 'gcp', 'sentinel']),
    record: z.record(z.string(), z.unknown()),
  })
  .strict();
export const EventSchema = z
  .object({
    id: string,
    provider: z.enum(['aws', 'azure', 'gcp', 'sentinel']),
    account: string,
    actor: string,
    time,
    action: z.enum([
      'privilege.grant',
      'credential.create',
      'logging.disable',
      'agent.denied',
      'approval.invalid',
      'other',
    ]),
    outcome: z.enum(['success', 'failure']),
    sourceIp: z.string().max(256),
    privileged: z.boolean(),
    tool: z.string().max(100),
    fingerprint: z.string().length(64),
  })
  .strict();
export type Event = z.infer<typeof EventSchema>;
export type Input = z.infer<typeof Envelope>;
export const Aws = z.object({
  eventID: string,
  eventTime: time,
  eventName: string,
  eventSource: string,
  recipientAccountId: z.string().regex(/^\d{12}$/),
  userIdentity: z.object({ principalId: string }),
  sourceIPAddress: z.string().max(256).optional(),
  errorCode: string.optional(),
  requestParameters: z.record(z.string(), z.unknown()).nullish(),
});
export const Azure = z.object({
  eventDataId: string,
  eventTimestamp: time,
  subscriptionId: string,
  caller: string,
  operationName: z.object({ value: string }),
  status: z.object({ value: string }),
  httpRequest: z.object({ clientIpAddress: z.string().max(256).optional() }).optional(),
  properties: z.object({ roleDefinitionId: string.optional() }).optional(),
});
export const Gcp = z.object({
  insertId: string,
  timestamp: time,
  resource: z.object({ labels: z.object({ project_id: string }) }),
  protoPayload: z.object({
    methodName: string,
    serviceName: string,
    authenticationInfo: z.object({ principalEmail: string }),
    requestMetadata: z.object({ callerIp: z.string().max(256).optional() }).optional(),
    status: z.object({ code: z.number().int().min(0) }).optional(),
    serviceData: z
      .object({
        policyDelta: z.object({
          bindingDeltas: z
            .array(z.object({ action: z.string(), role: z.string(), member: z.string() }))
            .max(100),
        }),
      })
      .optional(),
  }),
});
const Agent = z.object({
  seq: z.number().int().positive(),
  at: time,
  tenant: string,
  actor: string,
  action: string,
  outcome: z.enum(['allowed', 'denied', 'error', 'pending', 'approved', 'rejected']),
  detail: z.record(z.string(), z.unknown()),
  prev: string,
  hash: z.string().length(64),
});
export function normalize(input: unknown): Event {
  const { provider, record } = Envelope.parse(input);
  const fingerprint = digest(record);
  if (provider === 'aws') {
    const r = Aws.parse(record),
      p = r.requestParameters ?? {};
    const grant =
      r.eventSource === 'iam.amazonaws.com' &&
      ['AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy'].includes(r.eventName);
    const privileged = grant && p.policyArn === 'arn:aws:iam::aws:policy/AdministratorAccess';
    const action = grant
      ? 'privilege.grant'
      : r.eventSource === 'iam.amazonaws.com' && r.eventName === 'CreateAccessKey'
        ? 'credential.create'
        : r.eventSource === 'cloudtrail.amazonaws.com' &&
            ['StopLogging', 'DeleteTrail'].includes(r.eventName)
          ? 'logging.disable'
          : 'other';
    return EventSchema.parse({
      id: r.eventID,
      time: r.eventTime,
      provider,
      account: r.recipientAccountId,
      actor: r.userIdentity.principalId,
      action,
      outcome: r.errorCode ? 'failure' : 'success',
      sourceIp: r.sourceIPAddress ?? '',
      privileged,
      tool: '',
      fingerprint,
    });
  }
  if (provider === 'azure') {
    const r = Azure.parse(record),
      op = r.operationName.value.toLowerCase();
    const action =
      op === 'microsoft.authorization/roleassignments/write'
        ? 'privilege.grant'
        : op === 'microsoft.insights/diagnosticsettings/delete'
          ? 'logging.disable'
          : 'other';
    // Exact built-in role IDs. Activity records without this context stay unclassified.
    const role = r.properties?.roleDefinitionId?.split('/').at(-1)?.toLowerCase();
    const privileged =
      action === 'privilege.grant' &&
      ['8e3af657-a8ff-443c-a75c-2fe8c4bcb635', 'b24988ac-6180-42a0-ab88-20f7382dd24c'].includes(
        role ?? '',
      );
    return EventSchema.parse({
      id: r.eventDataId,
      time: r.eventTimestamp,
      provider,
      account: r.subscriptionId,
      actor: r.caller,
      action,
      outcome: r.status.value.toLowerCase() === 'succeeded' ? 'success' : 'failure',
      sourceIp: r.httpRequest?.clientIpAddress ?? '',
      privileged,
      tool: '',
      fingerprint,
    });
  }
  if (provider === 'gcp') {
    const r = Gcp.parse(record),
      p = r.protoPayload;
    const action =
      p.serviceName === 'cloudresourcemanager.googleapis.com' &&
      ['SetIamPolicy', 'google.iam.v1.IAMPolicy.SetIamPolicy'].includes(p.methodName)
        ? 'privilege.grant'
        : p.serviceName === 'iam.googleapis.com' &&
            p.methodName === 'google.iam.admin.v1.CreateServiceAccountKey'
          ? 'credential.create'
          : p.serviceName === 'logging.googleapis.com' &&
              p.methodName === 'google.logging.v2.ConfigServiceV2.DeleteSink'
            ? 'logging.disable'
            : 'other';
    const privileged =
      action === 'privilege.grant' &&
      (p.serviceData?.policyDelta.bindingDeltas ?? []).some(
        (d) => d.action === 'ADD' && ['roles/owner', 'roles/editor'].includes(d.role),
      );
    return EventSchema.parse({
      id: r.insertId,
      time: r.timestamp,
      provider,
      account: r.resource.labels.project_id,
      actor: p.authenticationInfo.principalEmail,
      action,
      outcome: !p.status || p.status.code === 0 ? 'success' : 'failure',
      sourceIp: p.requestMetadata?.callerIp ?? '',
      privileged,
      tool: '',
      fingerprint,
    });
  }
  const r = Agent.parse(record);
  return EventSchema.parse({
    id: String(r.seq),
    time: r.at,
    provider,
    account: r.tenant,
    actor: r.actor,
    action:
      r.action === 'tool.denied'
        ? 'agent.denied'
        : r.action === 'approval.invalid'
          ? 'approval.invalid'
          : 'other',
    outcome: r.outcome === 'denied' ? 'failure' : 'success',
    sourceIp: '',
    privileged: false,
    tool: typeof r.detail.tool === 'string' ? r.detail.tool : '',
    fingerprint,
  });
}
export function normalizeBatch(input: unknown): Event[] {
  const items = z.array(Envelope).min(1).max(2000).parse(input),
    events = new Map<string, Event>();
  for (const item of items) {
    const e = normalize(item),
      key = JSON.stringify([e.provider, e.account, e.id]);
    if (events.has(key) && events.get(key)!.fingerprint !== e.fingerprint)
      throw new Fault(400, 'conflicting_event_id');
    events.set(key, e);
  }
  return [...events.values()].sort(
    (a, b) => Date.parse(a.time) - Date.parse(b.time) || a.id.localeCompare(b.id),
  );
}
