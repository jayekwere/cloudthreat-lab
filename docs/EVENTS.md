# Event contracts

A batch is a JSON array of `{ "provider": "aws|azure|gcp|sentinel", "record": { ... } }`. Do not submit a raw CloudTrail `Records` wrapper, an Azure event-hub envelope, or a log-query response wrapper. Extract records and label their provider first. Maximum batch size is 2,000 events; HTTP is capped at 256 KiB. Required strings are nonempty and at most 512 characters. ISO timestamps require an explicit time zone. Unknown fields in source records are ignored after fingerprinting.

## AWS export adapter

Requires `eventID`, `eventTime`, `eventName`, `eventSource`, a twelve-digit `recipientAccountId`, and `userIdentity.principalId`. Optional `sourceIPAddress`, `errorCode`, and `requestParameters` are parsed. Any nonempty error code marks failure. These actions are mapped only for the expected source service:

- `iam.amazonaws.com`: `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy` map to privilege grant. Only the exact `arn:aws:iam::aws:policy/AdministratorAccess` request policy marks a recognized broad role. `CreateAccessKey` maps to credential creation.
- `cloudtrail.amazonaws.com`: `StopLogging` and `DeleteTrail` map to logging disruption.

Inline policies, custom administrative policies, permission boundaries, role trust changes, alternate partitions, and the full IAM escalation graph are not covered. A principal ID is kept exactly as supplied, including session suffixes. No assumed-role identity resolution is performed.

## Azure export adapter

Accepts the REST/portal-style Activity Log projection with `eventDataId`, `eventTimestamp`, `subscriptionId`, `caller`, `operationName.value`, and `status.value`. Only `Succeeded` case-insensitively counts as success. Started, accepted, and failed activity does not count as a completed change. Optional source IP is `httpRequest.clientIpAddress`.

`Microsoft.Authorization/roleAssignments/write` maps to a grant. `Microsoft.Insights/diagnosticSettings/delete` maps to logging disruption. Broad role classification requires `properties.roleDefinitionId` in the supplied projection, with final role ID equal to the built-in Owner or Contributor ID. The fixture explicitly supplies this role context. Activity Log exports do not consistently include it; this lab does not fetch or infer the role definition. Enrich that projection through a trusted process if your original export omits the field. Missing context remains `privileged=false` and does not trigger broad-role rules. A role assignment can be benign even when the role is broad.

This is not an adapter for every Activity Log export schema. Entra audit logs and credential changes are not implemented. Deleting a diagnostic setting means a specific route was removed, not that all Azure audit evidence ceased.

## GCP export adapter

Requires `insertId`, `timestamp`, `resource.labels.project_id`, and `protoPayload` with `methodName`, `serviceName`, and `authenticationInfo.principalEmail`. Optional `requestMetadata.callerIp` is preserved. Omitted status or `status.code=0` is success; a nonzero code is failure.

- `cloudresourcemanager.googleapis.com`: exact `SetIamPolicy` or `google.iam.v1.IAMPolicy.SetIamPolicy` maps to a grant. Broad role context requires `serviceData.policyDelta.bindingDeltas` containing `action=ADD` with `roles/owner` or `roles/editor`.
- `iam.googleapis.com`: `google.iam.admin.v1.CreateServiceAccountKey` maps to credential creation.
- `logging.googleapis.com`: `google.logging.v2.ConfigServiceV2.DeleteSink` maps to logging disruption.

Other method representations, policyDelta locations, resource label types, policy contents without deltas, delegated identities, and missing principal emails are not silently guessed. Sink deletion can remove one route while other collection continues. The signal does not claim all audit logging is disabled.

## Sentinel adapter

Accepts actual gateway audit-shaped objects with positive integer `seq`, `at`, `tenant`, `actor`, `action`, recognized `outcome`, `detail`, `prev`, and a 64-character `hash`. `tool.denied` maps to agent denial and `approval.invalid` to invalid approval. The source tenant becomes normalized account scope, not the API storage tenant. The uploaded hash is not verified with an audit key. It is imported as supplied evidence; use independent chain verification to authenticate a real export.

`fixtures/sentinel-export.json` is an actual synthetic demo export from MCP Sentinel. Its fixture audit key is disposable and the values contain no live authentication tokens. Tests replay it and assert denial-burst and invalid-approval detections.

## Stable normalized representation

Each normalized event retains source ID, provider, account, exact actor, source time, known action, success/failure, optional source IP, privileged-context flag, optional tool name, and full raw-record SHA-256 fingerprint. Arbitrary raw fields are discarded. Deduplication keys use provider/account/event ID. An exact duplicate is removed; the same key with a different fingerprint rejects the whole batch. Fingerprints identify content, not authenticity.

Source references: [CloudTrail record fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html), [Activity Log schema](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log-schema), and [AuditLog structure](https://cloud.google.com/logging/docs/audit/understanding-audit-logs). The implementation intentionally supports the narrower contracts above. No live cloud API call was used to validate these adapters.
