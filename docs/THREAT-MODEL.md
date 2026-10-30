# Threat model

Protect tenant investigations, operator deletion authority, audit integrity, authentication material, and availability. Event producers and imported files can be malicious or mistaken. Provider-shaped input is not authenticated provider evidence. The issuer, identity registry, rule files, service host, and audit key are operator trust decisions.

| Threat                                                          | Implemented control                                                                       | Residual limitation                                                      |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| A caller promotes itself through role or tenant claims          | Signed token constraints and server subject registry                                      | Compromised issuer or stolen valid token remains a trust issue           |
| An analyst retrieves or deletes another tenant's investigation  | Server tenant assignment, scoped queries, operator-only deletion                          | Host administrators control the database                                 |
| A malformed batch leaves partial state                          | Full normalization before a transactional run and audit write                             | Disk failure can still cause request failure                             |
| A record spoofs its provider, actor, status, or operation shape | Explicit provider schemas, known action and service mappings, failure classification      | No signature attestation or collector provenance verification            |
| Duplicate delivery inflates detections                          | Deduplication by provider/account/event ID with content fingerprint                       | Conflicting IDs reject rather than automatically choosing a record       |
| Identity strings cause accidental cross-account correlations    | Exact provider/account/actor grouping                                                     | Identity aliases and cross-cloud activity require explicit future design |
| Rule content executes arbitrary code                            | Strict bounded JSON DSL, no eval or supplied regex                                        | Operators still control rule meaning and may create noisy logic          |
| Event text executes browser script                              | Text-node rendering, strict CSP, no external assets                                       | No independent browser security audit claimed                            |
| Attack data exhausts CPU or disk                                | Body, event, field, rule, window, rate-bucket and run bounds; indexed sequence evaluation | Audit storage needs external retention and disk monitoring               |
| An investigator mistakes fixture metrics for live coverage      | Explicit scenario-rule denominators, visible expectations and limitations                 | Synthetic fixtures do not establish field performance                    |
| Local history is altered                                        | HMAC audit chain and startup verification                                                 | Suffix rollback and audit-key compromise require external checkpoints    |

Security invariants: caller-controlled data cannot assign storage tenant or role; failed operations cannot satisfy successful-mutation predicates; correlation cannot join distinct provider/account/actor scopes; invalid batches do not persist partial investigations; rule text never executes; no live credentials or arbitrary raw payloads enter stored evidence.

Missing logs, unknown cloud operation shapes, upstream log forgery, target-principal reasoning, behavioral baselines, and live incident response are outside the implemented scope. Agent audit hashes are structurally validated but not cryptographically verified during import. Use a trusted collection path and preserve original evidence independently when adapting this lab to real investigations.
