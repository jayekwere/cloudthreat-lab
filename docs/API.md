# API contract

All `/api/*` endpoints require `Authorization: Bearer <token>`. Use JSON content type for replay bodies. The identity registry, not the request body or token's role claims, determines tenant and role.

| Route                  | Role                    | Result                                                                    |
| ---------------------- | ----------------------- | ------------------------------------------------------------------------- |
| `GET /health`          | Public                  | Liveness                                                                  |
| `GET /api/me`          | Any registered identity | Server-owned identity                                                     |
| `GET /api/rules`       | Analyst, operator       | Versioned rule catalog                                                    |
| `GET /api/scenarios`   | Analyst, operator       | Labeled synthetic source fixtures                                         |
| `GET /api/evaluation`  | Analyst, operator       | Scenario-rule confusion matrix and row expectations                       |
| `POST /api/replay`     | Analyst, operator       | `{name, events}`; 201 investigation with ID, digests, events and findings |
| `GET /api/runs`        | Analyst, operator       | Last fifty tenant run summaries                                           |
| `GET /api/runs/:id`    | Analyst, operator       | Full tenant run or 404                                                    |
| `DELETE /api/runs/:id` | Operator                | 204 on scoped deletion, 404 for an unknown or foreign ID                  |
| `GET /api/audit`       | Analyst, operator       | Recent tenant audit events and full-chain verification                    |

Names are 1 to 80 characters. A batch contains 1 to 2,000 provider envelopes. A tenant can retain at most 100 runs. Delete unneeded runs as an operator. No pagination or continuous history search is implemented beyond the fifty recent summaries. Direct lookup works for every retained run ID.

```sh
# ASSIGN ANALYST_TOKEN from the local demo terminal, then:
node --input-type=module -e '
import {readFileSync} from "node:fs";
const r=await fetch("http://127.0.0.1:4320/api/replay",{
  method:"POST",
  headers:{authorization:"Bearer "+process.env.ANALYST_TOKEN,"content-type":"application/json"},
  body:JSON.stringify({name:"aws-example",events:JSON.parse(readFileSync("fixtures/aws-attack.json","utf8"))})
});
console.log(r.status,await r.json());
'
```

Set the environment variable in your current terminal without committing it. To use the CLI without authentication or a server, run `node --import tsx scripts/replay.ts fixtures/aws-attack.json`. The CLI processes a local file and writes JSON to standard output; it does not persist a server investigation.

Errors use stable codes: 400 invalid request or conflicting event ID, 401 invalid token, 403 forbidden or untrusted origin, 404 run not found, 409 run quota reached, 413 oversized body, 429 rate limit, and a generic 500 for unexpected internal failure. Malformed input is rejected before persistence. No arbitrary raw record or access token is stored in investigations or audit details.
