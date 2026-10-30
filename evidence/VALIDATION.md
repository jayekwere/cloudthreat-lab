# Release validation

Recorded on 2026-10-30. These are executed checks, not proposed acceptance criteria. Host validation used Node 26.3.0, and the pinned Alpine image independently ran the suite on Node 24. Browser workflows used a locally installed compatible browser through Playwright. Hosted CI uses the Playwright Chromium build and is visible in the repository Actions tab.

| Check | Observed result | Evidence |
| --- | --- | --- |
| Formatter, strict types, build and demo | Passed | [verify.txt](verify.txt) |
| Automated tests | 55 passed, zero failed or skipped | [coverage.txt](coverage.txt) |
| V8 coverage, exercised source modules | 96.85% lines, 91.73% branches | [coverage.txt](coverage.txt) |
| Browser workflow | Passed at 1440px desktop and 390px mobile widths, no page errors | [browser.txt](browser.txt), [desktop](../docs/dashboard.png), [mobile](../docs/dashboard-mobile.png) |
| Container build | Passed, includes Node 24 type and test checks | [container-build.txt](container-build.txt) |
| Restricted runtime | Passed with non-root user, read-only root, dropped capabilities and process/memory limits | [container-smoke.txt](container-smoke.txt) |
| Locked dependency advisory query | Zero reported advisories at validation time | [dependencies.json](dependencies.json) |
| Tracked text policy and credential-pattern inspection | Passed | `node scripts/check-content.mjs` and local tracked-file inspection |

The coverage report includes modules loaded by the automated tests. Startup configuration, the main entrypoint, and browser source are not included in those percentages. Browser and container checks exercise those paths separately. Coverage is evidence of execution, not proof that all security properties hold. Dependency advisory results change over time and do not cover every vulnerability in a container base.

[Source manifest](source-manifest.json) fingerprints the implementation, tests, build scripts, workflow, and dependency lockfile. The full test output records case names and actual outcomes. Disposable tokens are intentionally absent from committed logs. Demo timestamps, request IDs, approval IDs, audit hashes, and measured durations vary per run.

The fixture evaluator measured 18 true positives, zero false positives, zero false negatives, and 90 true negatives over 18 scenarios and six rules. Precision and recall are both 1.0 on that fixture set only. Tests introduce deliberately incorrect labels and confirm false positives and misses are reported. Separate cases cover exact sequence-window boundaries, source-service mismatch, simultaneous timestamps, duplicate delivery, conflicting IDs, cross-identity/account/provider isolation, and a maximum-size 2,000-event batch.

The browser test imports hostile markup as an actor string and confirms it appears as text with no image node. API tests confirm invalid batches persist nothing, arbitrary raw source fields are discarded, analyst deletion is denied, and foreign tenant run IDs return 404. A captured synthetic Sentinel export is replayed through the agent adapter. No live cloud telemetry, collector provenance, production tenant, or field detection performance was tested.
