# BountyPilot AI architecture

The CLI, storage, scope models, planner, and `PolicyEngine` are separate so providers and checks cannot silently expand authority. The policy engine receives a complete URL for every request and redirect destination; it does not inherit permission from the original URL. SQLite stores metadata and audit events locally, while the audit logger intentionally removes response bodies and common credential fields.

## Planning trust boundary

`PlanningProvider` is a narrow protocol that returns structured action data. It has no access to subprocesses, HTTP clients, storage, credentials, or execution callbacks. `Planner` parses the provider result into `PlanAction`, rejects unsupported or malformed values, and calls `PolicyEngine.validate_proposal` for every action. The resulting `SecurityPlan` is a proposal document only.
Passive reconnaissance is represented by the `passive_recon` category and does not require active approval. `xss` and `sqli` are active categories: they are generated only when the configured scope enables active testing, are always marked as requiring approval, and must pass a separate `authorize_for_execution(..., confirmed=True)` call before the CLI scanners issue requests. The CLI executor is deliberately narrow: it only runs the bounded XSS and SQLi modules after a saved plan and command-level approval.

When no provider is supplied, `RuleBasedPlanner` produces a conservative local plan. This keeps planning usable without an API key and makes tests deterministic.

## XSS detection boundary

`XssScanner` derives query and safe-GET form candidates from `ReconResult`; it does not discover arbitrary new targets. Each payload URL is checked by `PolicyEngine.authorize` with `active=True`, `confirmed=True`, category `xss`, and method `GET` immediately before the request. Responses are bounded and redirects are not followed. A raw reflection produces evidence and a `Candidate` or `Needs verification` finding, never `Verified` by itself. Optional `PlaywrightVerifier` uses a fresh browser context with no stored credentials and only checks a controlled in-page marker. The four finding statuses are persisted through the existing SQLite findings table.

`SqlInjectionScanner` uses the same candidate boundary and approval gate. For each candidate it requests the original value as a baseline, then at most two quote perturbations. It compares status, bounded body length, digest, and known error signatures without retaining complete response bodies. A consistent difference or SQL-like error creates a `Needs verification` finding with reproducible request inputs and response context; no automated path marks SQLi `Verified`. Generic unchanged error responses are ignored as false-positive behavior. No destructive, data-extraction, table-dumping, or authentication-bypass payloads are present.

## End-to-end workflow and reports

`workflow.py` persists an assessment identifier, scope snapshot, timestamp, and lifecycle state in SQLite metadata. The CLI requires `init → scope validate → start → plan` before reconnaissance, and requires the reviewed plan before recon or active checks. XSS and SQLi additionally require their own `--approve` flag; approval is passed only to the immediate scanner invocation and is not stored as blanket authorization. `stop` persists the kill switch and transitions the assessment to `stopped`.

`reporting.py` builds a sanitized report from the scope snapshot, audit actions, and persisted findings. It omits complete response bodies, redacts secret-like keys and values, and includes evidence, reproduction guidance, impact, remediation, and explicit limitations. Markdown and JSON are generated together so the human-readable and machine-readable reports describe the same assessment.

## Reconnaissance boundary

`Reconnaissance` uses an `httpx` client with redirects disabled. It validates every seed, discovered link, form action, and `Location` destination against the policy engine. Only explicitly in-scope GET requests are made. A queue, depth limit, URL limit, page-byte limit, configured timeout, and request-rate gate bound the crawl. HTML is parsed with Python's standard-library parser; scripts are never executed and forms are never submitted. Response headers are retained for passive analysis, with cookie and authorization-like values redacted. Each seed, policy decision, destination decision, request start, completion, or failure is recorded in the audit log.
