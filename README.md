# BountyPilot AI

BountyPilot AI is a **policy-first command-line toolkit for authorized security testing**. It combines deterministic scope and safety controls with bounded passive reconnaissance, structured planning, conservative XSS/SQLi checks, audit logging, local SQLite persistence, and sanitized Markdown/JSON reporting.

> Use this project only against systems for which you have explicit written authorization. The tool does not expand scope, bypass policy, attack credentials, dump databases, or run active checks without an explicit approval flag.

## What is implemented

- Python package with a `bountypilot` console command
- Pydantic validation for hosts, schemes, ports, paths, exclusions, methods, and categories
- Deterministic policy engine with scope checks, safe-method checks, rate limiting, timeouts, active-test approval, and a persistent kill switch
- Persisted assessment lifecycle: `init → scope validate → start → plan → recon → approved checks → findings → report`
- Rule-based planning fallback that works without an API key
- Vendor-neutral `PlanningProvider` interface for mocked or future AI adapters
- Bounded passive HTTP reconnaissance with headers, titles, metadata, links, forms, technology indicators, redirect checks, and JSON export
- Conservative reflected-XSS checks with optional isolated Playwright marker verification
- Conservative SQLi checks using a baseline plus at most two controlled quote perturbations
- SQLite findings and append-only audit records
- Assessment-scoped Markdown and JSON reports with secret-like value redaction
- Local mock-lab integration tests and GitHub Actions CI

## Requirements

- Python 3.11 or newer
- `python3-venv` on Debian/Kali systems
- Network access during installation to download Python packages
- Optional: Playwright and Chromium only for isolated XSS browser verification

The default runtime dependencies are intentionally small and are all used directly:

| Package | Purpose |
|---|---|
| `httpx` | Bounded HTTP requests with timeouts and redirects disabled |
| `pydantic` | Validated scope, plan, scan, workflow, and report models |
| `rich` | Human-readable CLI output |
| `typer` | CLI command and option handling |

`pytest` is only in the `test` extra. `playwright` is only in the optional `browser` extra and is not installed by default.

## Kali Linux installation

Clone the repository and install it into an isolated virtual environment:

```bash
sudo apt update
sudo apt install -y python3 python3-venv git
cd ~
git clone https://github.com/YOUR-USERNAME/bountypilot-ai.git
cd bountypilot-ai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
python -m pip check
pytest -q
bountypilot --help
bountypilot status
```

The repository currently requires Python `>=3.11`; CI checks Python 3.11 and 3.12. The installation was verified in a clean Python 3.12 virtual environment with the test suite and CLI smoke checks.

## End-to-end workflow

```bash
bountypilot init
bountypilot scope validate --host 127.0.0.1 --path / --active
bountypilot start --target "local intentionally vulnerable lab"
bountypilot plan

# Review the plan before continuing.
bountypilot recon \
  --max-depth 1 \
  --max-urls 25 \
  --output .bountypilot/recon.json

# Each active check requires separate explicit approval.
bountypilot test xss \
  --recon .bountypilot/recon.json \
  --approve \
  --output .bountypilot/xss-result.json

bountypilot test sqli \
  --recon .bountypilot/recon.json \
  --approve \
  --output .bountypilot/sqli-result.json

bountypilot findings
bountypilot report
bountypilot status
```

`start` requires a non-empty validated scope. `plan` must be saved before reconnaissance or active checks. `--approve` applies only to the immediate XSS or SQLi command and is not stored as blanket authorization. The `stop` command activates the persistent kill switch and prevents future policy-authorized requests.

State and generated artifacts are stored under `.bountypilot/`, which is excluded from Git.

## Architecture

The main modules are:

- `scope.py` — validated authorized hosts, ports, paths, exclusions, methods, and categories
- `policy.py` — deterministic final gate for every proposed or executable request
- `planner.py` / `providers.py` — ordered structured plans and vendor-neutral provider contract
- `recon.py` — bounded passive crawler; no form submission or script execution
- `xss.py` — reflected-XSS candidates, evidence, statuses, and optional isolated browser verification
- `sqli.py` — baseline comparison, SQL-error indicators, response differences, and conservative evidence
- `workflow.py` — persisted assessment identity and lifecycle state
- `storage.py` / `audit.py` — local SQLite metadata, findings, and append-only audit events
- `reporting.py` — assessment-scoped sanitized Markdown and JSON reports
- `cli.py` — explicit workflow commands and approval boundaries

The AI/provider boundary is intentionally narrow: a provider can return structured action proposals only. It receives no shell, HTTP client, credentials, callbacks, or tool handles. Trusted application code validates every proposal through the deterministic policy engine.

## Security model

### Scope engine

Every request must match an explicit scheme, host, optional port, and allowed path. Excluded paths, methods, and categories are rejected. URL credentials and fragments are invalid. Redirect destinations are checked independently; scope is never inherited through a redirect.

### Approval process

Planning never executes requests. Reconnaissance is passive. XSS and SQLi require both active testing enabled in the saved scope and an explicit `--approve` flag. The CLI also requires a saved reviewed plan before recon or active checks.

### Audit log

Policy decisions, request starts/completions/failures, redirect decisions, lifecycle transitions, and report creation are recorded in SQLite. Response bodies are not stored by the audit logger. Cookie-like and authorization-like response headers are redacted.

### Kill switch

```bash
bountypilot stop
```

The kill switch is persisted in `.bountypilot/bountypilot.sqlite3`. Future policy requests are rejected until the project is reinitialized with `bountypilot init`.

### Reporting privacy

Reports are limited to bounded evidence and sanitized contexts. Common secret-like keys and values are redacted. Do not place credentials, cookies, private records, or unnecessary personal information in scope files, fixtures, or command arguments.

## Local lab setup and safe testing

Use a loopback-only intentionally vulnerable lab or the included Python mock applications in the tests. The repository does not start or download OWASP Juice Shop automatically, and it does not claim a Juice Shop integration.

A sample local-only scope is provided in [`examples/scope.json`](examples/scope.json). It contains only `127.0.0.1`, port `3000`, and an excluded `/admin` path. It is a reference file, not real target authorization.

Detailed local-lab procedures are in [`docs/local-lab.md`](docs/local-lab.md). In summary:

1. Bind the lab to `127.0.0.1`.
2. Configure the exact local port and path.
3. Run `init`, `scope validate`, `start`, and `plan`.
4. Review the plan and passive recon result.
5. Use `--approve` only for the specific bounded check.
6. Use `stop` if behavior is unexpected.
7. Never use credential attacks, destructive queries, table dumps, data extraction, or authentication bypass attempts.

XSS browser verification is optional:

```bash
python -m pip install -e '.[browser]'
playwright install chromium
bountypilot test xss --recon .bountypilot/recon.json --approve --browser-verify
```

If Playwright is unavailable, a potentially executable reflection remains unverified.

## Optional AI provider configuration

The current CLI uses the deterministic local planner and **does not make LLM calls**. The provider interface is available for mocked or future adapters, but no external provider adapter is wired into the command-line workflow yet.

The reserved environment variable names are documented in [`.env.example`](.env.example):

```bash
export BOUNTYPILOT_LLM_PROVIDER=none
export BOUNTYPILOT_LLM_API_KEY=
export BOUNTYPILOT_LLM_MODEL=
```

Do not put real credentials in `.env.example`, Git, scope files, reports, or issue comments. A future adapter must explicitly load these variables, return structured proposals through `PlanningProvider`, and remain subject to the same deterministic validation. Setting these variables alone does not activate network calls in the current release.

## Reports

```bash
bountypilot findings
bountypilot report
```

By default, reports are written to `.bountypilot/report.md` and `.bountypilot/report.json`. Custom paths are supported:

```bash
bountypilot report --output assessment.md --json-output assessment.json
```

Reports include the assessment identifier and timestamps, authorized scope, testing performed, findings, severity, confidence, status, affected endpoint and input location, bounded evidence, reproduction steps, impact, remediation, and limitations/tests not performed.

## CI and verification

GitHub Actions runs on Python 3.11 and 3.12 and performs:

- Editable installation with the test extra
- `pip check`
- Full `pytest` suite
- Python compilation
- `bountypilot --help` and `bountypilot status` smoke tests

Run the same checks locally:

```bash
python -m pip install -e '.[test]'
python -m pip check
pytest -q
python -m compileall -q src tests
bountypilot --help
bountypilot status
```

## Push to GitHub

Create an empty private repository first if the code is not ready for public release. Then from the repository root:

```bash
git init
git add .
git diff --cached --check
git commit -m "Prepare BountyPilot AI for Kali installation"
gh repo create bountypilot-ai --private --source=. --remote=origin --push
```

For an existing GitHub repository, use:

```bash
git remote add origin https://github.com/YOUR-USERNAME/bountypilot-ai.git
git branch -M main
git add .
git diff --cached --check
git commit -m "Prepare BountyPilot AI for Kali installation"
git push -u origin main
```

Replace `YOUR-USERNAME` with the repository owner. Do not put a token in the remote URL; use the authenticated `gh` CLI or Git credential manager.

## Known limitations

- The current AI provider variables are reserved only; the CLI uses the rule-based planner and does not call an LLM.
- SQLi findings remain `Needs verification` at most; no automated exploit confirmation is performed.
- XSS browser verification requires the optional Playwright package and a locally installed Chromium browser.
- The scanners support bounded safe HTTP GET testing only; they do not submit forms or test authenticated workflows.
- Local SQLite is not a multi-user server or a tamper-proof evidence store.
- The project does not automatically install or manage OWASP Juice Shop.
- The default install does not include Playwright, reducing installation size and attack surface.

## License

MIT; see [`LICENSE`](LICENSE).
