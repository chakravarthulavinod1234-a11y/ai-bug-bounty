# Local lab setup and safe testing

BountyPilot AI is intended to be used against systems that are explicitly authorized. The safest development target is a local intentionally vulnerable lab bound to loopback, such as a small mock application or an OWASP Juice Shop instance running on `127.0.0.1`.

## Minimal local workflow

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
pytest -q
```

Initialize and configure a loopback-only scope:

```bash
bountypilot init
bountypilot scope validate \
  --host 127.0.0.1 \
  --path / \
  --active
bountypilot start --target "local lab"
bountypilot plan
```

Review the plan and the scope snapshot before continuing. Run passive reconnaissance first:

```bash
bountypilot recon \
  --max-depth 1 \
  --max-urls 25 \
  --output .bountypilot/recon.json
```

Only after reviewing the recon result should you explicitly approve a bounded check:

```bash
bountypilot test xss \
  --recon .bountypilot/recon.json \
  --approve

bountypilot test sqli \
  --recon .bountypilot/recon.json \
  --approve
```

Generate the assessment reports:

```bash
bountypilot findings
bountypilot report
```

## OWASP Juice Shop or another local lab

If you independently install a local lab, bind it to loopback and configure the exact port and path in scope. For example, if the lab listens on `127.0.0.1:3000`, a sample scope is available at [`examples/scope.json`](../examples/scope.json). The sample is a configuration reference only; it does not start Juice Shop and it does not authorize any remote host.

Do not point BountyPilot at a public Juice Shop deployment, a shared training server, or any system without written authorization. Confirm the process is local before running active tests:

```bash
ss -ltnp | grep ':3000'
curl --fail --silent --show-error http://127.0.0.1:3000/ >/dev/null
```

## Safety rules

- Use only loopback or another explicitly authorized lab address.
- Review the saved plan and recon result before active testing.
- Use `--approve` only for the specific check you intend to run.
- Keep the default bounds; increase them only for a documented lab reason.
- Never add credentials, cookies, tokens, or private records to scope or fixtures.
- Do not submit login forms or use password attacks.
- Do not use destructive queries, table dumps, record extraction, or authentication-bypass payloads.
- Use `bountypilot stop` if the target behaves unexpectedly:

```bash
bountypilot stop
```

The kill switch is persisted in the local SQLite state and blocks subsequent policy-authorized requests until the project is reinitialized.
