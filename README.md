# AppSec Triage Agent

A scanner-first application security triage platform built as a modular Python
monolith. Semgrep Community Edition produces normalised evidence; optional OpenAI
Agents SDK analysis adds independent assessments. Findings are never automatically
suppressed or removed based on a model verdict.

## Current features

- Configurable Semgrep rulesets, bounded execution, normalised findings and errors.
- Pydantic v2 models and JSON reports with severity counts and failed assessments.
- Read-only, repository-scoped source context with traversal, link and secret-file checks.
- Optional structured triage, evidence citations, remediation and conservative review outcomes.
- Offline tests using mocked scanner/model responses.

## Requirements and installation

Python 3.11+ and Semgrep CE on PATH. Use a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Configuration

`.env.example` lists supported environment variables; `.env` files are **not**
loaded automatically. Export variables in your shell. Only `triage` requires
`OPENAI_API_KEY` and `OPENAI_MODEL` (choose a model supporting structured outputs).
Never commit credentials.

`--config settings.toml` accepts an application TOML file, for example:

```toml
semgrep_config = ["auto"]
scan_timeout = 300
max_findings = 20
log_level = "INFO"
```

Environment variables override TOML; CLI `--max-findings` overrides both.
`SEMGREP_CONFIG` specifies one ruleset; TOML supports multiple rulesets. Local rule
paths are relative to the TOML file (or current directory when no file is supplied).
`auto` and registry rulesets require network access; use trusted local YAML rules
for offline scanning. Semgrep requires its metrics mode for `auto`; this adapter
uses `--metrics=auto` for that ruleset and disables metrics for explicit rulesets.
Use explicit rules (for example `p/default`) to disable metrics. Only use
configuration you trust.

## CLI usage

```bash
appsec-triage scan ./examples/vulnerable_app
appsec-triage scan ./examples/vulnerable_app --output reports/scan.json
appsec-triage triage ./examples/vulnerable_app --output reports/triage.json --max-findings 10
```

Both commands support `--config`, `--output`, `--max-findings` and `--verbose`.
Without `--output`, JSON goes to stdout; operational logs go to stderr.
The limit applies only to assessments, in scanner order, and never removes scan
findings. Zero skips assessments. Exit codes: 0 success (including findings),
1 scan/assessment failure or partial scan, 2 configuration/usage/output error.
Reports contain a scan ID, UTC timestamps, scanner version, status, findings,
counts, assessments and errors. A partial scan is not a clean security result.

## Local interface

Start the local report viewer from your activated Python environment:

```bash
appsec-triage ui
```

Open http://127.0.0.1:8765 in your browser. Use `--port 8766` if the port is busy.
Load an existing JSON report with **Load JSON report**, search by rule, file or
message, and filter by severity or assessment verdict. Select a finding to see
scanner evidence, AI reasoning, citations, impact and remediation. **Export report**
downloads the complete report regardless of active filters. Imported reports stay
in the browser and are not uploaded to the local server.

To scan, enter an existing local repository folder and choose **Semgrep scan** or
**Scan + AI triage**. Relative paths resolve from the folder where the UI was
started. AI mode uses `OPENAI_API_KEY` and `OPENAI_MODEL` inherited by the server;
set them before starting the UI. Selected source excerpts are sent to OpenAI in
AI mode. The assessment limit never removes scanner findings.

For a local repository, **Browse…** opens a desktop folder chooser and fills in
the path. Windows uses its built-in folder dialog; macOS uses its system chooser;
Linux uses Zenity or KDialog, with Python Tk as a fallback (install `python3-tk`
if needed). Cancel leaves your current path unchanged. You can always type or
paste the path instead. The picker opens on the computer running the Python
server and requires a graphical desktop; it is not a remote file uploader.

Only one scan runs at a time. The page shows partial results, scanner errors and
failed assessments; these are not clean security results. The latest scan result
is kept in server memory until another scan replaces it or the server stops.
Export it to keep a copy. Refreshing reconnects to the latest server scan; imported
reports need to be loaded again. Press Ctrl+C in the terminal to stop the server.
The interface binds only to IPv4 loopback and is intended for a single local user.

### GitHub and GitLab repositories

In the scan form, choose **GitHub / GitLab**, enter a repository URL, and optionally
specify a branch. Supported URL forms include:

```text
https://github.com/owner/repository.git
https://gitlab.com/group/subgroup/repository.git
git@github.com:owner/repository.git
ssh://git@gitlab.com/group/repository.git
```

Git must be installed on PATH. Public HTTPS repositories need no credentials.
Private HTTPS repositories use your existing Git credential manager (which may
store a PAT); SSH repositories use your SSH agent and existing host trust.
Configure and verify access with Git in your terminal before starting the UI.
Start the UI from the same terminal so it inherits the SSH agent environment.
Authentication is noninteractive: the UI does not prompt for passwords, tokens,
key passphrases or host-key acceptance. It rejects credentials embedded in URLs.

The app creates a shallow checkout of the selected/default branch in a temporary
folder, scans it, and deletes the checkout afterward, including on clone/scan
failure. Export the report to keep results. Cloning has a five-minute timeout.
Submodules and Git LFS objects are not downloaded; findings do not cover their
contents. This first version supports github.com and gitlab.com, not self-hosted
instances or SSH aliases. It uses trusted local Git configuration and credential
helpers. Repository source is not executed by the app.

## Testing

```bash
pytest
```

Tests need no network or API key. The intentionally vulnerable example contains
SQL injection, command injection, unsafe deserialisation and dummy credentials;
scan it without executing it. Detection coverage depends on the selected ruleset.

## Limitations and security

Triage sends bounded source excerpts and selected finding fields to OpenAI. Use it
only for code you are authorised to share. SDK tracing is disabled and response
storage is disabled; provider data policies still apply. Secret-file exclusions
are defence in depth, not comprehensive secret detection: inline secrets may
remain in source, scanner messages, metadata or reports. Treat reports as sensitive.

The reader rejects symlinks/junctions and non-regular or oversized files, replaces
invalid UTF-8, and limits context. Unavailable context yields `needs_review` without
a model call. Model statements are untrusted suggestions, not verified proofs.
There are no model tools, command execution, repository edits or automatic suppression.

Use a stable checkout: filesystem checks do not provide an OS sandbox against
concurrent malicious filesystem changes. Semgrep parses untrusted input; run it
under an unprivileged account or isolated environment for hostile repositories.
Limits include one scanner worker, per-file timeout/memory limits, an overall
timeout, polled output-size limits and a 90-second timeout per assessment. These
are operational bounds, not hard OS resource quotas. Raw scanner stderr is omitted
to avoid copying sensitive source; errors identify failed stages/results.

## Future development

Extend scanner adapters for CodeQL, Trivy and authorised ZAP scans, then add
correlation, historical vulnerability management, backend APIs, a dashboard and
CI integrations. Active DAST will require explicit authorisation; any future
automated code changes will require human approval. None is implemented yet.
