# AppSec Triage Agent

A scanner-first application security triage platform built as a modular Python
monolith. Semgrep Community Edition produces normalised evidence; optional AI
analysis from OpenAI, Anthropic Claude or Google Gemini adds independent assessments. Findings are never automatically
suppressed or removed based on a model verdict.

## Current features

- Configurable Semgrep rulesets, bounded execution, normalised findings and errors.
- Pydantic v2 models and JSON reports with severity counts and failed assessments.
- Read-only, repository-scoped source context with traversal, link and secret-file checks.
- Optional structured triage, evidence citations, remediation and conservative review outcomes.
- Choice of AI provider: OpenAI (Agents SDK), Anthropic Claude or Google Gemini.
- Offline tests using mocked scanner/model responses.

## Requirements and installation

### Docker on Windows, macOS, and Linux

Start Docker Desktop on Windows (Linux containers) or macOS. On Linux, use Docker
Engine with the Compose plugin or Docker Desktop. From this project's directory,
run the same command in PowerShell, Bash, or Zsh:

```sh
docker compose up --build
```

Open http://127.0.0.1:8765. The image includes Git, Semgrep, Trivy, and Gitleaks.
If that port is busy, set `APPSEC_PORT=8766` in the project's local `.env`,
rerun Compose, and open http://127.0.0.1:8766.
In **Local folder** mode, scan `/workspace` to try the included vulnerable example.
To scan another folder, set `APPSEC_SCAN_DIR` in the project's local `.env`
file, then run `docker compose up -d` again. Use the host's absolute path,
for example `APPSEC_SCAN_DIR="C:/Users/Alex/My Projects/demo"` on Windows or
`APPSEC_SCAN_DIR=/home/alex/projects/demo` on Linux. Docker must have read access
to that folder. Its path in the dashboard is always `/workspace`.

For remote repositories, choose **Git repository URL** and paste the clone URL.
For a private HTTPS repository, open **Private repository access** and use its
provider link to create a read-only token. Paste the token, click **Check repository
access**, then start the scan. The dashboard clones the repository inside the
container and clears the token from the form when the scan starts.
For optional AI triage, Compose passes the provider variables listed under
[AI providers](#ai-providers) from your shell or local `.env` into the container.
Scan-only mode needs none of them.
The first Trivy scan downloads its database and later runs reuse a Docker volume.
Run `docker compose down` to stop the dashboard and retain that cache.

### Native Python setup

Python 3.11+ and Semgrep CE on PATH. Use a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Configuration

`.env.example` lists supported environment variables; `.env` files are **not**
loaded automatically. Export variables in your shell, or save keys in the
dashboard's **Settings** page. Only `triage` requires an AI provider key. Never
commit credentials.

### AI providers

| Provider | `--provider` | API key variable | Model variable | Default model |
| --- | --- | --- | --- | --- |
| OpenAI | `openai` | `OPENAI_API_KEY` | `OPENAI_MODEL` | none, required |
| Anthropic Claude | `anthropic` | `ANTHROPIC_API_KEY` | `ANTHROPIC_MODEL` | `claude-opus-5-5` |
| Google Gemini | `gemini` | `GEMINI_API_KEY` or `GOOGLE_API_KEY` | `GEMINI_MODEL` | `gemini-3.8-flash` |

The provider is chosen in this order: `--provider`, then `AI_PROVIDER`, then the
default saved in Settings, then `openai`. The model follows the same order:
`--model`, the `*_MODEL` variable, the Settings default, then the table default.
For example:

```bash
appsec-triage triage ./repo --provider anthropic
appsec-triage triage ./repo --provider gemini --model gemini-4-argon
```

Every provider must return the same structured assessment schema. Claude
requests on current models use high effort and server-side refusal fallbacks
(`fallbacks: "default"`), so a safety-classifier decline is retried on another
Claude model instead of failing the assessment. Report `model_name` values
record the provider, for example `anthropic/claude-opus-5-5`.

### Managing keys in the dashboard

Open **Settings** to connect a provider. Paste a key and choose **Save & verify**.
The key is checked with a free model-list request before it is saved, so an
invalid or revoked key is rejected immediately; the same request lists the
models the key can use, which fills the model picker. **Test connection**
re-checks a saved key. The check proves the key authenticates; it does not
prove billing or quota for generation.

Saved keys are stored in the operating system's credential store (macOS
Keychain, Windows Credential Manager or Linux Secret Service). Where none is
available, including in Docker, they are stored in `credentials.json` in the
data folder (`APPSEC_DATA_DIR`, default `~/.appsec-triage`) with owner-only
permissions; in Docker that file lives in the `projects` volume. Set
`APPSEC_SECRET_BACKEND=file` to force the file store. The CLI reads the same
store, so keys saved in the dashboard also work for `appsec-triage triage`.

Environment variables always take priority and cannot be changed from the
dashboard.

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
The dashboard has two views:

- **Scan**: a three-step form (repository → what to check → optional AI review)
  with a live summary of what will run, then a progress screen with elapsed time.
- **Results**: severity and AI-verdict summaries you can click to filter, a
  searchable, sortable finding list (optionally grouped by file), and a detail
  pane that leads with **How to fix**, then the AI review, affected code,
  scanner details and CWE links. Use <kbd>j</kbd>/<kbd>k</kbd> to move between
  findings and <kbd>/</kbd> to search.

Saved projects are in the sidebar (with a search box once you have more than six); the selected project's scans are under **Scan history** in the top bar. **Open report** loads
an existing JSON report.

While a scan runs, the progress screen shows each step live: cloning or checking
the repository, each scanner with its finding count, the AI review finding by
finding (for example “3 of 5 · formatted-sql-query · app/db.py:42”), and writing
the report, with timings and an activity log. If a step fails, the error names it,
and files Semgrep could only partly parse (often newer TypeScript/JSX syntax) are
listed as *coverage warnings* that name the file, without failing the scan; Semgrep's
raw diagnostic text is never copied because it can quote source code. Failed AI
reviews give a reason such as “timed out after 240 s” or
“provider server error, HTTP 503”. **Stop scan** ends the scan and every scanner
process it started; the run is saved as *cancelled* and partial results are
discarded.

Each AI review may take up to `AI_TIMEOUT` seconds (default 240), including
retries. Gemini requests retry temporary errors (429 and 5xx) with backoff, as
the Anthropic and OpenAI SDKs already do. If a provider is overloaded, reviews
can still fail; rerun later or pick another provider.

To repeat a scan, use **Rerun scan** on the results page, the ↻ button next to a
run in the history, or **Run again** when a scan finishes. Reruns use the same
project, scanners, AI provider, model and finding limit as the original run.
AI-review reruns ask for confirmation because they use API credits.

To delete a project, hover over it in the sidebar and choose the bin icon, or use
**Delete project** on its Scan page, then type the project name to confirm. This
removes the project and all of its saved scans, findings and AI reviews from the
dashboard; deleted rows are overwritten in the history database because reports
contain source excerpts. It never deletes your source code: local folders and
Remote repositories are left untouched (temporary clones are already
removed after every scan). A project cannot be deleted while it is being scanned.
New scans save bounded source excerpts in the report, including in Semgrep-only mode.
Older reports need a new scan to include source code. Excluded or unavailable files
show an explanation instead. Exported reports include these excerpts; treat them as sensitive. **JSON** (next to PDF report)
downloads the complete report regardless of active filters. Imported reports stay
in the browser and are not uploaded to the local server.

To scan, enter an existing local repository folder, tick what to look for (**Code
issues**, **Vulnerable dependencies** and/or **Secrets**, in current files or Git
history; any combination runs as one scan with one report), and optionally turn on
**AI review**, which needs Code issues and never receives secret findings. Relative paths resolve from the folder where the UI was
started. With AI review on, pick a provider and optionally a model. Connect
providers in **Settings** first; saved keys are write-only and never returned to
the browser. Selected source excerpts are sent to the chosen provider in AI mode. The assessment limit never removes scanner findings.

For a local repository, **Browse…** opens a desktop folder chooser and fills in
the path. Windows uses its built-in folder dialog; macOS uses its system chooser;
Linux uses Zenity or KDialog, with Python Tk as a fallback (install `python3-tk`
if needed). Cancel leaves your current path unchanged. You can always type or
paste the path instead. The picker opens on the computer running the Python
server and requires a graphical desktop; it is not a remote file uploader.

Choose **New project**, enter a project name and repository, then click **Save project**
or **Start scan**. Select a saved project to run it again or click an entry in its
history to reopen the full report, including its SAST and SCA views. History records
the start time, scanner, mode, Git commit when available, and outcome. Failed runs
without reports retain their error. Only one scan runs at a time per dashboard.

The dashboard stores scan history in SQLite, under `~/.appsec-triage` by default.
Set `APPSEC_DATA_DIR` to choose another directory for native use. Compose keeps
this directory in the named `projects` volume. Restarting or recreating the
container preserves reports. Removing the volume deletes its history.
Each developer has a local project library. Reports can contain source excerpts.
Imported JSON remains in the browser. Export a report to share a copy.

### Human review

Every finding (code, dependency or secret) has a **Human review** card next to
the AI review. Mark it **Confirmed**, **False positive**, **Accepted risk** or
**Fixed** (keyboard: `c`, `f`, `a`, `x`), and add notes such as evidence or a
ticket link. Each verdict change is recorded in the finding's discussion as an
audit trail that can't be deleted; written notes can be.

Reviews belong to the saved project and are keyed by the finding's stable ID, so
decisions carry over to later scans of the same project. Reports opened from a
file are read-only.

Human verdicts are kept separate from AI verdicts:

- Each finding shows **Scanner → AI review → Human review** and flags when the
  reviewer overrode the AI.
- The **Human review** summary shows the raw scanner count against the count
  after review (false positives and fixed items removed); click a verdict to
  filter.
- **Scanner view** shows every finding, striking through reviewed false
  positives and fixed items; **Reviewed view** hides them.

### PDF reports

**PDF report** in the results header downloads a designed PDF of the open scan: a cover
page, summary tiles, a severity chart, a scanner-versus-review comparison and a
per-category table, then every finding with its AI and human verdicts, review
notes, fix and optional code excerpt. Group findings by **category** (code,
dependencies, secrets), **severity**, **human review** or **file**; each group is
a bookmark in the PDF's sidebar. You can leave out false positives, review notes
or code excerpts. With code excerpts the PDF contains source code, so share it
accordingly.

Saved scans are rendered from the server's copy with their stored reviews.

The report is an A4 portrait document with a title page and document control
table, contents, numbered sections (executive summary with an overall risk
rating, scope and methodology, findings overview, detailed findings with IDs
such as F-001) and a finding index, with running headers and "Page X of Y".
Fonts come from the operating system, so nothing is bundled: running text is
Times New Roman, headings and tables are Arial, and code uses the platform's
coding font (Consolas on Windows, Menlo on macOS, DejaVu Sans Mono on Linux and
in Docker). Docker uses Liberation Serif and Liberation Sans, which have the same
metrics as Times New Roman and Arial. Any missing font falls back to the PDF
viewer's built-in Times, Helvetica or Courier.
Characters a font lacks, such as Thai, fall back to another installed font, and
tabs and invisible characters in code are normalised so nothing prints as a box.

### Remote Git repositories

In the scan form, choose **Git repository URL**, paste the clone URL, and
optionally specify a branch. Supported URL forms include:

```text
https://github.com/owner/repository.git
https://gitlab.com/group/subgroup/repository.git
https://bitbucket.org/workspace/repository.git
https://dev.azure.com/organization/project/_git/repository
git@github.com:owner/repository.git
ssh://git@gitlab.com/group/repository.git
git@bitbucket.org:workspace/repository.git
git@ssh.dev.azure.com:v3/organization/project/repository
```

Git must be installed on PATH. On a desktop with Git Credential Manager enabled,
choose **Connect and check access** for an HTTPS repository. If sign-in is needed,
complete it in the window opened by Git Credential Manager, then return to the
dashboard. Git Credential Manager handles credential storage. Public HTTPS
repositories can be scanned directly.

For an SSH repository, **Check repository access** uses your existing SSH agent
and trusted host keys. With **Private repository access**, an HTTPS access token
is supplied only to the requested repository's Git operation and is never saved
in project settings, scan history, or reports. Enter a token again when prompted
to rerun a token-authenticated scan. Scan clones run without prompting. Use clone
URLs without embedded passwords or tokens.

The app checks out the selected/default branch in a temporary folder. Git history
scans clone the branch's history, while other scans use a shallow checkout.
The app deletes the checkout afterward, including on clone/scan
failure. Export the report to keep results. Cloning has a five-minute timeout.
Submodules and Git LFS objects are not downloaded; findings do not cover their
contents. The supported hosts are GitHub.com, GitLab.com, Bitbucket Cloud, and
Azure Repos on dev.azure.com. The app uses trusted local Git configuration and
credential helpers. Repository source is not executed by the app.

## Testing

```bash
pytest
```

Tests need no network or API key. The intentionally vulnerable example contains
SQL injection, command injection, unsafe deserialisation and dummy credentials;
scan it without executing it. Detection coverage depends on the selected ruleset.

## Limitations and security

### Dashboard security

The dashboard is a local tool and is hardened like one:

- It listens on 127.0.0.1 only (in Docker, Compose publishes it on 127.0.0.1).
- Every API request needs a per-session token embedded in the page, compared in
  constant time. Requests must use the exact `127.0.0.1:<port>` host (blocking
  DNS rebinding), and cross-site requests are rejected using the `Origin` and
  `Sec-Fetch-Site` headers. Writes must be JSON and are size-limited.
- Responses send a strict Content Security Policy (scripts only with a
  per-response nonce, no framing, no plugins), `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `nosniff` and `no-store`.
- API keys are write-only, shown only as their last four characters, never
  logged or written to history or reports, and passed to a scan only for the
  selected provider through its environment, never its command line. Provider
  error text is not shown, because it can echo request details.
- Key checks are limited to one at a time and twelve per minute.

Any program running as your user can read your data folder and reach the local
port, as with other local developer tools. Use OS-level account separation if
that is a concern.


Triage sends bounded source excerpts and selected finding fields to the selected
AI provider. Use it only for code you are authorised to share. For OpenAI, SDK
tracing and response storage are disabled; each provider's data policies apply. Secret-file exclusions
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

Extend scanner adapters for CodeQL and authorised ZAP scans, then add
correlation, historical vulnerability management, backend APIs, a dashboard and
CI integrations. Active DAST will require explicit authorisation; any future
automated code changes will require human approval. None is implemented yet.

## Secret scanning

Choose **Secrets in current files** to check the selected folder, including
uncommitted files. Choose **Secrets in Git history** to check commits reachable
from local Git refs. Select the checkout root and make its Git metadata
available to the scanner. A shallow clone limits coverage to available commits.

Docker bundles Gitleaks. For native execution, install Gitleaks 8.30.1 or newer
and put it on PATH. History scans also require Git on PATH.

```sh
appsec-triage scan ./your-repository --scanner gitleaks-files
appsec-triage scan ./your-repository --scanner gitleaks-history
```

Reports include the rule, file, line range, and commit hash when available.
Secret values and source excerpts are omitted, and these scans run without AI.
Gitleaks honors a repository's `.gitleaksignore` file.

## Dependency vulnerability scanning (SCA)

Install Trivy separately and put its executable on PATH. See the
[official Trivy installation instructions](https://trivy.dev/latest/getting-started/installation/).
SCA scans supported dependency manifests and lockfiles without installing or executing packages.
Trivy needs access to its vulnerability database, including a download on first use.
Detection coverage depends on supported files and available version information;
a completed scan with no findings does not prove that all dependencies were identified.

```bash
appsec-triage scan ./your-repository --scanner trivy --output reports/sca.json
appsec-triage scan ./your-repository --scanner all --output reports/combined.json
appsec-triage scan ./your-repository --scanner semgrep+trivy+gitleaks-files --output reports/full.json
```

`--scanner` takes one scanner or several joined with `+` (`semgrep`, `trivy`,
`gitleaks-files`, `gitleaks-history`; `all` means `semgrep+trivy`). Choose one secret
scope at a time.

The default scanner remains Semgrep. In the UI tick **Vulnerable dependencies**, alone or
with the other scans. Local folders and remote checkouts support every combination.
Dependency findings include the advisory ID, package, installed version, available
fixed version and dependency file. Missing fixes are shown explicitly; no source
line is invented. Export preserves these fields. Scanner errors remain visible,
and failure of either scanner makes a combined report partial or failed.

SCA requires no AI provider credentials. AI triage currently assesses only SAST findings;
the assessment limit applies to those findings. Use scan mode for SCA alone.
This adapter enables only library vulnerability scanning, not container, secret,
license or misconfiguration scanning. Repository-local Trivy configuration and
ignore files do not control its scan policy. Trivy runs with a bounded timeout
and output size, using the same process controls as the Semgrep adapter.
