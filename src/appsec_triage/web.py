"""Loopback-only UI; scanner execution remains in the existing CLI."""
import json
import os
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pydantic import ValidationError

from appsec_triage.repositories import (
    RepositoryError, check_repository_access, clone_repository, validate_remote, validate_repository_token,
)
from appsec_triage.scanners.base import parse_scanners, scanner_spec
from appsec_triage.folder_picker import FolderPickerError, choose_folder
from appsec_triage.history import REVIEW_VERDICTS, History
from appsec_triage.reporting.json_reporter import Report
from appsec_triage.reporting.pdf_report import GROUPINGS, build_pdf
from appsec_triage.progress import ProgressState
from appsec_triage.secrets_store import KEY_FORMAT, KeyStore, Preferences, data_dir, env_key, resolve_key
from appsec_triage.services.key_check import KeyCheck, run_check
from appsec_triage.services.providers import PROVIDERS

# Empty means the provider default; a leading letter/digit keeps it from parsing as a CLI flag.
MODEL_ID = re.compile(r"|[A-Za-z0-9][A-Za-z0-9._:/@-]{0,199}")
CHECKS_PER_MINUTE = 12
FINDING_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
CSP = ("default-src 'none'; script-src 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
       "form-action 'none'; object-src 'none'")


class ScanCancelled(Exception):
    pass


def run_scan_process(args, *, env, timeout, cancel):
    """Run the scan CLI; stop it and its scanner children when cancelled or too slow."""
    posix = os.name == "posix"
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
                               start_new_session=posix)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                process.wait(timeout=0.25)
                return process
            except subprocess.TimeoutExpired:
                pass
            if cancel.is_set() or time.monotonic() > deadline:
                break
    except BaseException:
        cancel.set()
        raise
    finally:
        if process.poll() is None:
            # The CLI starts Semgrep and Trivy; stop the whole process group, gently first.
            for sig, wait in ((signal.SIGTERM, 5), (signal.SIGKILL if posix else None, 5)):
                try:
                    if posix:
                        os.killpg(process.pid, sig)
                    elif sig is signal.SIGTERM:
                        process.terminate()
                    else:
                        process.kill()
                except (ProcessLookupError, PermissionError, OSError):
                    break
                try:
                    process.wait(timeout=wait)
                    break
                except subprocess.TimeoutExpired:
                    continue
    if cancel.is_set():
        raise ScanCancelled()
    raise subprocess.TimeoutExpired(args, timeout)


def git_revision(target):
    executable = shutil.which("git")
    if not executable:
        return None
    try:
        result = subprocess.run([executable, "-c", f"safe.directory={target}", "-C", str(target),
                                 "rev-parse", "--verify", "HEAD"], capture_output=True, timeout=5)
        revision = result.stdout.strip()
        if result.returncode == 0 and re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", revision):
            return revision.decode("ascii")
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port):
        self.container = os.environ.get("APPSEC_CONTAINER") == "1"
        super().__init__(("0.0.0.0" if self.container else "127.0.0.1", port), Handler)
        try:
            self.history = History(data_dir())
        except Exception:
            self.server_close()
            raise
        self.keys = KeyStore()
        self.preferences = Preferences()
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.picker_lock = threading.Lock()
        self.repository_access_lock = threading.Lock()
        self.check_lock = threading.Lock()
        self.pdf_lock = threading.Lock()
        self.check_times = deque()
        self.job = {"status": "idle"}
        self.cancel = threading.Event()

    def server_close(self):
        super().server_close()
        if hasattr(self, "history"):
            self.history.lease.close()

    def provider_status(self, provider):
        key, source = resolve_key(provider, self.keys)
        found = env_key(provider)
        return {
            "name": provider.name, "label": provider.label, "configured": bool(key),
            "key_source": source, "env_var": found[0] if found else None, "key_env": list(provider.key_env),
            # Only the last four characters are shown, as provider consoles do.
            "key_hint": "…" + key[-4:] if key and len(key) >= 16 else None,
            "default_model": self.preferences.model(provider),
            "model_locked": bool(os.environ.get(provider.model_env, "").strip()),
            "model_env": provider.model_env, "key_url": provider.key_url,
        }

    def check_allowed(self):
        now = time.monotonic()
        while self.check_times and now - self.check_times[0] > 60:
            self.check_times.popleft()
        if len(self.check_times) >= CHECKS_PER_MINUTE:
            return False
        self.check_times.append(now)
        return True

    def publish(self, state, started, **extra):
        snapshot = state.snapshot()
        with self.lock:
            if self.cancel.is_set():
                return  # Keep the "Stopping" state visible until the worker finishes.
            self.job = {"status": "running", "started": started, "now": time.time(),
                        "phase": snapshot["phase"] or "Scanning", "mode": self.job.get("mode"), "run_id": self.job.get("run_id"),
                        "steps": snapshot["steps"], "log": snapshot["log"], **extra}

    def watch(self, path, state, started, stop):
        """Fold CLI progress events into the job until the scan process exits."""
        offset, pending = 0, b""
        while True:
            finished = stop.wait(0.4)
            try:
                with open(path, "rb") as stream:
                    stream.seek(offset)
                    chunk = stream.read()
                    offset += len(chunk)
            except OSError:
                chunk = b""
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop()
            for line in lines:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if isinstance(event, dict):
                    state.apply(event)
            if chunk:
                self.publish(state, started)
            if finished:
                return

    def scan(self, target, mode, limit, source="local", branch="", scanner="semgrep", run_id=None,
             provider="openai", model="", *, repository_token=""):
        revision = None
        started = time.time()
        env = dict(os.environ)
        if mode == "triage":
            # Pass only the selected provider's key, through the environment rather than argv.
            details = PROVIDERS[provider]
            key, key_source = resolve_key(details, self.keys)
            if key and key_source != "environment":
                env[details.key_env[0]] = key
            model = model or self.preferences.model(details)
        state = ProgressState([{"id": "prepare", "label": "Clone repository" if source == "remote" else "Check repository folder"}])
        try:
            with tempfile.TemporaryDirectory(prefix="appsec-ui-") as directory:
                output = Path(directory) / "report.json"
                progress_file = Path(directory) / "progress.jsonl"
                scan_target = target
                state.apply({"time": started, "step": "prepare", "status": "start",
                             "detail": target if source == "remote" else None})
                self.publish(state, started)
                if source == "remote":
                    clone_options = {"full_history": True} if "gitleaks-history" in parse_scanners(scanner) else {}
                    if repository_token:
                        clone_options["token"] = repository_token
                    scan_target = str(clone_repository(target, branch, Path(directory), **clone_options))
                if run_id is not None:
                    revision = git_revision(scan_target)
                state.apply({"step": "prepare", "status": "done", "time": time.time(),
                             "detail": f"Commit {revision[:8]}" if revision else None})
                self.publish(state, started)
                ai = ["--provider", provider] + (["--model", model] if model else []) if mode == "triage" else []
                stop = threading.Event()
                watcher = threading.Thread(target=self.watch, args=(progress_file, state, started, stop), daemon=True)
                watcher.start()
                try:
                    if self.cancel.is_set():
                        raise ScanCancelled()
                    result = run_scan_process(
                        [sys.executable, "-m", "appsec_triage.cli", mode, scan_target,
                         "--scanner", scanner, "--max-findings", str(limit),
                         "--progress", str(progress_file), "--output", str(output), *ai],
                        env=env, timeout=7200, cancel=self.cancel,
                    )
                finally:
                    stop.set()
                    watcher.join(timeout=5)
                if output.exists():
                    job = {"status": "completed", "report": json.loads(output.read_text(encoding="utf-8"))}
                    if source == "remote":
                        job["report"]["scan"]["target"] = target
                        job["report"]["repository"] = {"url": target, "branch": branch or "default"}
                else:
                    failed = next((s for s in state.steps if s["status"] == "failed"), None)
                    reason = f" during “{failed['label']}”" + (f": {failed['detail']}" if failed.get("detail") else "") if failed else ""
                    job = {"status": "failed", "error": f"Scan exited with code {result.returncode}{reason}. Check the repository path, scanner installation, and AI configuration in Settings."}
        except ScanCancelled:
            job = {"status": "cancelled", "error": "Scan stopped. Partial results were discarded."}
        except RepositoryError as exc:
            if self.cancel.is_set():
                job = {"status": "cancelled", "error": "Scan stopped. Partial results were discarded."}
            state.apply({"step": "prepare", "status": "failed", "time": time.time(), "detail": str(exc)})
            job = job if self.cancel.is_set() else {"status": "failed", "error": str(exc)}
        except subprocess.TimeoutExpired:
            job = {"status": "failed", "error": "The scan took longer than two hours and was stopped."}
        except Exception:
            job = {"status": "failed", "error": "Scan could not finish. Check local configuration or run the CLI for diagnostics."}
        # Steps that never reported are left pending; a running step at the end was interrupted.
        for step in state.steps:
            if step["status"] == "running":
                step.update(status={"failed": "failed", "cancelled": "cancelled"}.get(job["status"], "done"), finished=time.time())
        if job["status"] == "cancelled":
            state.add_log(time.time(), "Scan stopped by user", "warning")
        snapshot = state.snapshot()
        job.update(started=started, finished=time.time(), steps=snapshot["steps"], log=snapshot["log"], run_id=run_id)
        if run_id is not None:
            try:
                job["project_id"] = self.history.finish(run_id, job, revision)
            except sqlite3.Error:
                job["history_error"] = "Could not save this scan. Export the report before closing the dashboard."
        with self.lock:
            self.job = job


class RequestError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Handler(BaseHTTPRequestHandler):
    server_version = "AppSecTriage"
    sys_version = ""

    def log_message(self, *args):
        pass

    def respond(self, status, payload, content_type="application/json", nonce=None, headers=None):
        body = payload if isinstance(payload, bytes) else payload.encode() if isinstance(payload, str) \
            else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Content-Security-Policy", CSP.format(nonce=nonce or secrets.token_urlsafe(16)))
        self.end_headers()
        self.wfile.write(body)

    def trusted_host(self):
        return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

    def guard(self, post=False):
        """Reject requests that did not come from this dashboard page."""
        if not self.trusted_host():
            raise RequestError(403, "Local access only")
        # Browsers label cross-site requests; reject them before checking anything else.
        if self.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
            raise RequestError(403, "Cross-site requests are not allowed")
        if not secrets.compare_digest(self.headers.get("X-Appsec-Token", ""), self.server.token):
            raise RequestError(403, "Local access only")
        origin = self.headers.get("Origin")
        if post and origin and origin != f"http://127.0.0.1:{self.server.server_port}":
            raise RequestError(403, "Invalid origin")

    def read_json(self, limit):
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            raise RequestError(415, "Expected a JSON request")
        try:
            size = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            raise RequestError(400, "Invalid Content-Length")
        if not 0 < size <= limit:
            raise RequestError(413 if size > limit else 400, "Request body is missing or too large")
        try:
            data = json.loads(self.rfile.read(size))
        except ValueError:
            raise RequestError(400, "Request body is not valid JSON")
        if not isinstance(data, dict):
            raise RequestError(400, "Request body must be a JSON object")
        return data

    def do_GET(self):
        if self.path == "/healthz":
            # Used by the container healthcheck; reveals no data.
            return self.respond(200, {"ok": True}) if self.trusted_host() else self.respond(403, {"error": "Local access only"})
        if self.path == "/":
            if not self.trusted_host():
                return self.respond(403, {"error": "Local access only"})
            nonce = secrets.token_urlsafe(16)
            page = Path(__file__).with_name("web_ui.html").read_text(encoding="utf-8")
            page = page.replace("__CONTAINER__", json.dumps(self.server.container))
            page = page.replace("<script>", f'<script nonce="{nonce}">').replace("__NONCE__", nonce)
            page = page.replace("__TOKEN__", self.server.token)
            return self.respond(200, page, "text/html; charset=utf-8", nonce)
        if self.path == "/assets/highlight.min.js":
            if not self.trusted_host():
                return self.respond(403, {"error": "Local access only"})
            script = Path(__file__).with_name("assets") / "highlight.min.js"
            return self.respond(200, script.read_text(encoding="utf-8"), "application/javascript; charset=utf-8")
        try:
            self.guard()
        except RequestError as exc:
            return self.respond(exc.status, {"error": str(exc)})
        if self.path == "/api/job":
            with self.server.lock:
                return self.respond(200, self.server.job)
        if self.path == "/api/providers":
            prefs = self.server.preferences.load()
            providers = [self.server.provider_status(p) for p in PROVIDERS.values()]
            default = os.environ.get("AI_PROVIDER", "").strip() or prefs["provider"]
            if default not in PROVIDERS:
                default = next((p["name"] for p in providers if p["configured"]), "openai")
            return self.respond(200, {"providers": providers, "default_provider": default,
                                      "default_locked": bool(os.environ.get("AI_PROVIDER", "").strip()),
                                      "storage": self.server.keys.backend, "storage_label": self.server.keys.describe()})
        try:
            if self.path == "/api/projects":
                projects = self.server.history.projects()
                for project in projects:
                    project["available"] = not project["mount"] or (
                        self.server.container and project["mount"] == os.getenv("APPSEC_MOUNT_LABEL", "/workspace"))
                return self.respond(200, projects)
            match = re.fullmatch(r"/api/projects/([0-9]{1,18})/runs", self.path)
            if match:
                return self.respond(200, self.server.history.runs(int(match[1])))
            match = re.fullmatch(r"/api/projects/([0-9]{1,18})/reviews", self.path)
            if match:
                self.project_or_404(int(match[1]))
                return self.respond(200, self.server.history.reviews(int(match[1])))
            match = re.fullmatch(r"/api/runs/([0-9]{1,18})", self.path)
            if match:
                result = self.server.history.result(int(match[1]))
                return self.respond(200, result) if result else self.respond(404, {"error": "Unknown scan"})
        except RequestError as exc:
            return self.respond(exc.status, {"error": str(exc)})
        except sqlite3.Error:
            return self.respond(503, {"error": "Scan history is unavailable."})
        self.respond(404, {"error": "Not found"})

    def do_POST(self):
        try:
            self.guard(post=True)
            if self.path == "/api/folder":
                return self.folder()
            if self.path == "/api/repository/access":
                return self.repository_access(self.read_json(4096))
            if self.path == "/api/job/cancel":
                with self.server.lock:
                    if self.server.job.get("status") != "running":
                        raise RequestError(409, "No scan is running.")
                    self.server.cancel.set()
                    self.server.job = {**self.server.job, "phase": "Stopping", "cancelling": True}
                return self.respond(202, {"status": "cancelling"})
            if self.path.startswith("/api/settings/"):
                return self.settings(self.read_json(4096))
            if self.path in ("/api/scan", "/api/projects"):
                return self.scan_request(self.read_json(8192), save_only=self.path == "/api/projects")
            match = re.fullmatch(r"/api/runs/([0-9]{1,18})/rerun", self.path)
            if match:
                data = self.read_json(4096) if self.headers.get("Content-Length", "0") != "0" else {}
                return self.rerun(int(match[1]), data.pop("repository_token", ""))
            match = re.fullmatch(r"/api/projects/([0-9]{1,18})/delete", self.path)
            if match:
                return self.delete_project(int(match[1]))
            match = re.fullmatch(r"/api/projects/([0-9]{1,18})/(reviews|comments)", self.path)
            if match:
                return self.review(int(match[1]), match[2], self.read_json(8192))
            match = re.fullmatch(r"/api/comments/([0-9]{1,18})/delete", self.path)
            if match:
                return self.delete_comment(int(match[1]))
            if self.path == "/api/pdf":
                return self.pdf(self.read_json(25 * 1024 * 1024))
            raise RequestError(404, "Not found")
        except RequestError as exc:
            return self.respond(exc.status, {"error": str(exc)})

    def folder(self):
        if self.server.container:
            return self.respond(400, {"error": "Use the folder mounted at /workspace."})
        if not self.server.picker_lock.acquire(blocking=False):
            return self.respond(409, {"error": "A folder picker is already open."})
        try:
            status, result = 200, {"path": choose_folder()}
        except FolderPickerError as exc:
            status, result = 503, {"error": str(exc)}
        finally:
            self.server.picker_lock.release()
        return self.respond(status, result)

    def repository_access(self, data):
        lock = self.server.repository_access_lock
        if not lock.acquire(blocking=False):
            raise RequestError(409, "A repository access check is already running.")
        try:
            with tempfile.TemporaryDirectory(prefix="appsec-git-access-") as directory:
                check_repository_access(data.get("target", ""), data.get("branch", ""), Path(directory),
                                        allow_sign_in=not self.server.container, token=data.pop("repository_token", ""))
        except RepositoryError as exc:
            raise RequestError(400, str(exc)) from None
        except OSError:
            raise RequestError(503, "Could not create a temporary workspace to check access.") from None
        finally:
            lock.release()
        return self.respond(200, {"ok": True})

    def checked(self, provider, key, model):
        if not self.server.check_lock.acquire(blocking=False):
            raise RequestError(429, "A key check is already running.")
        try:
            if not self.server.check_allowed():
                raise RequestError(429, "Too many key checks. Wait a minute and try again.")
            return run_check(provider, key, model)
        finally:
            self.server.check_lock.release()

    def settings(self, data):
        server = self.server
        provider = PROVIDERS.get(data.get("provider")) if isinstance(data.get("provider"), str) else None
        if self.path == "/api/settings/preferences":
            default, models = data.get("default_provider"), data.get("models", {})
            if (default is not None and default not in PROVIDERS) or not isinstance(models, dict):
                raise RequestError(400, "Choose a supported provider and valid model IDs.")
            try:
                server.preferences.save(default, models)
            except ValueError:
                raise RequestError(400, "Model IDs may contain letters, digits and . _ : / @ - only.")
            except OSError:
                raise RequestError(503, "Could not save preferences. Check the data folder permissions.")
            return self.respond(200, {"ok": True})
        if provider is None:
            raise RequestError(400, "Choose a supported AI provider.")
        model = data.get("model", "")
        if not isinstance(model, str) or not MODEL_ID.fullmatch(model.strip()):
            raise RequestError(400, "Model IDs may contain letters, digits and . _ : / @ - only.")
        model = model.strip()
        found = env_key(provider)
        if self.path == "/api/settings/test":
            key, _ = resolve_key(provider, server.keys)
            if not key:
                raise RequestError(400, f"Add an API key for {provider.label} first.")
            check = self.checked(provider.name, key, model or server.preferences.model(provider))
            return self.respond(200, {"check": check.public(), "provider": server.provider_status(provider)})
        if found:
            raise RequestError(409, f"This key is set by the {found[0]} environment variable. Change or unset it there.")
        try:
            if self.path == "/api/settings/key/remove":
                server.keys.delete(provider.name)
                return self.respond(200, {"provider": server.provider_status(provider)})
            if self.path != "/api/settings/key":
                raise RequestError(404, "Not found")
            key = data.get("key")
            if not isinstance(key, str) or not KEY_FORMAT.fullmatch(key.strip()):
                raise RequestError(400, "That doesn't look like an API key. Paste the whole key without spaces.")
            key = key.strip()
            check = KeyCheck("unverified", "Saved without checking.")
            if data.get("verify", True) is not False:
                check = self.checked(provider.name, key, model or server.preferences.model(provider))
                if check.status == "invalid":
                    return self.respond(400, {"error": check.message, "check": check.public()})
                if check.status == "unreachable":
                    return self.respond(502, {"error": check.message, "check": check.public(), "can_save_unverified": True})
            server.keys.set(provider.name, key)
            return self.respond(200, {"check": check.public(), "provider": server.provider_status(provider)})
        except RequestError:
            raise
        except Exception:
            # Keychain and file errors can include paths or item names; keep the message generic.
            raise RequestError(503, "Could not update the key store. Unlock your keychain or check data folder permissions.")

    def project_or_404(self, project_id):
        try:
            project = next((p for p in self.server.history.projects() if p["id"] == project_id), None)
        except sqlite3.Error:
            raise RequestError(503, "Scan history is unavailable.") from None
        if not project:
            raise RequestError(404, "Unknown project")
        return project

    @staticmethod
    def person(value):
        if value is None:
            return ""
        if not isinstance(value, str) or len(value) > 80 or not value.strip().isprintable():
            raise RequestError(400, "Names may be up to 80 printable characters.")
        return value.strip()

    def review(self, project_id, kind, data):
        """Record a human verdict or comment. Human review is stored apart from AI verdicts."""
        self.project_or_404(project_id)
        finding = data.get("finding_id")
        if not isinstance(finding, str) or not FINDING_ID.fullmatch(finding):
            raise RequestError(400, "Unknown finding.")
        history = self.server.history
        try:
            if kind == "reviews":
                verdict = data.get("verdict")
                if verdict is not None and verdict not in REVIEW_VERDICTS:
                    raise RequestError(400, "Choose Confirmed, False positive, Accepted risk or Fixed.")
                history.set_review(project_id, finding, verdict, self.person(data.get("reviewer")))
            else:
                body = data.get("body")
                if not isinstance(body, str) or not body.strip() or len(body) > 4000:
                    raise RequestError(400, "Comments must be between 1 and 4,000 characters.")
                history.add_comment(project_id, finding, self.person(data.get("author")), body.strip())
            return self.respond(200, history.reviews(project_id).get(finding) or
                                {"verdict": None, "reviewer": "", "updated": None, "comments": []})
        except sqlite3.Error:
            raise RequestError(503, "Could not save the review.") from None

    def delete_comment(self, comment_id):
        try:
            project = self.server.history.delete_comment(comment_id)
        except sqlite3.Error:
            raise RequestError(503, "Could not delete the comment.") from None
        if project is None:
            raise RequestError(404, "Unknown comment, or it is a review event that can't be deleted.")
        return self.respond(200, {"deleted": comment_id})

    def pdf(self, data):
        """Render one scan as a PDF. Saved scans use the server's copy and stored human reviews."""
        options = data.get("options") or {}
        if not isinstance(options, dict) or options.get("group", "category") not in GROUPINGS or any(
                not isinstance(options.get(key, True), bool)
                for key in ("include_false_positives", "include_code", "include_comments")):
            raise RequestError(400, "Invalid PDF options.")
        run_id, name, reviews, meta = data.get("run_id"), "report", {}, {}
        try:
            if run_id is not None:
                if type(run_id) is not int:
                    raise RequestError(400, "Invalid scan.")
                run, result = self.server.history.run(run_id), self.server.history.result(run_id)
                if not run or not result or not result.get("report"):
                    raise RequestError(404, "This scan has no saved report.")
                project = self.project_or_404(run["project_id"])
                report, reviews = result["report"], self.server.history.reviews(project["id"])
                name = project["name"]
                meta = {"project": project["name"], "branch": project["branch"]}
            else:
                report = json.loads(Report.model_validate(data.get("report")).model_dump_json())
                name = str(data.get("name") or "report")[:80]
                meta = {"project": name}
        except sqlite3.Error:
            raise RequestError(503, "Scan history is unavailable.") from None
        except ValidationError:
            raise RequestError(400, "This report can't be converted to PDF because it is not a valid AppSec report.") from None
        if not self.server.pdf_lock.acquire(blocking=False):
            raise RequestError(429, "Another PDF is being generated. Try again in a moment.")
        try:
            document = build_pdf(report, reviews, meta, options)
        except Exception:
            raise RequestError(500, "The PDF could not be generated.") from None
        finally:
            self.server.pdf_lock.release()
        stamp = time.strftime("%Y%m%d-%H%M")
        filename = f"appsec-{re.sub(r'[^A-Za-z0-9._-]+', '-', name).strip('-')[:60] or 'report'}-{stamp}.pdf"
        return self.respond(200, document, "application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    def delete_project(self, project_id):
        """Remove a project and its saved scan results. Source code is never touched."""
        server = self.server
        with server.lock:
            try:
                job_run = server.history.run(server.job["run_id"]) if server.job.get("run_id") else None
                if server.job.get("status") == "running" and job_run and job_run["project_id"] == project_id:
                    raise RequestError(409, "This project is being scanned. Stop the scan first.")
                removed = server.history.delete_project(project_id)
            except sqlite3.Error:
                raise RequestError(503, "Scan history is unavailable.")
            if removed is None:
                raise RequestError(404, "Unknown project")
            # Forget the last finished report too, so it can't reappear after a refresh.
            if server.job.get("status") != "running" and (server.job.get("project_id") == project_id
                                                         or (job_run and job_run["project_id"] == project_id)):
                server.job = {"status": "idle"}
        return self.respond(200, {"deleted": project_id, "scans_removed": removed})

    def rerun(self, run_id, repository_token=""):
        """Start a new scan with the same project and settings as an earlier run."""
        try:
            run = self.server.history.run(run_id)
            project = next((p for p in self.server.history.projects() if run and p["id"] == run["project_id"]), None)
        except sqlite3.Error:
            raise RequestError(503, "Scan history is unavailable.")
        if not run or not project:
            raise RequestError(404, "Unknown scan")
        mount = os.getenv("APPSEC_MOUNT_LABEL", "/workspace")
        if project["mount"] and not (self.server.container and project["mount"] == mount):
            raise RequestError(400, "This project's repository is not mounted, so it can't be scanned again.")
        settings = run["settings"]
        if settings.get("repository_token_required") and repository_token == "":
            raise RequestError(428, "Enter a repository access token to rerun this scan.")
        prefs = self.server.preferences.load()
        default_provider = os.environ.get("AI_PROVIDER", "").strip() or prefs["provider"] or "openai"
        data = {"project_id": project["id"], "name": project["name"], "source": project["source"],
                "target": project["target"], "branch": project["branch"], "scanner": run["scanner"],
                "mode": run["mode"], "limit": settings.get("limit", 5),
                "provider": settings.get("provider") or default_provider, "model": settings.get("model", ""),
                "repository_token": repository_token}
        return self.scan_request(data, rerun_of=run_id)

    def scan_request(self, data, save_only=False, rerun_of=None):
        repository_token = data.pop("repository_token", "")
        if save_only and repository_token != "":
            return self.respond(400, {"error": "Use repository access tokens when checking access or running a scan."})
        try:
            target, mode, limit = data["target"], data.get("mode", "scan"), data.get("limit", 0)
            scanner = data.get("scanner", "semgrep")
            try:
                scanner = scanner_spec(scanner)
            except (ValueError, AttributeError):
                return self.respond(400, {"error": "Choose at least one valid scanner."})
            if mode == "triage" and "semgrep" not in parse_scanners(scanner):
                return self.respond(400, {"error": "AI review needs a code (SAST) scan. Secret findings are never sent to AI."})
            provider, model = data.get("provider", "openai"), data.get("model", "")
            if provider not in PROVIDERS or not isinstance(model, str) or not MODEL_ID.fullmatch(model.strip()):
                return self.respond(400, {"error": "Choose a supported AI provider and a valid model ID."})
            model = model.strip()
            if mode == "triage" and not save_only and not resolve_key(PROVIDERS[provider], self.server.keys)[0]:
                return self.respond(400, {"error": f"Add an API key for {PROVIDERS[provider].label} in Settings first."})
            source, branch = data.get("source", "local"), data.get("branch", "")
            if not isinstance(target, str) or not target.strip() or mode not in ("scan", "triage"):
                raise ValueError()
            if type(limit) is not int or not 0 <= limit <= 100:
                raise ValueError()
            if source == "remote":
                target, branch = validate_remote(target, branch)
                repository_token = validate_repository_token(target, repository_token)
            elif source == "local":
                validate_repository_token("", repository_token)
                target = str(Path(target).resolve(strict=True))
                if self.server.container and not Path(target).is_relative_to("/workspace"):
                    return self.respond(400, {"error": "Choose /workspace or a folder inside it."})
                if not Path(target).is_dir():
                    raise ValueError()
                branch = ""
            else:
                raise ValueError()
            name = data.get("name", "")
            if not isinstance(name, str) or len(name) > 120:
                raise ValueError()
            mount = os.getenv("APPSEC_MOUNT_LABEL", "/workspace") if self.server.container and source == "local" else ""
            name = name.strip() or Path(mount or target).name or target
            if data.get("project_id") is not None:
                existing = next((p for p in self.server.history.projects() if p["id"] == data["project_id"]), None)
                if not existing or (name, source, target, branch, mount) != tuple(
                        existing[k] for k in ("name", "source", "target", "branch", "mount")):
                    return self.respond(400, {"error": "This project no longer matches the selected repository or mount."})
            project = self.server.history.project(name, source, target, branch, mount)
            if save_only:
                return self.respond(200, {"id": project})
        except sqlite3.Error:
            return self.respond(503, {"error": "Could not save the project."})
        except RepositoryError as exc:
            return self.respond(400, {"error": str(exc)})
        except (ValueError, KeyError, TypeError, OSError):
            return self.respond(400, {"error": "Choose an existing repository folder and an assessment limit between 0 and 100."})
        with self.server.lock:
            if self.server.job["status"] == "running":
                return self.respond(409, {"error": "A scan is already running."})
            try:
                settings = {"limit": limit, **({"provider": provider, "model": model} if mode == "triage" else {})}
                if repository_token:
                    settings["repository_token_required"] = True
                run_id = self.server.history.start(project, scanner, mode, settings)
                self.server.cancel.clear()
            except sqlite3.Error:
                return self.respond(503, {"error": "Could not create a scan history entry."})
            self.server.job = {"status": "running", "mode": mode, "run_id": run_id, "started": time.time(), "now": time.time()}
        scan_auth = {"repository_token": repository_token} if repository_token else {}
        threading.Thread(target=self.server.scan, args=(target, mode, limit, source, branch, scanner, run_id, provider, model),
                         kwargs=scan_auth, daemon=True).start()
        self.respond(202, {"status": "running", "project_id": project, "run_id": run_id, "rerun_of": rerun_of,
                           "scan": {"source": source, "scanner": scanner, "mode": mode, "limit": limit,
                                    "provider": provider if mode == "triage" else None, "model": model or None}})


def serve(port=8765):
    if not 0 <= port <= 65535:
        print("Port must be between 0 and 65535", file=sys.stderr)
        return 2
    try:
        with LocalServer(port) as server:
            print(f"AppSec Triage: http://127.0.0.1:{server.server_port} (Ctrl+C to stop)", flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        return 0
    except sqlite3.Error:
        print("Could not open scan history. Check APPSEC_DATA_DIR permissions and close any dashboard using it.", file=sys.stderr)
        return 2
    except OSError:
        print("Unable to start local UI; try another --port.", file=sys.stderr)
        return 2
