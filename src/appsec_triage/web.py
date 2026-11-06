"""Loopback-only UI; scanner execution remains in the existing CLI."""
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from appsec_triage.repositories import RepositoryError, clone_repository, validate_remote
from appsec_triage.folder_picker import FolderPickerError, choose_folder
from appsec_triage.history import History


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
            self.history = History(os.getenv("APPSEC_DATA_DIR") or Path.home() / ".appsec-triage")
        except Exception:
            self.server_close()
            raise
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.picker_lock = threading.Lock()
        self.job = {"status": "idle"}

    def server_close(self):
        super().server_close()
        if hasattr(self, "history"):
            self.history.lease.close()

    def scan(self, target, mode, limit, source="local", branch="", scanner="semgrep", run_id=None):
        revision = None
        try:
            with tempfile.TemporaryDirectory(prefix="appsec-ui-") as directory:
                output = Path(directory) / "report.json"
                scan_target = target
                if source == "remote":
                    with self.lock:
                        self.job = {"status": "running", "phase": "Cloning repository"}
                    scan_target = str(clone_repository(target, branch, Path(directory)))
                if run_id is not None:
                    revision = git_revision(scan_target)
                with self.lock:
                    self.job = {"status": "running", "phase": "Scanning repository"}
                result = subprocess.run(
                    [sys.executable, "-m", "appsec_triage.cli", mode, scan_target,
                     "--scanner", scanner, "--max-findings", str(limit), "--output", str(output)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=7200, check=False,
                )
                if output.exists():
                    job = {"status": "completed", "report": json.loads(output.read_text(encoding="utf-8"))}
                    if source == "remote":
                        job["report"]["scan"]["target"] = target
                        job["report"]["repository"] = {"url": target, "branch": branch or "default"}
                else:
                    job = {"status": "failed", "error": f"Scan exited with code {result.returncode}. Check the repository path, scanner installation, and environment configuration."}
        except RepositoryError as exc:
            job = {"status": "failed", "error": str(exc)}
        except Exception:
            job = {"status": "failed", "error": "Scan could not finish. Check local configuration or run the CLI for diagnostics."}
        if run_id is not None:
            try:
                job["project_id"] = self.history.finish(run_id, job, revision)
            except sqlite3.Error:
                job["history_error"] = "Could not save this scan. Export the report before closing the dashboard."
        with self.lock:
            self.job = job


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, payload, content_type="application/json"):
        body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)

    def trusted_host(self):
        return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

    def do_GET(self):
        if not self.trusted_host():
            return self.respond(403, {"error": "Local access only"})
        if self.path == "/":
            page = Path(__file__).with_name("web_ui.html").read_text(encoding="utf-8")
            page = page.replace("__CONTAINER__", json.dumps(self.server.container))
            return self.respond(200, page.replace("__TOKEN__", self.server.token), "text/html; charset=utf-8")
        if self.path == "/api/job":
            with self.server.lock:
                return self.respond(200, self.server.job)
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
            match = re.fullmatch(r"/api/runs/([0-9]{1,18})", self.path)
            if match:
                result = self.server.history.result(int(match[1]))
                return self.respond(200, result) if result else self.respond(404, {"error": "Unknown scan"})
        except sqlite3.Error:
            return self.respond(503, {"error": "Scan history is unavailable."})
        self.respond(404, {"error": "Not found"})

    def do_POST(self):
        if not self.trusted_host() or self.headers.get("X-Appsec-Token") != self.server.token:
            return self.respond(403, {"error": "Local access only"})
        origin = self.headers.get("Origin")
        if origin and origin != f"http://127.0.0.1:{self.server.server_port}":
            return self.respond(403, {"error": "Invalid origin"})
        if self.path == "/api/folder":
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
        if self.path not in ("/api/scan", "/api/projects"):
            return self.respond(404, {"error": "Not found"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 8192:
                raise ValueError()
            data = json.loads(self.rfile.read(size))
            target, mode, limit = data["target"], data.get("mode", "scan"), data.get("limit", 0)
            scanner = data.get("scanner", "semgrep")
            if scanner not in ("semgrep", "trivy", "all"):
                raise ValueError()
            source, branch = data.get("source", "local"), data.get("branch", "")
            if not isinstance(target, str) or not target.strip() or mode not in ("scan", "triage"):
                raise ValueError()
            if type(limit) is not int or not 0 <= limit <= 100:
                raise ValueError()
            if source == "remote":
                target, branch = validate_remote(target, branch)
            elif source == "local":
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
            if self.path == "/api/projects":
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
                run_id = self.server.history.start(project, scanner, mode)
            except sqlite3.Error:
                return self.respond(503, {"error": "Could not create a scan history entry."})
            self.server.job = {"status": "running"}
        threading.Thread(target=self.server.scan, args=(target, mode, limit, source, branch, scanner, run_id), daemon=True).start()
        self.respond(202, {"status": "running", "project_id": project, "run_id": run_id})


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
