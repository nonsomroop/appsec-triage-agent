"""Loopback-only UI; scanner execution remains in the existing CLI."""
import json
import secrets
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from appsec_triage.repositories import RepositoryError, clone_repository, validate_remote
from appsec_triage.folder_picker import FolderPickerError, choose_folder


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port):
        super().__init__(("127.0.0.1", port), Handler)
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.picker_lock = threading.Lock()
        self.job = {"status": "idle"}

    def scan(self, target, mode, limit, source="local", branch=""):
        try:
            with tempfile.TemporaryDirectory(prefix="appsec-ui-") as directory:
                output = Path(directory) / "report.json"
                scan_target = target
                if source == "remote":
                    with self.lock:
                        self.job = {"status": "running", "phase": "Cloning repository"}
                    scan_target = str(clone_repository(target, branch, Path(directory)))
                with self.lock:
                    self.job = {"status": "running", "phase": "Scanning repository"}
                result = subprocess.run(
                    [sys.executable, "-m", "appsec_triage.cli", mode, scan_target,
                     "--max-findings", str(limit), "--output", str(output)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=7200, check=False,
                )
                if output.exists():
                    job = {"status": "completed", "report": json.loads(output.read_text(encoding="utf-8"))}
                    if source == "remote":
                        job["report"]["scan"]["target"] = target
                        job["report"]["repository"] = {"url": target, "branch": branch or "default"}
                else:
                    job = {"status": "failed", "error": f"Scan exited with code {result.returncode}. Check the repository path, Semgrep installation, and environment configuration."}
        except RepositoryError as exc:
            job = {"status": "failed", "error": str(exc)}
        except Exception:
            job = {"status": "failed", "error": "Scan could not finish. Check local configuration or run the CLI for diagnostics."}
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
            return self.respond(200, page.replace("__TOKEN__", self.server.token), "text/html; charset=utf-8")
        if self.path == "/api/job":
            with self.server.lock:
                return self.respond(200, self.server.job)
        self.respond(404, {"error": "Not found"})

    def do_POST(self):
        if not self.trusted_host() or self.headers.get("X-Appsec-Token") != self.server.token:
            return self.respond(403, {"error": "Local access only"})
        origin = self.headers.get("Origin")
        if origin and origin != f"http://127.0.0.1:{self.server.server_port}":
            return self.respond(403, {"error": "Invalid origin"})
        if self.path == "/api/folder":
            if not self.server.picker_lock.acquire(blocking=False):
                return self.respond(409, {"error": "A folder picker is already open."})
            try:
                return self.respond(200, {"path": choose_folder()})
            except FolderPickerError as exc:
                return self.respond(503, {"error": str(exc)})
            finally:
                self.server.picker_lock.release()
        if self.path != "/api/scan":
            return self.respond(404, {"error": "Not found"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 8192:
                raise ValueError()
            data = json.loads(self.rfile.read(size))
            target, mode, limit = data["target"], data["mode"], data["limit"]
            source, branch = data.get("source", "local"), data.get("branch", "")
            if not isinstance(target, str) or not target.strip() or mode not in ("scan", "triage"):
                raise ValueError()
            if type(limit) is not int or not 0 <= limit <= 100:
                raise ValueError()
            if source == "remote":
                target, branch = validate_remote(target, branch)
            elif source == "local":
                target = str(Path(target).resolve(strict=True))
                if not Path(target).is_dir():
                    raise ValueError()
                branch = ""
            else:
                raise ValueError()
        except RepositoryError as exc:
            return self.respond(400, {"error": str(exc)})
        except (ValueError, KeyError, TypeError, OSError):
            return self.respond(400, {"error": "Choose an existing repository folder and an assessment limit between 0 and 100."})
        with self.server.lock:
            if self.server.job["status"] == "running":
                return self.respond(409, {"error": "A scan is already running."})
            self.server.job = {"status": "running"}
        threading.Thread(target=self.server.scan, args=(target, mode, limit, source, branch), daemon=True).start()
        self.respond(202, {"status": "running"})


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
    except OSError:
        print("Unable to start local UI; try another --port.", file=sys.stderr)
        return 2
