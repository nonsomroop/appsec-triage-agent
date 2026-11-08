import json
import os
import re
import stat
import threading
import time
from contextlib import contextmanager
from http.client import HTTPConnection
from pathlib import Path
from types import SimpleNamespace
import pytest

from appsec_triage.web import LocalServer
from appsec_triage.folder_picker import FolderPickerError


@pytest.fixture(autouse=True)
def isolated_history(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_DATA_DIR", str(tmp_path / "history"))


@contextmanager
def running_server():
    with LocalServer(0) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=3)


def request(server, method, path, body=None, headers=None):
    headers = dict(headers or {})
    if body is not None:
        headers.setdefault("Content-Type", "application/json")
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    result = response.status, response.read().decode()
    connection.close()
    return result


def test_local_page_and_host_protection():
    with running_server() as server:
        status, page = request(server, "GET", "/")
        assert status == 200 and server.token in page and "__TOKEN__" not in page
        assert request(server, "GET", "/", headers={"Host": "evil.example"})[0] == 403
        assert request(server, "GET", "/api/job")[0] == 403
        token = {"X-Appsec-Token": server.token}
        assert json.loads(request(server, "GET", "/api/job", headers=token)[1])["status"] == "idle"
        assert json.loads(request(server, "GET", "/healthz")[1]) == {"ok": True}


def test_scan_auth_validation_and_busy(monkeypatch):
    monkeypatch.setattr(LocalServer, "scan", lambda *args: None)
    with running_server() as server:
        body = json.dumps({"target": str(Path.cwd()), "mode": "scan", "limit": 2})
        headers = {"X-Appsec-Token": server.token, "Content-Type": "application/json"}
        assert request(server, "POST", "/api/scan", body)[0] == 403
        assert request(server, "POST", "/api/scan", body, {**headers, "Origin": "http://evil.example"})[0] == 403
        assert request(server, "POST", "/api/scan", '{}', headers)[0] == 400
        assert request(server, "POST", "/api/scan", body.replace('"scan"', '"shell"'), headers)[0] == 400
        assert request(server, "POST", "/api/scan", body, headers)[0] == 202
        assert request(server, "POST", "/api/scan", body, headers)[0] == 409


def test_scan_worker_preserves_partial_report(monkeypatch):
    def fake_run(args, **kwargs):
        assert args[1:4] == ["-m", "appsec_triage.cli", "scan"]
        Path(args[-1]).write_text('{"scan":{"status":"partial"}}', encoding="utf-8")
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr("appsec_triage.web.run_scan_process", fake_run)
    with LocalServer(0) as server:
        server.scan(str(Path.cwd()), "scan", 2)
        assert server.job["report"]["scan"]["status"] == "partial"


def test_scan_worker_reports_failure(monkeypatch):
    monkeypatch.setattr("appsec_triage.web.run_scan_process", lambda *a, **k: SimpleNamespace(returncode=2))
    with LocalServer(0) as server:
        server.scan(str(Path.cwd()), "triage", 2)
        assert server.job["status"] == "failed"
        assert "configuration" in server.job["error"]


def test_remote_scan_request(monkeypatch):
    calls = []
    monkeypatch.setenv("OPENAI_API_KEY", "dummy-offline-test-key")
    monkeypatch.setattr(LocalServer, "scan", lambda self, *args: calls.append(args))
    with running_server() as server:
        headers = {"X-Appsec-Token": server.token}
        data = {"target": "git@gitlab.com:group/repo.git", "mode": "triage", "limit": 5,
                "source": "remote", "branch": "develop"}
        assert request(server, "POST", "/api/scan", json.dumps(data), headers)[0] == 202
        assert calls == [(data["target"], "triage", 5, "remote", "develop", "semgrep", 1, "openai", "")]
        data["target"] = "https://secret@github.com/owner/repo"
        assert request(server, "POST", "/api/scan", json.dumps(data), headers)[0] == 400


def test_folder_picker_endpoint(monkeypatch):
    calls = []
    def picker():
        calls.append(True)
        return str(Path.cwd())
    monkeypatch.setattr("appsec_triage.web.choose_folder", picker)
    with running_server() as server:
        headers = {"X-Appsec-Token": server.token}
        assert request(server, "POST", "/api/folder")[0] == 403
        assert request(server, "POST", "/api/folder", headers={**headers, "Origin": "https://evil.example"})[0] == 403
        assert not calls
        status, body = request(server, "POST", "/api/folder", headers=headers)
        assert status == 200 and json.loads(body)["path"] == str(Path.cwd())
        with server.picker_lock:
            assert request(server, "POST", "/api/folder", headers=headers)[0] == 409
        monkeypatch.setattr("appsec_triage.web.choose_folder", lambda: None)
        assert json.loads(request(server, "POST", "/api/folder", headers=headers)[1])["path"] is None
        def fail():
            raise FolderPickerError("Picker unavailable")
        monkeypatch.setattr("appsec_triage.web.choose_folder", fail)
        assert request(server, "POST", "/api/folder", headers=headers)[0] == 503
        assert not server.picker_lock.locked()


def test_sca_request_selection_and_validation(monkeypatch):
    calls = []
    monkeypatch.setattr(LocalServer, "scan", lambda self, *args: calls.append(args))
    with running_server() as server:
        headers = {"X-Appsec-Token": server.token}
        data = {"target": str(Path.cwd()), "mode": "scan", "limit": 0, "scanner": "invalid"}
        assert request(server, "POST", "/api/scan", json.dumps(data), headers)[0] == 400
        data["scanner"] = "trivy"
        assert request(server, "POST", "/api/scan", json.dumps(data), headers)[0] == 202
        assert calls[0][5] == "trivy"

def test_two_scans_survive_restart(monkeypatch, tmp_path):
    from time import monotonic, sleep
    from appsec_triage.models.scan import Scan
    from appsec_triage.reporting.json_reporter import Report

    def execute(args, **kwargs):
        scan = Scan(target=str(tmp_path), scanner="semgrep", status="completed")
        Path(args[-1]).write_text(Report(scan=scan).model_dump_json(), encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("appsec_triage.web.git_revision", lambda _: "a" * 40)
    monkeypatch.setattr("appsec_triage.web.run_scan_process", execute)
    data = dict(name="Demo", target=str(tmp_path), source="local", mode="scan", limit=0)
    with running_server() as server:
        headers = {"X-Appsec-Token": server.token}
        status, body = request(server, "POST", "/api/projects", json.dumps(data), headers)
        assert status == 200
        project = json.loads(body)["id"]
        for _ in range(2):
            status, _ = request(server, "POST", "/api/scan", json.dumps(dict(data, project_id=project)), headers)
            assert status == 202
            deadline = monotonic() + 5
            while server.job["status"] == "running" and monotonic() < deadline:
                sleep(.01)
            assert server.job["status"] == "completed"
    with running_server() as server:
        headers = {"X-Appsec-Token": server.token}
        runs = json.loads(request(server, "GET", f"/api/projects/{project}/runs", headers=headers)[1])
        assert len(runs) == 2 and all(r["revision"] == "a" * 40 for r in runs)
        reports = [json.loads(request(server,"GET",f"/api/runs/{r['id']}",headers=headers)[1])["report"] for r in runs]
        assert reports[0]["scan"]["id"] != reports[1]["scan"]["id"]



ANTHROPIC_KEY = "sk-ant-api03-offline-test-key-abcd1234"


def settings_post(server, path, data, extra=None):
    headers = {"X-Appsec-Token": server.token, **(extra or {})}
    status, body = request(server, "POST", path, json.dumps(data), headers)
    return status, json.loads(body)


def providers(server):
    body = request(server, "GET", "/api/providers", headers={"X-Appsec-Token": server.token})[1]
    return json.loads(body)


def fake_check(status="valid", models=("claude-opus-5-5",)):
    from appsec_triage.services.key_check import KeyCheck
    calls = []
    def run(provider, key, model=""):
        calls.append((provider, key, model))
        return KeyCheck(status, f"check {status}", list(models), model in models if model else None)
    return run, calls


def test_security_headers_and_script_nonce():
    with running_server() as server:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", "/")
        response = connection.getresponse()
        page = response.read().decode()
        csp = response.getheader("Content-Security-Policy")
        nonce = re.search(r"'nonce-([^']+)'", csp)[1]
        assert f'<script nonce="{nonce}">' in page and "'unsafe-inline'" not in csp.split("style-src")[0]
        assert response.getheader("X-Frame-Options") == "DENY"
        assert response.getheader("Referrer-Policy") == "no-referrer"
        assert "Python" not in (response.getheader("Server") or "")
        connection.close()


def test_api_rejects_cross_site_and_non_json(monkeypatch):
    monkeypatch.setattr(LocalServer, "scan", lambda self, *args: None)
    with running_server() as server:
        token = {"X-Appsec-Token": server.token}
        assert request(server, "GET", "/api/job", headers={**token, "Sec-Fetch-Site": "cross-site"})[0] == 403
        assert request(server, "GET", "/api/job", headers={"X-Appsec-Token": "wrong"})[0] == 403
        body = json.dumps({"target": str(Path.cwd()), "mode": "scan", "limit": 0})
        assert request(server, "POST", "/api/scan", body, {**token, "Content-Type": "text/plain"})[0] == 415
        assert request(server, "POST", "/api/scan", "x" * 9000, token)[0] == 413
        assert request(server, "POST", "/api/scan", "[1]", token)[0] == 400


def test_save_key_verifies_and_never_returns_it(monkeypatch, tmp_path):
    run, calls = fake_check()
    monkeypatch.setattr("appsec_triage.web.run_check", run)
    with running_server() as server:
        status, body = settings_post(server, "/api/settings/key", {"provider": "anthropic", "key": ANTHROPIC_KEY})
        assert status == 200 and body["check"]["status"] == "valid"
        assert calls == [("anthropic", ANTHROPIC_KEY, "claude-opus-5-5")]
        listing = request(server, "GET", "/api/providers", headers={"X-Appsec-Token": server.token})[1]
        assert ANTHROPIC_KEY not in listing and ANTHROPIC_KEY[:-4] not in listing
        anthropic = next(p for p in json.loads(listing)["providers"] if p["name"] == "anthropic")
        assert anthropic["configured"] and anthropic["key_source"] == "file" and anthropic["key_hint"] == "…1234"
        credentials = Path(server.keys.file)
        assert json.loads(credentials.read_text())["anthropic"] == ANTHROPIC_KEY
        if os.name != "nt":
            assert stat.S_IMODE(credentials.stat().st_mode) == 0o600
        status, body = settings_post(server, "/api/settings/key/remove", {"provider": "anthropic"})
        assert status == 200 and not body["provider"]["configured"]


def test_invalid_or_unreachable_key_is_not_saved(monkeypatch):
    with running_server() as server:
        monkeypatch.setattr("appsec_triage.web.run_check", fake_check("invalid")[0])
        status, body = settings_post(server, "/api/settings/key", {"provider": "anthropic", "key": ANTHROPIC_KEY})
        assert status == 400 and server.keys.get("anthropic") is None
        monkeypatch.setattr("appsec_triage.web.run_check", fake_check("unreachable")[0])
        status, body = settings_post(server, "/api/settings/key", {"provider": "anthropic", "key": ANTHROPIC_KEY})
        assert status == 502 and body["can_save_unverified"] and server.keys.get("anthropic") is None
        status, body = settings_post(server, "/api/settings/key", {"provider": "anthropic", "key": ANTHROPIC_KEY, "verify": False})
        assert status == 200 and body["check"]["status"] == "unverified"
        assert settings_post(server, "/api/settings/key", {"provider": "anthropic", "key": "short"})[0] == 400
        assert settings_post(server, "/api/settings/key", {"provider": "anthropic", "key": "has spaces in it 1234567890"})[0] == 400


def test_environment_keys_are_locked(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSy-environment-key-0000000000")
    with running_server() as server:
        status, body = settings_post(server, "/api/settings/key", {"provider": "gemini", "key": ANTHROPIC_KEY})
        assert status == 409 and "GEMINI_API_KEY" in body["error"]
        gemini = next(p for p in providers(server)["providers"] if p["name"] == "gemini")
        assert gemini["key_source"] == "environment" and gemini["env_var"] == "GEMINI_API_KEY"


def test_key_checks_are_rate_limited(monkeypatch):
    run, calls = fake_check()
    monkeypatch.setattr("appsec_triage.web.run_check", run)
    monkeypatch.setenv("ANTHROPIC_API_KEY", ANTHROPIC_KEY)
    with running_server() as server:
        statuses = [settings_post(server, "/api/settings/test", {"provider": "anthropic"})[0] for _ in range(14)]
        assert statuses[:12] == [200] * 12 and statuses[12:] == [429, 429]
        assert settings_post(server, "/api/settings/test", {"provider": "openai"})[0] == 400


def test_preferences_drive_defaults(monkeypatch):
    with running_server() as server:
        status, _ = settings_post(server, "/api/settings/preferences",
                                  {"default_provider": "gemini", "models": {"gemini": "gemini-4-argon"}})
        assert status == 200
        listing = providers(server)
        assert listing["default_provider"] == "gemini"
        assert next(p for p in listing["providers"] if p["name"] == "gemini")["default_model"] == "gemini-4-argon"
        assert settings_post(server, "/api/settings/preferences", {"models": {"gemini": "--evil"}})[0] == 400
        assert settings_post(server, "/api/settings/preferences", {"default_provider": "nope"})[0] == 400


def test_triage_requires_key_and_passes_it_by_environment(monkeypatch):
    calls = []
    real_scan = LocalServer.scan
    monkeypatch.setattr(LocalServer, "scan", lambda self, *args: calls.append(args))
    with running_server() as server:
        headers = {"X-Appsec-Token": server.token}
        data = {"target": str(Path.cwd()), "mode": "triage", "limit": 1, "provider": "unknown"}
        assert request(server, "POST", "/api/scan", json.dumps(data), headers)[0] == 400
        data.update(provider="anthropic", model="--output=/etc/passwd")
        assert request(server, "POST", "/api/scan", json.dumps(data), headers)[0] == 400
        data["model"] = " claude-sonnet-5-5 "
        status, body = request(server, "POST", "/api/scan", json.dumps(data), headers)
        assert status == 400 and "Settings" in body
        server.keys.set("anthropic", ANTHROPIC_KEY)
        assert request(server, "POST", "/api/scan", json.dumps(data), headers)[0] == 202
        assert calls[0][-2:] == ("anthropic", "claude-sonnet-5-5")

    seen = []
    def fake_run(args, **kwargs):
        seen.append((args, kwargs["env"]))
        return SimpleNamespace(returncode=2)
    monkeypatch.setattr("appsec_triage.web.run_scan_process", fake_run)
    monkeypatch.setattr(LocalServer, "scan", real_scan)
    with LocalServer(0) as server:
        server.keys.set("anthropic", ANTHROPIC_KEY)
        server.keys.set("gemini", "AIzaSy-stored-gemini-key-000000000")
        server.scan(str(Path.cwd()), "triage", 2, provider="anthropic", model="")
        server.scan(str(Path.cwd()), "scan", 2, provider="anthropic", model="claude-sonnet-5-5")
    args, env = seen[0]
    assert args[-4:] == ["--provider", "anthropic", "--model", "claude-opus-5-5"]
    assert env["ANTHROPIC_API_KEY"] == ANTHROPIC_KEY and ANTHROPIC_KEY not in " ".join(args)
    assert "GEMINI_API_KEY" not in env
    assert "--provider" not in seen[1][0] and "ANTHROPIC_API_KEY" not in seen[1][1]


def test_rerun_repeats_saved_settings(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(LocalServer, "scan", lambda self, *args: calls.append(args))
    with running_server() as server:
        server.keys.set("anthropic", ANTHROPIC_KEY)
        headers = {"X-Appsec-Token": server.token}
        data = {"name": "Demo", "target": str(tmp_path), "source": "local", "scanner": "all", "mode": "triage",
                "limit": 7, "provider": "anthropic", "model": "claude-sonnet-5-5"}
        status, body = request(server, "POST", "/api/scan", json.dumps(data), headers)
        first = json.loads(body)
        assert status == 202
        server.job = {"status": "completed"}
        runs = json.loads(request(server, "GET", f"/api/projects/{first['project_id']}/runs", headers=headers)[1])
        assert runs[0]["settings"] == {"limit": 7, "provider": "anthropic", "model": "claude-sonnet-5-5"}
        status, body = request(server, "POST", f"/api/runs/{first['run_id']}/rerun", "{}", headers)
        rerun = json.loads(body)
        assert status == 202 and rerun["rerun_of"] == first["run_id"] and rerun["run_id"] != first["run_id"]
        assert rerun["scan"] == {"source": "local", "scanner": "all", "mode": "triage", "limit": 7,
                                 "provider": "anthropic", "model": "claude-sonnet-5-5"}
        assert calls[0] == calls[1][:6] + (first["run_id"],) + calls[1][7:]
        assert request(server, "POST", f"/api/runs/{rerun['run_id']}/rerun", "{}", headers)[0] == 409
        server.job = {"status": "completed"}
        assert request(server, "POST", "/api/runs/999/rerun", "{}", headers)[0] == 404
        assert request(server, "POST", f"/api/runs/{first['run_id']}/rerun", "{}")[0] == 403
        server.keys.delete("anthropic")
        status, body = request(server, "POST", f"/api/runs/{first['run_id']}/rerun", "{}", headers)
        assert status == 400 and "Settings" in body


def test_rerun_refuses_unmounted_project(monkeypatch, tmp_path):
    monkeypatch.setattr(LocalServer, "scan", lambda self, *args: None)
    with running_server() as server:
        project = server.history.project("Old mount", "local", str(tmp_path), "", "/some/other/mount")
        run = server.history.start(project, "semgrep", "scan", {"limit": 0})
        server.history.finish(run, {"status": "failed", "error": "x"}, None)
        status, body = request(server, "POST", f"/api/runs/{run}/rerun", "{}", {"X-Appsec-Token": server.token})
        assert status == 400 and "not mounted" in body


def test_history_upgrades_old_database(tmp_path):
    import sqlite3
    from appsec_triage.history import History
    directory = tmp_path / "old"
    directory.mkdir()
    with sqlite3.connect(directory / "history.sqlite3") as db:
        db.executescript("""
            CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL,
                target TEXT NOT NULL, branch TEXT NOT NULL, mount TEXT NOT NULL, UNIQUE(name, source, target, branch, mount));
            CREATE TABLE runs (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
                started TEXT NOT NULL, scanner TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL,
                revision TEXT, error TEXT, report TEXT);
            INSERT INTO projects VALUES (1, 'Legacy', 'local', '/repo', '', '');
            INSERT INTO runs VALUES (1, 1, '2026-01-01T00:00:00+00:00', 'semgrep', 'scan', 'completed', NULL, NULL, NULL);
        """)
    history = History(directory)
    try:
        assert history.runs(1)[0]["settings"] == {}
        assert history.run(1)["scanner"] == "semgrep"
    finally:
        history.lease.close()


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-only")
def test_cancel_stops_scan_and_its_children(tmp_path):
    import sys
    import threading
    from appsec_triage.web import ScanCancelled, run_scan_process
    pid_file = tmp_path / "child.pid"
    # Stands in for the CLI starting a long-running scanner child process.
    script = ("import subprocess, sys, time;"
              f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']);"
              f"open({str(pid_file)!r}, 'w').write(str(child.pid)); time.sleep(60)")
    cancel = threading.Event()
    threading.Timer(1.0, cancel.set).start()
    started = time.monotonic()
    with pytest.raises(ScanCancelled):
        run_scan_process([sys.executable, "-c", script], env=dict(os.environ), timeout=60, cancel=cancel)
    assert time.monotonic() - started < 10
    child = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail("scanner child process survived cancellation")


def test_cancel_endpoint_marks_run_cancelled(monkeypatch, tmp_path):
    from appsec_triage.web import ScanCancelled

    def blocking(args, *, env, timeout, cancel):
        assert cancel.wait(5), "cancel was never requested"
        raise ScanCancelled()

    monkeypatch.setattr("appsec_triage.web.run_scan_process", blocking)
    monkeypatch.setattr("appsec_triage.web.git_revision", lambda _: None)
    with running_server() as server:
        headers = {"X-Appsec-Token": server.token}
        assert request(server, "POST", "/api/job/cancel", "{}", headers)[0] == 409
        data = {"target": str(tmp_path), "mode": "scan", "limit": 0}
        status, body = request(server, "POST", "/api/scan", json.dumps(data), headers)
        started = json.loads(body)
        assert status == 202
        assert request(server, "POST", "/api/job/cancel", "{}")[0] == 403
        assert request(server, "POST", "/api/job/cancel", "{}", headers)[0] == 202
        deadline = time.monotonic() + 5
        while server.job["status"] == "running" and time.monotonic() < deadline:
            time.sleep(0.02)
        job = server.job
        assert job["status"] == "cancelled" and "stopped" in job["error"].lower()
        assert any(entry["message"] == "Scan stopped by user" for entry in job["log"])
        runs = json.loads(request(server, "GET", f"/api/projects/{started['project_id']}/runs", headers=headers)[1])
        assert runs[0]["status"] == "cancelled"
        # A new scan clears the cancel flag.
        monkeypatch.setattr("appsec_triage.web.run_scan_process", lambda args, **kw: SimpleNamespace(returncode=2))
        assert request(server, "POST", "/api/scan", json.dumps(data), headers)[0] == 202
        deadline = time.monotonic() + 5
        while server.job["status"] == "running" and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.job["status"] == "failed"


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-only")
def test_cancel_stops_semgrep_started_in_its_own_session(tmp_path):
    import sys
    import threading
    from appsec_triage.web import ScanCancelled, run_scan_process
    bin_dir, pid_file = tmp_path / "bin", tmp_path / "semgrep.pid"
    bin_dir.mkdir()
    fake = bin_dir / "semgrep"
    fake.write_text(f"#!{sys.executable}\nimport os, time\nopen({str(pid_file)!r}, 'w').write(str(os.getpid()))\ntime.sleep(60)\n")
    fake.chmod(0o755)
    (tmp_path / "repo").mkdir()
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "APPSEC_DATA_DIR": str(tmp_path / "data")}
    cancel = threading.Event()
    def stop_when_semgrep_runs():
        deadline = time.monotonic() + 20
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        cancel.set()
    threading.Thread(target=stop_when_semgrep_runs, daemon=True).start()
    with pytest.raises(ScanCancelled):
        run_scan_process([sys.executable, "-m", "appsec_triage.cli", "scan", str(tmp_path / "repo"),
                          "--output", str(tmp_path / "out.json")], env=env, timeout=60, cancel=cancel)
    semgrep = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(semgrep, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    os.kill(semgrep, 9)
    pytest.fail("Semgrep survived cancellation")


def test_delete_project_removes_scans_but_not_source(monkeypatch, tmp_path):
    import sqlite3
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("print('keep me')")
    with running_server() as server:
        headers = {"X-Appsec-Token": server.token}
        keep = server.history.project("Keep", "local", str(tmp_path / "other"), "", "")
        gone = server.history.project("Gone", "local", str(source), "", "")
        for project in (keep, gone, gone):
            run = server.history.start(project, "semgrep", "scan", {"limit": 0})
            server.history.finish(run, {"status": "completed", "report": {"scan": {"status": "completed"}, "marker": "SECRET-SNIPPET"}}, None)
        server.job = {"status": "completed", "project_id": gone, "run_id": run, "report": {}}
        assert request(server, "POST", f"/api/projects/{gone}/delete", "{}")[0] == 403
        status, body = request(server, "POST", f"/api/projects/{gone}/delete", "{}", headers)
        assert status == 200 and json.loads(body) == {"deleted": gone, "scans_removed": 2}
        assert [p["name"] for p in server.history.projects()] == ["Keep"]
        assert len(server.history.runs(keep)) == 1 and server.history.runs(gone) == []
        assert server.job == {"status": "idle"}
        assert request(server, "POST", f"/api/projects/{gone}/delete", "{}", headers)[0] == 404
        assert (source / "app.py").read_text() == "print('keep me')"
        with sqlite3.connect(server.history.path) as db:
            assert db.execute("PRAGMA secure_delete").fetchone()[0] in (0, 1)
        server.history.lease.close()
        raw = Path(server.history.path).read_bytes()
        assert raw.count(b"SECRET-SNIPPET") == 1  # only the kept project's report remains on disk


def test_cannot_delete_project_while_it_scans(monkeypatch, tmp_path):
    with running_server() as server:
        headers = {"X-Appsec-Token": server.token}
        project = server.history.project("Busy", "local", str(tmp_path), "", "")
        run = server.history.start(project, "semgrep", "scan", {"limit": 0})
        server.job = {"status": "running", "run_id": run}
        status, body = request(server, "POST", f"/api/projects/{project}/delete", "{}", headers)
        assert status == 409 and "Stop the scan" in body
        server.job = {"status": "idle"}
