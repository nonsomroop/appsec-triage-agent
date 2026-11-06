import json
import threading
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
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = response.status, response.read().decode()
    connection.close()
    return result


def test_local_page_and_host_protection():
    with running_server() as server:
        status, page = request(server, "GET", "/")
        assert status == 200 and server.token in page and "__TOKEN__" not in page
        assert request(server, "GET", "/", headers={"Host": "evil.example"})[0] == 403
        assert json.loads(request(server, "GET", "/api/job")[1])["status"] == "idle"


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

    monkeypatch.setattr("appsec_triage.web.subprocess.run", fake_run)
    with LocalServer(0) as server:
        server.scan(str(Path.cwd()), "scan", 2)
        assert server.job["report"]["scan"]["status"] == "partial"


def test_scan_worker_reports_failure(monkeypatch):
    monkeypatch.setattr("appsec_triage.web.subprocess.run", lambda *a, **k: SimpleNamespace(returncode=2))
    with LocalServer(0) as server:
        server.scan(str(Path.cwd()), "triage", 2)
        assert server.job["status"] == "failed"
        assert "configuration" in server.job["error"]


def test_remote_scan_request(monkeypatch):
    calls = []
    monkeypatch.setattr(LocalServer, "scan", lambda self, *args: calls.append(args))
    with running_server() as server:
        headers = {"X-Appsec-Token": server.token}
        data = {"target": "git@gitlab.com:group/repo.git", "mode": "triage", "limit": 5,
                "source": "remote", "branch": "develop"}
        assert request(server, "POST", "/api/scan", json.dumps(data), headers)[0] == 202
        assert calls == [(data["target"], "triage", 5, "remote", "develop", "semgrep", 1)]
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
        assert calls[0][-2] == "trivy"

def test_two_scans_survive_restart(monkeypatch, tmp_path):
    from time import monotonic, sleep
    from appsec_triage.models.scan import Scan
    from appsec_triage.reporting.json_reporter import Report

    def execute(args, **kwargs):
        scan = Scan(target=str(tmp_path), scanner="semgrep", status="completed")
        Path(args[-1]).write_text(Report(scan=scan).model_dump_json(), encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("appsec_triage.web.git_revision", lambda _: "a" * 40)
    monkeypatch.setattr("appsec_triage.web.subprocess.run", execute)
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
        runs = json.loads(request(server, "GET", f"/api/projects/{project}/runs")[1])
        assert len(runs) == 2 and all(r["revision"] == "a" * 40 for r in runs)
        reports = [json.loads(request(server,"GET",f"/api/runs/{r['id']}")[1])["report"] for r in runs]
        assert reports[0]["scan"]["id"] != reports[1]["scan"]["id"]
