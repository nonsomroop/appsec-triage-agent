import json
import threading
from contextlib import contextmanager
from http.client import HTTPConnection
from pathlib import Path
from types import SimpleNamespace

from appsec_triage.web import LocalServer
from appsec_triage.folder_picker import FolderPickerError


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
        assert calls == [(data["target"], "triage", 5, "remote", "develop")]
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
