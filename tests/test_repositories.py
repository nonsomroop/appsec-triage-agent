import subprocess
from pathlib import Path

import pytest

from appsec_triage.repositories import RepositoryError, clone_repository, validate_remote
from appsec_triage.web import LocalServer


@pytest.mark.parametrize("url", [
    "https://github.com/owner/repo.git", "https://gitlab.com/group/subgroup/repo",
    "git@github.com:owner/repo.git", "ssh://git@gitlab.com/group/repo.git",
])
def test_supported_urls(url):
    assert validate_remote(url, "feature/new-ui") == (url, "feature/new-ui")


@pytest.mark.parametrize("url", [
    "https://token@github.com/owner/repo", "https://user:secret@github.com/owner/repo",
    "ssh://user:secret@github.com/owner/repo", "http://github.com/owner/repo",
    "file:///tmp/repo", "ext::command", "-upload-pack=command", "C:/repos/project",
    "https://github.com.evil.example/owner/repo", "git@evil.example:owner/repo",
    "https://github.com/owner/../repo", "https://github.com/owner/repo?token=secret",
    "https://github.com/owner/repo#secret", "https://github.com:443/owner/repo",
    "https://github.com/owner/repo\n", "ssh://github.com/owner/repo",
])
def test_rejected_urls(url):
    # Surrounding whitespace is normalized; internal whitespace is rejected.
    if url.endswith("\n"):
        url = url.replace("/owner/", "/ow\nner/")
    with pytest.raises(RepositoryError):
        validate_remote(url)


@pytest.mark.parametrize("branch", ["--upload-pack=x", "../main", "main.lock", "a//b", "a/", "a b", "a/.hidden", "a..b"])
def test_rejected_branches(branch):
    with pytest.raises(RepositoryError):
        validate_remote("https://github.com/owner/repo", branch)


def test_clone_uses_existing_auth_and_no_shell(monkeypatch, tmp_path):
    monkeypatch.setattr("appsec_triage.repositories.shutil.which", lambda name: "git")
    monkeypatch.setenv("SSH_AUTH_SOCK", "existing-agent")
    monkeypatch.setenv("GIT_TRACE", "1")
    calls = []
    monkeypatch.setattr("appsec_triage.repositories.subprocess.run", lambda args, **kw: calls.append((args, kw)))
    target = clone_repository("git@github.com:owner/repo", "feature/new-ui", tmp_path)
    args, options = calls[0]
    assert target == tmp_path / "repository"
    assert args[-3:] == ["--", "git@github.com:owner/repo", str(target)]
    assert args[args.index("--branch") + 1] == "feature/new-ui"
    assert options["shell"] is False and options["timeout"] == 300
    assert options["env"]["SSH_AUTH_SOCK"] == "existing-agent"
    assert options["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert "StrictHostKeyChecking=yes" in options["env"]["GIT_SSH_COMMAND"]
    assert "GIT_TRACE" not in options["env"]


@pytest.mark.parametrize("error", [subprocess.CalledProcessError(128, "git", stderr="secret"), subprocess.TimeoutExpired("git", 300)])
def test_clone_errors_do_not_expose_credentials(monkeypatch, tmp_path, error):
    monkeypatch.setattr("appsec_triage.repositories.shutil.which", lambda name: "git")
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr("appsec_triage.repositories.subprocess.run", fail)
    with pytest.raises(RepositoryError) as caught:
        clone_repository("https://github.com/owner/repo", "", tmp_path)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize("fail_clone", [False, True])
def test_remote_worker_cleans_checkout(monkeypatch, fail_clone):
    workspaces = []
    def clone(url, branch, workspace):
        workspaces.append(workspace)
        target = workspace / "repository"
        target.mkdir()
        (target / "source.py").write_text("example")
        if fail_clone:
            raise RepositoryError("Clone failed")
        return target
    def scan(args, **kwargs):
        assert Path(args[4]).is_dir()
        Path(args[-1]).write_text('{"scan":{"status":"completed","target":"temporary"}}')
    monkeypatch.setattr("appsec_triage.web.clone_repository", clone)
    monkeypatch.setattr("appsec_triage.web.subprocess.run", scan)
    with LocalServer(0) as server:
        server.scan("https://github.com/owner/repo", "scan", 2, "remote", "main")
        assert not workspaces[0].exists()
        if fail_clone:
            assert server.job["status"] == "failed"
        else:
            assert server.job["report"]["scan"]["target"] == "https://github.com/owner/repo"
            assert server.job["report"]["repository"]["branch"] == "main"
