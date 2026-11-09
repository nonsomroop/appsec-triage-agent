import subprocess
from base64 import b64decode
from pathlib import Path

import pytest

from appsec_triage.repositories import RepositoryError, check_repository_access, clone_repository, validate_remote
from appsec_triage.services.providers import PROVIDERS
from appsec_triage.web import LocalServer


@pytest.mark.parametrize("url", [
    "https://github.com/owner/repo.git", "https://gitlab.com/group/subgroup/repo",
    "git@github.com:owner/repo.git", "ssh://git@gitlab.com/group/repo.git",
    "https://bitbucket.org/team/repo.git", "git@bitbucket.org:team/repo.git",
    "https://dev.azure.com/org/my%20project/_git/repo", "git@ssh.dev.azure.com:v3/org/project/repo",
])
def test_supported_urls(url):
    assert validate_remote(url, "feature/new-ui") == (url, "feature/new-ui")


def test_normalizes_azure_clone_url():
    assert validate_remote("https://org@dev.azure.com/org/project/_git/repo") == (
        "https://dev.azure.com/org/project/_git/repo", "")


@pytest.mark.parametrize("url", [
    "https://token@github.com/owner/repo", "https://user:secret@github.com/owner/repo",
    "ssh://user:secret@github.com/owner/repo", "http://github.com/owner/repo",
    "file:///tmp/repo", "ext::command", "-upload-pack=command", "C:/repos/project",
    "https://github.com.evil.example/owner/repo", "git@evil.example:owner/repo",
    "https://github.com/owner/../repo", "https://github.com/owner/repo?token=secret",
    "https://github.com/owner/repo#secret", "https://github.com:443/owner/repo",
    "https://github.com/owner/repo\n", "ssh://github.com/owner/repo",
    "https://secret@dev.azure.com/org/project/_git/repo",
    "https://org:secret@dev.azure.com/org/project/_git/repo",
    "https://dev.azure.com/org/project/_git/repo%2Fother",
    "https://dev.azure.com/org/project",
    "git@ssh.dev.azure.com:other/org/project/repo",
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
    monkeypatch.setenv("OPENAI_API_KEY", "dummy-ai-key")
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
    assert "OPENAI_API_KEY" not in options["env"]


@pytest.mark.parametrize(("url", "allow_sign_in", "interactive"), [
    ("https://github.com/owner/repo", True, True),
    ("https://gitlab.com/group/repo", True, True),
    ("https://bitbucket.org/team/repo", True, True),
    ("https://dev.azure.com/org/project/_git/repo", True, True),
    ("https://gitlab.com/group/repo", False, False),
    ("git@bitbucket.org:team/repo", True, False),
])
def test_repository_access_checks_branch_with_explicit_sign_in(monkeypatch, tmp_path, url, allow_sign_in, interactive):
    monkeypatch.setattr("appsec_triage.repositories.shutil.which", lambda name: "git")
    monkeypatch.setenv("GIT_TRACE", "1")
    monkeypatch.setenv("SSH_ASKPASS", "custom-askpass")
    monkeypatch.setenv("GH_TOKEN", "dummy-git-token")
    ai_key_names = {name for provider in PROVIDERS.values() for name in provider.key_env}
    for name in ai_key_names:
        monkeypatch.setenv(name, "dummy-ai-key")

    def run(args, **options):
        assert args[-7:] == ["ls-remote", "--quiet", "--exit-code", "--heads", "--", url, "refs/heads/main"]
        assert f"credential.interactive={str(interactive).lower()}" in args
        assert options["stdout"] == subprocess.DEVNULL and options["stderr"] == subprocess.PIPE
        assert not options["shell"]
        env = options["env"]
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert "GIT_TRACE" not in env
        assert ai_key_names.isdisjoint(env)
        assert env["GH_TOKEN"] == "dummy-git-token"
        if interactive:
            assert env["GCM_GITHUB_AUTHMODES"] == env["GCM_GITLAB_AUTHMODES"] == "browser"
            assert env["GCM_BITBUCKET_AUTHMODES"] == "oauth"
            assert env["GCM_MSAUTH_FLOW"] == "system"
            assert "SSH_ASKPASS" not in env
        else:
            assert env["GCM_INTERACTIVE"] == "Never"
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("appsec_triage.repositories.subprocess.run", run)
    check_repository_access(url, "main", tmp_path, allow_sign_in=allow_sign_in)


@pytest.mark.parametrize(("code", "message"), [(2, "branch was not found"), (128, "Could not read the repository")])
def test_repository_access_errors_are_safe(monkeypatch, tmp_path, code, message):
    monkeypatch.setattr("appsec_triage.repositories.shutil.which", lambda name: "git")
    monkeypatch.setattr("appsec_triage.repositories.subprocess.run",
                        lambda args, **kw: subprocess.CompletedProcess(args, code, stderr=b"secret"))
    with pytest.raises(RepositoryError, match=message) as caught:
        check_repository_access("https://github.com/owner/repo", "main", tmp_path, allow_sign_in=True)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize(("url", "username"), [
    ("https://github.com/owner/repo", "x-access-token"),
    ("https://gitlab.com/group/repo", "oauth2"),
    ("https://bitbucket.org/team/repo", "x-bitbucket-api-token-auth"),
    ("https://dev.azure.com/org/project/_git/repo", ""),
])
def test_access_token_stays_in_process_environment(monkeypatch, tmp_path, url, username):
    token = "dummy-read-token"
    monkeypatch.setattr("appsec_triage.repositories.shutil.which", lambda name: "git")
    calls = []

    def run(args, **options):
        calls.append(args)
        assert token not in " ".join(args)
        assert "credential.helper=" in args and "http.followRedirects=false" in args
        assert options["stdout"] == subprocess.DEVNULL and options["stderr"] == subprocess.PIPE
        env = options["env"]
        assert env["GCM_INTERACTIVE"] == "Never"
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert env["GIT_CONFIG_KEY_0"] == f"http.{url}.extraHeader"
        assert b64decode(env["GIT_CONFIG_VALUE_0"].removeprefix("Authorization: Basic ")).decode() == f"{username}:{token}"
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("appsec_triage.repositories.subprocess.run", run)
    check_repository_access(url, "", tmp_path, allow_sign_in=True, token=token)
    clone_repository(url, "", tmp_path, token=token)
    assert "ls-remote" in calls[0] and "clone" in calls[1]


@pytest.mark.parametrize(("url", "token"), [
    ("git@github.com:owner/repo", "dummy-read-token"),
    ("https://github.com/owner/repo", "dummy\nheader"),
])
def test_access_rejects_unsafe_token_before_git(monkeypatch, tmp_path, url, token):
    monkeypatch.setattr("appsec_triage.repositories.subprocess.run", lambda *a, **kw: pytest.fail("Git ran"))
    with pytest.raises(RepositoryError):
        check_repository_access(url, "", tmp_path, allow_sign_in=False, token=token)


@pytest.mark.parametrize("error", [subprocess.CalledProcessError(128, "git", stderr=b"secret"), subprocess.TimeoutExpired("git", 300)])
def test_clone_errors_do_not_expose_credentials(monkeypatch, tmp_path, error):
    monkeypatch.setattr("appsec_triage.repositories.shutil.which", lambda name: "git")
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr("appsec_triage.repositories.subprocess.run", fail)
    with pytest.raises(RepositoryError) as caught:
        clone_repository("https://github.com/owner/repo", "", tmp_path)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize(("url", "token", "stderr", "guidance"), [
    ("https://github.com/org/repo", "dummy-pat", b"remote: Repository not found.", "pending organization approval"),
    ("https://github.com/org/repo", "dummy-pat", b"remote: This organization has enforced SAML SSO.", "requires SAML single sign-on"),
    ("https://github.com/org/repo", "dummy-pat", b"fatal: The requested URL returned error: 403", "provider denied access"),
    ("https://gitlab.com/group/repo", "dummy-pat", b"remote: HTTP Basic: Access denied.", "could not authenticate"),
    ("https://github.com/org/repo", "", b"fatal: could not read Username: terminal prompts disabled", "Private repository access"),
    ("https://github.com/org/repo", "", b"fatal: Remote branch main not found in upstream origin", "selected branch was not found"),
    ("git@github.com:org/repo", "", b"Host key verification failed.", "could not verify the Git host"),
    ("git@github.com:org/repo", "", b"git@github.com: Permission denied (publickey).", "rejected the SSH key"),
    ("https://github.com/org/repo", "", b"fatal: SSL certificate problem", "could not verify the server's HTTPS certificate"),
    ("https://github.com/org/repo", "", b"fatal: Could not resolve host: github.com", "Check network access"),
    ("https://github.com/org/repo", "", b"fatal: The requested URL returned error: 301", "redirected the clone URL"),
])
def test_git_failures_share_actionable_safe_guidance(monkeypatch, tmp_path, url, token, stderr, guidance):
    monkeypatch.setattr("appsec_triage.repositories.shutil.which", lambda name: "git")

    def run(args, **options):
        raw_error = stderr + b"\nremote: never-display-this-value " + token.encode("ascii")
        result = subprocess.CompletedProcess(args, 128, stderr=raw_error)
        if options.get("check"):
            result.check_returncode()
        return result

    monkeypatch.setattr("appsec_triage.repositories.subprocess.run", run)
    for operation, kwargs in ((check_repository_access, {"allow_sign_in": False}), (clone_repository, {})):
        with pytest.raises(RepositoryError, match=guidance) as caught:
            operation(url, "main", tmp_path, token=token, **kwargs)
        assert "never-display-this-value" not in str(caught.value)
        assert "dummy-pat" not in str(caught.value)


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
    monkeypatch.setattr("appsec_triage.web.run_scan_process", scan)
    with LocalServer(0) as server:
        server.scan("https://github.com/owner/repo", "scan", 2, "remote", "main")
        assert not workspaces[0].exists()
        if fail_clone:
            assert server.job["status"] == "failed"
        else:
            assert server.job["report"]["scan"]["target"] == "https://github.com/owner/repo"
            assert server.job["report"]["repository"]["branch"] == "main"
