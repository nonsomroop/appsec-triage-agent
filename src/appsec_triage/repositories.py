"""Temporary GitHub/GitLab checkouts using the user's configured Git credentials."""
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


class RepositoryError(ValueError):
    pass


def validate_remote(url: str, branch: str = "") -> tuple[str, str]:
    message = "Use a GitHub.com or GitLab.com HTTPS or SSH repository URL without embedded credentials."
    if not isinstance(url, str) or not isinstance(branch, str):
        raise RepositoryError(message)
    url, branch = url.strip(), branch.strip()
    if any(c.isspace() or ord(c) < 32 for c in url):
        raise RepositoryError(message)
    if url.startswith("git@"):
        match = re.fullmatch(r"git@(github\.com|gitlab\.com):(.+)", url)
        if not match:
            raise RepositoryError(message)
        path = match[2]
    else:
        try:
            parsed = urlsplit(url)
            if (parsed.scheme not in ("https", "ssh") or parsed.hostname not in ("github.com", "gitlab.com")
                    or parsed.port is not None or parsed.query or parsed.fragment or parsed.password
                    or (parsed.scheme == "https" and parsed.username is not None)
                    or (parsed.scheme == "ssh" and parsed.username != "git")):
                raise ValueError()
            path = parsed.path.removeprefix("/")
        except ValueError:
            raise RepositoryError(message) from None
    parts = path.split("/")
    if len(parts) < 2 or any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", p) or p in (".", "..") for p in parts):
        raise RepositoryError(message)
    if branch and (len(branch) > 200 or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]*", branch)
                   or ".." in branch or "//" in branch or branch.endswith(("/", "."))
                   or any(p.startswith(".") or p.endswith(".lock") for p in branch.split("/"))):
        raise RepositoryError("Enter a valid branch name, or leave it empty for the default branch.")
    return url, branch


def clone_repository(url: str, branch: str, workspace: Path) -> Path:
    url, branch = validate_remote(url, branch)
    git = shutil.which("git")
    if not git:
        raise RepositoryError("Git is not installed or is missing from PATH.")
    target = workspace / "repository"
    # Fresh empty hooks/template directories prevent local template hooks from running.
    hooks = workspace / "empty-hooks"
    hooks.mkdir()
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_") and key not in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
            env.pop(key)
    env.update(GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never", GIT_LFS_SKIP_SMUDGE="1",
               GIT_SSH_COMMAND="ssh -o BatchMode=yes -o StrictHostKeyChecking=yes")
    command = [git, "-c", f"core.hooksPath={hooks}", "-c", "credential.interactive=false",
               "-c", "http.followRedirects=false", "-c", "protocol.allow=never",
               "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always",
               "clone", "--depth", "1", "--single-branch", "--no-tags", f"--template={hooks}"]
    if branch:
        command += ["--branch", branch]
    command += ["--", url, str(target)]
    try:
        subprocess.run(command, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=300, check=True, shell=False)
    except subprocess.TimeoutExpired:
        raise RepositoryError("Repository clone timed out after 5 minutes.") from None
    except (OSError, subprocess.CalledProcessError):
        raise RepositoryError("Clone failed. Check the URL and branch, and configure Git credentials or your SSH agent in the terminal first. SSH hosts must already be trusted.") from None
    return target
