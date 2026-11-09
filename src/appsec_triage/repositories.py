"""Check and clone remote repositories using the user's configured Git credentials."""
import os
import re
import shutil
import subprocess
from base64 import b64encode
from pathlib import Path
from urllib.parse import urlsplit

from appsec_triage.services.providers import PROVIDERS


TOKEN_USERNAMES = {"github.com": "x-access-token", "gitlab.com": "oauth2",
                   "bitbucket.org": "x-bitbucket-api-token-auth", "dev.azure.com": ""}
HTTPS_HOSTS = frozenset(TOKEN_USERNAMES)
SSH_HOSTS = (HTTPS_HOSTS - {"dev.azure.com"}) | {"ssh.dev.azure.com"}

# Display fixed guidance only. Git output can include credentials, URLs, or arbitrary remote text.
GIT_FAILURE_HINTS = (
    (rb"saml (?:sso|single sign-on)|sso authorization (?:is )?required",
     "The organization requires SAML single sign-on. Complete its SSO authorization for repository access, then retry."),
    (rb"remote branch .* not found|couldn't find remote ref",
     "The selected branch was not found. Check its spelling or clear the Branch field to use the default."),
    (rb"host key verification failed|remote host identification has changed",
     "SSH could not verify the Git host. Confirm its host key and update the known hosts used by the scanner."),
    (rb"permission denied \(publickey",
     "The Git host rejected the SSH key. Load the correct key into the SSH agent used by the scanner."),
    (rb"certificate (?:problem|verify failed|verification failed)|ssl certificate|schannel:.*cert",
     "Git could not verify the server's HTTPS certificate. Check the certificate trust settings used by the scanner."),
    (rb"could not resolve (?:host|hostname|proxy)|failed to connect|connection timed out|connection refused|proxy connect aborted",
     "Git could not connect to the provider. Check network access, DNS, and proxy settings where the dashboard runs."),
    (rb"returned error: 30[12378]\b|unable to update url base from redirection",
     "The provider redirected the clone URL. Copy the current HTTPS clone URL from the repository's Code or Clone menu."),
)


class RepositoryError(ValueError):
    pass


def validate_remote(url: str, branch: str = "") -> tuple[str, str]:
    message = "Use a GitHub.com, GitLab.com, Bitbucket Cloud or Azure Repos clone URL without embedded credentials."
    if not isinstance(url, str) or not isinstance(branch, str):
        raise RepositoryError(message)
    url, branch = url.strip(), branch.strip()
    if any(c.isspace() or ord(c) < 32 for c in url):
        raise RepositoryError(message)
    if url.startswith("git@"):
        match = re.fullmatch(r"git@([^:]+):(.+)", url)
        if not match or match[1] not in SSH_HOSTS:
            raise RepositoryError(message)
        host, path = match.groups()
    else:
        try:
            parsed = urlsplit(url)
            hosts = {"https": HTTPS_HOSTS, "ssh": SSH_HOSTS}
            path = parsed.path.removeprefix("/")
            azure_org = (parsed.hostname == "dev.azure.com" and parsed.username is not None
                         and parsed.username.casefold() == path.split("/", 1)[0].casefold())
            if (parsed.hostname not in hosts.get(parsed.scheme, ())
                    or parsed.port is not None or parsed.query or parsed.fragment or parsed.password is not None
                    or (parsed.scheme == "https" and parsed.username is not None and not azure_org)
                    or (parsed.scheme == "ssh" and parsed.username != "git")):
                raise ValueError()
            host = parsed.hostname
            if azure_org:
                url = f"https://dev.azure.com/{path}"
        except ValueError:
            raise RepositoryError(message) from None
    parts = path.split("/")
    if host == "dev.azure.com" and (len(parts) != 4 or parts[2] != "_git"):
        raise RepositoryError("Use an Azure Repos URL in the form https://dev.azure.com/organization/project/_git/repository.")
    if host == "ssh.dev.azure.com" and (len(parts) != 4 or parts[0] != "v3"):
        raise RepositoryError("Use an Azure Repos SSH URL in the form git@ssh.dev.azure.com:v3/organization/project/repository.")
    if len(parts) < 2 or any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*",
                                             p.replace("%20", "_") if host == "dev.azure.com" else p) for p in parts):
        raise RepositoryError(message)
    if branch and (len(branch) > 200 or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]*", branch)
                   or ".." in branch or "//" in branch or branch.endswith(("/", "."))
                   or any(p.startswith(".") or p.endswith(".lock") for p in branch.split("/"))):
        raise RepositoryError("Enter a valid branch name, or leave it empty for the default branch.")
    return url, branch


def validate_repository_token(url: str, token: str) -> str:
    if token == "":
        return ""
    if not isinstance(token, str) or not re.fullmatch(r"[\x21-\x7e]{1,2048}", token):
        raise RepositoryError("Enter a repository access token without spaces.")
    if urlsplit(url).scheme != "https":
        raise RepositoryError("Repository access tokens require a supported HTTPS clone URL.")
    return token


def _remote_git(url: str, workspace: Path, *, browser_sign_in: bool = False,
                token: str = "") -> tuple[list[str], dict[str, str]]:
    git = shutil.which("git")
    if not git:
        raise RepositoryError("Git is not installed or is missing from PATH.")
    env = os.environ.copy()
    for provider in PROVIDERS.values():
        for name in provider.key_env:
            env.pop(name, None)
    for key in list(env):
        if key.startswith("GIT_") and key not in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
            env.pop(key)
    env.update(GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never", GIT_LFS_SKIP_SMUDGE="1",
               GIT_SSH_COMMAND="ssh -o BatchMode=yes -o StrictHostKeyChecking=yes", LC_ALL="C")
    if browser_sign_in:
        env.pop("SSH_ASKPASS", None)
        env.update(GCM_INTERACTIVE="auto", GCM_GUI_PROMPT="true", GCM_GITHUB_AUTHMODES="browser",
                   GCM_GITLAB_AUTHMODES="browser", GCM_BITBUCKET_AUTHMODES="oauth", GCM_MSAUTH_FLOW="system")
    command = [git, "-c", f"credential.interactive={str(browser_sign_in).lower()}",
               "-c", "http.followRedirects=false", "-c", "protocol.allow=never",
               "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always"]
    if token:
        username = TOKEN_USERNAMES[urlsplit(url).hostname]
        authorization = b64encode(f"{username}:{token}".encode("ascii")).decode("ascii")
        # Keep the token off argv and out of the clone's config. Ignore config that could rewrite the URL.
        env.pop("SSH_ASKPASS", None)
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                   GIT_CEILING_DIRECTORIES=str(workspace.parent), GIT_CONFIG_COUNT="1",
                   GIT_CONFIG_KEY_0=f"http.{url}.extraHeader",
                   GIT_CONFIG_VALUE_0=f"Authorization: Basic {authorization}")
        command += ["-c", "credential.helper=", "-c", "core.askPass=", "-c", "protocol.ssh.allow=never"]
    return command, env


def _git_failure(stderr: bytes | None, url: str, *, has_token: bool, browser_sign_in: bool = False) -> str:
    details = (stderr or b"")[-16384:].lower()
    for pattern, hint in GIT_FAILURE_HINTS:
        if re.search(pattern, details):
            return hint

    if re.search(rb"repository (?:not found|[^\n]+ not found)|returned error: 404\b", details):
        message = "The provider could not find the repository or did not grant access. Copy the clone URL from the repository page."
    elif re.search(rb"returned error: 403\b|resource not accessible by|you are not allowed to download code", details):
        message = "The provider denied access to the repository."
    elif re.search(rb"returned error: 401\b|authentication failed|invalid username or token|http basic: access denied|could not read (?:username|password)", details):
        message = "Git could not authenticate to the repository."
    else:
        message = "Could not read the repository. Check the clone URL and branch."

    parsed = urlsplit(url)
    if has_token and parsed.hostname == "github.com":
        return (f"{message} Check that the token is active. For a fine-grained token, select the correct resource owner "
                "and repository, grant Contents: Read-only, and check for pending organization approval. "
                "For a classic token, use Configure SSO if the organization requires it.")
    if has_token:
        return f"{message} Check that the token is active and has repository read permission."
    if parsed.scheme != "https":
        return f"{message} Check your SSH key and the account's repository access."
    if browser_sign_in:
        return f"{message} Complete sign-in if prompted, or enter a token under Private repository access."
    return f"{message} For a private HTTPS repository, enter a read-only token under Private repository access."


def check_repository_access(url: str, branch: str, workspace: Path, *, allow_sign_in: bool, token: str = "") -> None:
    url, branch = validate_remote(url, branch)
    token = validate_repository_token(url, token)
    https = urlsplit(url).scheme == "https"
    browser_sign_in = allow_sign_in and https and not token
    command, env = _remote_git(url, workspace, browser_sign_in=browser_sign_in, token=token)
    if browser_sign_in:
        command += ["-c", "core.askPass=", "-c", "protocol.ssh.allow=never"]
    command += ["ls-remote", "--quiet"]
    if branch:
        command += ["--exit-code", "--heads"]
    command += ["--", url]
    if branch:
        command.append(f"refs/heads/{branch}")
    try:
        result = subprocess.run(command, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                timeout=120 if browser_sign_in else 20, shell=False,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        message = "The access check timed out."
        if browser_sign_in:
            message += " Complete any open sign-in and try again."
        raise RepositoryError(message) from None
    except OSError:
        raise RepositoryError("Could not run Git to check repository access.") from None
    if branch and result.returncode == 2:
        raise RepositoryError("The repository is accessible, but that branch was not found.")
    if result.returncode != 0:
        raise RepositoryError(_git_failure(result.stderr, url, has_token=bool(token), browser_sign_in=browser_sign_in))


def clone_repository(url: str, branch: str, workspace: Path, *, full_history: bool = False, token: str = "") -> Path:
    url, branch = validate_remote(url, branch)
    token = validate_repository_token(url, token)
    command, env = _remote_git(url, workspace, token=token)
    target = workspace / "repository"
    # Fresh empty hooks/template directories prevent local template hooks from running.
    hooks = workspace / "empty-hooks"
    hooks.mkdir()
    command += ["-c", f"core.hooksPath={hooks}", "clone", "--quiet", "--single-branch", "--no-tags", f"--template={hooks}"]
    if not full_history:
        command += ["--depth", "1"]
    if branch:
        command += ["--branch", branch]
    command += ["--", url, str(target)]
    try:
        subprocess.run(command, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                       timeout=300, check=True, shell=False)
    except subprocess.TimeoutExpired:
        raise RepositoryError("Repository clone timed out after 5 minutes.") from None
    except subprocess.CalledProcessError as exc:
        raise RepositoryError(f"Clone failed. {_git_failure(exc.stderr, url, has_token=bool(token))}") from None
    except OSError:
        raise RepositoryError("Could not run Git to clone the repository.") from None
    return target
