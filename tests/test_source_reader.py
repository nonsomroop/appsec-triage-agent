import pytest

from appsec_triage.utils.source_reader import SourceReader, SourceReadError


@pytest.mark.parametrize("path", ["../outside.py", "nested/../../outside.py", ".env", ".env.local",
                                  "credentials.json", "secret.key", "id_ed25519", ".aws/config",
                                  ".git/config", "secrets.yaml", "C:/outside.py", "app.py:stream"])
def test_reject_paths(tmp_path, path):
    with pytest.raises(SourceReadError):
        SourceReader(tmp_path).read(path, 1, 1)


def test_absolute_escape(tmp_path):
    with pytest.raises(SourceReadError):
        SourceReader(tmp_path).read(str(tmp_path.parent / "outside.py"), 1, 1)


def test_symlink_escape(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("sensitive")
    try:
        (root / "alias.py").symlink_to(outside)
    except OSError:
        pytest.skip("OS does not permit symlink creation")
    with pytest.raises(SourceReadError):
        SourceReader(root).read("alias.py", 1, 1)


def test_secret_alias(tmp_path):
    (tmp_path / ".env").write_text("SECRET=value")
    try:
        (tmp_path / "alias.py").symlink_to(tmp_path / ".env")
    except OSError:
        pytest.skip("OS does not permit symlink creation")
    with pytest.raises(SourceReadError):
        SourceReader(tmp_path).read("alias.py", 1, 1)


def test_context_encoding_and_limits(tmp_path):
    (tmp_path / "app.py").write_bytes(b"line1\nline\xff2\nline3\n")
    reader = SourceReader(tmp_path, context_lines=0)
    assert reader.read("app.py", 2, 2) == "2: line\ufffd2"
    with pytest.raises(SourceReadError, match="size"):
        SourceReader(tmp_path, max_file_bytes=2).read("app.py", 1, 1)
    assert "truncated" in SourceReader(tmp_path, max_context_chars=4).read("app.py", 1, 3)
    with pytest.raises(SourceReadError):
        reader.read("app.py", 99, 99)
    with pytest.raises(SourceReadError):
        reader.read(".", 1, 1)


def test_link_policy_without_os_privileges(tmp_path, monkeypatch):
    from pathlib import Path
    (tmp_path / "alias.py").write_text("secret")
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path.name == "alias.py" or original(path))
    with pytest.raises(SourceReadError, match="links"):
        SourceReader(tmp_path).read("alias.py", 1, 1)
