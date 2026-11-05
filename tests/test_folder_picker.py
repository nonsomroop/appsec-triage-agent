import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_triage.folder_picker import FolderPickerError, choose_folder


@pytest.mark.parametrize("platform,helper,expected", [
    ("win32", None, "powershell.exe"), ("darwin", None, "osascript"),
    ("linux", "zenity", "zenity"), ("linux", "kdialog", "kdialog"),
    ("linux", None, None),
])
def test_platform_picker_and_unicode_path(monkeypatch, tmp_path, platform, helper, expected):
    folder = tmp_path / "My projects café"
    folder.mkdir()
    calls = []
    monkeypatch.setattr("appsec_triage.folder_picker.sys.platform", platform)
    monkeypatch.setattr("appsec_triage.folder_picker.shutil.which", lambda name: name if name == helper else None)
    def run(command, **kwargs):
        calls.append(command)
        assert kwargs["shell"] is False
        return SimpleNamespace(returncode=0, stdout=str(folder).encode("utf-8"))
    monkeypatch.setattr("appsec_triage.folder_picker.subprocess.run", run)
    assert choose_folder() == str(folder)
    if expected:
        assert calls[0][0].endswith(expected)
    else:
        assert "tkinter" in calls[0][-1]


@pytest.mark.parametrize("code,output", [(0, b""), (1, b"")])
def test_cancel(monkeypatch, code, output):
    monkeypatch.setattr("appsec_triage.folder_picker.sys.platform", "linux")
    monkeypatch.setattr("appsec_triage.folder_picker.shutil.which", lambda name: "zenity")
    monkeypatch.setattr("appsec_triage.folder_picker.subprocess.run", lambda *a, **k: SimpleNamespace(returncode=code, stdout=output))
    assert choose_folder() is None


@pytest.mark.parametrize("error", [OSError(), subprocess.TimeoutExpired("picker", 120)])
def test_unavailable_and_timeout(monkeypatch, error):
    def run(*args, **kwargs):
        raise error
    monkeypatch.setattr("appsec_triage.folder_picker.subprocess.run", run)
    with pytest.raises(FolderPickerError, match="manually"):
        choose_folder()
