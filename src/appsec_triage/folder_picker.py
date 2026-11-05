"""Desktop folder selection in a child process, keeping GUI work off HTTP threads."""
import base64
import os
import shutil
import subprocess
import sys
from pathlib import Path


class FolderPickerError(RuntimeError):
    pass


def choose_folder() -> str | None:
    cancel_codes = set()
    if sys.platform == "win32":
        script = """
Add-Type -AssemblyName System.Windows.Forms
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$picker = New-Object System.Windows.Forms.FolderBrowserDialog
$picker.Description = 'Select a repository folder'
$picker.ShowNewFolderButton = $false
try {
    if ($picker.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        [Console]::Write($picker.SelectedPath)
    }
} finally { $picker.Dispose() }
"""
        executable = str(Path(os.environ.get("SystemRoot", "C:/Windows")) /
                         "System32/WindowsPowerShell/v1.0/powershell.exe")
        command = [executable, "-NoProfile", "-STA", "-EncodedCommand",
                   base64.b64encode(script.encode("utf-16-le")).decode("ascii")]
    elif sys.platform == "darwin":
        command = ["/usr/bin/osascript", "-e", '''
try
    tell application "System Events"
        activate
        set chosenFolder to choose folder with prompt "Select a repository folder"
    end tell
    return POSIX path of chosenFolder
on error number -128
    return ""
end try
''']
    elif shutil.which("zenity"):
        command = [shutil.which("zenity"), "--file-selection", "--directory",
                   "--title=Select a repository folder"]
        cancel_codes = {1}
    elif shutil.which("kdialog"):
        command = [shutil.which("kdialog"), "--getexistingdirectory", str(Path.home()),
                   "--title", "Select a repository folder"]
        cancel_codes = {1}
    else:
        # Tk is available in many Python distributions; Linux may need python3-tk.
        command = [sys.executable, "-c", """
import sys
import tkinter as tk
from tkinter.filedialog import askdirectory
root = tk.Tk()
root.withdraw()
try:
    path = askdirectory(title='Select a repository folder', mustexist=True, parent=root)
    sys.stdout.buffer.write(path.encode('utf-8'))
finally:
    root.destroy()
"""]
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=120, check=False, shell=False)
    except subprocess.TimeoutExpired:
        raise FolderPickerError("Folder selection timed out. Try Browse again or enter the path manually.") from None
    except OSError:
        raise FolderPickerError("The desktop folder picker is unavailable. Enter the path manually.") from None
    if result.returncode in cancel_codes:
        return None
    if result.returncode != 0:
        raise FolderPickerError("Could not open the desktop folder picker. On Linux, install Zenity, KDialog, or Python Tk support, or enter the path manually.")
    path = result.stdout.decode("utf-8").rstrip("\r\n")
    if not path:
        return None
    if not Path(path).is_dir():
        raise FolderPickerError("The selected folder is no longer available. Choose another folder.")
    return path
