"""Windows System Restore points: create one before cleaning, and open System Restore.

Creating a restore point needs administrator rights. When the app is not elevated, only
the PowerShell step is elevated (one UAC prompt). Windows allows one new restore point
every 24 hours by default; in that case the most recent existing point is reported, since
it still predates the cleaning.
"""
import ctypes
import json
import os
import subprocess
import tempfile
from ctypes import wintypes

import rules
from winutil import is_admin

_POWERSHELL = os.path.join(rules.WINDIR, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
_NO_WINDOW = 0x08000000
_TIMEOUT_MS = 10 * 60 * 1000

_SCRIPT = r"""
param([string]$Description, [string]$ResultPath)
$result = @{ created = $false; latest = $null; error = $null }
function Latest {
    Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object SequenceNumber | Select-Object -Last 1
}
function Stamp($p) {
    if ($p) { [Management.ManagementDateTimeConverter]::ToDateTime($p.CreationTime).ToString('yyyy-MM-dd HH:mm') }
}
try {
    $before = Latest
    Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop -WarningAction SilentlyContinue
    $after = Latest
    $result.created = [bool]($after -and (-not $before -or $after.SequenceNumber -gt $before.SequenceNumber))
    $result.latest = Stamp $after
    if ($after) { $result.latest_name = $after.Description }
} catch {
    $result.error = $_.Exception.Message
}
$result | ConvertTo-Json | Set-Content -LiteralPath $ResultPath -Encoding UTF8
"""


class RestorePointResult:
    def __init__(self, data):
        self.created = bool(data.get("created"))
        self.latest = data.get("latest")
        self.latest_name = data.get("latest_name")
        self.error = data.get("error")
        self.cancelled = bool(data.get("cancelled"))

    @property
    def protection_off(self):
        e = (self.error or "").lower()
        return any(s in e for s in ("disabled", "deshabilitad", "service cannot be started", "turned off",
                                    "desactivad", "0x80070422"))

    def describe(self):
        """A plain-language explanation of what happened."""
        if self.created:
            return f"Windows restore point created ({self.latest})."
        if self.cancelled:
            return "The administrator prompt was declined, so no restore point was created."
        if self.protection_off:
            return ("System Protection is turned off on this PC, so Windows can't create restore points. "
                    "You can turn it on in System Properties › System Protection.")
        if self.error:
            return f"Windows could not create a restore point: {self.error}"
        if self.latest:
            return (f"Windows only allows one new restore point every 24 hours. The most recent one is from "
                    f"{self.latest} (\"{self.latest_name}\"); it was made before this cleaning, so it still "
                    "lets you go back.")
        return "Windows did not create a restore point and there is no earlier one to fall back on."

    @property
    def usable(self):
        """True if there is a restore point from before the cleaning."""
        return self.created or (not self.error and bool(self.latest))


def description(count):
    """Name shown in Windows System Restore (kept short; Windows adds the date)."""
    return f"{rules.APP_NAME}: before cleaning {count} item{'s' if count != 1 else ''}"


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
    ]


def _run_elevated(args):
    """Run PowerShell elevated and wait. Returns False if the UAC prompt was declined."""
    info = _SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40  # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = _POWERSHELL
    info.lpParameters = subprocess.list2cmdline(args)
    info.nShow = 0  # SW_HIDE
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_SHELLEXECUTEINFOW)]
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        if ctypes.get_last_error() == 1223:  # ERROR_CANCELLED
            return False
        raise ctypes.WinError(ctypes.get_last_error())
    k32 = ctypes.windll.kernel32
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.WaitForSingleObject(info.hProcess, _TIMEOUT_MS)
    k32.CloseHandle(info.hProcess)
    return True


def create(desc):
    """Create a restore point. Always returns a RestorePointResult (never raises)."""
    with tempfile.TemporaryDirectory(prefix=f"{rules.APP_NAME}-") as tmp:
        script = os.path.join(tmp, "restorepoint.ps1")
        result_path = os.path.join(tmp, "result.json")
        with open(script, "w", encoding="utf-8-sig") as f:
            f.write(_SCRIPT)
        args = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
                "-Description", desc, "-ResultPath", result_path]
        try:
            if is_admin():
                subprocess.run([_POWERSHELL, *args], capture_output=True, creationflags=_NO_WINDOW,
                               timeout=_TIMEOUT_MS / 1000)
            elif not _run_elevated(args):
                return RestorePointResult({"cancelled": True})
            with open(result_path, encoding="utf-8-sig") as f:
                return RestorePointResult(json.load(f))
        except FileNotFoundError:
            return RestorePointResult({"error": "PowerShell did not report a result."})
        except Exception as e:
            return RestorePointResult({"error": str(e)})


def open_system_restore():
    """Open Windows System Restore, where restore points are applied."""
    os.startfile(os.path.join(rules.WINDIR, "System32", "rstrui.exe"))


def open_protection_settings():
    """Open System Properties › System Protection (to turn restore points on)."""
    os.startfile(os.path.join(rules.WINDIR, "System32", "SystemPropertiesProtection.exe"))
