"""Windows helpers: registry, known folders, processes and paths."""
import ctypes
import os
import re
import uuid
import winreg
from ctypes import wintypes

ROOTS = {
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
}

# Always use the 64-bit registry view; the 32-bit view is walked
# explicitly through SOFTWARE\WOW6432Node.
_VIEW = winreg.KEY_WOW64_64KEY


# ---------------------------------------------------------------- registry

def reg_open(path, access=winreg.KEY_READ):
    root, _, sub = path.partition("\\")
    return winreg.OpenKey(ROOTS[root.upper()], sub, 0, access | _VIEW)


def reg_exists(path):
    try:
        with reg_open(path):
            return True
    except OSError:
        return False


def reg_subkeys(path):
    out = []
    try:
        with reg_open(path) as key:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def reg_values(path):
    """Return {name: (data, type)} for a key."""
    out = {}
    try:
        with reg_open(path) as key:
            i = 0
            while True:
                try:
                    name, data, kind = winreg.EnumValue(key, i)
                except OSError:
                    break
                out[name] = (data, kind)
                i += 1
    except OSError:
        pass
    return out


def reg_is_empty(path):
    try:
        with reg_open(path) as key:
            subkeys, values, _ = winreg.QueryInfoKey(key)
            return subkeys == 0 and values == 0
    except OSError:
        return False


# ---------------------------------------------------------------- system

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def known_folder(guid, fallback):
    """Path of a known folder (honours redirections such as OneDrive)."""
    try:
        u = uuid.UUID(guid)
        g = _GUID(u.fields[0], u.fields[1], u.fields[2], (ctypes.c_ubyte * 8)(*u.bytes[8:]))
        ptr = ctypes.c_wchar_p()
        shell32 = ctypes.windll.shell32
        shell32.SHGetKnownFolderPath.argtypes = [
            ctypes.POINTER(_GUID), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)]
        if shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(ptr)) == 0:
            value = ptr.value
            ctypes.windll.ole32.CoTaskMemFree(ptr)
            if value:
                return value
    except Exception:
        pass
    return fallback


def running_exe_paths():
    """Executable paths of the running processes."""
    out = []
    try:
        psapi = ctypes.WinDLL("psapi")
        k32 = ctypes.WinDLL("kernel32")
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        pids = (wintypes.DWORD * 8192)()
        needed = wintypes.DWORD()
        if not psapi.EnumProcesses(pids, ctypes.sizeof(pids), ctypes.byref(needed)):
            return out
        for pid in pids[: needed.value // ctypes.sizeof(wintypes.DWORD)]:
            if not pid:
                continue
            handle = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if not handle:
                continue
            try:
                buf = ctypes.create_unicode_buffer(1024)
                size = wintypes.DWORD(1024)
                if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                    out.append(buf.value)
            finally:
                k32.CloseHandle(handle)
    except Exception:
        pass
    return out


# ---------------------------------------------------------------- paths

_EXE_RE = re.compile(r"(.+?\.(?:exe|com|bat|cmd|dll|sys|msc|vbs|ps1|cpl|scr))(?=\s|,|$)", re.I)
_ABS_RE = re.compile(r"^[a-zA-Z]:\\")


def exe_from_command(cmd):
    """Extract the absolute executable path from a command line.

    Returns None when it cannot be determined reliably, so an entry we merely
    failed to parse is never reported as "broken".
    """
    if not isinstance(cmd, str):
        return None
    cmd = os.path.expandvars(cmd.strip())
    if cmd.startswith("\\??\\"):
        cmd = cmd[4:]
    if cmd.lower().startswith("\\systemroot\\"):
        cmd = os.environ.get("SystemRoot", r"C:\Windows") + cmd[11:]
    if not cmd:
        return None
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        path = cmd[1:end] if end > 0 else cmd[1:]
    else:
        m = _EXE_RE.match(cmd)
        if not m:
            return None
        path = m.group(1)
    path = path.strip()
    if not _ABS_RE.match(path):
        return None
    return os.path.normpath(path)


def drive_exists(path):
    return bool(path) and len(path) >= 3 and os.path.exists(path[:3])


def is_missing(path):
    """True only if the drive exists and the file does not (avoids false
    positives with disconnected removable or network drives)."""
    return bool(path) and drive_exists(path) and not os.path.exists(path)


def npath(path):
    return os.path.normcase(os.path.normpath(path))


def is_link_or_junction(entry):
    try:
        if entry.is_symlink():
            return True
        if hasattr(entry, "is_junction") and entry.is_junction():
            return True
    except OSError:
        return True
    return False


def list_dirs(path):
    """Real subfolders of a folder (no symlinks or junctions)."""
    out = []
    try:
        with os.scandir(path) as it:
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False) and not is_link_or_junction(e):
                        out.append(e)
                except OSError:
                    pass
    except OSError:
        pass
    return out


def folder_stats(path, max_entries=150_000):
    """(size, file count, newest mtime, truncated, had_errors)."""
    size = files = count = 0
    newest = 0.0
    truncated = errors = False
    stack = [path]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    count += 1
                    if count > max_entries:
                        truncated = True
                        stack.clear()
                        break
                    try:
                        if is_link_or_junction(e):
                            files += 1  # counts as content: never "empty"
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            st = e.stat(follow_symlinks=False)
                            size += st.st_size
                            files += 1
                            newest = max(newest, st.st_mtime)
                    except OSError:
                        errors = True
        except OSError:
            errors = True
    return size, files, newest, truncated, errors
