"""Reversible cleaning: everything goes through the quarantine first, where it can be restored.

- Folders and files are moved into the quarantine.
- Registry keys are exported to a .reg file before being deleted.
- Registry values are stored in the manifest before being deleted.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import winreg
import zipfile

import rules
from winutil import ROOTS, reg_open

_REG_EXE = os.path.join(rules.WINDIR, "System32", "reg.exe")
_NO_WINDOW = 0x08000000
MANIFEST = "manifest.json"

STATUS_QUARANTINED = "quarantined"
STATUS_RESTORED = "restored"
STATUS_PURGED = "deleted"


def _reg(*args):
    r = subprocess.run([_REG_EXE, *args], capture_output=True, creationflags=_NO_WINDOW)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).decode("oem", "replace").strip()
        raise OSError(msg or f"reg.exe exited with code {r.returncode}")


def _force_remove(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _rmtree(path):
    shutil.rmtree(path, onexc=_force_remove)


def _same_drive(a, b):
    return os.path.splitdrive(a)[0].lower() == os.path.splitdrive(b)[0].lower()


def _move_out(src, dest):
    """Move src to dest without ever leaving half-made copies.

    It is renamed in place first: if any file is in use, Windows refuses and
    nothing is touched."""
    if _same_drive(src, dest):
        os.rename(src, dest)
        return
    staging = f"{src}.{rules.APP_NAME}-tmp"
    os.rename(src, staging)
    try:
        if os.path.isdir(staging):
            shutil.copytree(staging, dest, symlinks=True)
        else:
            shutil.copy2(staging, dest)
    except Exception:
        if os.path.isdir(dest):
            _rmtree(dest)
        os.rename(staging, src)
        raise
    if os.path.isdir(staging):
        _rmtree(staging)
    else:
        os.remove(staging)


def _encode_value(data, kind):
    if isinstance(data, bytes):
        return {"type": kind, "hex": data.hex()}
    return {"type": kind, "data": data}


def _decode_value(blob):
    if "hex" in blob:
        return bytes.fromhex(blob["hex"]), blob["type"]
    return blob["data"], blob["type"]


def validate(item):
    if item.kind in ("folder", "file"):
        if not os.path.lexists(item.path):
            raise ValueError("It no longer exists.")
        rules.check_fs_path(item.path)
    elif item.kind in ("regkey", "regvalue"):
        rules.check_reg_path(item.path, item.kind)
    else:
        raise ValueError(f"Unknown type: {item.kind}")


class Session:
    """One quarantine folder per cleaning run."""

    def __init__(self):
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = os.path.join(rules.QUARANTINE_DIR, stamp)
        n = 1
        while os.path.exists(base):
            n += 1
            base = os.path.join(rules.QUARANTINE_DIR, f"{stamp}-{n}")
        self.dir = base
        self.records = []
        self._created = False

    def _ensure(self):
        if not self._created:
            os.makedirs(os.path.join(self.dir, "files"))
            os.makedirs(os.path.join(self.dir, "registry"))
            self._created = True

    def _save(self):
        _write_manifest(self.dir, self.records)

    def quarantine(self, item):
        self._ensure()
        idx = len(self.records) + 1
        rec = {
            "id": idx, "kind": item.kind, "path": item.path, "value": item.value, "category": item.category,
            "confidence": item.confidence, "reason": item.reason, "size": item.size,
            "date": time.strftime("%Y-%m-%d %H:%M:%S"), "status": STATUS_QUARANTINED,
        }
        if item.kind in ("folder", "file"):
            name = os.path.basename(item.path.rstrip("\\")) or "item"
            dest = os.path.join(self.dir, "files", f"{idx:04d}_{name}")
            _move_out(item.path, dest)
            rec["backup"] = dest
        elif item.kind == "regkey":
            backup = os.path.join(self.dir, "registry", f"{idx:04d}.reg")
            _reg("export", item.path, backup, "/y")
            try:
                _reg("delete", item.path, "/f")
            except Exception:
                os.remove(backup)
                raise
            rec["backup"] = backup
        elif item.kind == "regvalue":
            with reg_open(item.path, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
                data, kind = winreg.QueryValueEx(key, item.value)
                rec["backup_value"] = _encode_value(data, kind)
                self.records.append(rec)
                self._save()  # the backup is saved before deleting
                try:
                    winreg.DeleteValue(key, item.value)
                except Exception:
                    self.records.pop()
                    self._save()
                    raise
            return rec
        self.records.append(rec)
        self._save()
        return rec


def clean(items, progress=lambda m: None):
    """Move the items into the quarantine. Returns (done, [(item, error)])."""
    session = Session()
    done, errors = [], []
    for i, item in enumerate(items, 1):
        progress(f"Moving to quarantine ({i}/{len(items)}): {item.display_path}")
        try:
            validate(item)
            session.quarantine(item)
            done.append(item)
        except PermissionError:
            errors.append((item, "Access denied: it is in use or requires administrator rights."))
        except Exception as e:
            errors.append((item, str(e)))
    progress(f"Cleaning finished: {len(done)} moved to quarantine, {len(errors)} failed.")
    return done, errors


# ---------------------------------------------------------------- ZIP backup

BACKUP_DIR = os.path.join(rules.DOCUMENTS, f"{rules.APP_NAME} Backups")
_KIND_NAME = {"folder": "Folder", "file": "File", "regkey": "Registry key", "regvalue": "Registry value"}
_REG_ROOT_NAME = {"HKCU": "HKEY_CURRENT_USER", "HKLM": "HKEY_LOCAL_MACHINE"}


def backup_name(count):
    """Suggested name, e.g. "LeftoverSweeper Backup 2026-10-21 14.30 (57 items).zip"."""
    stamp = time.strftime("%Y-%m-%d %H.%M")
    return f"{rules.APP_NAME} Backup {stamp} ({count} item{'s' if count != 1 else ''}).zip"


def _safe_name(text):
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", text).strip(" .") or "item"


def _reg_value_file(path, value):
    """Contents of a .reg file that recreates a single registry value."""
    root, _, sub = path.partition("\\")
    with reg_open(path) as key:
        data, kind = winreg.QueryValueEx(key, value)
    name = "@" if value == "" else '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if kind == winreg.REG_SZ:
        body = '"' + str(data).replace("\\", "\\\\").replace('"', '\\"') + '"'
    elif kind == winreg.REG_DWORD:
        body = f"dword:{data & 0xFFFFFFFF:08x}"
    else:
        if kind in (winreg.REG_EXPAND_SZ, winreg.REG_MULTI_SZ):
            text = "\0".join(data) + "\0" if isinstance(data, list) else str(data)
            raw = (text + "\0").encode("utf-16-le")
        elif kind == winreg.REG_QWORD:
            raw = int(data).to_bytes(8, "little")
        else:
            raw = bytes(data or b"")
        body = f"hex({kind:x}):" + ",".join(f"{b:02x}" for b in raw)
    return f"Windows Registry Editor Version 5.00\r\n\r\n[{_REG_ROOT_NAME[root.upper()]}\\{sub}]\r\n{name}={body}\r\n"


def create_backup(items, zip_path, progress=lambda m: None):
    """Save a copy of the items in a ZIP before touching them.

    Returns the list of (path, reason) of whatever could not be copied."""
    os.makedirs(os.path.dirname(zip_path), exist_ok=True)
    skipped = []
    index = []
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf, \
            tempfile.TemporaryDirectory() as tmp:
        for n, item in enumerate(items, 1):
            progress(f"Creating backup ({n}/{len(items)}): {item.display_path}")
            prefix = f"{n:03d}"
            try:
                if item.kind == "folder":
                    arc_root = f"Files/{prefix} {_safe_name(os.path.basename(item.path))}"
                    zf.write(item.path, arc_root)
                    for root, dirs, files in os.walk(item.path):
                        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                        rel = os.path.relpath(root, item.path)
                        for d in dirs:
                            zf.write(os.path.join(root, d), os.path.normpath(os.path.join(arc_root, rel, d)))
                        for f in files:
                            src = os.path.join(root, f)
                            try:
                                zf.write(src, os.path.normpath(os.path.join(arc_root, rel, f)))
                            except OSError as e:
                                skipped.append((src, e.strerror or str(e)))
                    where = arc_root
                elif item.kind == "file":
                    where = f"Files/{prefix} {_safe_name(os.path.basename(item.path))}"
                    zf.write(item.path, where)
                elif item.kind == "regkey":
                    where = f"Registry/{prefix} {_safe_name(item.path.rsplit(chr(92), 1)[-1])}.reg"
                    tmp_reg = os.path.join(tmp, f"{prefix}.reg")
                    _reg("export", item.path, tmp_reg, "/y")
                    zf.write(tmp_reg, where)
                else:
                    where = f"Registry/{prefix} {_safe_name(item.value or 'value')} (value).reg"
                    zf.writestr(where, _reg_value_file(item.path, item.value).encode("utf-16"))
                index.append(f"{prefix}  {_KIND_NAME[item.kind]}\r\n     Original: {item.display_path}\r\n"
                             f"     In this backup: {where}\r\n     Reason: {item.reason}\r\n")
            except Exception as e:
                skipped.append((item.display_path, str(e)))
                index.append(f"{prefix}  {_KIND_NAME[item.kind]} — COULD NOT BE COPIED ({e})\r\n"
                             f"     Original: {item.display_path}\r\n")
        zf.writestr("README - How to restore.txt", (
            f"Backup created by {rules.APP_NAME} on {time.strftime('%Y-%m-%d at %H:%M')}.\r\n\r\n"
            "HOW TO RESTORE\r\n"
            "- Easiest: the app's \"Quarantine\" tab > Restore.\r\n"
            "- By hand, files and folders: copy the contents of \"Files\" back to their original location.\r\n"
            "- By hand, registry: double-click the .reg file in the \"Registry\" folder.\r\n\r\n"
            f"CONTENTS ({len(items)} items)\r\n\r\n" + "\r\n".join(index)).encode("utf-8-sig"))
    progress(f"Backup created: {os.path.basename(zip_path)}")
    return skipped


# ---------------------------------------------------------------- quarantine management

def _write_manifest(session_dir, records):
    tmp = os.path.join(session_dir, MANIFEST + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=1)
    os.replace(tmp, os.path.join(session_dir, MANIFEST))


def _read_manifest(session_dir):
    try:
        with open(os.path.join(session_dir, MANIFEST), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def list_quarantine():
    """List of (session_folder, record) for the items still in quarantine."""
    out = []
    try:
        sessions = sorted(os.listdir(rules.QUARANTINE_DIR), reverse=True)
    except OSError:
        return out
    for name in sessions:
        sdir = os.path.join(rules.QUARANTINE_DIR, name)
        for rec in _read_manifest(sdir):
            if rec.get("status") == STATUS_QUARANTINED:
                out.append((sdir, rec))
    return out


def _restore_one(rec):
    kind = rec["kind"]
    if kind in ("folder", "file"):
        if os.path.lexists(rec["path"]):
            raise FileExistsError("Something already exists at the original location.")
        os.makedirs(os.path.dirname(rec["path"]), exist_ok=True)
        shutil.move(rec["backup"], rec["path"])
    elif kind == "regkey":
        _reg("import", rec["backup"])
        os.remove(rec["backup"])
    elif kind == "regvalue":
        data, vtype = _decode_value(rec["backup_value"])
        root, _, sub = rec["path"].partition("\\")
        with winreg.CreateKeyEx(ROOTS[root.upper()], sub, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.SetValueEx(key, rec["value"], 0, vtype, data)


def _purge_one(rec):
    backup = rec.get("backup")
    if backup and os.path.lexists(backup):
        if os.path.isdir(backup):
            _rmtree(backup)
        else:
            os.remove(backup)


def _apply(entries, action, new_status, progress):
    done, errors = [], []
    by_session = {}
    for sdir, rec in entries:
        by_session.setdefault(sdir, []).append(rec["id"])
    for sdir, ids in by_session.items():
        records = _read_manifest(sdir)
        for rec in records:
            if rec["id"] not in ids or rec.get("status") != STATUS_QUARANTINED:
                continue
            progress(f"{new_status.capitalize()}: {rec['path']}")
            try:
                action(rec)
                rec["status"] = new_status
                done.append(rec)
            except PermissionError:
                errors.append((rec, "Access denied: requires administrator rights or it is in use."))
            except Exception as e:
                errors.append((rec, str(e)))
            _write_manifest(sdir, records)
        if not any(r.get("status") == STATUS_QUARANTINED for r in records):
            try:
                _rmtree(sdir)
            except OSError:
                pass
    return done, errors


def restore(entries, progress=lambda m: None):
    return _apply(entries, _restore_one, STATUS_RESTORED, progress)


def purge(entries, progress=lambda m: None):
    return _apply(entries, _purge_one, STATUS_PURGED, progress)
