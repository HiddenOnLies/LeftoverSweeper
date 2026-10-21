"""Limpieza reversible: todo pasa primero por la cuarentena, desde donde se puede restaurar.

- Carpetas y archivos se mueven a la cuarentena.
- Las claves del registro se exportan a un .reg antes de borrarlas.
- Los valores del registro se guardan en el manifiesto antes de borrarlos.
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

STATUS_QUARANTINED = "en cuarentena"
STATUS_RESTORED = "restaurado"
STATUS_PURGED = "eliminado"


def _reg(*args):
    r = subprocess.run([_REG_EXE, *args], capture_output=True, creationflags=_NO_WINDOW)
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).decode("oem", "replace").strip()
        raise OSError(msg or f"reg.exe terminó con código {r.returncode}")


def _force_remove(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _rmtree(path):
    shutil.rmtree(path, onexc=_force_remove)


def _same_drive(a, b):
    return os.path.splitdrive(a)[0].lower() == os.path.splitdrive(b)[0].lower()


def _move_out(src, dest):
    """Mueve src a dest sin dejar copias a medias.

    Primero se renombra en su sitio: si algún archivo está en uso, Windows lo
    impide y no se toca nada."""
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
            raise ValueError("Ya no existe.")
        rules.check_fs_path(item.path)
    elif item.kind in ("regkey", "regvalue"):
        rules.check_reg_path(item.path, item.kind)
    else:
        raise ValueError(f"Tipo desconocido: {item.kind}")


class Session:
    """Una carpeta de cuarentena por cada limpieza."""

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
            os.makedirs(os.path.join(self.dir, "archivos"))
            os.makedirs(os.path.join(self.dir, "registro"))
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
            name = os.path.basename(item.path.rstrip("\\")) or "elemento"
            dest = os.path.join(self.dir, "archivos", f"{idx:04d}_{name}")
            _move_out(item.path, dest)
            rec["backup"] = dest
        elif item.kind == "regkey":
            backup = os.path.join(self.dir, "registro", f"{idx:04d}.reg")
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
                self._save()  # la copia queda guardada antes de borrar
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
    """Mueve los elementos a la cuarentena. Devuelve (hechos, [(elemento, error)])."""
    session = Session()
    done, errors = [], []
    for i, item in enumerate(items, 1):
        progress(f"Moviendo a cuarentena ({i}/{len(items)}): {item.display_path}")
        try:
            validate(item)
            session.quarantine(item)
            done.append(item)
        except PermissionError:
            errors.append((item, "Acceso denegado: está en uso o requiere permisos de administrador."))
        except Exception as e:
            errors.append((item, str(e)))
    progress(f"Limpieza terminada: {len(done)} movidos a cuarentena, {len(errors)} con error.")
    return done, errors


# ---------------------------------------------------------------- copia de seguridad en ZIP

BACKUP_DIR = os.path.join(rules.DOCUMENTS, f"{rules.APP_NAME} - Copias de seguridad")
_KIND_NAME = {"folder": "Carpeta", "file": "Archivo", "regkey": "Clave del registro", "regvalue": "Valor del registro"}
_REG_ROOT_NAME = {"HKCU": "HKEY_CURRENT_USER", "HKLM": "HKEY_LOCAL_MACHINE"}


def backup_name(count):
    """Nombre sugerido, p. ej. «Copia de seguridad LimpiaResiduos 21-10-2026 14.30 (57 elementos).zip»."""
    stamp = time.strftime("%d-%m-%Y %H.%M")
    return f"Copia de seguridad {rules.APP_NAME} {stamp} ({count} elemento{'s' if count != 1 else ''}).zip"


def _safe_name(text):
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", text).strip(" .") or "elemento"


def _reg_value_file(path, value):
    """Contenido de un .reg que vuelve a crear un único valor del registro."""
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
    """Guarda una copia de los elementos en un ZIP antes de tocarlos.

    Devuelve la lista de (ruta, motivo) de lo que no se pudo copiar."""
    os.makedirs(os.path.dirname(zip_path), exist_ok=True)
    skipped = []
    index = []
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf, \
            tempfile.TemporaryDirectory() as tmp:
        for n, item in enumerate(items, 1):
            progress(f"Creando copia de seguridad ({n}/{len(items)}): {item.display_path}")
            prefix = f"{n:03d}"
            try:
                if item.kind == "folder":
                    arc_root = f"Archivos/{prefix} {_safe_name(os.path.basename(item.path))}"
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
                    where = f"Archivos/{prefix} {_safe_name(os.path.basename(item.path))}"
                    zf.write(item.path, where)
                elif item.kind == "regkey":
                    where = f"Registro/{prefix} {_safe_name(item.path.rsplit(chr(92), 1)[-1])}.reg"
                    tmp_reg = os.path.join(tmp, f"{prefix}.reg")
                    _reg("export", item.path, tmp_reg, "/y")
                    zf.write(tmp_reg, where)
                else:
                    where = f"Registro/{prefix} {_safe_name(item.value or 'valor')} (valor).reg"
                    zf.writestr(where, _reg_value_file(item.path, item.value).encode("utf-16"))
                index.append(f"{prefix}  {_KIND_NAME[item.kind]}\r\n     Original: {item.display_path}\r\n"
                             f"     En la copia: {where}\r\n     Motivo: {item.reason}\r\n")
            except Exception as e:
                skipped.append((item.display_path, str(e)))
                index.append(f"{prefix}  {_KIND_NAME[item.kind]} — NO SE PUDO COPIAR ({e})\r\n"
                             f"     Original: {item.display_path}\r\n")
        zf.writestr("LÉEME - Cómo restaurar.txt", (
            f"Copia de seguridad creada por {rules.APP_NAME} el {time.strftime('%d/%m/%Y a las %H:%M')}.\r\n\r\n"
            "CÓMO RESTAURAR\r\n"
            "- Lo más fácil: pestaña «Cuarentena» de la aplicación › Restaurar.\r\n"
            "- A mano, archivos y carpetas: copia el contenido de «Archivos» a su ubicación original.\r\n"
            "- A mano, registro: haz doble clic en el .reg de la carpeta «Registro».\r\n\r\n"
            f"CONTENIDO ({len(items)} elementos)\r\n\r\n" + "\r\n".join(index)).encode("utf-8-sig"))
    progress(f"Copia de seguridad creada: {os.path.basename(zip_path)}")
    return skipped


# ---------------------------------------------------------------- gestión de la cuarentena

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
    """Lista de (carpeta_sesión, registro) de los elementos aún en cuarentena."""
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
            raise FileExistsError("Ya existe algo en la ubicación original.")
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
                errors.append((rec, "Acceso denegado: requiere permisos de administrador o está en uso."))
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
