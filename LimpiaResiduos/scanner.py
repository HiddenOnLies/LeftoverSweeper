"""Motor de escaneo: detecta restos de programas desinstalados. Solo lee, nunca modifica."""
import bisect
import os
import re
import time
from dataclasses import dataclass

import lnk
import rules
from rules import norm
from winutil import (drive_exists, exe_from_command, folder_stats, is_missing, list_dirs, npath, reg_is_empty,
                     reg_subkeys, reg_values, running_exe_paths)

_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

RECENT_DAYS = 30

# Carpetas en las que la búsqueda por nombre no entra (apps de la Tienda, temporales…).
_NO_DESCEND = {norm(n) for n in ["Packages", "WindowsApps", "Temp", "Package Cache", "WinSxS", "Installer"]}

_STOPWORDS = {norm(w) for w in [
    "update", "updates", "setup", "version", "runtime", "driver", "drivers", "tools", "toolkit", "service",
    "services", "player", "media", "studio", "client", "server", "manager", "office", "windows", "microsoft",
    "system", "software", "edition", "professional", "english", "spanish", "language", "package",
    "redistributable", "library", "components", "support", "helper", "plugin", "framework", "desktop",
    "launcher", "installer", "uninstaller", "center", "utility", "utilities", "control", "assistant",
    "extension", "extensions", "viewer", "reader", "editor", "audio", "video", "graphics", "network",
    "device", "devices", "security", "corporation", "technologies", "limited", "inc", "free", "online",
]}
_CORP_SUFFIX = re.compile(r"\b(inc|corp|corporation|llc|ltd|limited|gmbh|co|sa|srl|ag|bv|technologies|"
                          r"software|systems|international|company)\b\.?", re.I)


@dataclass
class Item:
    kind: str          # folder | file | regkey | regvalue
    path: str
    confidence: str    # alta | media | baja
    category: str
    reason: str
    value: str = None  # nombre del valor (solo regvalue)
    size: int = 0
    size_truncated: bool = False

    @property
    def key(self):
        return f"{self.kind}|{self.path.lower()}|{(self.value or '').lower()}"

    @property
    def display_path(self):
        return f"{self.path}  →  {self.value}" if self.kind == "regvalue" else self.path


# ---------------------------------------------------------------- inventario de lo instalado

@dataclass
class UninstallEntry:
    key: str
    name: str
    publisher: str
    location: str
    uninstall_exe: str
    icon_exe: str
    msi: bool
    broken: bool


def read_uninstall_entries():
    entries = []
    for base in rules.UNINSTALL_KEYS:
        for sub in reg_subkeys(base):
            path = f"{base}\\{sub}"
            vals = {k: v[0] for k, v in reg_values(path).items()}
            name = str(vals.get("DisplayName") or "").strip()
            uninstall = str(vals.get("UninstallString") or vals.get("QuietUninstallString") or "")
            location = os.path.expandvars(str(vals.get("InstallLocation") or "").strip().strip('"'))
            msi = vals.get("WindowsInstaller") == 1 or "msiexec" in uninstall.lower()
            uexe = None if msi else exe_from_command(uninstall)
            broken = bool(name and uexe and is_missing(uexe)
                          and (not location or is_missing(location)))
            entries.append(UninstallEntry(
                key=path, name=name, publisher=str(vals.get("Publisher") or "").strip(),
                location=location, uninstall_exe=uexe or "",
                icon_exe=exe_from_command(str(vals.get("DisplayIcon") or "")) or "",
                msi=msi, broken=broken))
    return entries


class Known:
    """Lo que está instalado o en uso: nombres de productos, fabricantes y rutas."""

    def __init__(self):
        self.products = set()
        self.publishers = set()
        self.words = set()
        self._paths = set()
        self.installed_names = []

    def add_product(self, text):
        n = norm(text)
        if len(n) >= 3:
            self.products.add(n)
        for w in re.split(r"[^a-z0-9]+", (text or "").lower()):
            if len(w) >= 5 and w not in _STOPWORDS and not w.isdigit():
                self.words.add(w)

    def add_publisher(self, text):
        for n in (norm(text), norm(_CORP_SUFFIX.sub("", text or ""))):
            if len(n) >= 3:
                self.publishers.add(n)

    def add_path(self, path, is_file=False):
        if not path or not os.path.isabs(path):
            return
        p = os.path.dirname(path) if is_file else path
        if len(p) > 3:
            self._paths.add(npath(p))

    def freeze(self):
        self.paths = sorted(self._paths)
        self._product_blob = "|".join(sorted(self.products))
        self._publisher_blob = "|".join(sorted(self.publishers))

    def path_inside(self, path):
        """True si alguna ruta en uso está dentro de `path` (o es ella)."""
        p = npath(path)
        i = bisect.bisect_left(self.paths, p)
        while i < len(self.paths) and self.paths[i].startswith(p):
            k = self.paths[i]
            if len(k) == len(p) or k[len(p)] == "\\":
                return True
            i += 1
        return False

    def match_name(self, name):
        """'product', 'publisher' o None."""
        f = norm(name)
        if len(f) < 3:
            return "product"  # nombres demasiado cortos: no se arriesga
        if f in self._product_blob or any(len(k) >= 4 and k in f for k in self.products):
            return "product"
        if any(w in f for w in self.words):
            return "product"
        if f in self._publisher_blob or any(len(k) >= 4 and k in f for k in self.publishers):
            return "publisher"
        return None

    def folder_status(self, name, path, child=False):
        """'owned' (en uso), 'container' (carpeta de fabricante) u 'orphan'."""
        if self.match_name(name) == "product" or self.path_inside(path):
            return "owned"
        if not child and self.match_name(name) == "publisher":
            return "container"
        return "orphan"


def _shortcuts(dirs, recursive=True):
    for d in dirs:
        if recursive:
            for root, subdirs, files in os.walk(d):
                for f in files:
                    yield os.path.join(root, f)
        else:
            try:
                for f in os.listdir(d):
                    yield os.path.join(d, f)
            except OSError:
                pass


def build_known(progress=lambda m: None):
    progress("Leyendo programas instalados…")
    known = Known()
    entries = read_uninstall_entries()
    for e in entries:
        if e.broken:
            continue
        if e.name:
            known.add_product(e.name)
            known.installed_names.append(e.name)
        if e.publisher:
            known.add_publisher(e.publisher)
        if e.location and os.path.isdir(e.location):
            known.add_path(e.location)
            known.add_product(os.path.basename(e.location.rstrip("\\")))
        for exe in (e.uninstall_exe, e.icon_exe):
            if exe and os.path.exists(exe):
                known.add_path(exe, is_file=True)

    progress("Leyendo aplicaciones de la Microsoft Store…")
    for pkg in reg_subkeys(rules.APPX_PACKAGES_KEY):
        name = pkg.split("_")[0]
        known.add_product(name)
        last = name.split(".")[-1]
        if not name.lower().startswith("microsoft.") and not _GUID_RE.match(last):
            known.add_product(last)
        display = reg_values(f"{rules.APPX_PACKAGES_KEY}\\{pkg}").get("DisplayName")
        if display and isinstance(display[0], str) and not display[0].startswith(("@", "ms-resource")):
            known.add_product(display[0])
            known.installed_names.append(display[0])

    progress("Revisando servicios y procesos en ejecución…")
    services = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
    for svc in reg_subkeys(services):
        image = reg_values(f"{services}\\{svc}").get("ImagePath")
        exe = exe_from_command(str(image[0])) if image else None
        if exe and os.path.exists(exe):
            known.add_path(exe, is_file=True)
    for exe in running_exe_paths():
        known.add_path(exe, is_file=True)
    for d in os.environ.get("PATH", "").split(";"):
        d = os.path.expandvars(d.strip().strip('"'))
        if d and os.path.isdir(d):
            known.add_path(d)

    progress("Revisando programas de inicio y accesos directos…")
    for key in rules.RUN_KEYS:
        for data, _kind in reg_values(key).values():
            exe = exe_from_command(str(data))
            if exe and os.path.exists(exe):
                known.add_path(exe, is_file=True)
    for path in _shortcuts(rules.SHORTCUT_DIRS):
        if path.lower().endswith(".lnk"):
            t = lnk.target(path)
            if t and os.path.exists(t):
                known.add_path(t, is_file=os.path.isfile(t))
    for path in _shortcuts(rules.DESKTOP_DIRS, recursive=False):
        if path.lower().endswith(".lnk"):
            t = lnk.target(path)
            if t and os.path.exists(t):
                known.add_path(t, is_file=os.path.isfile(t))

    known.freeze()
    return known, entries


# ---------------------------------------------------------------- creación de elementos

def _date(ts):
    return time.strftime("%d/%m/%Y", time.localtime(ts)) if ts else "?"


def _folder_item(path, base_conf, category, reason):
    size, files, newest, truncated, errors = folder_stats(path)
    conf = base_conf
    if files == 0 and not errors:
        conf, reason = "alta", "Carpeta vacía. " + reason
    else:
        reason += f" Último cambio: {_date(newest)}."
        if errors:
            reason += " Algunos archivos no se pudieron leer."
        if newest and time.time() - newest < RECENT_DAYS * 86400:
            conf = "baja"
            reason += " Modificada recientemente: podría estar en uso."
    return Item("folder", path, conf, category, reason, size=size, size_truncated=truncated)


def _reg_item(path, category, reason, conf="baja"):
    if reg_is_empty(path):
        conf, reason = "alta", "Clave vacía. " + reason
    return Item("regkey", path, conf, category, reason)


_PLAIN_PATH_RE = re.compile(r'^[a-zA-Z]:\\[^"<>|*?\r\n]*$')


def _reg_paths(path, max_keys=60):
    """Rutas de archivo/carpeta que aparecen en los valores de una clave y sus subclaves."""
    out, stack, visited = [], [path], 0
    while stack and visited < max_keys:
        key = stack.pop()
        visited += 1
        for data, _kind in reg_values(key).values():
            if not isinstance(data, str) or len(data) < 4:
                continue
            p = exe_from_command(data)
            if not p:
                plain = data.strip().strip('"')
                if _PLAIN_PATH_RE.match(plain):
                    p = os.path.normpath(plain)
            if p and len(p) > 3 and not npath(p).startswith(npath(rules.WINDIR)) \
                    and npath(p) not in rules.PROTECTED_DIRS:
                out.append(p)
        stack.extend(f"{key}\\{s}" for s in reg_subkeys(key))
    return out


def _reg_candidate(path, category, reason):
    """Clave candidata, o None si sus valores apuntan a archivos que siguen existiendo."""
    paths = [p for p in _reg_paths(path) if drive_exists(p)]
    if any(os.path.exists(p) for p in paths):
        return None
    if paths:
        return _reg_item(path, category, reason + f" Apunta a ubicaciones que ya no existen (p. ej. {paths[0]}).",
                         conf="media")
    return _reg_item(path, category, reason)


# ---------------------------------------------------------------- escaneo completo

def scan(progress=lambda m: None):
    known, entries = build_known(progress)
    items = []

    progress("Buscando entradas de desinstalación rotas…")
    for e in entries:
        if e.broken:
            items.append(Item("regkey", e.key, "alta", "Entrada de desinstalación rota",
                              f"«{e.name}» aparece como instalado pero su desinstalador ya no existe "
                              f"({e.uninstall_exe})."))

    for base in rules.APP_PATHS_KEYS:
        for sub in reg_subkeys(base):
            path = f"{base}\\{sub}"
            default = reg_values(path).get("")
            exe = exe_from_command(str(default[0])) if default else None
            if exe and is_missing(exe):
                items.append(Item("regkey", path, "alta", "Ruta de aplicación rota",
                                  f"Registra «{sub}» apuntando a un archivo que ya no existe ({exe})."))

    progress("Buscando programas de inicio rotos…")
    for key in rules.RUN_KEYS:
        for name, (data, _kind) in reg_values(key).items():
            exe = exe_from_command(str(data))
            if exe and is_missing(exe):
                items.append(Item("regvalue", key, "alta", "Inicio automático roto",
                                  f"Intenta ejecutar al iniciar Windows un archivo que ya no existe ({exe}).",
                                  value=name))

    progress("Buscando accesos directos rotos…")
    for path in list(_shortcuts(rules.SHORTCUT_DIRS)) + list(_shortcuts(rules.DESKTOP_DIRS, recursive=False)):
        if path.lower().endswith(".lnk"):
            t = lnk.target(path)
            if t and is_missing(t):
                items.append(Item("file", path, "alta", "Acceso directo roto",
                                  f"Apunta a un archivo que ya no existe ({t}).",
                                  size=_file_size(path)))
    for d in rules.SHORTCUT_DIRS:
        for root, subdirs, files in os.walk(d, topdown=False):
            if npath(root) == npath(d) or norm(os.path.basename(root)) in rules.SAFE_FOLDER_NAMES:
                continue
            try:
                if not os.listdir(root):
                    items.append(Item("folder", root, "alta", "Carpeta vacía del menú Inicio",
                                      "Carpeta del menú Inicio sin ningún acceso directo."))
            except OSError:
                pass

    for root, label, base_conf in rules.FOLDER_ROOTS:
        progress(f"Analizando carpetas: {label}…")
        for entry in list_dirs(root):
            if rules.is_safe_folder(entry.name):
                continue
            status = known.folder_status(entry.name, entry.path)
            if status == "owned":
                continue
            if status == "container":
                for child in list_dirs(entry.path):
                    if rules.is_safe_folder(child.name):
                        continue
                    if known.folder_status(child.name, child.path, child=True) == "orphan":
                        items.append(_folder_item(
                            child.path, "baja", f"Carpeta huérfana · {label}",
                            f"El fabricante «{entry.name}» tiene otros programas instalados, "
                            f"pero ninguno usa esta carpeta."))
                continue
            items.append(_folder_item(entry.path, base_conf, f"Carpeta huérfana · {label}",
                                      "Ningún programa instalado ni en ejecución coincide con esta carpeta."))

    for base, label in rules.REG_ROOTS:
        progress(f"Analizando {label}…")
        for sub in reg_subkeys(base):
            if rules.is_safe_reg(sub):
                continue
            path = f"{base}\\{sub}"
            match = known.match_name(sub)
            if match == "product":
                continue
            if match == "publisher":
                for child in reg_subkeys(path):
                    if known.match_name(child) != "product":
                        items.append(_reg_candidate(f"{path}\\{child}", f"Clave huérfana · {label}",
                                                    f"El fabricante «{sub}» tiene otros programas instalados, "
                                                    f"pero ninguno coincide con esta clave."))
                continue
            items.append(_reg_candidate(path, f"Clave huérfana · {label}",
                                        "Ningún programa instalado coincide con esta clave."))

    progress("Escaneo terminado.")
    return _dedupe([i for i in items if i is not None])


def _file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _dedupe(items):
    seen, out = set(), []
    for it in items:
        if it.key not in seen:
            seen.add(it.key)
            out.append(it)
    return out


# ---------------------------------------------------------------- búsqueda por nombre

def search(term, progress=lambda m: None):
    """Busca restos de un programa concreto por su nombre.

    Devuelve (elementos, nombres_instalados_que_coinciden)."""
    t = norm(term)
    if len(t) < 3:
        raise ValueError("Escribe al menos 3 letras o números.")
    if t in rules.BLOCKED_TERMS:
        raise ValueError(f"«{term}» es demasiado genérico; podría coincidir con componentes de Windows.")

    known, entries = build_known(progress)
    still_installed = sorted({e.name for e in entries if not e.broken and e.name and t in norm(e.name)})
    items = []

    def conf_for(path=None):
        if path and known.path_inside(path):
            return "baja", "Lo usa un programa instalado o en ejecución."
        if still_installed:
            return "baja", "Hay un programa instalado con un nombre parecido."
        return "media", f"Su nombre coincide con «{term}»."

    progress("Buscando en entradas de desinstalación…")
    for e in entries:
        if e.name and t in norm(e.name) and e.broken:
            items.append(Item("regkey", e.key, "alta", "Entrada de desinstalación rota",
                              f"«{e.name}»: su desinstalador ya no existe."))

    search_roots = [(r, label, 3) for r, label, _ in rules.FOLDER_ROOTS]
    search_roots += [(rules.DOCUMENTS, "Documentos", 2), (rules.USER_PROFILE, "Perfil de usuario", 1)]
    for root, label, depth in search_roots:
        if not root or not os.path.isdir(root):
            continue
        progress(f"Buscando carpetas en {label}…")
        stack = [(root, 1)]
        while stack:
            folder, level = stack.pop()
            for entry in list_dirs(folder):
                n = norm(entry.name)
                if t in n and n not in rules.SAFE_FOLDER_NAMES and not _is_protected(entry.path):
                    conf, reason = conf_for(entry.path)
                    if npath(root) == npath(rules.DOCUMENTS):
                        conf, reason = "baja", reason + " Está en Documentos: revisa que no sean archivos tuyos."
                    items.append(_folder_item(entry.path, conf, f"Coincidencia · {label}", reason))
                elif level < depth and n not in _NO_DESCEND:
                    stack.append((entry.path, level + 1))

    progress("Buscando en el registro…")
    for base, label in rules.REG_ROOTS:
        stack = [(base, 1)]
        while stack:
            key, level = stack.pop()
            for sub in reg_subkeys(key):
                if level == 1 and norm(sub) in rules.CRITICAL_REG_NAMES:
                    continue
                path = f"{key}\\{sub}"
                if t in norm(sub):
                    conf, reason = conf_for()
                    items.append(_reg_item(path, f"Coincidencia · {label}", reason, conf))
                elif level < 3:
                    stack.append((path, level + 1))
    for base in rules.APP_PATHS_KEYS:
        for sub in reg_subkeys(base):
            if t in norm(sub):
                conf, reason = conf_for()
                items.append(Item("regkey", f"{base}\\{sub}", conf, "Ruta de aplicación", reason))
    for key in rules.RUN_KEYS:
        for name, (data, _kind) in reg_values(key).items():
            if t in norm(name) or t in norm(str(data)):
                exe = exe_from_command(str(data))
                conf, reason = ("alta", "Su archivo ya no existe.") if exe and is_missing(exe) else conf_for()
                items.append(Item("regvalue", key, conf, "Inicio automático", reason, value=name))

    progress("Buscando accesos directos…")
    for d in rules.SHORTCUT_DIRS + rules.DESKTOP_DIRS:
        recursive = d in rules.SHORTCUT_DIRS
        for root, subdirs, files in (os.walk(d) if recursive else [(d, [], _safe_listdir(d))]):
            for name in subdirs:
                if t in norm(name) and npath(os.path.join(root, name)) not in rules.PROTECTED_DIRS:
                    items.append(_folder_item(os.path.join(root, name), "media", "Carpeta del menú Inicio",
                                              f"Su nombre coincide con «{term}»."))
            for name in files:
                p = os.path.join(root, name)
                if t in norm(os.path.splitext(name)[0]) and name.lower().endswith((".lnk", ".url")):
                    tg = lnk.target(p) if name.lower().endswith(".lnk") else None
                    if tg and is_missing(tg):
                        conf, reason = "alta", f"Acceso directo roto ({tg})."
                    else:
                        conf, reason = conf_for()
                    items.append(Item("file", p, conf, "Acceso directo", reason, size=_file_size(p)))

    progress("Búsqueda terminada.")
    return _drop_nested(_dedupe(items)), still_installed


def _safe_listdir(d):
    try:
        return [f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f))]
    except OSError:
        return []


def _is_protected(path):
    try:
        rules.check_fs_path(path)
        return False
    except ValueError:
        return True


def _drop_nested(items):
    """Quita carpetas que ya están incluidas dentro de otra carpeta de la lista."""
    folders = sorted(npath(i.path) for i in items if i.kind == "folder")
    out = []
    for it in items:
        if it.kind == "folder":
            p = npath(it.path)
            if any(p.startswith(f + "\\") for f in folders):
                continue
        out.append(it)
    return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        found, installed = search(" ".join(sys.argv[1:]), progress=lambda m: print("·", m))
        if installed:
            print("Sigue instalado:", ", ".join(installed))
    else:
        found = scan(progress=lambda m: print("·", m))
    order = {"alta": 0, "media": 1, "baja": 2}
    for it in sorted(found, key=lambda i: (order[i.confidence], i.category, i.path.lower())):
        print(f"[{it.confidence:5}] {it.category:45} {it.display_path}  ({it.size // 1024} KB)\n        {it.reason}")
    print(f"\n{len(found)} elementos encontrados.")
