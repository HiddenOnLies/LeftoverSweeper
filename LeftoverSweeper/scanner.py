"""Scan engine: finds leftovers of uninstalled programs. Read-only, never modifies anything."""
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

# Folders the search by name does not descend into (Store apps, temp files…).
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
    confidence: str    # high | medium | low
    category: str
    reason: str
    value: str = None  # value name (regvalue only)
    size: int = 0
    size_truncated: bool = False

    @property
    def key(self):
        return f"{self.kind}|{self.path.lower()}|{(self.value or '').lower()}"

    @property
    def display_path(self):
        return f"{self.path}  →  {self.value}" if self.kind == "regvalue" else self.path


# ---------------------------------------------------------------- inventory of what is installed

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
    """What is installed or in use: product names, publishers and paths."""

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
        """True if any in-use path is inside `path` (or is `path` itself)."""
        p = npath(path)
        i = bisect.bisect_left(self.paths, p)
        while i < len(self.paths) and self.paths[i].startswith(p):
            k = self.paths[i]
            if len(k) == len(p) or k[len(p)] == "\\":
                return True
            i += 1
        return False

    def match_name(self, name):
        """'product', 'publisher' or None."""
        f = norm(name)
        if len(f) < 3:
            return "product"  # names too short to judge: don't take the risk
        if f in self._product_blob or any(len(k) >= 4 and k in f for k in self.products):
            return "product"
        if any(w in f for w in self.words):
            return "product"
        if f in self._publisher_blob or any(len(k) >= 4 and k in f for k in self.publishers):
            return "publisher"
        return None

    def folder_status(self, name, path, child=False):
        """'owned' (in use), 'container' (publisher folder) or 'orphan'."""
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
    progress("Reading installed programs…")
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

    progress("Reading Microsoft Store apps…")
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

    progress("Checking services and running processes…")
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

    progress("Checking startup programs and shortcuts…")
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


# ---------------------------------------------------------------- building items

def _date(ts):
    return time.strftime("%Y-%m-%d", time.localtime(ts)) if ts else "?"


def _folder_item(path, base_conf, category, reason):
    size, files, newest, truncated, errors = folder_stats(path)
    conf = base_conf
    if files == 0 and not errors:
        conf, reason = "high", "Empty folder. " + reason
    else:
        reason += f" Last modified: {_date(newest)}."
        if errors:
            reason += " Some files could not be read."
        if newest and time.time() - newest < RECENT_DAYS * 86400:
            conf = "low"
            reason += " Recently modified: it may still be in use."
    return Item("folder", path, conf, category, reason, size=size, size_truncated=truncated)


def _reg_item(path, category, reason, conf="low"):
    if reg_is_empty(path):
        conf, reason = "high", "Empty key. " + reason
    return Item("regkey", path, conf, category, reason)


_PLAIN_PATH_RE = re.compile(r'^[a-zA-Z]:\\[^"<>|*?\r\n]*$')


def _reg_paths(path, max_keys=60):
    """File/folder paths found in the values of a key and its subkeys."""
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
    """Candidate key, or None if its values point to files that still exist."""
    paths = [p for p in _reg_paths(path) if drive_exists(p)]
    if any(os.path.exists(p) for p in paths):
        return None
    if paths:
        return _reg_item(path, category, reason + f" It points to locations that no longer exist (e.g. {paths[0]}).",
                         conf="medium")
    return _reg_item(path, category, reason)


# ---------------------------------------------------------------- full scan

def scan(progress=lambda m: None):
    known, entries = build_known(progress)
    items = []

    progress("Looking for broken uninstall entries…")
    for e in entries:
        if e.broken:
            items.append(Item("regkey", e.key, "high", "Broken uninstall entry",
                              f"\"{e.name}\" is listed as installed but its uninstaller no longer exists "
                              f"({e.uninstall_exe})."))

    for base in rules.APP_PATHS_KEYS:
        for sub in reg_subkeys(base):
            path = f"{base}\\{sub}"
            default = reg_values(path).get("")
            exe = exe_from_command(str(default[0])) if default else None
            if exe and is_missing(exe):
                items.append(Item("regkey", path, "high", "Broken app path",
                                  f"Registers \"{sub}\" pointing to a file that no longer exists ({exe})."))

    progress("Looking for broken startup entries…")
    for key in rules.RUN_KEYS:
        for name, (data, _kind) in reg_values(key).items():
            exe = exe_from_command(str(data))
            if exe and is_missing(exe):
                items.append(Item("regvalue", key, "high", "Broken startup entry",
                                  f"Tries to launch a file that no longer exists when Windows starts ({exe}).",
                                  value=name))

    progress("Looking for broken shortcuts…")
    for path in list(_shortcuts(rules.SHORTCUT_DIRS)) + list(_shortcuts(rules.DESKTOP_DIRS, recursive=False)):
        if path.lower().endswith(".lnk"):
            t = lnk.target(path)
            if t and is_missing(t):
                items.append(Item("file", path, "high", "Broken shortcut",
                                  f"Points to a file that no longer exists ({t}).",
                                  size=_file_size(path)))
    for d in rules.SHORTCUT_DIRS:
        for root, subdirs, files in os.walk(d, topdown=False):
            if npath(root) == npath(d) or norm(os.path.basename(root)) in rules.SAFE_FOLDER_NAMES:
                continue
            try:
                if not os.listdir(root):
                    items.append(Item("folder", root, "high", "Empty Start menu folder",
                                      "Start menu folder without any shortcut."))
            except OSError:
                pass

    for root, label, base_conf in rules.FOLDER_ROOTS:
        progress(f"Scanning folders: {label}…")
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
                            child.path, "low", f"Orphan folder · {label}",
                            f"The publisher \"{entry.name}\" has other programs installed, "
                            f"but none of them uses this folder."))
                continue
            items.append(_folder_item(entry.path, base_conf, f"Orphan folder · {label}",
                                      "No installed or running program matches this folder."))

    for base, label in rules.REG_ROOTS:
        progress(f"Scanning {label}…")
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
                        items.append(_reg_candidate(f"{path}\\{child}", f"Orphan key · {label}",
                                                    f"The publisher \"{sub}\" has other programs installed, "
                                                    f"but none of them matches this key."))
                continue
            items.append(_reg_candidate(path, f"Orphan key · {label}",
                                        "No installed program matches this key."))

    progress("Scan finished.")
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


# ---------------------------------------------------------------- search by name

def search(term, progress=lambda m: None):
    """Look for the leftovers of a specific program by name.

    Returns (items, installed_names_that_match)."""
    t = norm(term)
    if len(t) < 3:
        raise ValueError("Type at least 3 letters or digits.")
    if t in rules.BLOCKED_TERMS:
        raise ValueError(f"\"{term}\" is too generic; it could match Windows components.")

    known, entries = build_known(progress)
    still_installed = sorted({e.name for e in entries if not e.broken and e.name and t in norm(e.name)})
    items = []

    def conf_for(path=None):
        if path and known.path_inside(path):
            return "low", "Used by an installed or running program."
        if still_installed:
            return "low", "A program with a similar name is still installed."
        return "medium", f"Its name matches \"{term}\"."

    progress("Searching uninstall entries…")
    for e in entries:
        if e.name and t in norm(e.name) and e.broken:
            items.append(Item("regkey", e.key, "high", "Broken uninstall entry",
                              f"\"{e.name}\": its uninstaller no longer exists."))

    search_roots = [(r, label, 3) for r, label, _ in rules.FOLDER_ROOTS]
    search_roots += [(rules.DOCUMENTS, "Documents", 2), (rules.USER_PROFILE, "User profile", 1)]
    for root, label, depth in search_roots:
        if not root or not os.path.isdir(root):
            continue
        progress(f"Searching folders in {label}…")
        stack = [(root, 1)]
        while stack:
            folder, level = stack.pop()
            for entry in list_dirs(folder):
                n = norm(entry.name)
                if t in n and n not in rules.SAFE_FOLDER_NAMES and not _is_protected(entry.path):
                    conf, reason = conf_for(entry.path)
                    if npath(root) == npath(rules.DOCUMENTS):
                        conf, reason = "low", reason + " It is in Documents: make sure these are not your files."
                    items.append(_folder_item(entry.path, conf, f"Match · {label}", reason))
                elif level < depth and n not in _NO_DESCEND:
                    stack.append((entry.path, level + 1))

    progress("Searching the registry…")
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
                    items.append(_reg_item(path, f"Match · {label}", reason, conf))
                elif level < 3:
                    stack.append((path, level + 1))
    for base in rules.APP_PATHS_KEYS:
        for sub in reg_subkeys(base):
            if t in norm(sub):
                conf, reason = conf_for()
                items.append(Item("regkey", f"{base}\\{sub}", conf, "App path", reason))
    for key in rules.RUN_KEYS:
        for name, (data, _kind) in reg_values(key).items():
            if t in norm(name) or t in norm(str(data)):
                exe = exe_from_command(str(data))
                conf, reason = ("high", "Its file no longer exists.") if exe and is_missing(exe) else conf_for()
                items.append(Item("regvalue", key, conf, "Startup entry", reason, value=name))

    progress("Searching shortcuts…")
    for d in rules.SHORTCUT_DIRS + rules.DESKTOP_DIRS:
        recursive = d in rules.SHORTCUT_DIRS
        for root, subdirs, files in (os.walk(d) if recursive else [(d, [], _safe_listdir(d))]):
            for name in subdirs:
                if t in norm(name) and npath(os.path.join(root, name)) not in rules.PROTECTED_DIRS:
                    items.append(_folder_item(os.path.join(root, name), "medium", "Start menu folder",
                                              f"Its name matches \"{term}\"."))
            for name in files:
                p = os.path.join(root, name)
                if t in norm(os.path.splitext(name)[0]) and name.lower().endswith((".lnk", ".url")):
                    tg = lnk.target(p) if name.lower().endswith(".lnk") else None
                    if tg and is_missing(tg):
                        conf, reason = "high", f"Broken shortcut ({tg})."
                    else:
                        conf, reason = conf_for()
                    items.append(Item("file", p, conf, "Shortcut", reason, size=_file_size(p)))

    progress("Search finished.")
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
    """Drop folders that are already included inside another folder of the list."""
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
            print("Still installed:", ", ".join(installed))
    else:
        found = scan(progress=lambda m: print("·", m))
    order = {"high": 0, "medium": 1, "low": 2}
    for it in sorted(found, key=lambda i: (order[i.confidence], i.category, i.path.lower())):
        print(f"[{it.confidence:6}] {it.category:42} {it.display_path}  ({it.size // 1024} KB)\n         {it.reason}")
    print(f"\n{len(found)} items found.")
