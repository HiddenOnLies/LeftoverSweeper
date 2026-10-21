"""Reglas de seguridad: ubicaciones, nombres que nunca se tocan y rutas protegidas."""
import os
import re

from winutil import known_folder, npath

APP_NAME = "LimpiaResiduos"
APP_VERSION = "1.0.0"


def norm(text):
    """Normaliza un nombre para compararlo: minúsculas y solo letras/números."""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _env(name, default=""):
    return os.environ.get(name, default)


# ---------------------------------------------------------------- ubicaciones

SYSTEM_DRIVE = _env("SystemDrive", "C:") + "\\"
WINDIR = _env("SystemRoot", r"C:\Windows")
PROGRAM_FILES = _env("ProgramW6432") or _env("ProgramFiles", r"C:\Program Files")
PROGRAM_FILES_X86 = _env("ProgramFiles(x86)", "")
PROGRAM_DATA = _env("ProgramData", r"C:\ProgramData")
USER_PROFILE = _env("USERPROFILE", "")
APPDATA = _env("APPDATA", "")
LOCALAPPDATA = _env("LOCALAPPDATA", "")
LOCALLOW = os.path.join(os.path.dirname(LOCALAPPDATA), "LocalLow") if LOCALAPPDATA else ""
USER_PROGRAMS = os.path.join(LOCALAPPDATA, "Programs") if LOCALAPPDATA else ""
PUBLIC = _env("PUBLIC", "")

DATA_DIR = os.path.join(LOCALAPPDATA, APP_NAME)
QUARANTINE_DIR = os.path.join(DATA_DIR, "Cuarentena")

START_MENU_USER = known_folder("A77F5D77-2E2B-44C3-A6A2-ABA601054A51",
                               os.path.join(APPDATA, r"Microsoft\Windows\Start Menu\Programs"))
START_MENU_COMMON = known_folder("0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8",
                                 os.path.join(PROGRAM_DATA, r"Microsoft\Windows\Start Menu\Programs"))
DESKTOP_USER = known_folder("B4BFCC3A-DB2C-424C-B029-7FE99A87C641",
                            os.path.join(USER_PROFILE, "Desktop"))
DESKTOP_PUBLIC = known_folder("C4AA340D-F20F-4863-AFEF-F87EF2E6BA25",
                              os.path.join(PUBLIC, "Desktop"))
DOCUMENTS = known_folder("FDD39AD0-238F-46AF-ADB4-6C85480369C7",
                         os.path.join(USER_PROFILE, "Documents"))


def _dedupe(paths):
    seen, out = set(), []
    for p in paths:
        if p and npath(p) not in seen and os.path.isdir(p):
            seen.add(npath(p))
            out.append(p)
    return out


# Ubicaciones donde los programas dejan carpetas: (ruta, etiqueta, confianza base)
FOLDER_ROOTS = [
    (r, label, conf) for r, label, conf in [
        (PROGRAM_FILES, "Archivos de programa", "media"),
        (PROGRAM_FILES_X86, "Archivos de programa (x86)", "media"),
        (USER_PROGRAMS, "Programas del usuario", "media"),
        (os.path.join(PROGRAM_FILES, "Common Files"), "Archivos comunes", "baja"),
        (os.path.join(PROGRAM_FILES_X86, "Common Files") if PROGRAM_FILES_X86 else "", "Archivos comunes (x86)", "baja"),
        (PROGRAM_DATA, "ProgramData", "baja"),
        (APPDATA, "AppData\\Roaming", "baja"),
        (LOCALAPPDATA, "AppData\\Local", "baja"),
        (LOCALLOW, "AppData\\LocalLow", "baja"),
    ] if r and os.path.isdir(r)
]
_seen = set()
FOLDER_ROOTS = [x for x in FOLDER_ROOTS if not (npath(x[0]) in _seen or _seen.add(npath(x[0])))]

SHORTCUT_DIRS = _dedupe([START_MENU_USER, START_MENU_COMMON])
DESKTOP_DIRS = _dedupe([DESKTOP_USER, DESKTOP_PUBLIC])

REG_ROOTS = [
    ("HKCU\\Software", "Registro (usuario)"),
    ("HKLM\\SOFTWARE", "Registro (equipo)"),
    ("HKLM\\SOFTWARE\\WOW6432Node", "Registro (equipo, 32 bits)"),
]

UNINSTALL_KEYS = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
]

APP_PATHS_KEYS = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths",
]

APPX_PACKAGES_KEY = ("HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion"
                     "\\AppModel\\Repository\\Packages")

RUN_KEYS = [
    f"{base}\\Microsoft\\Windows\\CurrentVersion\\{name}"
    for base in ("HKCU\\Software", "HKLM\\SOFTWARE", "HKLM\\SOFTWARE\\WOW6432Node")
    for name in ("Run", "RunOnce")
]


# ---------------------------------------------------------------- nombres seguros

# Carpetas del sistema o compartidas que nunca se proponen como residuo.
SAFE_FOLDER_NAMES = {norm(n) for n in [
    APP_NAME, "Common Files", "Internet Explorer", "Windows Defender", "Windows Defender Advanced Threat Protection",
    "WindowsApps", "ModifiableWindowsApps", "Windows Mail", "Windows Media Player", "Windows Multimedia Platform",
    "Windows NT", "Windows Photo Viewer", "Windows Portable Devices", "Windows Security", "Windows Sidebar",
    "WindowsPowerShell", "Reference Assemblies", "MSBuild", "dotnet", "Uninstall Information", "Package Cache",
    "Packages", "Temp", "Tmp", "CrashDumps", "D3DSCache", "ConnectedDevicesPlatform", "Comms", "PeerDistRepub",
    "PlaceholderTileLogoFolder", "Publishers", "VirtualStore", "IsolatedStorage", "History", "Programs",
    "Application Data", "Desktop", "Documents", "Start Menu", "Templates", "Favorites", "ssh", "USOShared",
    "USOPrivate", "SoftwareDistribution", "PackageManagement", "boost_interprocess", "Default", "Public",
    "Temporary Internet Files", "Low", "fontconfig", "Downloaded Installations", "Downloaded Program Files",
    "Desktop.ini", "Device Stage", "WinSAT", "Speech", "Speech Engines", "ClickToRun", "Office", "OneDrive",
    "Startup", "Inicio",
]}

# Prefijos de fabricantes del sistema/hardware que se tratan como seguros.
SAFE_PREFIXES = ("microsoft", "windows", "msft", "regid", "intel", "nvidia", "realtek", "amd")

SAFE_REG_NAMES = {norm(n) for n in [
    "Microsoft", "Classes", "Policies", "Wow6432Node", "Clients", "RegisteredApplications", "ODBC", "Windows",
    "Khronos", "Partner", "OEM", "DefaultUserEnvironment", "AppDataLow", "System", "CBSTemp", "Description",
    "Intel", "NVIDIA Corporation", "AMD", "ATI Technologies", "Realtek", "Dolby", "DTS", "Waves Audio",
    "Synaptics", "Elantech", "Conexant", "IDT", "Qualcomm", "Broadcom", "MediaTek", "Lenovo", "Dell", "HP",
    "Hewlett-Packard", "ASUS", "ASUSTeK Computer Inc.", "Acer", "MSI", "Gigabyte", "Samsung", "Toshiba",
    "Huawei", "Alps", "Thunderbolt", "Setup", "OpenSSH", "Volatile", "dotnet", "SyncIntegrationClients",
    "Package Cache", APP_NAME,
]}

# Claves que el limpiador jamás borra, aunque el usuario las marque.
CRITICAL_REG_NAMES = {norm(n) for n in [
    "Microsoft", "Classes", "Policies", "Wow6432Node", "Clients", "RegisteredApplications", "ODBC",
    "Description", "Windows",
]}

# Términos demasiado genéricos para la búsqueda por nombre.
BLOCKED_TERMS = {norm(n) for n in [
    "microsoft", "windows", "system", "system32", "program", "programs", "programa", "files", "common", "app",
    "apps", "data", "local", "roaming", "software", "users", "user", "temp", "cache", "config", "update",
    "setup", "install", "driver", "drivers", "documents", "desktop", "appdata", "programdata", "classes",
]}

# Carpetas estándar del perfil de usuario (protegidas).
_PROFILE_STD = ["Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos", "OneDrive", "AppData",
                "Contacts", "Favorites", "Links", "Saved Games", "Searches", "3D Objects", "Escritorio",
                "Documentos", "Descargas", "Música", "Imágenes", "Vídeos"]


def is_safe_folder(name):
    n = norm(name)
    return not n or n in SAFE_FOLDER_NAMES or n.startswith(SAFE_PREFIXES)


def is_safe_reg(name):
    n = norm(name)
    return not n or n in SAFE_REG_NAMES or n.startswith(SAFE_PREFIXES)


# ---------------------------------------------------------------- protección del limpiador

def _protected_dirs():
    dirs = [SYSTEM_DRIVE, WINDIR, PROGRAM_FILES, PROGRAM_FILES_X86, PROGRAM_DATA, USER_PROFILE,
            os.path.dirname(USER_PROFILE) if USER_PROFILE else "", APPDATA, LOCALAPPDATA, LOCALLOW,
            USER_PROGRAMS, PUBLIC, START_MENU_USER, START_MENU_COMMON, DESKTOP_USER, DESKTOP_PUBLIC,
            DOCUMENTS, DATA_DIR, QUARANTINE_DIR]
    dirs += [r for r, _, _ in FOLDER_ROOTS]
    dirs += [os.path.join(USER_PROFILE, n) for n in _PROFILE_STD if USER_PROFILE]
    dirs += [os.path.join(START_MENU_USER, "Startup"), os.path.join(START_MENU_COMMON, "Startup")]
    return {npath(d) for d in dirs if d}


PROTECTED_DIRS = _protected_dirs()

ALLOWED_FS_ROOTS = sorted({npath(r) for r in
                           [r for r, _, _ in FOLDER_ROOTS] + SHORTCUT_DIRS + DESKTOP_DIRS + [DOCUMENTS, USER_PROFILE]
                           if r}, key=len, reverse=True)

ADMIN_FS_ROOTS = [npath(p) for p in [PROGRAM_FILES, PROGRAM_FILES_X86, PROGRAM_DATA, START_MENU_COMMON,
                                     DESKTOP_PUBLIC] if p]


def _under(path, root):
    return path.startswith(root.rstrip("\\") + "\\")


def check_fs_path(path):
    """Lanza ValueError si la ruta no se puede tocar con seguridad."""
    p = npath(path)
    if not os.path.isabs(p) or len(p) <= 3:
        raise ValueError("Ruta no válida o raíz de unidad.")
    if p in PROTECTED_DIRS or any(_under(d, p) for d in PROTECTED_DIRS):
        raise ValueError("Es una carpeta protegida del sistema o contiene una.")
    if _under(p, npath(WINDIR)) or _under(p, npath(QUARANTINE_DIR)):
        raise ValueError("Está dentro de Windows o de la propia cuarentena.")
    if not any(_under(p, r) for r in ALLOWED_FS_ROOTS):
        raise ValueError("Está fuera de las ubicaciones que analiza la aplicación.")
    if norm(os.path.basename(p)) in SAFE_FOLDER_NAMES:
        raise ValueError("Es una carpeta compartida o del sistema.")


_REG_RE = re.compile(r"^(HKCU|HKLM)\\SOFTWARE\\(?:WOW6432NODE\\)?(.+)$", re.I)


def check_reg_path(path, kind):
    """Lanza ValueError si la clave/valor del registro no se puede tocar."""
    m = _REG_RE.match(path)
    if not m:
        raise ValueError("Solo se permiten claves dentro de SOFTWARE.")
    parts = [x.upper() for x in m.group(2).split("\\")]
    cv = ["MICROSOFT", "WINDOWS", "CURRENTVERSION"]
    if kind == "regvalue":
        if parts[:3] == cv and len(parts) == 4 and parts[3] in ("RUN", "RUNONCE"):
            return
        raise ValueError("Solo se permiten valores de las claves de inicio (Run).")
    if parts[:3] == cv and len(parts) == 5 and parts[3] in ("UNINSTALL", "APP PATHS"):
        return
    if norm(parts[0]) in CRITICAL_REG_NAMES:
        raise ValueError("Es una clave crítica del sistema.")


def requires_admin(item):
    if item.kind in ("regkey", "regvalue"):
        return item.path.upper().startswith("HKLM")
    p = npath(item.path)
    return any(_under(p, r) for r in ADMIN_FS_ROOTS)
