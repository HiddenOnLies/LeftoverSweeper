"""Search inside the quarantine by program name, file name or a pasted error message.

A query is turned into weighted terms:
- full paths (C:\\..., HKEY_...\\...)  -> matched against the original location;
- file names (foo.dll, app.exe, ...)    -> matched against names and the files inside quarantined folders;
- remaining meaningful words            -> matched everywhere, with less weight.
"""
import os
import re

from rules import norm

_MAX_FILES_PER_ITEM = 20_000
MIN_RELATIVE_SCORE = 0.3

_PATH_RE = re.compile(r"[a-zA-Z]:\\[^\"'<>|*?\r\n]+")
_REG_RE = re.compile(r"\b(HKEY_[A-Z_]+|HKCU|HKLM)\\[^\"'<>|*?\r\n]+", re.I)
_FILE_RE = re.compile(r"[\w\-.()+]+\.(?:dll|exe|sys|ocx|ini|cfg|conf|config|json|xml|dat|db|log|lnk|msi|"
                      r"bat|cmd|ps1|vbs|jar|pak|bin|reg|tmp|manifest)\b", re.I)
_ROOT_ALIASES = {"HKEY_CURRENT_USER": "HKCU", "HKEY_LOCAL_MACHINE": "HKLM"}

# Words that appear in error messages but say nothing about the program (English and Spanish).
_STOPWORDS = set("""
the a an and or of to in on at for from with by is are was were be been it its this that these those not no
cannot can could would should may might must will error errors code execution proceed because found missing
reinstall reinstalling reinstalar program programs application app file files folder windows system fix problem
problems failed fail failure start started starting run running open opening load loading unable occurred
please try again your you computer machine pc access denied find specified path entry point procedure module
library located dynamic link correctly properly side configuration incorrect launch version make sure
typed name names read reading write writing check data value key make sure valid invalid exist exists
does doesn't didn't there here when then than some been being has have had other another
el la los las un una unos unas de del al y o en con por para que se no es fue ha han puede pueden podria
falta faltan encontro encontrado encontrar archivo archivos programa programas aplicacion error errores codigo
ejecucion continuar porque problema problemas intentar intente equipo sistema iniciar inicio abrir cargar
acceso denegado ruta especificada punto entrada procedimiento modulo biblioteca
""".split())


# Path components that say nothing about which program something belongs to.
_GENERIC_PARTS = {norm(p) for p in [
    "C:", "Program Files", "Program Files (x86)", "ProgramData", "Users", "AppData", "Local", "Roaming",
    "LocalLow", "Programs", "Common Files", "Windows", "System32", "SysWOW64", "Software", "WOW6432Node",
    "Microsoft", "CurrentVersion", "Uninstall", "Run", "RunOnce", "App Paths", "Start Menu", "Desktop",
    "Documents", "HKCU", "HKLM", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "bin", "lib",
    os.path.basename(os.environ.get("USERPROFILE", "")),
] if p}


def _parts(path):
    """Meaningful components of a file or registry path."""
    return [p for p in re.split(r"[\\/]", path) if p and norm(p) not in _GENERIC_PARTS]


def _fold(text):
    """Lowercase and strip Spanish accents so 'aplicación' matches 'aplicacion'."""
    return (text or "").lower().translate(str.maketrans("áéíóúüñ", "aeiouun"))


def _norm_reg(path):
    root, _, rest = path.partition("\\")
    return f"{_ROOT_ALIASES.get(root.upper(), root.upper())}\\{rest}".rstrip("\\. ").lower()


def parse_query(query):
    """List of (kind, text, weight). kind: 'path' | 'name' | 'word'."""
    q = (query or "").strip()
    if not q:
        return []
    terms, seen = [], set()

    def add(kind, text, weight):
        text = text.strip().strip("'\".,;:()[]").lower()
        min_len = 4 if kind == "word" else 3
        if len(norm(text)) >= min_len and (kind, text) not in seen:
            seen.add((kind, text))
            terms.append((kind, text, weight))

    rest = q
    for m in _PATH_RE.finditer(q):
        p = m.group(0).rstrip("'\".,;: ")
        add("path", os.path.normpath(p), 5)
        for part in _parts(p):
            add("name", part, 3)
        rest = rest.replace(m.group(0), " ")
    for m in _REG_RE.finditer(q):
        add("path", _norm_reg(m.group(0)), 5)
        for part in _parts(m.group(0)):
            add("name", part, 2)
        rest = rest.replace(m.group(0), " ")
    for m in _FILE_RE.finditer(rest):
        add("name", m.group(0), 4)
        add("name", os.path.splitext(m.group(0))[0], 2)
        rest = rest.replace(m.group(0), " ")

    words = [w for w in re.split(r"[^\w\-]+", _fold(rest)) if w]
    if len(words) <= 3 and not terms:
        # A short query is a program name: keep it whole as well as word by word.
        add("name", " ".join(words), 3)
    for w in words:
        if w not in _STOPWORDS and not w.isdigit():
            add("word", w, 1)
    return terms


def index_record(rec):
    """Searchable text for one quarantined record."""
    names = _parts(rec.get("path", "")) + [rec.get("value") or ""]
    contents = []
    backup = rec.get("backup")
    if rec.get("kind") == "folder" and backup and os.path.isdir(backup):
        for root, dirs, files in os.walk(backup):
            for f in dirs + files:
                contents.append(os.path.relpath(os.path.join(root, f), backup))
                if len(contents) >= _MAX_FILES_PER_ITEM:
                    break
            if len(contents) >= _MAX_FILES_PER_ITEM:
                break
    reg_text = ""
    if rec.get("kind") == "regkey" and backup and os.path.isfile(backup):
        try:
            with open(backup, "rb") as f:
                raw = f.read(2_000_000)
            reg_text = raw.decode("utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8", "replace")
        except OSError:
            pass
    if rec.get("kind") == "regvalue":
        reg_text = str((rec.get("backup_value") or {}).get("data", ""))
    return {
        "path": rec.get("path", "").lower(),
        "names": [_fold(n) for n in names if n],
        "names_norm": [norm(n) for n in names if n],
        "contents": [c.lower() for c in contents],
        "reg": _fold(reg_text),
        "about": _fold(f"{rec.get('category', '')} {rec.get('reason', '')}"),
    }


def _hit(term, texts, texts_norm=None):
    t_norm = norm(term)
    for i, text in enumerate(texts):
        if term in text or (texts_norm is not None and len(t_norm) >= 4 and t_norm in texts_norm[i]):
            return text
    return None


def score(index, terms):
    """(score, [human-readable reasons]) for one record."""
    total, why = 0, []
    item_path = index["path"]
    for kind, term, weight in terms:
        if kind == "path":
            is_reg = term.startswith(("hkcu\\", "hklm\\"))
            mine = _norm_reg(item_path) if is_reg else os.path.normcase(os.path.normpath(item_path))
            theirs = term if is_reg else os.path.normcase(term)
            specific = len(_parts(theirs)) >= 2  # a parent only counts if it names something concrete
            if theirs == mine or theirs.startswith(mine + "\\") or (specific and mine.startswith(theirs + "\\")):
                total += weight * 2
                why.append("same location")
            continue
        if _hit(term, index["names"], index["names_norm"]):
            total += weight * 2
            why.append(f"name: {term}")
            continue
        inside = _hit(term, index["contents"])
        if inside:
            total += weight * 1.5
            why.append(f"contains {inside}")
            continue
        if term in index["reg"]:
            total += weight
            why.append(f"registry data: {term}")
            continue
        if term in index["about"]:
            total += weight * 0.5
            why.append(f"related: {term}")
    return total, why


def search(entries, query, cache):
    """Rank quarantine entries [(session_dir, record)] for `query`.

    `cache` is a dict reused between calls so folders are only walked once.
    Returns [(entry, score, reasons)] best first; an empty query returns everything and a
    query with nothing specific in it (e.g. "the application failed to start") returns nothing."""
    if not (query or "").strip():
        return [(e, 0, []) for e in entries]
    terms = parse_query(query)
    if not terms:
        return []
    results = []
    for entry in entries:
        sdir, rec = entry
        key = (sdir, rec["id"])
        if key not in cache:
            cache[key] = index_record(rec)
        s, why = score(cache[key], terms)
        if s > 0:
            results.append((entry, s, why))
    results.sort(key=lambda r: -r[1])
    if results:  # drop weak, incidental matches far below the best one
        cutoff = results[0][1] * MIN_RELATIVE_SCORE
        results = [r for r in results if r[1] >= cutoff]
    return results


def needs_indexing(entries, cache):
    return any((sdir, rec["id"]) not in cache for sdir, rec in entries)
