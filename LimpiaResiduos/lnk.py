"""Lector mínimo de accesos directos .lnk (formato MS-SHLLINK) para obtener su destino."""
import os
import struct

_HAS_ID_LIST = 0x01
_HAS_LINK_INFO = 0x02
_HAS_DARWIN_ID = 0x1000  # acceso directo «anunciado» de Windows Installer
_VOLUME_ID_AND_LOCAL_BASE_PATH = 0x01


def _read_ansi(data, pos):
    end = data.find(b"\x00", pos)
    return data[pos:end if end >= 0 else len(data)].decode("mbcs", "replace")


def _read_utf16(data, pos):
    end = pos
    while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
        end += 2
    return data[pos:end].decode("utf-16-le", "replace")


def target(path):
    """Ruta local de destino del acceso directo, o None si no se puede saber
    (destinos de red, accesos de Windows Installer, de la Tienda, etc.)."""
    try:
        with open(path, "rb") as f:
            data = f.read(256 * 1024)
        if len(data) < 0x4C or data[:4] != b"\x4c\x00\x00\x00":
            return None
        flags = struct.unpack_from("<I", data, 0x14)[0]
        if flags & _HAS_DARWIN_ID or not flags & _HAS_LINK_INFO:
            return None
        pos = 0x4C
        if flags & _HAS_ID_LIST:
            pos += 2 + struct.unpack_from("<H", data, pos)[0]
        li = pos
        (_size, header_size, li_flags, _vol, base_off, _net, suffix_off) = struct.unpack_from("<7I", data, li)
        if not li_flags & _VOLUME_ID_AND_LOCAL_BASE_PATH:
            return None
        if header_size >= 0x24:
            base_u, suffix_u = struct.unpack_from("<2I", data, li + 28)
            base = _read_utf16(data, li + base_u) if base_u else _read_ansi(data, li + base_off)
            suffix = _read_utf16(data, li + suffix_u) if suffix_u else ""
        else:
            base = _read_ansi(data, li + base_off)
            suffix = _read_ansi(data, li + suffix_off) if suffix_off else ""
        result = os.path.expandvars(base + suffix)
        if len(result) < 3 or result[1] != ":":
            return None
        return os.path.normpath(result)
    except (OSError, struct.error, ValueError):
        return None
