# CubeHead Checker — local Minecraft .jar scan. Nothing leaves this PC.
import io
import json
import math
import os
import queue
import re
import struct
import sys
import threading
import zipfile
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent

CHEAT_CLIENTS = {
    "wurst",
    "meteor client",
    "liquidbounce",
    "bleachhack",
    "aristois",
    "impact",
    "sigma",
    "kami",
    "phobos",
    "future",
    "rusherhack",
    "konas",
    "salhack",
    "wolfram",
    "novoline",
    "astolfo",
    "tenacity",
    "rise",
    "exhibition",
    "doomsday",
    "forgehax",
}

VERIFIED_WORDS = [
    "sodium",
    "iris",
    "lithium",
    "phosphor",
    "indium",
    "ferritecore",
    "modmenu",
    "cloth-config",
    "fabric-api",
    "optifine",
    "jei",
    "roughlyenoughitems",
    "appleskin",
    "lambdynamiclights",
    "continuity",
    "entityculling",
    "krypton",
    "modernfix",
    "geckolib",
    "architectury",
    "yacl",
    "puzzleslib",
    "fabric-language-kotlin",
]


def app_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return HERE


def bundle_dir():
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", app_dir()))
    return HERE


def signatures_file():
    beside = app_dir() / "signatures.json"
    bundled = bundle_dir() / "signatures.json"
    if not beside.exists() and bundled.exists():
        try:
            beside.write_text(bundled.read_text(encoding="utf-8"), encoding="utf-8")
        except OSError:
            return bundled
    return beside if beside.exists() else bundled

SKIP_DIR_NAMES = {
    "libraries",
    "assets",
    "natives",
    "node_modules",
    ".git",
    "windows",
    "winsxs",
    "$recycle.bin",
    "system volume information",
    "program files",
    "program files (x86)",
    "programdata",
    ".gradle",
    ".m2",
    "site-packages",
    "maven",
}


def load_rules():
    data = json.loads(signatures_file().read_text(encoding="utf-8"))
    rules = []
    for raw in data.get("rules") or []:
        name = str(raw.get("name") or "Совпадение")
        level = str(raw.get("level") or "blocked").lower()
        if name.lower() in CHEAT_CLIENTS or level == "cheat":
            level = "cheat"
        elif level in ("ban", "blocked", "review"):
            level = "blocked"
        else:
            level = "blocked"
        rules.append(
            {
                "name": name,
                "level": level,
                "file": [s.lower() for s in raw.get("file") or []],
                "path": [s.lower() for s in raw.get("path") or []],
                "id": [s.lower() for s in raw.get("id") or []],
            }
        )
    return rules


def pc_roots():
    import string
    import ctypes

    roots = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i, letter in enumerate(string.ascii_uppercase):
        if not bitmask & (1 << i):
            continue
        path = Path(f"{letter}:\\")
        kind = ctypes.windll.kernel32.GetDriveTypeW(str(path))
        if kind == 3 and path.exists():
            roots.append(path)
    return roots or default_roots()


def default_roots():
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
    candidates = [
        appdata / ".minecraft",
        appdata / ".tlauncher",
        appdata / "PrismLauncher",
        appdata / "MultiMC",
        appdata / ".feather",
        appdata / ".lunarclient",
        appdata / "ModrinthApp",
        appdata / "com.modrinth.theseus",
        local / "PrismLauncher",
        local / "CurseForge",
        local / "ModrinthApp",
        local / "Temp",
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
    ]
    curse = local / "CurseForge" / "minecraft" / "Instances"
    if curse.is_dir():
        candidates.append(curse)
    out = []
    seen = set()
    for path in candidates:
        try:
            key = str(path.resolve()).lower()
        except OSError:
            continue
        if key in seen or not path.exists():
            continue
        seen.add(key)
        out.append(path)
    return out


def profile_root():
    return Path.home()


def _skip_dir(name):
    return name.lower() in SKIP_DIR_NAMES


def iter_jars(roots, stop):
    for root in roots:
        if stop.is_set():
            return
        if not root.exists():
            continue
        if root.is_file() and root.suffix.lower() in {".jar", ".exe"}:
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if stop.is_set():
                return
            dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
            for name in filenames:
                if name.lower().endswith(".jar"):
                    yield Path(dirpath) / name


def _read_meta(zf, names):
    wanted = (
        "fabric.mod.json",
        "quilt.mod.json",
        "META-INF/mods.toml",
        "mcmod.info",
    )
    chunks = []
    picked = 0
    for name in names:
        low = name.lower().replace("\\", "/")
        if not any(low == w or low.endswith("/" + w) for w in wanted):
            continue
        try:
            info = zf.getinfo(name)
        except KeyError:
            continue
        if info.file_size > 262144:
            continue
        try:
            raw = zf.read(name)
        except Exception:
            continue
        chunks.append(raw[:262144].decode("utf-8", "replace"))
        picked += 1
        if picked >= 6:
            break
    return "\n".join(chunks).lower()


BYTE_MARKS = (
    ("Wurst", "cheat", b"net/wurstclient"),
    ("Wurst", "cheat", b"wurstclient"),
    ("Meteor Client", "cheat", b"meteordevelopment/meteorclient"),
    ("Meteor Client", "cheat", b"meteorclient"),
    ("LiquidBounce", "cheat", b"net/ccbluex/liquidbounce"),
    ("LiquidBounce", "cheat", b"liquidbounce"),
    ("BleachHack", "cheat", b"bleachhack"),
    ("Aristois", "cheat", b"aristois"),
    ("Impact", "cheat", b"impactclient"),
    ("Sigma", "cheat", b"sigmaclient"),
    ("RusherHack", "cheat", b"rusherhack"),
    ("Future", "cheat", b"futureclient"),
    ("Kami", "cheat", b"kamiblue"),
    ("Phobos", "cheat", b"me/earth/phobos"),
    ("Novoline", "cheat", b"novoline"),
    ("Astolfo", "cheat", b"astolfo"),
    ("Tenacity", "cheat", b"tenacityclient"),
    ("Rise", "cheat", b"riseclient"),
    ("Doomsday", "cheat", b"doomsdayclient"),
    ("ForgeHax", "cheat", b"forgehax"),
    ("Baritone", "blocked", b"baritone/api"),
    ("Tweakeroo", "blocked", b"fi/dy/masa/tweakeroo"),
    ("Replay Mod", "blocked", b"com/replaymod"),
    ("SeedCracker", "blocked", b"seedcracker"),
    ("FreeCam", "blocked", b"freecam"),
    ("Inventory Profiles Next", "blocked", b"inventoryprofilesnext"),
    ("World Downloader", "blocked", b"net/minecraft/wdl"),
    ("Better PVP", "blocked", b"betterpvp"),
    ("ClientCommands", "blocked", b"clientcommands"),
    ("Chest Locator", "blocked", b"chestlocator"),
    ("Wall-Jump", "blocked", b"walljump"),
    ("Auto Clicker", "blocked", b"autoclicker"),
    ("Elytra Utilities", "blocked", b"elytrautilities"),
    ("Squake", "blocked", b"squake"),
    ("Bedrock Miner", "blocked", b"bedrockminer"),
    ("FindMe", "blocked", b"findme"),
)


def _scan_bytes(zf, names):
    found = []
    seen = set()
    budget = 8_000_000
    used = 0
    pending = list(BYTE_MARKS)
    files = [n for n in names if n.lower().endswith((".class", ".json", ".toml", ".txt", ".xml"))]
    nested = [n for n in names if n.lower().endswith(".jar")][:4]
    for name in files:
        if not pending or used >= budget:
            break
        try:
            info = zf.getinfo(name)
        except KeyError:
            continue
        if info.file_size <= 0 or info.file_size > 1_800_000:
            continue
        try:
            raw = zf.read(name).lower()
        except Exception:
            continue
        used += len(raw)
        still = []
        for item in pending:
            if item[2] in raw:
                if item[0] not in seen:
                    found.append({"name": item[0], "level": item[1]})
                    seen.add(item[0])
            else:
                still.append(item)
        pending = still
    for name in nested:
        if used >= budget:
            break
        try:
            raw = zf.read(name)
        except Exception:
            continue
        used += len(raw)
        try:
            inner = zipfile.ZipFile(io.BytesIO(raw))
        except Exception:
            continue
        blob = "\n".join(inner.namelist()).lower().encode("latin1", "ignore")
        for item in list(pending):
            if item[2] in blob and item[0] not in seen:
                found.append({"name": item[0], "level": item[1]})
                seen.add(item[0])
    return found


def inspect_exe(path, rules):
    try:
        mtime = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        size = path.stat().st_size
    except OSError as exc:
        return {"path": str(path), "file": path.name, "status": "error", "hits": [], "detail": str(exc), "mtime": "", "size": 0}
    blob = path.name.lower().encode("latin1", "ignore")
    try:
        with open(path, "rb") as fh:
            blob += fh.read(8_000_000).lower()
    except OSError:
        pass
    hits = []
    seen = set()
    for name, level, mark in BYTE_MARKS:
        if mark in blob and name not in seen:
            hits.append({"name": name, "level": level})
            seen.add(name)
    for rule in rules:
        if rule["name"] in seen:
            continue
        for needle in rule["file"] + rule["path"]:
            if needle and needle.encode("latin1", "ignore") in blob:
                hits.append({"name": rule["name"], "level": rule["level"]})
                seen.add(rule["name"])
                break
    levels = {h["level"] for h in hits}
    if "cheat" in levels:
        status = "cheat"
    elif "blocked" in levels:
        status = "blocked"
    else:
        status = "unknown"
    return {
        "path": str(path),
        "file": path.name,
        "status": status,
        "hits": hits,
        "detail": ", ".join(dict.fromkeys(h["name"] for h in hits)) or "программа",
        "mtime": mtime,
        "size": size,
    }


def inspect_any(path, rules):
    if str(path).lower().endswith(".exe"):
        return inspect_exe(path, rules)
    return inspect_jar(path, rules)


def inspect_jar(path, rules):
    filename = path.name.lower()
    stem = path.stem.lower()
    try:
        mtime = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        size = path.stat().st_size
    except OSError as exc:
        return {
            "path": str(path),
            "file": path.name,
            "status": "error",
            "hits": [],
            "detail": str(exc),
            "mtime": "",
            "size": 0,
        }

    hits = []
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            if len(names) > 12000:
                names = names[:12000]
            entry_blob = "\n".join(n.lower().replace("\\", "/") for n in names)
            meta = _read_meta(zf, names) or ""
            byte_hits = _scan_bytes(zf, names) or []
    except zipfile.BadZipFile:
        return {
            "path": str(path),
            "file": path.name,
            "status": "error",
            "hits": [],
            "detail": "не jar / битый архив",
            "mtime": mtime,
            "size": size,
        }
    except Exception as exc:
        return {
            "path": str(path),
            "file": path.name,
            "status": "error",
            "hits": [],
            "detail": str(exc),
            "mtime": mtime,
            "size": size,
        }

    for rule in rules:
        matched = False
        for needle in rule["file"]:
            if needle and (needle in filename or needle in stem):
                matched = True
                break
        if not matched:
            for needle in rule["id"]:
                if needle and re.search(
                    r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])",
                    meta,
                ):
                    matched = True
                    break
        if not matched:
            for needle in rule["path"]:
                if needle and (needle in entry_blob or needle in meta or needle in filename):
                    matched = True
                    break
        if matched:
            hits.append({"name": rule["name"], "level": rule["level"]})

    for extra in byte_hits:
        if extra["name"] not in {h["name"] for h in hits}:
            hits.append(extra)

    levels = {h["level"] for h in hits}
    if "cheat" in levels:
        status = "cheat"
    elif "blocked" in levels:
        status = "blocked"
    elif _is_verified(filename, stem, meta):
        status = "verified"
    else:
        status = "unknown"
    return {
        "path": str(path),
        "file": path.name,
        "status": status,
        "hits": hits,
        "detail": ", ".join(dict.fromkeys(h["name"] for h in hits)),
        "mtime": mtime,
        "size": size,
    }


def _is_verified(filename, stem, meta):
    blob = filename + "\n" + stem + "\n" + meta
    for word in VERIFIED_WORDS:
        if re.search(r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])", blob):
            return True
    return False


def class_names(path, limit=2500):
    with zipfile.ZipFile(path) as zf:
        names = [n for n in zf.namelist() if n.endswith(".class")]
    return names[:limit]


def jar_entries(path):
    with zipfile.ZipFile(path) as zf:
        return [n for n in zf.namelist() if not n.endswith("/")]


def class_strings(data, limit=500):
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        text = data[:4000].decode("utf-8", "replace")
        return [line for line in text.splitlines() if line.strip()][:limit]
    count = int.from_bytes(data[8:10], "big")
    i = 10
    out = []
    n = 1
    while n < count and i < len(data):
        tag = data[i]
        i += 1
        if tag == 1:
            if i + 2 > len(data):
                break
            ln = int.from_bytes(data[i : i + 2], "big")
            i += 2
            raw = data[i : i + ln]
            i += ln
            text = raw.decode("utf-8", "replace")
            if text and any(ch.isprintable() for ch in text):
                out.append(text)
            if len(out) >= limit:
                break
        elif tag in (7, 8, 16, 19, 20):
            i += 2
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            i += 4
        elif tag in (5, 6):
            i += 8
            n += 1
        elif tag == 15:
            i += 3
        else:
            break
        n += 1
    return out


def entry_preview(path, name):
    with zipfile.ZipFile(path) as zf:
        info = zf.getinfo(name)
        if info.file_size > 1_500_000:
            return ["Файл больше 1.5 МБ, показаны только имя и размер.", name, str(info.file_size)]
        raw = zf.read(name)
    if name.endswith(".class"):
        return class_strings(raw)
    return raw[:12000].decode("utf-8", "replace").splitlines()


def loaded_log_text():
    appdata = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    chunks = []
    for rel in (
        Path(".minecraft") / "logs" / "latest.log",
        Path(".minecraft") / "logs" / "debug.log",
    ):
        path = appdata / rel
        if not path.exists():
            continue
        try:
            data = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        chunks.append(data[-500000:].lower())
    return "\n".join(chunks)


def scan(roots, rules, stop, on_jar=None, on_tick=None):
    results = []
    seen = set()
    walked = 0
    for jar in iter_jars(roots, stop):
        if stop.is_set():
            break
        try:
            key = str(jar.resolve()).lower()
        except OSError:
            key = str(jar).lower()
        if key in seen:
            continue
        seen.add(key)
        walked += 1
        if on_tick and walked % 25 == 0:
            on_tick(walked, jar)
        row = inspect_any(jar, rules)
        results.append(row)
        if on_jar:
            on_jar(row, walked)
    return results


STATUS_RU = {
    "verified": "Verified",
    "unknown": "Unknown",
    "cheat": "Cheats",
    "blocked": "Blocked",
    "error": "Error",
}


def write_report(path, rows):
    lines = [
        "CubeHead Checker",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "",
    ]
    counts = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    lines.append(
        "jar: {0} | verified: {1} | unknown: {2} | cheats: {3} | blocked: {4}".format(
            len(rows),
            counts.get("verified", 0),
            counts.get("unknown", 0) + counts.get("error", 0),
            counts.get("cheat", 0),
            counts.get("blocked", 0),
        )
    )
    lines.append("")
    for row in rows:
        if row["status"] in ("verified",):
            continue
        lines.append(
            "{status}\t{detail}\t{file}\t{path}".format(
                status=STATUS_RU.get(row["status"], row["status"]),
                detail=row.get("detail") or "",
                file=row["file"],
                path=row["path"],
            )
        )
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


_YCHECK = {"proc": None}
_WIN = {}


def ycheck_exe():
    names = ("Y-check.exe", "Y-Check.exe", "y-check.exe")
    folders = (
        Path(r"C:\Users\TRXPC\Downloads"),
        app_dir(),
        Path.home() / "Downloads",
    )
    for folder in folders:
        for name in names:
            path = folder / name
            if path.exists():
                return path
    return None


def _win_api():
    if _WIN:
        return _WIN["user32"], _WIN["text"], _WIN["num"]
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    text = user32.SendMessageW
    text.argtypes = [wintypes.HWND, ctypes.c_uint, wintypes.WPARAM, wintypes.LPCWSTR]
    text.restype = ctypes.c_ssize_t
    number = ctypes.WinDLL("user32", use_last_error=True).SendMessageW
    number.argtypes = [wintypes.HWND, ctypes.c_uint, wintypes.WPARAM, wintypes.LPARAM]
    number.restype = ctypes.c_ssize_t
    _WIN["user32"] = user32
    _WIN["text"] = text
    _WIN["num"] = number
    _WIN["ctypes"] = ctypes
    _WIN["wintypes"] = wintypes
    return user32, text, number


def _ycheck_hwnd(pid):
    import ctypes
    from ctypes import wintypes

    user32, _, _ = _win_api()
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def enum_top(hwnd, _lparam):
        got = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(got))
        if got.value != pid:
            return True
        title = ctypes.create_unicode_buffer(64)
        user32.GetWindowTextW(hwnd, title, 64)
        if title.value == "Y-check":
            found.append(hwnd)
        return True

    user32.EnumWindows(enum_top, 0)
    return found[0] if found else None


def _ycheck_controls(main):
    import ctypes
    from ctypes import wintypes

    user32, _, _ = _win_api()
    found = {"edit": None, "scan": None, "pc": None, "rich": None}

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def enum_child(hwnd, _lparam):
        cls = ctypes.create_unicode_buffer(220)
        txt = ctypes.create_unicode_buffer(40)
        user32.GetClassNameW(hwnd, cls, 220)
        user32.GetWindowTextW(hwnd, txt, 40)
        name = cls.value
        if "RICHEDIT" in name:
            found["rich"] = hwnd
        elif "Edit" in name:
            found["edit"] = hwnd
        elif "Button" in name and txt.value == "Scan":
            found["scan"] = hwnd
        elif "Button" in name and txt.value == "Scan PC":
            found["pc"] = hwnd
        return True

    user32.EnumChildWindows(main, enum_child, 0)
    return found


def _hwnd_text(hwnd):
    import ctypes

    _, text, number = _win_api()
    length = number(hwnd, 0x000E, 0, 0)
    if length <= 0:
        return ""
    length = min(int(length), 200000)
    buf = ctypes.create_unicode_buffer(length + 1)
    text(hwnd, 0x000D, length + 1, ctypes.cast(buf, ctypes.c_wchar_p))
    return buf.value


def _window_on_screen(hwnd):
    import ctypes
    from ctypes import wintypes

    user32, _, _ = _win_api()
    if not user32.IsWindowVisible(hwnd):
        return False
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    return rect.right > 0 and rect.bottom > 0 and rect.left < 8000 and rect.top < 5000


def _force_hide(hwnd):
    import ctypes

    user32, _, _ = _win_api()
    GWL_EXSTYLE = -20
    WS_EX_APPWINDOW = 0x00040000
    WS_EX_TOOLWINDOW = 0x00000080
    if not _WIN.get("longptr"):
        user32.GetWindowLongPtrW.restype = ctypes.c_ssize_t
        user32.GetWindowLongPtrW.argtypes = [ctypes.c_void_p, ctypes.c_int]
        user32.SetWindowLongPtrW.restype = ctypes.c_ssize_t
        user32.SetWindowLongPtrW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_ssize_t]
        _WIN["longptr"] = True
    style = int(user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE) or 0)
    style = (style | WS_EX_TOOLWINDOW) & ~WS_EX_APPWINDOW
    user32.SetWindowLongPtrW(hwnd, GWL_EXSTYLE, style)
    user32.SetWindowPos(hwnd, 0, -32000, -32000, 0, 0, 0x0001 | 0x0004 | 0x0010 | 0x0020)


def _hide_ycheck_windows(pid):
    import ctypes
    from ctypes import wintypes

    user32, _, _ = _win_api()
    hwnds = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def enum_top(hwnd, _lparam):
        got = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(got))
        if got.value == pid:
            hwnds.append(hwnd)
        return True

    user32.EnumWindows(enum_top, 0)
    main = None
    for hwnd in hwnds:
        title = ctypes.create_unicode_buffer(64)
        user32.GetWindowTextW(hwnd, title, 64)
        if title.value != "Y-check":
            continue
        main = hwnd
        if _window_on_screen(hwnd) or not _YCHECK.get("hidden"):
            _force_hide(hwnd)
            _YCHECK["hidden"] = True
    return main


def _ensure_ycheck():
    import subprocess
    import time

    exe = ycheck_exe()
    if exe is None:
        raise FileNotFoundError("Y-check.exe не найден")
    proc = _YCHECK.get("proc")
    if proc is not None and proc.poll() is None:
        hwnd = _hide_ycheck_windows(proc.pid) or _ycheck_hwnd(proc.pid)
        if hwnd:
            return proc, hwnd
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 4
    proc = subprocess.Popen([str(exe)], startupinfo=startup)
    _YCHECK["proc"] = proc
    _YCHECK["hidden"] = False
    hwnd = None
    for _ in range(50):
        time.sleep(0.1)
        hwnd = _ycheck_hwnd(proc.pid)
        if hwnd:
            break
    if not hwnd:
        raise RuntimeError("Y-check не открыл окно")
    _hide_ycheck_windows(proc.pid)
    return proc, hwnd


def _clean_title(name):
    name = (name or "").strip()
    if name and not name[:1].isalnum():
        return name[1:].strip() or name
    return name


def _ycheck_level(name, note):
    note_l = (note or "").strip().lower()
    mark = (name or "")[:1]
    if note_l == "verified" or mark == "\u2713":
        return "verified"
    if note_l in ("cheats", "cheat") or mark in ("\u2717", "\u2715", "\u2716", "\u00d7"):
        return "cheat"
    if note_l == "blocked":
        return "blocked"
    return "unknown"


def _read_ycheck_items(hwnd):
    import json
    import subprocess
    import tempfile

    script = r"""
param(
  [Parameter(Mandatory=$true)][string]$Hwnd,
  [Parameter(Mandatory=$true)][string]$Out
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient
$root = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]([long]$Hwnd))
$cond = New-Object System.Windows.Automation.PropertyCondition(
  [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
  [System.Windows.Automation.ControlType]::ListItem
)
$items = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)
$rows = New-Object System.Collections.Generic.List[object]
foreach ($item in $items) {
  $kids = $item.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
  $texts = New-Object System.Collections.Generic.List[string]
  foreach ($kid in $kids) {
    if ($kid.Current.ControlType.ProgrammaticName -eq "ControlType.Text") {
      $texts.Add([string]$kid.Current.Name)
    }
  }
  if ($texts.Count -lt 1 -or [string]::IsNullOrWhiteSpace($texts[0])) { continue }
  $rows.Add([pscustomobject]@{
    name = $texts[0]
    path = $(if ($texts.Count -gt 1) { $texts[1] } else { "" })
    date = $(if ($texts.Count -gt 2) { $texts[2] } else { "" })
    size = $(if ($texts.Count -gt 3) { $texts[3] } else { "" })
    note = $(if ($texts.Count -gt 4) { $texts[4] } else { "" })
  })
}
if ($rows.Count -eq 0) { $json = "[]" } else { $json = ConvertTo-Json -InputObject @($rows.ToArray()) -Compress -Depth 4 }
[System.IO.File]::WriteAllText($Out, $json, [System.Text.UTF8Encoding]::new($false))
"""
    with tempfile.TemporaryDirectory() as folder:
        ps1 = Path(folder) / "read.ps1"
        out = Path(folder) / "rows.json"
        ps1.write_text(script, encoding="utf-8")
        done = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ps1),
                "-Hwnd",
                str(int(hwnd)),
                "-Out",
                str(out),
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        if done.returncode != 0 or not out.exists():
            detail = (done.stderr or done.stdout or "список не прочитался").strip()
            raise RuntimeError(detail[-400:])
        data = json.loads(out.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = [data]
    rows = []
    for item in data or []:
        title = _clean_title(item.get("name"))
        if not title:
            continue
        note = (item.get("note") or "").strip()
        size = (item.get("size") or "").strip()
        plain = {"verified", "unknown", "cheats", "cheat", "blocked", "processed"}
        detail = size or note if note.lower() in plain else (note or size)
        rows.append(
            {
                "path": item.get("path") or "",
                "file": title,
                "status": _ycheck_level(item.get("name") or "", note),
                "hits": [],
                "detail": detail or "Y-check",
                "mtime": item.get("date") or "",
                "size": 0,
            }
        )
    return rows


def _ycheck_status_line(main):
    import ctypes
    from ctypes import wintypes

    user32, text, number = _win_api()
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def enum_child(hwnd, _lparam):
        length = number(hwnd, 0x000E, 0, 0)
        if not (0 < length < 240):
            return True
        buf = ctypes.create_unicode_buffer(length + 1)
        text(hwnd, 0x000D, length + 1, ctypes.cast(buf, ctypes.c_wchar_p))
        value = buf.value.strip()
        if value.startswith("Байткод") or value.startswith("Анализ байткода"):
            found.append(value)
        return True

    user32.EnumChildWindows(main, enum_child, 0)
    return found[-1] if found else ""


def ycheck_scan(folder, pc, stop, on_tick=None):
    import time

    proc, hwnd = _ensure_ycheck()
    _, text, number = _win_api()
    _hide_ycheck_windows(proc.pid)
    controls = _ycheck_controls(hwnd)
    if not controls["rich"] or not (controls["pc"] if pc else controls["scan"] and controls["edit"]):
        raise RuntimeError("У Y-check нет кнопки Scan")
    previous = _hwnd_text(controls["rich"])
    if pc:
        number(controls["pc"], 0x00F5, 0, 0)
    else:
        text(controls["edit"], 0x000C, 0, str(folder))
        number(controls["scan"], 0x00F5, 0, 0)
    deadline = time.time() + 20 * 60
    last = ""
    summary = ""
    started = False
    while time.time() < deadline:
        if stop is not None and stop.is_set():
            proc.kill()
            _YCHECK["proc"] = None
            return []
        summary = _hwnd_text(controls["rich"])
        line = _ycheck_status_line(hwnd)
        if not line:
            for part in reversed(summary.splitlines()):
                if part.strip():
                    line = part.strip()
                    break
        if summary != previous:
            started = True
        if line and line != last and on_tick:
            on_tick(line[:220])
            last = line
        if started and "Done:" in summary:
            break
        _hide_ycheck_windows(proc.pid)
        time.sleep(0.25)
    else:
        raise RuntimeError("Y-check не закончил проверку за 20 минут")
    _hide_ycheck_windows(proc.pid)
    rows = _read_ycheck_items(hwnd)
    if not rows and "Found 0" not in summary and "Done: 0 verified, 0 unknown, 0 cheats, 0 blocked" not in summary:
        raise RuntimeError("Y-check закончил проверку, но список модов не прочитался")
    return rows


def run_headless(roots):
    rules = load_rules()
    rows = scan(roots, rules, threading.Event())
    hits = [r for r in rows if r["status"] in ("cheat", "blocked")]
    print(f"JARS {len(rows)} HITS {len(hits)}")
    for row in hits:
        print(f"{row['status'].upper()} {row['detail']} | {row['path']}")
    return rows


def icon_file():
    for folder in (bundle_dir(), app_dir(), HERE):
        candidate = folder / "cubehead.ico"
        if candidate.exists():
            return candidate
    return HERE / "cubehead.ico"


def play_tone(freq=680, ms=45, volume=0.16):
    try:
        import winsound
    except Exception:
        return
    rate = 22050
    n = max(1, int(rate * ms / 1000))
    frames = bytearray()
    for i in range(n):
        env = 1 - (i / n)
        sample = int(volume * 32767 * math.sin(2 * math.pi * freq * i / rate) * env)
        frames += struct.pack("<h", sample)
    data = bytes(frames)
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + len(data),
        b"WAVE",
        b"fmt ",
        16,
        1,
        1,
        rate,
        rate * 2,
        2,
        16,
        b"data",
        len(data),
    )
    try:
        winsound.PlaySound(header + data, winsound.SND_MEMORY | winsound.SND_ASYNC)
    except Exception:
        pass


def launch_gui():
    import ctypes
    import tkinter as tk
    from tkinter import filedialog, messagebox

    BG = "#241c2c"
    PANEL = "#2c2236"
    CARD = "#32283b"
    EDGE = "#4a3d55"
    TEXT = "#f7f1f6"
    MUTED = "#b5a7b8"
    PINK = "#e3b4c8"
    PINK_BTN = "#d7a4bb"
    GREEN = "#8ed48f"
    CHEAT_C = "#e7a4ae"
    BLOCK_C = "#b7a6ea"
    FONT = "Segoe UI"

    rules = load_rules()
    stop = threading.Event()
    events = queue.Queue()
    rows = []
    worker = {"thread": None}
    selected = {"path": ""}
    page = {"name": "mods"}
    winbox = {"max": False, "geo": "1120x720"}

    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("CubeHead.Checker")
    except Exception:
        pass

    root = tk.Tk()
    root.title("CubeHead Checker")
    root.geometry("1120x720")
    root.configure(bg=BG)
    root.overrideredirect(True)
    root.update_idletasks()
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"1120x720+{(sw - 1120) // 2}+{(sh - 720) // 2}")

    def taskbar():
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        GWL_EXSTYLE = -20
        style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        style = (style & ~0x00000080) | 0x00040000
        ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)
        pref = ctypes.c_int(2)
        try:
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(pref), ctypes.sizeof(pref))
        except Exception:
            pass
        ico = icon_file()
        if ico.exists():
            try:
                root.iconbitmap(default=str(ico))
            except Exception:
                pass

    root.after(10, taskbar)
    root.after(80, lambda: (root.withdraw(), root.after(40, root.deiconify), root.after(60, taskbar)))

    drag = {"x": 0, "y": 0}

    def start_drag(event):
        drag["x"], drag["y"] = event.x, event.y

    def on_drag(event):
        if winbox["max"]:
            return
        x = root.winfo_x() + event.x - drag["x"]
        y = root.winfo_y() + event.y - drag["y"]
        root.geometry(f"+{x}+{y}")

    def minimize():
        root.overrideredirect(False)
        root.iconify()

    def restore(_event=None):
        if root.state() == "normal":
            root.overrideredirect(True)
            root.after(10, taskbar)

    def toggle_max():
        if winbox["max"]:
            root.geometry(winbox["geo"])
            winbox["max"] = False
        else:
            winbox["geo"] = root.geometry()
            root.geometry(f"{sw}x{sh}+0+0")
            winbox["max"] = True

    root.bind("<Map>", restore)

    shell = tk.Frame(root, bg=BG, highlightbackground=EDGE, highlightthickness=1)
    shell.pack(fill="both", expand=True)

    top = tk.Frame(shell, bg=BG, height=58)
    top.pack(fill="x")
    top.pack_propagate(False)
    top.bind("<Button-1>", start_drag)
    top.bind("<B1-Motion>", on_drag)

    logo = tk.Canvas(top, width=36, height=36, bg=BG, highlightthickness=0)
    logo.pack(side="left", padx=(16, 10), pady=11)
    logo.create_oval(1, 1, 35, 35, fill=PINK, outline="")
    logo.create_text(18, 18, text="C", fill="#3a2433", font=(FONT, 16, "bold"))
    logo.bind("<Button-1>", start_drag)
    logo.bind("<B1-Motion>", on_drag)

    namebox = tk.Frame(top, bg=BG)
    namebox.pack(side="left")
    namebox.bind("<Button-1>", start_drag)
    namebox.bind("<B1-Motion>", on_drag)
    title = tk.Label(namebox, text="CubeHead", bg=BG, fg=TEXT, font=(FONT, 14, "bold"))
    title.pack(anchor="w")
    subtitle = tk.Label(namebox, text="MOD ANALYZER", bg=BG, fg=MUTED, font=(FONT, 8))
    subtitle.pack(anchor="w")
    title.bind("<Button-1>", start_drag)
    title.bind("<B1-Motion>", on_drag)
    subtitle.bind("<Button-1>", start_drag)
    subtitle.bind("<B1-Motion>", on_drag)

    def win_btn(text, command, hover="#3a3144"):
        b = tk.Label(top, text=text, bg="#32283b", fg=TEXT, font=(FONT, 11), width=3, padx=4, pady=2, cursor="hand2")
        b.pack(side="right", padx=(0, 8), pady=14)
        def press(_e):
            play_tone(500, 24)
            command()

        b.bind("<Button-1>", press)
        b.bind("<Enter>", lambda _e: b.configure(bg=hover))
        b.bind("<Leave>", lambda _e: b.configure(bg="#32283b"))
        return b

    win_btn("✕", root.destroy, "#8a3d4a")
    win_btn("▢", toggle_max)
    win_btn("—", minimize)

    view = {"sort": "status", "loaded_only": False, "menu": None}

    def close_menu(_e=None):
        menu = view["menu"]
        if menu is not None:
            try:
                menu.destroy()
            except Exception:
                pass
            view["menu"] = None

    def menu_item(parent, text, command, arrow=False):
        row = tk.Label(
            parent,
            text=(text + "    ›") if arrow else text,
            bg="#2a2233",
            fg=TEXT,
            anchor="w",
            font=(FONT, 10),
            padx=14,
            pady=8,
            cursor="hand2",
        )
        row.pack(fill="x")

        def enter(_e):
            row.configure(bg="#3a3144")

        def leave(_e):
            row.configure(bg="#2a2233")

        def press(_e):
            row.configure(bg=PINK_BTN, fg="#3a2433")
            play_tone(640, 30)
            root.after(70, lambda: (row.configure(bg="#3a3144", fg=TEXT), command()))

        row.bind("<Enter>", enter)
        row.bind("<Leave>", leave)
        row.bind("<Button-1>", press)
        return row

    def save_desktop():
        close_menu()
        desk = Path.home() / "Desktop"
        dest = desk / "cubehead-report.txt"
        write_report(dest, rows)
        status.configure(text="Сохранено: " + str(dest))
        play_tone(520, 40)
        play_tone(760, 60)

    def clear_results():
        close_menu()
        rows.clear()
        selected["path"] = ""
        paint_results()
        status.configure(text="Результаты очищены")
        play_tone(420, 40)

    def toggle_loaded():
        close_menu()
        view["loaded_only"] = not view["loaded_only"]
        paint_results()
        if view["loaded_only"] and not loaded_log_text():
            status.configure(text="Лог игры не найден. Запусти Minecraft хотя бы раз.")
        else:
            status.configure(text="Только загруженные моды" if view["loaded_only"] else "Все найденные файлы")

    def set_sort(mode):
        close_menu()
        view["sort"] = mode
        paint_results()

    def open_settings(anchor=None):
        close_menu()
        play_tone(600, 28)
        menu = tk.Frame(root, bg="#2a2233", highlightbackground=EDGE, highlightthickness=1)
        view["menu"] = menu
        menu_item(menu, "Только загруженные в игру моды", toggle_loaded)
        menu_item(menu, "Save — Рабочий стол", save_desktop)
        menu_item(menu, "Сортировка", lambda: open_sort(menu), arrow=True)
        menu_item(menu, "Clear (очистить результаты)", clear_results)
        menu.update_idletasks()
        x = root.winfo_width() - menu.winfo_reqwidth() - 18
        menu.place(x=x, y=54)
        root.bind("<Button-1>", lambda e: close_menu() if e.widget is root else None, add="+")

    def open_sort(parent):
        play_tone(600, 28)
        sub = tk.Frame(root, bg="#2a2233", highlightbackground=EDGE, highlightthickness=1)
        view["sort_menu"] = sub

        def pick(mode):
            try:
                sub.destroy()
            except Exception:
                pass
            set_sort(mode)

        menu_item(sub, "По статусу", lambda: pick("status"))
        menu_item(sub, "По имени", lambda: pick("name"))
        menu_item(sub, "По дате", lambda: pick("date"))
        parent.update_idletasks()
        x = root.winfo_width() - parent.winfo_width() - sub.winfo_reqwidth() - 24
        sub.place(x=max(8, x), y=54 + 16 + 36)

    win_btn("⚙", open_settings)

    body = tk.Frame(shell, bg=BG)
    body.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    side = tk.Frame(body, bg=BG, width=228)
    side.pack(side="left", fill="y", padx=(0, 12))
    side.pack_propagate(False)

    def card(parent, **pack):
        f = tk.Frame(parent, bg=PANEL, highlightbackground=EDGE, highlightthickness=1)
        f.pack(**pack)
        return f

    tools = card(side, fill="x", pady=(0, 10))
    tk.Label(tools, text="TOOLS", bg=PANEL, fg=MUTED, font=(FONT, 8)).pack(anchor="w", padx=12, pady=(10, 6))
    tool_btns = {}

    def tool_button(key, label):
        b = tk.Label(tools, text=label, bg=PANEL, fg=TEXT, font=(FONT, 10), anchor="w", padx=12, pady=7, cursor="hand2")
        b.pack(fill="x", padx=8, pady=2)
        b.bind("<Button-1>", lambda _e: show_page(key))
        tool_btns[key] = b
        return b

    tool_button("mods", "Mod Analyzer")
    tool_button("bytes", "Bytecode Viewer")
    tk.Frame(tools, bg=PANEL, height=8).pack()

    legend = card(side, fill="x")
    tk.Label(legend, text="LEGEND", bg=PANEL, fg=MUTED, font=(FONT, 8)).pack(anchor="w", padx=12, pady=(10, 6))

    def legend_row(color, name, desc):
        row = tk.Frame(legend, bg=PANEL)
        row.pack(fill="x", padx=12, pady=3)
        tk.Label(row, text="●", bg=PANEL, fg=color, font=(FONT, 9)).pack(side="left")
        box = tk.Frame(row, bg=PANEL)
        box.pack(side="left", padx=6)
        tk.Label(box, text=name, bg=PANEL, fg=TEXT, font=(FONT, 9, "bold")).pack(anchor="w")
        tk.Label(box, text=desc, bg=PANEL, fg=MUTED, font=(FONT, 8), wraplength=175, justify="left").pack(anchor="w")

    legend_row(GREEN, "Verified", "известный нормальный мод")
    legend_row("#f2f2f2", "Unknown", "нет в списках, смотри сам")
    legend_row(CHEAT_C, "Cheats", "чит-клиент")
    legend_row(BLOCK_C, "Blocked", "мод может быть запрещён")
    legend_row("#9a8ea0", "Processed", "классы внутри выбранного jar")
    tk.Frame(legend, bg=PANEL, height=8).pack()

    main = tk.Frame(body, bg=BG)
    main.pack(side="left", fill="both", expand=True)

    stats_row = tk.Frame(main, bg=BG)
    stats_row.pack(fill="x")
    stat_vals = {}

    def stat_card(key, color, caption):
        holder = tk.Frame(stats_row, bg=BG)
        holder.pack(side="left", fill="x", expand=True, padx=(0, 8))
        box = tk.Frame(holder, bg=CARD, highlightbackground=EDGE, highlightthickness=1)
        box.pack(fill="x")
        inner = tk.Frame(box, bg=CARD)
        inner.pack(fill="x", padx=10, pady=8)
        bar = tk.Frame(inner, bg=color, width=3)
        bar.pack(side="left", fill="y", padx=(0, 8))
        text = tk.Frame(inner, bg=CARD)
        text.pack(side="left", fill="x")
        num = tk.Label(text, text="0", bg=CARD, fg=color, font=(FONT, 18, "bold"))
        num.pack(anchor="w")
        tk.Label(text, text=caption, bg=CARD, fg=MUTED, font=(FONT, 8)).pack(anchor="w")
        stat_vals[key] = num

    stat_card("verified", GREEN, "VERIFIED")
    stat_card("unknown", "#f3f0f4", "UNKNOWN")
    stat_card("cheat", CHEAT_C, "CHEATS")
    stat_card("blocked", BLOCK_C, "BLOCKED")

    mods_page = tk.Frame(main, bg=BG)
    bytes_page = tk.Frame(main, bg=BG)

    path_var = tk.StringVar()
    path_row = tk.Frame(mods_page, bg=BG)
    path_row.pack(fill="x", pady=(12, 8))
    entry = tk.Entry(
        path_row,
        textvariable=path_var,
        bg="#1b1522",
        fg=TEXT,
        insertbackground=TEXT,
        relief="flat",
        font=(FONT, 10),
        highlightthickness=1,
        highlightbackground=EDGE,
        highlightcolor=PINK,
    )
    entry.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 8))
    PLACEHOLDER = "Path to mods folder..."

    def focus_in(_e=None):
        if entry.get() == PLACEHOLDER:
            entry.delete(0, "end")
            entry.configure(fg=TEXT)

    def focus_out(_e=None):
        if not entry.get().strip():
            entry.delete(0, "end")
            entry.insert(0, PLACEHOLDER)
            entry.configure(fg="#7d7084")

    entry.insert(0, PLACEHOLDER)
    entry.configure(fg="#7d7084")
    entry.bind("<FocusIn>", focus_in)
    entry.bind("<FocusOut>", focus_out)

    def flat_button(parent, text, command, fill=PINK_BTN, fg="#3a2433", pad=(14, 7)):
        width = max(86, 12 * len(text) + 28)
        height = 34
        c = tk.Canvas(parent, width=width, height=height, bg=BG, highlightthickness=0, cursor="hand2")
        c.pack(side="left")

        label = {"text": text}

        def draw(color):
            c.delete("all")
            r = 12
            x1, y1, x2, y2 = 1, 1, width - 1, height - 1
            c.create_polygon(
                x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
                x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
                smooth=True, fill=color, outline="",
            )
            c.create_text(width / 2, height / 2, text=label["text"], fill=fg, font=(FONT, 10, "bold"))

        draw(fill)

        def press(_e=None):
            draw("#c489a4" if fill == PINK_BTN else "#2a2433")
            play_tone(700, 32)
            root.after(90, lambda: (draw(fill), command()))

        def enter(_e):
            draw("#efc6d6" if fill == PINK_BTN else "#4a3d55")

        def leave(_e):
            draw(fill)

        def set_text(new):
            label["text"] = new
            draw(fill)

        c.set_text = set_text
        c.bind("<Button-1>", press)
        c.bind("<Enter>", enter)
        c.bind("<Leave>", leave)
        return c

    browse_btn = flat_button(path_row, "Browse", lambda: pick_folder(), fill="#3a3146", fg=TEXT)
    browse_btn.pack_configure(padx=(0, 8))
    scan_btn = flat_button(path_row, "Scan", lambda: scan_path())

    pc_row = tk.Frame(mods_page, bg=BG)
    pc_row.pack(fill="x", pady=(0, 10))
    pc_btn = flat_button(pc_row, "Scan PC", lambda: scan_pc())
    progress_label = tk.Label(pc_row, text="", bg=BG, fg=PINK, font=(FONT, 16, "bold"))
    progress_label.pack(side="left", padx=(16, 0))
    progress_caption = tk.Label(pc_row, text="", bg=BG, fg=MUTED, font=(FONT, 9))
    progress_caption.pack(side="left", padx=(8, 0))

    result = tk.Frame(mods_page, bg=CARD, highlightbackground=EDGE, highlightthickness=1)
    result.pack(fill="both", expand=True)
    result_text = tk.Text(
        result,
        bg=CARD,
        fg=TEXT,
        relief="flat",
        font=(FONT, 10),
        padx=16,
        pady=12,
        wrap="none",
        cursor="arrow",
        highlightthickness=0,
    )
    result_text.pack(fill="both", expand=True)
    result_text.configure(state="disabled")
    result_text.tag_configure("verified", foreground=GREEN)
    result_text.tag_configure("unknown", foreground="#f4f1f5")
    result_text.tag_configure("cheat", foreground=CHEAT_C)
    result_text.tag_configure("blocked", foreground=BLOCK_C)
    result_text.tag_configure("error", foreground="#cbb8a2")
    result_text.tag_configure("dim", foreground=MUTED)
    empty = tk.Label(
        result,
        text="Проверку делает Y-check.\nУкажи папку с модами и нажми Scan\nили Scan PC, чтобы пройтись по всем дискам",
        bg=CARD,
        fg=MUTED,
        font=(FONT, 11),
        justify="center",
    )
    empty.place(relx=0.5, rely=0.5, anchor="center")
    empty_hint = empty.cget("text")
    if not ycheck_exe():
        empty_hint = "Укажи папку с модами и нажми Scan\nили Scan PC, чтобы пройтись по всем дискам"
        empty.configure(text=empty_hint)
    progress_state = {"cur": 0, "total": 0}

    byte_bar = tk.Frame(bytes_page, bg=BG)
    byte_bar.pack(fill="x", pady=(12, 8))
    byte_file = tk.StringVar(value="No file loaded")

    def open_jar_dialog():
        play_tone(640, 28)
        picked = filedialog.askopenfilename(
            title="Открыть JAR",
            parent=root,
            filetypes=[("JAR", "*.jar"), ("Все файлы", "*.*")],
        )
        if picked:
            load_jar_viewer(picked)

    flat_button(byte_bar, "Open JAR", open_jar_dialog, fill="#3a3146", fg=TEXT)
    tk.Label(byte_bar, textvariable=byte_file, bg=BG, fg=MUTED, font=(FONT, 10)).pack(side="left", padx=10)
    tk.Label(byte_bar, text="drop jar anywhere", bg=BG, fg="#7d7084", font=(FONT, 9)).pack(side="right")

    panes = tk.Frame(bytes_page, bg=BG)
    panes.pack(fill="both", expand=True)
    files_card = tk.Frame(panes, bg=CARD, highlightbackground=EDGE, highlightthickness=1, width=280)
    files_card.pack(side="left", fill="y", padx=(0, 10))
    files_card.pack_propagate(False)
    tk.Label(files_card, text="Files", bg=CARD, fg=TEXT, font=(FONT, 10, "bold")).pack(anchor="w", padx=12, pady=(10, 6))
    file_tree = tk.Listbox(
        files_card,
        bg="#241c2c",
        fg=TEXT,
        selectbackground="#5a3d52",
        selectforeground=TEXT,
        relief="flat",
        highlightthickness=0,
        font=("Consolas", 9),
        activestyle="none",
    )
    file_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    drop_hint = tk.Label(files_card, text="Drop jar here\nor click to browse", bg=CARD, fg=MUTED, font=(FONT, 11), justify="center")
    drop_hint.place(relx=0.5, rely=0.55, anchor="center")

    view_card = tk.Frame(panes, bg=CARD, highlightbackground=EDGE, highlightthickness=1)
    view_card.pack(side="left", fill="both", expand=True)
    view_title = tk.Label(view_card, text="Viewer    Select a file in the tree", bg=CARD, fg=MUTED, font=(FONT, 10))
    view_title.pack(anchor="w", padx=12, pady=(10, 6))
    byte_text = tk.Text(view_card, bg="#241c2c", fg="#eadfeb", relief="flat", font=("Consolas", 10), padx=12, pady=10, wrap="none", highlightthickness=0)
    byte_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    byte_text.configure(state="disabled")
    viewer_entries = []

    def load_jar_viewer(path):
        selected["path"] = path
        byte_file.set(Path(path).name)
        drop_hint.place_forget()
        file_tree.delete(0, "end")
        viewer_entries.clear()
        try:
            names = jar_entries(path)
        except Exception as exc:
            set_text(byte_text, str(exc))
            return
        for name in names:
            viewer_entries.append(name)
            file_tree.insert("end", name)
        view_title.configure(text="Viewer    Select a file in the tree")
        set_text(byte_text, "")
        play_tone(540, 30)
        root.after(70, lambda: play_tone(760, 40))

    def on_tree_select(_event=None):
        if not file_tree.curselection() or not selected["path"]:
            return
        name = viewer_entries[file_tree.curselection()[0]]
        view_title.configure(text="Viewer    " + name)
        try:
            lines = entry_preview(selected["path"], name)
        except Exception as exc:
            set_text(byte_text, str(exc))
            return
        set_text(byte_text, "\n".join(lines) if lines else "Пусто")
        play_tone(880, 24)

    file_tree.bind("<<ListboxSelect>>", on_tree_select)
    drop_hint.bind("<Button-1>", lambda _e: open_jar_dialog())
    files_card.bind("<Button-1>", lambda _e: open_jar_dialog())

    status = tk.Label(mods_page, text="", bg=BG, fg=MUTED, font=(FONT, 9))
    status.pack(anchor="w", pady=(8, 0))

    def counts():
        data = {"verified": 0, "unknown": 0, "cheat": 0, "blocked": 0}
        for row in rows:
            key = row["status"]
            if key == "error":
                key = "unknown"
            if key in data:
                data[key] += 1
        return data

    def refresh_stats():
        data = counts()
        for key, num in data.items():
            stat_vals[key].configure(text=str(num))

    def set_text(widget, content, tags=None):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        if tags:
            for chunk, tag in tags:
                widget.insert("end", chunk, tag)
        else:
            widget.insert("end", content)
        widget.configure(state="disabled")

    def visible_rows():
        order_key = {"cheat": 0, "blocked": 1, "unknown": 2, "error": 3, "verified": 4}
        shown = list(rows)
        if view["loaded_only"]:
            log = loaded_log_text()
            if log:
                shown = [r for r in shown if r["file"].lower() in log or Path(r["file"]).stem.lower() in log]
        mode = view["sort"]
        if mode == "name":
            shown.sort(key=lambda r: r["file"].lower())
        elif mode == "date":
            shown.sort(key=lambda r: r.get("mtime") or "", reverse=True)
        else:
            shown.sort(key=lambda r: (order_key.get(r["status"], 9), r["file"].lower()))
        return shown

    def paint_results():
        if not rows:
            if not progress_state["total"]:
                empty.configure(text=empty_hint, fg=MUTED, font=(FONT, 11))
            empty.place(relx=0.5, rely=0.5, anchor="center")
            set_text(result_text, "")
            refresh_stats()
            return
        empty.place_forget()
        empty.configure(text=empty_hint, fg=MUTED, font=(FONT, 11))
        shown = visible_rows()
        tags = []
        clipped = False
        if len(shown) > 2500:
            shown = [r for r in shown if r["status"] in ("cheat", "blocked", "error")] + [
                r for r in shown if r["status"] not in ("cheat", "blocked", "error")
            ][:800]
            clipped = True
        for row in shown:
            line = f"{STATUS_RU.get(row['status'], row['status']):<10}  {row.get('detail') or '—':<22}  {row['file']}\n"
            tags.append((line, row["status"] if row["status"] in STATUS_RU else "unknown"))
            tags.append((f"{'':<10}  {row['path']}\n", "dim"))
        if clipped:
            tags.append(("\nСписок длинный: сверху срабатывания, остальное обрезано.\n", "dim"))
        set_text(result_text, "", tags)
        refresh_stats()

    def show_page(name):
        if page["name"] == name and name == "mods":
            return
        play_tone(620, 28)
        page["name"] = name
        subtitle.configure(text="BYTECODE VIEWER" if name == "bytes" else "MOD ANALYZER")
        for key, btn in tool_btns.items():
            if key == name:
                btn.configure(bg=PINK_BTN, fg="#3a2433")
            else:
                btn.configure(bg=PANEL, fg=TEXT)
        leaving = bytes_page if name == "mods" else mods_page
        coming = mods_page if name == "mods" else bytes_page
        leaving.pack_forget()
        coming.pack(fill="both", expand=True)
        coming.configure(bg="#3a2c44")

        def settle(step=0):
            shades = ("#34283c", "#2e2436", BG)
            if step >= len(shades):
                return
            try:
                coming.configure(bg=shades[step])
            except tk.TclError:
                return
            root.after(36, lambda: settle(step + 1))

        settle()
        if name == "bytes" and selected["path"]:
            load_jar_viewer(selected["path"])

    def on_result_click(event):
        index = result_text.index(f"@{event.x},{event.y}")
        line = int(str(index).split(".")[0])
        # each item is 2 lines
        item = (line - 1) // 2
        shown = visible_rows()
        if 0 <= item < len(shown):
            selected["path"] = shown[item]["path"]
            status.configure(text=shown[item]["path"])

    def on_result_double(_event):
        path = selected["path"]
        target = Path(path) if path else None
        if target and target.exists():
            os.startfile(target if target.is_dir() else target.parent)
        elif target and target.parent.exists():
            os.startfile(target.parent)

    result_text.bind("<Button-1>", on_result_click)
    result_text.bind("<Double-1>", on_result_double)

    def set_busy(busy):
        pc_btn.set_text("Stop" if busy else "Scan PC")

    def begin(roots, pc=False):
        if worker["thread"] and worker["thread"].is_alive():
            stop.set()
            status.configure(text="Останавливаю…")
            return
        folder = None
        if not pc:
            existing = [p for p in roots if p.exists()]
            if not existing:
                messagebox.showinfo("CubeHead", "Папка не найдена.", parent=root)
                return
            folder = existing[0]
            if folder.is_file():
                folder = folder.parent
        rows.clear()
        paint_results()
        stop.clear()
        set_busy(True)
        engine = ycheck_exe()
        progress_state["cur"] = 0
        progress_state["total"] = 0
        progress_label.configure(text="")
        progress_caption.configure(text="")
        empty.configure(text="0 / …\nпроверено", fg=PINK, font=(FONT, 28, "bold"))
        empty.place(relx=0.5, rely=0.5, anchor="center")
        status.configure(text="Y-check проверяет…" if engine else "Сканирую…")
        root.lift()

        def work():
            if engine:
                try:
                    found = ycheck_scan(folder, pc, stop, on_tick=lambda msg: events.put(("tick", "Y-check: " + msg)))
                except Exception as exc:
                    events.put(("done", f"Ошибка: {exc}"))
                    return
                for row in found:
                    if stop.is_set():
                        break
                    events.put(("jar", row))
                events.put(("done", "Остановлено" if stop.is_set() else "Готово · Y-check"))
                return

            def on_jar(row, n):
                events.put(("jar", row))
                if n % 10 == 0:
                    events.put(("tick", f"Проверено jar: {n}   {row['file']}"))

            try:
                scan(existing, rules, stop, on_jar=on_jar, on_tick=lambda n, p: events.put(("tick", f"Проверено jar: {n}   {p.name}")))
            except Exception as exc:
                events.put(("done", f"Ошибка: {exc}"))
                return
            events.put(("done", "Остановлено" if stop.is_set() else "Готово"))

        worker["thread"] = threading.Thread(target=work, daemon=True)
        worker["thread"].start()

    def pick_folder():
        play_tone(640, 28)
        dialog = tk.Toplevel(root)
        dialog.title("Куда смотреть")
        dialog.geometry("760x540")
        dialog.configure(bg=BG)
        dialog.transient(root)
        dialog.grab_set()
        tk.Label(dialog, text="Папка, диск или программа", bg=BG, fg=TEXT, font=(FONT, 16, "bold")).pack(anchor="w", padx=18, pady=(16, 4))
        tk.Label(dialog, text="Выбери диск или папку. Для exe/jar нажми «Программа».", bg=BG, fg=MUTED, font=(FONT, 10)).pack(anchor="w", padx=18, pady=(0, 10))
        listing = tk.Listbox(dialog, bg="#1b1522", fg=TEXT, selectbackground="#5a3d52", relief="flat", highlightthickness=0, font=(FONT, 12), activestyle="none")
        listing.pack(fill="both", expand=True, padx=18, pady=8)
        choices = []

        def add(label, path):
            choices.append(path)
            listing.insert("end", label)

        add("Загрузки", Path.home() / "Downloads")
        add("Рабочий стол", Path.home() / "Desktop")
        add("Документы", Path.home() / "Documents")
        mc = Path(os.environ.get("APPDATA", "")) / ".minecraft" / "mods"
        add("Minecraft mods", mc)
        for drive in pc_roots():
            add("Диск " + str(drive), drive)

        def use_path(path):
            dialog.destroy()
            entry.configure(fg=TEXT)
            path_var.set(str(path))
            play_tone(760, 36)

        def choose(_e=None):
            if not listing.curselection():
                return
            use_path(choices[listing.curselection()[0]])

        def pick_program():
            dialog.destroy()
            picked = filedialog.askopenfilename(
                title="Программа или jar",
                parent=root,
                filetypes=[("Программа или мод", "*.exe;*.jar"), ("EXE", "*.exe"), ("JAR", "*.jar")],
            )
            if picked:
                entry.configure(fg=TEXT)
                path_var.set(picked)
                play_tone(760, 36)

        listing.bind("<Double-1>", choose)
        buttons = tk.Frame(dialog, bg=BG)
        buttons.pack(fill="x", padx=18, pady=(0, 16))
        flat_button(buttons, "Открыть", choose)
        tk.Frame(buttons, width=8, bg=BG).pack(side="left")
        flat_button(buttons, "Программа", pick_program, fill="#3a3146", fg=TEXT)
        tk.Frame(buttons, width=8, bg=BG).pack(side="left")
        flat_button(buttons, "Закрыть", dialog.destroy, fill="#3a3146", fg=TEXT)

    def scan_path():
        raw = path_var.get().strip()
        if not raw or raw == "Path to mods folder...":
            messagebox.showinfo("CubeHead", "Укажи папку с модами.", parent=root)
            return
        begin([Path(raw)])

    def scan_pc():
        if worker["thread"] and worker["thread"].is_alive():
            stop.set()
            return
        if ycheck_exe():
            begin([], pc=True)
            return
        begin(pc_roots())

    def pump():
        dirty = False
        try:
            while True:
                kind, payload = events.get_nowait()
                if kind == "jar":
                    rows.append(payload)
                    dirty = True
                elif kind == "tick":
                    text = str(payload)
                    match = re.search(r"(\d+)\s*/\s*(\d+)", text)
                    found = re.search(r"Found\s+(\d+)", text, re.I)
                    mods = re.search(r"(\d+)\s*мод", text, re.I)
                    name = ""
                    if match:
                        progress_state["cur"] = int(match.group(1))
                        progress_state["total"] = int(match.group(2))
                        name = text[match.end():].strip(" :-")
                    elif mods:
                        progress_state["total"] = int(mods.group(1))
                    elif found:
                        progress_state["total"] = int(found.group(1))
                    else:
                        status.configure(text=text)
                    if progress_state["total"]:
                        cur = progress_state["cur"]
                        total = progress_state["total"]
                        progress_label.configure(text=f"{cur}/{total}")
                        progress_caption.configure(text="проверено")
                        empty.configure(text=f"{cur} / {total}\nпроверено", fg=PINK, font=(FONT, 28, "bold"))
                        if not rows:
                            empty.place(relx=0.5, rely=0.5, anchor="center")
                        status.configure(text=name or f"Проверено {cur} из {total}")
                elif kind == "done":
                    count = progress_label.cget("text")
                    status.configure(text=f"{payload}  {count}".strip())
                    set_busy(False)
                    dirty = True
                    if str(payload).startswith("Готово"):
                        play_tone(523, 50)
                        root.after(90, lambda: play_tone(784, 70))
        except queue.Empty:
            pass
        if dirty:
            paint_results()
        root.after(120, pump)

    try:
        import windnd

        def on_drop(files):
            for raw in files:
                path = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                if path.lower().endswith(".jar"):
                    load_jar_viewer(path)
                    show_page("bytes")
                    break

        windnd.hook_dropfiles(root, on_drop, force_unicode=True)
    except Exception:
        pass

    show_page("mods")
    refresh_stats()
    root.after(120, pump)

    if os.environ.get("CH_PAGE") == "bytes" and os.environ.get("CH_JAR"):
        root.after(500, lambda: (show_page("bytes"), load_jar_viewer(os.environ["CH_JAR"])))

    if os.environ.get("CH_SHOT"):
        def shot():
            root.update()
            try:
                from PIL import ImageGrab
                x, y = root.winfo_rootx(), root.winfo_rooty()
                w, h = root.winfo_width(), root.winfo_height()
                ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(os.environ["CH_SHOT"])
            except Exception as exc:
                Path(os.environ["CH_SHOT"] + ".err").write_text(str(exc), encoding="utf-8")
            root.destroy()
        root.after(1400, shot)

    root.mainloop()


def main(argv):
    if len(argv) >= 3 and argv[1] == "--check":
        rows = run_headless([Path(argv[2])])
        return 2 if any(r["status"] in ("cheat", "blocked") for r in rows) else 0
    if len(argv) >= 2 and argv[1] == "--scan-pc":
        run_headless(pc_roots())
        return 0
    launch_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
