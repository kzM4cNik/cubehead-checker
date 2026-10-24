# CubeHead Checker — local Minecraft jar scan.
# Official files are confirmed by sending only a SHA1 to Modrinth.
import hashlib
import io
import json
import math
import os
import queue
import re
import struct
import sys
import threading
import urllib.error
import urllib.request
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

VERIFIED_IDS = {
    "sodium",
    "iris",
    "lithium",
    "phosphor",
    "indium",
    "ferritecore",
    "modmenu",
    "cloth-config",
    "cloth_config",
    "fabric-api",
    "fabric_api",
    "optifine",
    "jei",
    "roughlyenoughitems",
    "appleskin",
    "lambdynamiclights",
    "lambdynlights",
    "continuity",
    "entityculling",
    "krypton",
    "modernfix",
    "geckolib",
    "architectury",
    "architectury-api",
    "yacl",
    "yet_another_config_lib_v3",
    "puzzleslib",
    "fabric-language-kotlin",
}


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
        if root.is_file() and root.suffix.lower() in {".jar", ".zip"}:
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if stop.is_set():
                return
            dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
            for name in filenames:
                if name.lower().endswith((".jar", ".zip")):
                    yield Path(dirpath) / name


def _entry_paths(names):
    return [n.lower().replace("\\", "/") for n in names]


def _path_has(paths, needle):
    needle = needle.lower().replace("\\", "/").strip("/")
    if not needle:
        return False
    if "/" in needle:
        return any(needle in path for path in paths)
    for path in paths:
        if needle in path.split("/"):
            return True
    return False


def _read_mod_info(zf, names):
    mod_id = ""
    mod_name = ""
    wanted = {"fabric.mod.json", "quilt.mod.json", "mods.toml", "mcmod.info"}
    for name in names:
        low = name.lower().replace("\\", "/")
        base = low.rsplit("/", 1)[-1]
        if base not in wanted and not low.endswith(tuple("/" + item for item in wanted)):
            continue
        try:
            info = zf.getinfo(name)
        except KeyError:
            continue
        if info.file_size > 262144:
            continue
        try:
            text = zf.read(name)[:262144].decode("utf-8", "replace")
        except Exception:
            continue
        if base.endswith(".json") or base == "mcmod.info":
            try:
                data = json.loads(text)
            except Exception:
                data = None
            if isinstance(data, list) and data:
                data = data[0]
            if isinstance(data, dict):
                mod_id = str(data.get("id") or data.get("modid") or mod_id)
                mod_name = str(data.get("name") or mod_name)
        else:
            found_id = re.search(r'(?im)^\s*modid\s*=\s*"([^"]+)"', text)
            found_name = re.search(r'(?im)^\s*displayname\s*=\s*"([^"]+)"', text)
            if found_id:
                mod_id = found_id.group(1)
            if found_name:
                mod_name = found_name.group(1)
        if mod_id and mod_name:
            break
    return mod_id.lower().strip(), mod_name.strip()


def _nested_paths(zf, names, depth=0):
    found = []
    if depth >= 2:
        return found
    seen = 0
    for name in names:
        if seen >= 4:
            break
        if not name.lower().endswith(".jar"):
            continue
        try:
            info = zf.getinfo(name)
        except KeyError:
            continue
        if info.file_size <= 0 or info.file_size > 30_000_000:
            continue
        try:
            inner = zipfile.ZipFile(io.BytesIO(zf.read(name)))
        except Exception:
            continue
        seen += 1
        inner_names = inner.namelist()[:8000]
        found.extend(_entry_paths(inner_names))
        found.extend(_nested_paths(inner, inner_names, depth + 1))
    return found


def _match_rules(rules, filename, stem, mod_id, paths):
    hits = []
    seen = set()
    for rule in rules:
        if rule["name"] in seen:
            continue
        matched = False
        for needle in rule["file"]:
            if needle and (needle in filename or needle in stem):
                matched = True
                break
        if not matched and mod_id:
            for needle in rule["id"]:
                if needle and mod_id == needle:
                    matched = True
                    break
        if not matched:
            for needle in rule["path"]:
                if needle and _path_has(paths, needle):
                    matched = True
                    break
        if matched:
            hits.append({"name": rule["name"], "level": rule["level"]})
            seen.add(rule["name"])
    return hits


_MODRINTH = {"map": None, "writes": 0, "lock": threading.Lock()}


def _modrinth_cache_path():
    folder = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "cubehead-checker"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "modrinth-cache.json"


def _modrinth_cache():
    if _MODRINTH["map"] is None:
        try:
            _MODRINTH["map"] = json.loads(_modrinth_cache_path().read_text(encoding="utf-8"))
        except Exception:
            _MODRINTH["map"] = {}
    return _MODRINTH["map"]


def _file_sha1(path):
    digest = hashlib.sha1()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def lookup_modrinth(sha1):
    cache = _modrinth_cache()
    with _MODRINTH["lock"]:
        cached = cache.get(sha1)
    if isinstance(cached, dict) and "known" in cached:
        return cached
    found = {"known": False, "name": ""}
    try:
        req = urllib.request.Request(
            f"https://api.modrinth.com/v2/version_file/{sha1}?algorithm=sha1",
            headers={"User-Agent": "CubeHeadChecker/1.1", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        found = {"known": True, "name": str(data.get("name") or data.get("version_number") or "Modrinth")}
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            return None
    except Exception:
        return None
    with _MODRINTH["lock"]:
        cache[sha1] = found
        _MODRINTH["writes"] += 1
        if _MODRINTH["writes"] % 20 == 1:
            try:
                _modrinth_cache_path().write_text(json.dumps(cache), encoding="utf-8")
            except OSError:
                pass
    return found


def _row(path, status, hits, detail, mtime, size, mod_name=""):
    return {
        "path": str(path),
        "file": path.name,
        "status": status,
        "hits": hits,
        "detail": detail,
        "mtime": mtime,
        "size": size,
        "mod_name": mod_name,
    }


def _level(hits):
    levels = {hit["level"] for hit in hits}
    if "cheat" in levels:
        return "cheat"
    if "blocked" in levels:
        return "blocked"
    return ""


def inspect_jar(path, rules):
    filename = path.name.lower()
    stem = path.stem.lower()
    try:
        mtime = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        size = path.stat().st_size
    except OSError as exc:
        return _row(path, "unknown", [], str(exc), "", 0)

    if path.suffix.lower() not in {".jar", ".zip"}:
        return _row(path, "unknown", [], "", mtime, size)

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            if len(names) > 12000:
                names = names[:12000]
            mod_id, mod_name = _read_mod_info(zf, names)
            paths = _entry_paths(names)
            paths.extend(_nested_paths(zf, names))
    except zipfile.BadZipFile:
        return _row(path, "unknown", [], "", mtime, size)
    except Exception:
        return _row(path, "unknown", [], "", mtime, size)

    hits = _match_rules(rules, filename, stem, mod_id, paths)
    level = _level(hits)
    if level:
        return _row(path, level, hits, ", ".join(dict.fromkeys(hit["name"] for hit in hits)), mtime, size, mod_name)

    detail = mod_name
    status = "unknown"
    if mod_id:
        try:
            remote = lookup_modrinth(_file_sha1(path))
        except OSError:
            remote = None
        if remote and remote.get("known"):
            status = "verified"
            detail = remote.get("name") or mod_name or mod_id
        elif remote is None and mod_id in VERIFIED_IDS:
            status = "verified"
            detail = mod_name or mod_id
        elif mod_name:
            detail = mod_name
    return _row(path, status, hits, detail, mtime, size, mod_name)


def inspect_any(path, rules):
    return inspect_jar(path, rules)


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
    paths = []
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
        paths.append(jar)
        if on_tick and len(paths) % 20 == 0:
            on_tick(-1, len(paths), jar)
    total = len(paths)
    for index, jar in enumerate(paths, 1):
        if stop.is_set():
            break
        row = inspect_any(jar, rules)
        results.append(row)
        if on_tick:
            on_tick(index, total, jar)
        if on_jar:
            on_jar(row, index, total)
    try:
        cache = _MODRINTH.get("map")
        if cache:
            _modrinth_cache_path().write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass
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
    return None
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

    BG = "#160d14"
    PANEL = "#24141c"
    CARD = "#2c1822"
    EDGE = "#6e3c50"
    TEXT = "#fff7f8"
    MUTED = "#d7b4c2"
    PINK = "#ffb7c5"
    PINK_BTN = "#f4a8bc"
    GREEN = "#b7e4c7"
    CHEAT_C = "#ff8fa3"
    BLOCK_C = "#e4c1f9"
    INK = "#3b1c28"
    FIELD = "#120910"
    SOFT = "#4a2834"
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
    if not os.environ.get("CH_SHOT"):
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

    def paint_flower(canvas, x, y, radius, color, tag=""):
        for step in range(5):
            angle = math.radians(-90 + step * 72)
            cx = x + math.cos(angle) * radius * 0.55
            cy = y + math.sin(angle) * radius * 0.55
            canvas.create_oval(
                cx - radius * 0.46,
                cy - radius * 0.32,
                cx + radius * 0.46,
                cy + radius * 0.32,
                fill=color,
                outline="",
                tags=tag,
            )
        canvas.create_oval(x - 3, y - 3, x + 3, y + 3, fill="#fff6ea", outline="", tags=tag)

    paint_flower(logo, 18, 18, 11, PINK)
    logo.bind("<Button-1>", start_drag)
    logo.bind("<B1-Motion>", on_drag)

    namebox = tk.Frame(top, bg=BG)
    namebox.pack(side="left")
    namebox.bind("<Button-1>", start_drag)
    namebox.bind("<B1-Motion>", on_drag)
    title = tk.Label(namebox, text="CubeHead", bg=BG, fg=TEXT, font=(FONT, 14, "bold"))
    title.pack(anchor="w")
    subtitle = tk.Label(namebox, text="SAKURA  ·  MOD ANALYZER", bg=BG, fg=PINK, font=(FONT, 8))
    subtitle.pack(anchor="w")
    title.bind("<Button-1>", start_drag)
    title.bind("<B1-Motion>", on_drag)
    subtitle.bind("<Button-1>", start_drag)
    subtitle.bind("<B1-Motion>", on_drag)

    def win_btn(text, command, hover="#5a3044"):
        b = tk.Label(top, text=text, bg=CARD, fg=TEXT, font=(FONT, 11), width=3, padx=4, pady=2, cursor="hand2")
        b.pack(side="right", padx=(0, 8), pady=14)
        def press(_e):
            play_tone(500, 24)
            command()

        b.bind("<Button-1>", press)
        b.bind("<Enter>", lambda _e: b.configure(bg=hover))
        b.bind("<Leave>", lambda _e: b.configure(bg=CARD))
        return b

    win_btn("✕", root.destroy, "#a84860")
    win_btn("▢", toggle_max)
    win_btn("—", minimize)

    import random

    sky = tk.Canvas(top, bg=BG, highlightthickness=0, bd=0)
    sky.place(x=0, y=0, relwidth=1, relheight=1)
    root.tk.call("lower", str(sky))
    header_petals = []
    petal_rng = random.Random(11)
    for _ in range(12):
        header_petals.append(
            {
                "x": petal_rng.uniform(0, 1100),
                "y": petal_rng.uniform(0, 58),
                "s": petal_rng.uniform(7, 13),
                "v": petal_rng.uniform(0.25, 0.7),
                "drift": petal_rng.uniform(-0.35, 0.35),
                "color": petal_rng.choice(("#ffb7c5", "#f7c6d4", "#ffe4ec", "#e7a4c4")),
            }
        )

    def drift_header():
        try:
            sky.delete("petal")
        except tk.TclError:
            return
        width = max(top.winfo_width(), 400)
        for petal in header_petals:
            petal["x"] += petal["drift"]
            petal["y"] += petal["v"] * 0.35
            if petal["x"] < -20:
                petal["x"] = width
            if petal["x"] > width + 20:
                petal["x"] = 0
            if petal["y"] > 70:
                petal["y"] = -8
                petal["x"] = petal_rng.uniform(0, width)
            paint_flower(sky, petal["x"], petal["y"], petal["s"] * 0.45, petal["color"], "petal")
        root.after(80, drift_header)

    root.after(80, drift_header)

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
            bg="#2a1622",
            fg=TEXT,
            anchor="w",
            font=(FONT, 10),
            padx=14,
            pady=8,
            cursor="hand2",
        )
        row.pack(fill="x")

        def enter(_e):
            row.configure(bg="#5a3044")

        def leave(_e):
            row.configure(bg="#2a1622")

        def press(_e):
            row.configure(bg=PINK_BTN, fg=INK)
            play_tone(640, 30)
            root.after(70, lambda: (row.configure(bg="#5a3044", fg=TEXT), command()))

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
        menu = tk.Frame(root, bg="#2a1622", highlightbackground=EDGE, highlightthickness=1)
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
        sub = tk.Frame(root, bg="#2a1622", highlightbackground=EDGE, highlightthickness=1)
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
        bg=FIELD,
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
            entry.configure(fg="#b08a9a")

    entry.insert(0, PLACEHOLDER)
    entry.configure(fg="#b08a9a")
    entry.bind("<FocusIn>", focus_in)
    entry.bind("<FocusOut>", focus_out)

    def flat_button(parent, text, command, fill=PINK_BTN, fg=INK, pad=(14, 7)):
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
            draw("#e090a8" if fill == PINK_BTN else "#3a1824")
            play_tone(700, 32)
            root.after(90, lambda: (draw(fill), command()))

        def enter(_e):
            draw("#ffd0dc" if fill == PINK_BTN else "#6e3c50")

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

    browse_btn = flat_button(path_row, "Browse", lambda: pick_folder(), fill=SOFT, fg=TEXT)
    browse_btn.pack_configure(padx=(0, 8))
    file_btn = flat_button(path_row, "File", lambda: pick_file(), fill=SOFT, fg=TEXT)
    file_btn.pack_configure(padx=(0, 8))
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
    empty_hint = "Укажи папку с модами и нажми Scan\nили Scan PC по всем дискам\n\nОбычные файлы, не jar, пропускаются"
    bloom = tk.Canvas(result, bg=CARD, highlightthickness=0, bd=0)
    bloom_petals = []
    for _ in range(16):
        bloom_petals.append(
            {
                "x": petal_rng.uniform(40, 700),
                "y": petal_rng.uniform(20, 420),
                "s": petal_rng.uniform(8, 16),
                "v": petal_rng.uniform(0.35, 0.9),
                "drift": petal_rng.uniform(-0.4, 0.4),
                "color": petal_rng.choice(("#ffb7c5", "#f7c6d4", "#ffe4ec", "#e7a4c4")),
            }
        )
    bloom_mode = {"big": False, "line": empty_hint}
    progress_state = {"cur": 0, "total": 0}

    def redraw_bloom():
        if not bloom.winfo_ismapped():
            return
        bloom.delete("all")
        width = max(bloom.winfo_width(), 320)
        height = max(bloom.winfo_height(), 220)
        for petal in bloom_petals:
            paint_flower(bloom, petal["x"], petal["y"], petal["s"] * 0.42, petal["color"])
        if bloom_mode["big"]:
            bloom.create_text(width / 2, height / 2 - 12, text=bloom_mode["line"], fill=PINK, font=(FONT, 32, "bold"))
            bloom.create_text(width / 2, height / 2 + 28, text="проверено", fill=MUTED, font=(FONT, 12))
        else:
            bloom.create_text(width / 2, height / 2, text=bloom_mode["line"], fill=MUTED, font=(FONT, 12), justify="center")

    def show_bloom():
        bloom.place(relx=0, rely=0, relwidth=1, relheight=1)
        root.tk.call("raise", str(bloom))
        redraw_bloom()

    def hide_bloom():
        bloom.place_forget()

    def drift_bloom():
        width = max(bloom.winfo_width(), 320)
        height = max(bloom.winfo_height(), 220)
        for petal in bloom_petals:
            petal["x"] += petal["drift"]
            petal["y"] += petal["v"]
            if petal["y"] > height + 16:
                petal["y"] = -16
                petal["x"] = petal_rng.uniform(0, width)
            if petal["x"] < -16:
                petal["x"] = width
            if petal["x"] > width + 16:
                petal["x"] = 0
        try:
            redraw_bloom()
        except tk.TclError:
            return
        root.after(90, drift_bloom)

    show_bloom()
    root.after(90, drift_bloom)

    byte_bar = tk.Frame(bytes_page, bg=BG)
    byte_bar.pack(fill="x", pady=(12, 8))
    byte_file = tk.StringVar(value="No file loaded")

    def open_jar_dialog():
        play_tone(640, 28)
        picked = system_dialog(
            lambda: filedialog.askopenfilename(
                title="Открыть JAR",
                parent=root,
                filetypes=[("JAR", "*.jar"), ("ZIP", "*.zip")],
            )
        )
        if picked:
            show_page("bytes")
            load_jar_viewer(picked)

    flat_button(byte_bar, "Open JAR", open_jar_dialog, fill=SOFT, fg=TEXT)
    tk.Label(byte_bar, textvariable=byte_file, bg=BG, fg=MUTED, font=(FONT, 10)).pack(side="left", padx=10)
    tk.Label(byte_bar, text="drop jar anywhere", bg=BG, fg="#b08a9a", font=(FONT, 9)).pack(side="right")

    panes = tk.Frame(bytes_page, bg=BG)
    panes.pack(fill="both", expand=True)
    files_card = tk.Frame(panes, bg=CARD, highlightbackground=EDGE, highlightthickness=1, width=280)
    files_card.pack(side="left", fill="y", padx=(0, 10))
    files_card.pack_propagate(False)
    tk.Label(files_card, text="Files", bg=CARD, fg=TEXT, font=(FONT, 10, "bold")).pack(anchor="w", padx=12, pady=(10, 6))
    file_tree = tk.Listbox(
        files_card,
        bg=FIELD,
        fg=TEXT,
        selectbackground="#6a3048",
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
    byte_text = tk.Text(view_card, bg=FIELD, fg="#ffe8ef", relief="flat", font=("Consolas", 10), padx=12, pady=10, wrap="none", highlightthickness=0)
    byte_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    byte_text.configure(state="disabled")
    viewer_entries = []

    def load_jar_viewer(path):
        selected["path"] = path
        byte_file.set(Path(path).name)
        drop_hint.place_forget()
        file_tree.delete(0, "end")
        viewer_entries.clear()
        if not str(path).lower().endswith((".jar", ".zip")):
            set_text(byte_text, "Это простой файл.\nПросмотр открывает только .jar")
            view_title.configure(text="Viewer")
            return
        try:
            names = jar_entries(path)
        except zipfile.BadZipFile:
            set_text(byte_text, "Файл не открылся как jar.\nПохоже на простой или битый файл.")
            view_title.configure(text="Viewer")
            return
        except Exception:
            set_text(byte_text, "Файл не открылся.\nНужен обычный .jar")
            view_title.configure(text="Viewer")
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

    def human_size(size):
        size = int(size or 0)
        if size < 1024:
            return f"{size} B"
        if size < 1024 * 1024:
            return f"{size / 1024:.0f} KB"
        return f"{size / 1024 / 1024:.1f} MB"

    def paint_results():
        if not rows:
            if not bloom_mode["big"] and not progress_state["total"]:
                bloom_mode["line"] = empty_hint
            show_bloom()
            set_text(result_text, "")
            refresh_stats()
            return
        hide_bloom()
        bloom_mode["big"] = False
        bloom_mode["line"] = empty_hint
        shown = visible_rows()
        tags = []
        clipped = False
        if len(shown) > 2500:
            shown = [r for r in shown if r["status"] in ("cheat", "blocked", "error")] + [
                r for r in shown if r["status"] not in ("cheat", "blocked", "error")
            ][:800]
            clipped = True
        for row in shown:
            title = row.get("mod_name") or row["file"]
            line = f"{STATUS_RU.get(row['status'], row['status']):<10}  {row.get('detail') or '—':<28}  {title}\n"
            tags.append((line, row["status"] if row["status"] in STATUS_RU else "unknown"))
            tags.append((f"{'':<10}  {row['path']}    {row.get('mtime') or ''}    {human_size(row.get('size'))}\n", "dim"))
        if clipped:
            tags.append(("\nСписок длинный: сверху срабатывания, остальное обрезано.\n", "dim"))
        set_text(result_text, "", tags)
        refresh_stats()

    def show_page(name):
        if page.get("ready") and page["name"] == name and name == "mods":
            return
        page["ready"] = True
        play_tone(620, 28)
        page["name"] = name
        subtitle.configure(text="SAKURA  ·  BYTECODE" if name == "bytes" else "SAKURA  ·  MOD ANALYZER")
        for key, btn in tool_btns.items():
            if key == name:
                btn.configure(bg=PINK_BTN, fg=INK)
            else:
                btn.configure(bg=PANEL, fg=TEXT)
        leaving = bytes_page if name == "mods" else mods_page
        coming = mods_page if name == "mods" else bytes_page
        leaving.pack_forget()
        coming.pack(fill="both", expand=True)
        coming.configure(bg="#3a2030")

        def settle(step=0):
            shades = ("#321c28", "#24141c", BG)
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
        scan_btn.set_text("Stop" if busy else "Scan")

    def begin(roots, pc=False):
        if worker["thread"] and worker["thread"].is_alive():
            stop.set()
            status.configure(text="Останавливаю…")
            return
        if pc:
            existing = pc_roots()
        else:
            existing = [p for p in roots if p.exists()]
            if not existing:
                status.configure(text="Такой папки нет.")
                return
        rows.clear()
        progress_state["cur"] = 0
        progress_state["total"] = 0
        progress_label.configure(text="")
        progress_caption.configure(text="")
        bloom_mode["big"] = True
        bloom_mode["line"] = "0 / …"
        paint_results()
        stop.clear()
        set_busy(True)
        status.configure(text="Ищу jar…")
        root.lift()

        def on_tick(index, total, jar):
            if index < 0:
                events.put(("tick", f"ищу {total}"))
                return
            events.put(("tick", f"{index}/{total} {jar.name}"))

        def work():
            try:
                found = scan(
                    existing,
                    rules,
                    stop,
                    on_jar=lambda row, index, total: events.put(("jar", row)),
                    on_tick=on_tick,
                )
            except Exception as exc:
                events.put(("done", f"Ошибка: {exc}"))
                return
            if stop.is_set():
                events.put(("done", "Остановлено"))
            elif not found:
                events.put(("done", "Jar нет. Обычные файлы пропущены."))
            else:
                events.put(("done", "Готово"))

        worker["thread"] = threading.Thread(target=work, daemon=True)
        worker["thread"].start()

    def system_dialog(run):
        root.overrideredirect(False)
        root.update_idletasks()
        try:
            return run()
        finally:
            if root.winfo_exists():
                root.overrideredirect(True)
                root.after(30, taskbar)

    def pick_folder():
        play_tone(640, 28)
        picked = system_dialog(lambda: filedialog.askdirectory(title="Папка с модами", parent=root))
        if picked:
            entry.configure(fg=TEXT)
            path_var.set(picked)
            play_tone(760, 36)

    def pick_file():
        play_tone(640, 28)
        picked = system_dialog(
            lambda: filedialog.askopenfilename(
                title="Один jar",
                parent=root,
                filetypes=[("JAR", "*.jar"), ("ZIP", "*.zip")],
            )
        )
        if picked:
            entry.configure(fg=TEXT)
            path_var.set(picked)
            play_tone(760, 36)

    def scan_path():
        if worker["thread"] and worker["thread"].is_alive():
            stop.set()
            status.configure(text="Останавливаю…")
            return
        raw = path_var.get().strip()
        if not raw or raw == PLACEHOLDER:
            status.configure(text="Укажи папку с модами или один jar.")
            return
        path = Path(raw)
        if not path.exists():
            status.configure(text="Такой папки нет.")
            return
        if path.is_file() and path.suffix.lower() not in {".jar", ".zip"}:
            status.configure(text="Это простой файл. Нужен .jar или папка с модами.")
            return
        begin([path])

    def scan_pc():
        if worker["thread"] and worker["thread"].is_alive():
            stop.set()
            status.configure(text="Останавливаю…")
            return
        begin([], pc=True)

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
                        bloom_mode["big"] = True
                        bloom_mode["line"] = f"{cur} / {total}"
                        if not rows:
                            show_bloom()
                        status.configure(text=name or f"Проверено {cur} из {total}")
                elif kind == "done":
                    count = progress_label.cget("text")
                    status.configure(text=f"{payload}  {count}".strip())
                    set_busy(False)
                    if not rows:
                        bloom_mode["big"] = False
                        if "Jar нет" in str(payload):
                            bloom_mode["line"] = "В папке нет jar.\nОбычные файлы пропущены."
                        else:
                            bloom_mode["line"] = empty_hint
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
                if path.lower().endswith((".jar", ".zip")):
                    load_jar_viewer(path)
                    show_page("bytes")
                    break
                status.configure(text="Это простой файл. В просмотр нужен jar.")

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
            root.deiconify()
            root.lift()
            root.attributes("-topmost", True)
            root.update()
            try:
                from PIL import ImageGrab
                x, y = root.winfo_rootx(), root.winfo_rooty()
                w, h = root.winfo_width(), root.winfo_height()
                Path(os.environ["CH_SHOT"] + ".txt").write_text(f"{x},{y},{w},{h}", encoding="utf-8")
                ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(os.environ["CH_SHOT"])
            except Exception as exc:
                Path(os.environ["CH_SHOT"] + ".err").write_text(str(exc), encoding="utf-8")
            root.destroy()
        root.after(1800, shot)

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
