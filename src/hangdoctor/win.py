"""Thin ctypes layer over the Windows APIs hangdoctor reads. Nothing here goes through WMI:
enumerating processes through WMI is itself a common cause of the freezes we look for."""

import ctypes
import ctypes.wintypes as wt
import os
import struct
import subprocess
import threading
import time
import winreg
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
powrprof = ctypes.WinDLL("powrprof")
pdh = ctypes.WinDLL("pdh")

ntdll.NtQuerySystemInformation.argtypes = [wt.ULONG, ctypes.c_void_p, wt.ULONG, ctypes.POINTER(wt.ULONG)]
ntdll.NtQuerySystemInformation.restype = ctypes.c_ulong
ntdll.NtQueryObject.argtypes = [wt.HANDLE, wt.ULONG, ctypes.c_void_p, wt.ULONG, ctypes.POINTER(wt.ULONG)]
ntdll.NtQueryObject.restype = ctypes.c_ulong
ntdll.NtQueryInformationProcess.argtypes = [wt.HANDLE, wt.ULONG, ctypes.c_void_p, wt.ULONG, ctypes.POINTER(wt.ULONG)]
ntdll.NtQueryInformationProcess.restype = ctypes.c_ulong
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.GetCurrentProcess.restype = wt.HANDLE
kernel32.DuplicateHandle.argtypes = [wt.HANDLE, wt.HANDLE, wt.HANDLE, ctypes.POINTER(wt.HANDLE), wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.GetProcessIdOfThread.argtypes = [wt.HANDLE]
kernel32.GetExitCodeThread.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
kernel32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
kernel32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
kernel32.GetTickCount64.restype = ctypes.c_ulonglong
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
user32.FindWindowW.restype = wt.HWND
user32.FindWindowW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
user32.SendMessageTimeoutW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM, wt.UINT, wt.UINT, ctypes.POINTER(ctypes.c_size_t)]
user32.SendMessageTimeoutW.restype = ctypes.c_size_t
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
user32.IsHungAppWindow.argtypes = [wt.HWND]
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
advapi32.OpenSCManagerW.restype = wt.HANDLE
advapi32.OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
advapi32.EnumServicesStatusExW.argtypes = [wt.HANDLE, ctypes.c_int, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD,
                                           ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD), wt.LPCWSTR]
advapi32.CloseServiceHandle.argtypes = [wt.HANDLE]
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
user32.EnumWindows.argtypes = [WNDENUMPROC, wt.LPARAM]

STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STILL_ACTIVE = 259
PROCESS_TERMINATE = 0x0001
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
DUPLICATE_SAME_ACCESS = 0x2
WM_CLOSE = 0x0010


def _query(cls: int, size: int = 1 << 20):
    while True:
        buf = ctypes.create_string_buffer(size)
        ret = wt.ULONG()
        st = ntdll.NtQuerySystemInformation(cls, buf, size, ctypes.byref(ret))
        if st == STATUS_INFO_LENGTH_MISMATCH:
            size = max(size * 2, ret.value + 65536)
            continue
        if st:
            raise OSError(f"NtQuerySystemInformation({cls}) failed: 0x{st:08X}")
        return buf, ret.value


@dataclass
class Proc:
    pid: int
    ppid: int
    name: str
    created: int
    cpu: int  # user + kernel time, 100 ns units
    handles: int
    threads: int
    private: int
    io_bytes: int


def processes() -> list[Proc]:
    buf, _ = _query(5, 4 << 20)
    out, off = [], 0
    while True:
        nxt, threads = struct.unpack_from("<II", buf, off)
        created, user, kern = struct.unpack_from("<qqq", buf, off + 0x20)
        nlen, _, nptr = struct.unpack_from("<HHxxxxQ", buf, off + 0x38)
        pid, ppid, handles = struct.unpack_from("<QQI", buf, off + 0x50)
        private, = struct.unpack_from("<Q", buf, off + 0xC8)
        rd, wr, other = struct.unpack_from("<QQQ", buf, off + 0xE8)
        name = ctypes.wstring_at(nptr, nlen // 2) if nptr else "Idle"
        out.append(Proc(pid, ppid, name, created, user + kern, handles, threads, private, rd + wr + other))
        if not nxt:
            return out
        off += nxt


@dataclass
class PoolTag:
    tag: str
    live: int
    bytes: int


def pool_tags() -> dict[str, PoolTag]:
    buf, _ = _query(22, 4 << 20)
    count, = struct.unpack_from("<I", buf, 0)
    tags = {}
    for i in range(count):
        raw, pa, pf, pused, na, nf, nused = struct.unpack_from("<4sIIxxxxQIIQ", buf, 8 + i * 40)
        name = raw.decode("latin-1")
        # Alloc and free counters are 32-bit and wrap; their difference doesn't.
        tags[name] = PoolTag(name, ((pa - pf) & 0xFFFFFFFF) + ((na - nf) & 0xFFFFFFFF), pused + nused)
    return tags


def cpu_times() -> tuple[int, ...]:
    """idle, kernel (includes idle), user, dpc, interrupt summed over the CPUs of the current group."""
    buf, ret = _query(8, 64 * 48)
    tot = [0, 0, 0, 0, 0]
    for i in range(ret // 48):
        for j, v in enumerate(struct.unpack_from("<qqqqq", buf, i * 48)):
            tot[j] += v
    return tuple(tot)


@dataclass
class ObjectType:
    name: str
    objects: int
    handles: int


def object_types() -> dict[int, ObjectType]:
    size = 1 << 20
    buf = ctypes.create_string_buffer(size)
    ret = wt.ULONG()
    if ntdll.NtQueryObject(None, 3, buf, size, ctypes.byref(ret)):
        return {}
    base = ctypes.addressof(buf)
    count, = struct.unpack_from("<I", buf, 0)
    types, off = {}, 8
    for _ in range(count):
        slen, smax, sptr = struct.unpack_from("<HHxxxxQ", buf, off)
        objects, handles = struct.unpack_from("<II", buf, off + 0x10)
        index = buf[off + 0x5A][0]
        types[index] = ObjectType(ctypes.wstring_at(sptr, slen // 2), objects, handles)
        off = ((sptr + smax + 7) & ~7) - base
    return types


@dataclass
class HandleStats:
    by_type: dict[str, int] = field(default_factory=dict)
    dead_own_threads: int = 0
    dead_processes: int = 0


def handle_stats(pids: set[int]) -> dict[int, HandleStats]:
    """Handle counts by type for the given processes, plus how many of their thread and process
    handles point to things that have already exited (a leak)."""
    types = object_types()
    thread_t = next((i for i, t in types.items() if t.name == "Thread"), -1)
    process_t = next((i for i, t in types.items() if t.name == "Process"), -1)
    buf, _ = _query(64, 64 << 20)
    n, = struct.unpack_from("<Q", buf, 0)
    stats: dict[int, HandleStats] = {}
    opened: dict[int, int] = {}
    me = kernel32.GetCurrentProcess()
    try:
        for _obj, pid, value, _acc, _bt, tidx, _attr, _r in struct.iter_unpack("<QQQIHHII", memoryview(buf).cast("B")[16:16 + n * 40]):
            if pid not in pids:
                continue
            s = stats.setdefault(pid, HandleStats())
            tname = types[tidx].name if tidx in types else f"#{tidx}"
            s.by_type[tname] = s.by_type.get(tname, 0) + 1
            if pid == 4 or tidx not in (thread_t, process_t):
                continue
            if pid not in opened:
                opened[pid] = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid) or 0
            if not opened[pid]:
                continue
            dup = wt.HANDLE()
            if not kernel32.DuplicateHandle(opened[pid], value, me, ctypes.byref(dup), 0, False, DUPLICATE_SAME_ACCESS):
                continue
            code = wt.DWORD()
            if tidx == thread_t:
                if kernel32.GetProcessIdOfThread(dup) == pid and kernel32.GetExitCodeThread(dup, ctypes.byref(code)) and code.value != STILL_ACTIVE:
                    s.dead_own_threads += 1
            elif kernel32.GetExitCodeProcess(dup, ctypes.byref(code)) and code.value != STILL_ACTIVE:
                s.dead_processes += 1
            kernel32.CloseHandle(dup)
    finally:
        for h in opened.values():
            if h:
                kernel32.CloseHandle(h)
    return stats


class StallProbe:
    """Pings the taskbar every 100 ms. A reply slower than 100 ms is what a user feels as a hitch."""

    def __init__(self, seconds: float):
        self.probes = self.slow = self.worst = 0
        self._end = time.monotonic() + seconds
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        res = ctypes.c_size_t()
        while time.monotonic() < self._end:
            tray = user32.FindWindowW("Shell_TrayWnd", None)
            t = time.perf_counter()
            user32.SendMessageTimeoutW(tray, 0, 0, 0, 0, 10000, ctypes.byref(res))
            ms = int((time.perf_counter() - t) * 1000)
            self.probes += 1
            self.slow += ms > 100
            self.worst = max(self.worst, ms)
            time.sleep(0.1)

    def join(self):
        self._thread.join()


def top_windows(pid: int | None = None, visible_only: bool = True) -> list[tuple[int, int, str]]:
    """(hwnd, pid, title) of top-level windows."""
    found = []

    def cb(hwnd, _):
        if visible_only and not user32.IsWindowVisible(hwnd):
            return True
        owner = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if pid is None or owner.value == pid:
            title = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, title, 256)
            found.append((hwnd, owner.value, title.value))
        return True

    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return found


def hung_windows() -> list[tuple[int, str]]:
    return [(p, title) for hwnd, p, title in top_windows() if title and user32.IsHungAppWindow(hwnd)]


class _PdhValue(ctypes.Structure):
    _fields_ = [("status", wt.DWORD), ("value", ctypes.c_double)]


class Counters:
    """English counter paths through PDH, so localized Windows works the same."""

    def __init__(self, paths: list[str]):
        self.query = ctypes.c_void_p()
        self.handles = {}
        if pdh.PdhOpenQueryW(None, 0, ctypes.byref(self.query)):
            return
        for p in paths:
            h = ctypes.c_void_p()
            if pdh.PdhAddEnglishCounterW(self.query, ctypes.c_wchar_p(p), 0, ctypes.byref(h)) == 0:
                self.handles[p] = h
        pdh.PdhCollectQueryData(self.query)

    def read(self) -> dict[str, float]:
        pdh.PdhCollectQueryData(self.query)
        out = {}
        for p, h in self.handles.items():
            v = _PdhValue()
            if pdh.PdhGetFormattedCounterValue(h, 0x200 | 0x8000, None, ctypes.byref(v)) == 0 and v.status in (0, 1):
                out[p] = v.value
        pdh.PdhCloseQuery(self.query)
        return out


class _PerfInfo(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("CommitTotal", ctypes.c_size_t), ("CommitLimit", ctypes.c_size_t),
                ("CommitPeak", ctypes.c_size_t), ("PhysicalTotal", ctypes.c_size_t), ("PhysicalAvailable", ctypes.c_size_t),
                ("SystemCache", ctypes.c_size_t), ("KernelTotal", ctypes.c_size_t), ("KernelPaged", ctypes.c_size_t),
                ("KernelNonpaged", ctypes.c_size_t), ("PageSize", ctypes.c_size_t), ("HandleCount", wt.DWORD),
                ("ProcessCount", wt.DWORD), ("ThreadCount", wt.DWORD)]


def memory() -> dict[str, int]:
    pi = _PerfInfo()
    pi.cb = ctypes.sizeof(pi)
    kernel32.K32GetPerformanceInfo(ctypes.byref(pi), pi.cb)
    page = pi.PageSize
    return {"commit": pi.CommitTotal * page, "commit_limit": pi.CommitLimit * page,
            "phys_total": pi.PhysicalTotal * page, "phys_avail": pi.PhysicalAvailable * page,
            "kernel_paged": pi.KernelPaged * page, "kernel_nonpaged": pi.KernelNonpaged * page}


def uptime_days() -> float:
    return kernel32.GetTickCount64() / 86_400_000


def enable_ansi() -> None:
    out = kernel32.GetStdHandle(-11)
    mode = wt.DWORD()
    if kernel32.GetConsoleMode(out, ctypes.byref(mode)):
        kernel32.SetConsoleMode(out, mode.value | 0x0004)


def is_admin() -> bool:
    return bool(shell32.IsUserAnAdmin())


def ui_language() -> str:
    return "ru" if kernel32.GetUserDefaultUILanguage() & 0x3FF == 0x19 else "en"


def active_power_scheme() -> str:
    ptr = ctypes.POINTER(ctypes.c_byte * 16)()
    if powrprof.PowerGetActiveScheme(None, ctypes.byref(ptr)):
        return ""
    raw = bytes(ptr.contents)
    kernel32.LocalFree(ptr)
    d1, d2, d3 = struct.unpack_from("<IHH", raw)
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{raw[8:10].hex()}-{raw[10:].hex()}"


def cpu_mhz() -> tuple[int, int]:
    """(max MHz, lowest current limit MHz) over all logical CPUs. A limit below max means throttling."""
    n = os.cpu_count() or 1
    buf = ctypes.create_string_buffer(24 * n)
    if powrprof.CallNtPowerInformation(11, None, 0, buf, len(buf)):
        return 0, 0
    rows = [struct.unpack_from("<IIIIII", buf, i * 24) for i in range(n)]
    return max(r[1] for r in rows), min(r[3] for r in rows)


def reboot_pending() -> bool:
    keys = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"]
    for k in keys:
        try:
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, k))
            return True
        except OSError:
            pass
    return False


def startup_entries() -> int:
    """Enabled autostart entries: Run keys and Startup folders, minus the ones switched off in Settings."""
    count = 0
    for hive, path, approved in [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Run32"),
    ]:
        disabled = set()
        try:
            with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\\" + approved) as k:
                for i in range(winreg.QueryInfoKey(k)[1]):
                    name, data, _ = winreg.EnumValue(k, i)
                    if isinstance(data, bytes) and data[:1] in (b"\x01", b"\x03"):
                        disabled.add(name.lower())
        except OSError:
            pass
        try:
            with winreg.OpenKey(hive, path) as k:
                for i in range(winreg.QueryInfoKey(k)[1]):
                    count += winreg.EnumValue(k, i)[0].lower() not in disabled
        except OSError:
            pass
    for folder in (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
                   os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp")):
        try:
            count += sum(1 for f in os.listdir(folder) if not f.lower().endswith(".ini"))
        except OSError:
            pass
    return count


def dir_size(path: str, budget_s: float = 3.0) -> int:
    total, end = 0, time.monotonic() + budget_s
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
        if time.monotonic() > end:
            break
    return total


@dataclass
class Event:
    log: str
    provider: str
    id: int
    level: int
    data: list[str]
    age_h: float = 0.0


def events(log: str, hours: int, max_level: int = 3, count: int = 3000) -> list[Event]:
    ms = hours * 3_600_000
    query = f"*[System[(Level>=1 and Level<={max_level}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    try:
        out = subprocess.run(["wevtutil", "qe", log, f"/q:{query}", "/f:xml", f"/c:{count}", "/rd:true"],
                             capture_output=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    try:
        root = ET.fromstring(b"<r>" + out + b"</r>")
    except ET.ParseError:
        return []
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    now = datetime.now(timezone.utc)
    result = []
    for e in root:
        sysn = e.find(ns + "System")
        if sysn is None:
            continue
        prov = sysn.find(ns + "Provider")
        created = sysn.find(ns + "TimeCreated")
        try:
            when = datetime.fromisoformat(created.get("SystemTime", "")[:26].rstrip("Z") + "+00:00")
            age = (now - when).total_seconds() / 3600
        except (AttributeError, ValueError):
            age = 0.0
        data = [d.text or "" for d in e.iter(ns + "Data")]
        result.append(Event(log, prov.get("Name", "") if prov is not None else "",
                            int(sysn.findtext(ns + "EventID", "0")), int(sysn.findtext(ns + "Level", "0")), data, age))
    return result


def process_image(pid: int) -> str:
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        size = wt.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        return buf.value if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)) else ""
    finally:
        kernel32.CloseHandle(h)


def process_cmdline(pid: int) -> str:
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        size = 65536
        buf = ctypes.create_string_buffer(size)
        ret = wt.ULONG()
        if ntdll.NtQueryInformationProcess(h, 60, buf, size, ctypes.byref(ret)):
            return ""
        ln, _, ptr = struct.unpack_from("<HHxxxxQ", buf, 0)
        return ctypes.wstring_at(ptr, ln // 2)
    finally:
        kernel32.CloseHandle(h)


def terminate(pid: int) -> bool:
    h = kernel32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, pid)
    if not h:
        return False
    try:
        ok = bool(kernel32.TerminateProcess(h, 1))
        kernel32.WaitForSingleObject(h, 5000)
        return ok
    finally:
        kernel32.CloseHandle(h)


def close_windows(pid: int) -> int:
    wins = top_windows(pid)
    for hwnd, _, _ in wins:
        user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
    return len(wins)


def alive(pid: int) -> bool:
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    try:
        code = wt.DWORD()
        return bool(kernel32.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(h)


@dataclass
class Service:
    name: str
    display: str
    running: bool
    pid: int


def services(drivers: bool = False) -> list[Service]:
    scm = advapi32.OpenSCManagerW(None, None, 0x0004)
    if not scm:
        return []
    try:
        kind = 0x0B if drivers else 0x30
        needed, returned, resume = wt.DWORD(), wt.DWORD(), wt.DWORD()
        advapi32.EnumServicesStatusExW(scm, 0, kind, 3, None, 0, ctypes.byref(needed), ctypes.byref(returned), ctypes.byref(resume), None)
        buf = ctypes.create_string_buffer(needed.value + 4096)
        resume.value = 0
        if not advapi32.EnumServicesStatusExW(scm, 0, kind, 3, buf, len(buf), ctypes.byref(needed), ctypes.byref(returned), ctypes.byref(resume), None):
            return []
        out = []
        for i in range(returned.value):
            name_p, disp_p = struct.unpack_from("<QQ", buf, i * 56)
            state, = struct.unpack_from("<I", buf, i * 56 + 16 + 4)
            pid, = struct.unpack_from("<I", buf, i * 56 + 16 + 28)
            out.append(Service(ctypes.wstring_at(name_p), ctypes.wstring_at(disp_p), state == 4, pid))
        return out
    finally:
        advapi32.CloseServiceHandle(scm)


def running_drivers() -> list[str]:
    """Image paths of the kernel drivers that are loaded right now."""
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    paths = []
    for s in services(drivers=True):
        if not s.running:
            continue
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{s.name}") as k:
                image = winreg.QueryValueEx(k, "ImagePath")[0]
        except OSError:
            image = rf"System32\drivers\{s.name}.sys"
        image = image.replace("\\??\\", "")
        low = image.lower()
        if low.startswith("\\systemroot\\"):
            image = windir + image[11:]
        elif low.startswith("system32\\"):
            image = os.path.join(windir, image)
        if os.path.isfile(image):
            paths.append(image)
    return paths


def find_tag_owner(tag: str, drivers: list[str]) -> str:
    needle = tag.encode("latin-1")
    for path in drivers:
        try:
            with open(path, "rb") as f:
                if needle in f.read():
                    return path
        except OSError:
            pass
    return ""
