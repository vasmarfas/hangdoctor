import base64
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass

from . import knowledge, win
from .i18n import t

NO_WINDOW = subprocess.CREATE_NO_WINDOW
DETACHED = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
ADMIN_KINDS = {"restart-service", "stop-service", "restart-wmi"}
RISK = {
    "end-process": "caution", "restart-app": "caution", "restart-service": "caution", "stop-service": "caution",
    "restart-explorer": "caution", "restart-wmi": "caution", "clean-temp": "safe", "open-cleanmgr": "safe",
    "power-balanced": "safe", "open-startup": "safe", "reboot": "danger",
}


@dataclass
class Fix:
    id: str          # "kind" or "kind:target", stable within one check
    kind: str
    target: str
    name: str        # process or service name the fix acts on, for messages
    risk: str        # safe | caution | danger
    admin: bool

    @property
    def label(self) -> str:
        return t(f"fix.{self.kind}", app=self.name, svc=self.name)

    @property
    def warning(self) -> str:
        return t(f"fix.{self.kind}.warn", app=self.name, svc=self.name)


def make(kind: str, target: str = "", name: str = "", risk: str = "") -> Fix:
    admin = kind in ADMIN_KINDS
    if kind in ("end-process", "restart-app") and target:
        h = win.kernel32.OpenProcess(win.PROCESS_TERMINATE, False, int(target))
        admin = not h
        if h:
            win.kernel32.CloseHandle(h)
    return Fix(f"{kind}:{target}" if target else kind, kind, target, name, risk or RISK[kind], admin)


def _ps(command: str) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                          capture_output=True, text=True, creationflags=NO_WINDOW, timeout=120)


def _wait_exit(pid: int, seconds: float) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not win.alive(pid):
            return True
        time.sleep(0.5)
    return not win.alive(pid)


def _restart_app(pid: int, name: str) -> str:
    exe, cmd = win.process_image(pid), win.process_cmdline(pid)
    if not exe:
        return t("fail.gone")
    recipe = knowledge.RESTART_RECIPES.get(name.lower())
    if recipe:
        subprocess.Popen([exe, *recipe[0]], creationflags=DETACHED)
        if not _wait_exit(pid, 60):
            win.terminate(pid)
        time.sleep(2)
        subprocess.Popen([exe, *recipe[1]], cwd=os.path.dirname(exe), creationflags=DETACHED)
    else:
        win.close_windows(pid)
        if not _wait_exit(pid, 15):
            win.terminate(pid)
        subprocess.Popen(cmd or exe, cwd=os.path.dirname(exe), creationflags=DETACHED)
    return t("done.restart-app", app=name)


def _clean_temp() -> str:
    root = os.environ.get("TEMP", "")
    if not root or not os.path.isdir(root):
        return t("fail", error="TEMP")
    cutoff = time.time() - 86400
    freed = 0
    for dirpath, dirnames, files in os.walk(root, topdown=False):
        for f in files:
            p = os.path.join(dirpath, f)
            try:
                st = os.lstat(p)
                if st.st_mtime < cutoff and not st.st_file_attributes & 0x400:
                    os.remove(p)
                    freed += st.st_size
            except OSError:
                pass
        for d in dirnames:
            p = os.path.join(dirpath, d)
            try:
                if not os.lstat(p).st_file_attributes & 0x400:
                    os.rmdir(p)
            except OSError:
                pass
    return t("done.clean-temp", mb=freed >> 20)


def _service_state(name: str) -> str:
    return _ps(f"(Get-Service -Name '{name}').Status").stdout.strip() or "?"


def apply_here(fix: Fix) -> str:
    """Runs the fix in this process. Raises nothing; returns a message for the user."""
    try:
        kind, target, name = fix.kind, fix.target, fix.name
        if "'" in target:
            return t("fail", error=target)
        if kind in ("end-process", "restart-app"):
            pid = int(target)
            procs = {p.pid: p.name for p in win.processes()}
            if pid not in procs:
                return t("fail.gone")
            if procs[pid].lower() in knowledge.CRITICAL or pid in (0, 4):
                return t("fail.critical")
            if kind == "restart-app":
                return _restart_app(pid, procs[pid])
            return t("done.end-process", app=name) if win.terminate(pid) else t("fail", error="TerminateProcess")
        if kind == "restart-service":
            _ps(f"Stop-Service -Name '{target}' -Force -ErrorAction SilentlyContinue")
            for _ in range(2):
                _ps(f"Start-Service -Name '{target}' -ErrorAction SilentlyContinue")
                if _service_state(target) == "Running":
                    break
                time.sleep(3)
            return t("done.restart-service", svc=name, state=_service_state(target))
        if kind == "stop-service":
            _ps(f"Stop-Service -Name '{target}' -Force; Set-Service -Name '{target}' -StartupType Manual")
            return t("done.stop-service", svc=name)
        if kind == "restart-explorer":
            subprocess.run(["taskkill", "/f", "/im", "explorer.exe"], capture_output=True, creationflags=NO_WINDOW)
            time.sleep(2)
            if not any(p.name.lower() == "explorer.exe" for p in win.processes()):
                subprocess.Popen("explorer.exe", creationflags=DETACHED)
            return t("done.restart-explorer")
        if kind == "restart-wmi":
            subprocess.run(["taskkill", "/f", "/im", "WmiPrvSE.exe"], capture_output=True, creationflags=NO_WINDOW)
            return t("done.restart-wmi")
        if kind == "clean-temp":
            return _clean_temp()
        if kind == "open-cleanmgr":
            subprocess.Popen("cleanmgr.exe", creationflags=DETACHED)
            return t("done.open")
        if kind == "open-startup":
            os.startfile("ms-settings:startupapps")
            return t("done.open")
        if kind == "power-balanced":
            subprocess.run(["powercfg", "/setactive", knowledge.BALANCED], capture_output=True, creationflags=NO_WINDOW)
            return t("done.power-balanced")
        if kind == "reboot":
            subprocess.run(["shutdown", "/r", "/t", "60", "/c", "hangdoctor"], capture_output=True, creationflags=NO_WINDOW)
            return t("done.reboot")
        return t("fail", error=kind)
    except Exception as e:  # a fix must never take the UI down with it
        return t("fail", error=e)


class _ShellExecuteInfo(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("fMask", wt.ULONG), ("hwnd", wt.HWND), ("lpVerb", wt.LPCWSTR),
                ("lpFile", wt.LPCWSTR), ("lpParameters", wt.LPCWSTR), ("lpDirectory", wt.LPCWSTR), ("nShow", ctypes.c_int),
                ("hInstApp", wt.HINSTANCE), ("lpIDList", ctypes.c_void_p), ("lpClass", wt.LPCWSTR), ("hkeyClass", wt.HKEY),
                ("dwHotKey", wt.DWORD), ("hIcon", wt.HANDLE), ("hProcess", wt.HANDLE)]


def _elevated(fix: Fix) -> str:
    """Runs `hangdoctor apply` for this fix in an elevated copy of ourselves and returns its message."""
    from .i18n import LANG
    out = os.path.join(tempfile.gettempdir(), f"hangdoctor-{os.getpid()}-{time.time_ns()}.json")
    spec = base64.urlsafe_b64encode(json.dumps(fix.__dict__).encode()).decode()
    args = f'--lang {LANG} apply --out "{out}" --spec {spec}'
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, args
    else:
        exe, params = sys.executable, f"-m hangdoctor {args}"
    # Run from the package's parent so `python -m hangdoctor` finds it even without an install.
    cwd = None if getattr(sys, "frozen", False) else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    info = _ShellExecuteInfo(cbSize=ctypes.sizeof(_ShellExecuteInfo), fMask=0x40, lpVerb="runas", lpFile=exe,
                             lpParameters=params, lpDirectory=cwd, nShow=0)
    if not win.shell32.ShellExecuteExW(ctypes.byref(info)):
        return t("fail.cancelled")
    win.kernel32.WaitForSingleObject(info.hProcess, 180_000)
    win.kernel32.CloseHandle(info.hProcess)
    try:
        with open(out, encoding="utf-8") as f:
            return json.load(f)["message"]
    except OSError:
        return t("fail", error="elevated run left no result")
    finally:
        try:
            os.remove(out)
        except OSError:
            pass


def apply(fix: Fix) -> str:
    if fix.admin and not win.is_admin():
        return _elevated(fix)
    return apply_here(fix)


def from_spec(spec: str) -> Fix:
    return Fix(**json.loads(base64.urlsafe_b64decode(spec)))
