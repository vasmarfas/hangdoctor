import os
import shutil
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from . import knowledge, win


@dataclass
class ProcUse:
    pid: int
    name: str
    cores: float
    private: int
    handles: int


@dataclass
class Spawn:
    parent: str
    child: str
    per_min: float
    parent_pid: int = 0


@dataclass
class Tag:
    tag: str
    mb: int
    live: int
    per_min: int
    owner: str = ""


@dataclass
class Sample:
    seconds: float
    stall_probes: int = 0
    stall_slow: int = 0
    stall_worst_ms: int = 0
    hung: dict[int, tuple[str, str]] = field(default_factory=dict)  # pid -> (process name, window title)
    procs: list[ProcUse] = field(default_factory=list)
    process_count: int = 0
    process_objects: int = 0
    spawns: list[Spawn] = field(default_factory=list)
    service_pids: dict[int, list[str]] = field(default_factory=dict)
    cpu_dpc_share: float = 0.0
    cpu_busy_share: float = 0.0
    logical_cpus: int = 1
    mem: dict[str, int] = field(default_factory=dict)
    pages_in_per_s: float = 0.0
    disk_ms: float = 0.0
    disk_idle: float = 100.0
    sys_drive: str = "C:"
    sys_free: int = 0
    sys_total: int = 0
    handle_stats: dict[int, win.HandleStats] = field(default_factory=dict)
    tags: list[Tag] = field(default_factory=list)
    events: list[win.Event] = field(default_factory=list)
    uptime_days: float = 0.0
    reboot_pending: bool = False
    power_scheme: str = ""
    cpu_max_mhz: int = 0
    cpu_limit_mhz: int = 0
    startup_count: int = 0
    temp_bytes: int = 0
    services: list[win.Service] = field(default_factory=list)


COUNTERS = [r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer", r"\PhysicalDisk(_Total)\% Idle Time", r"\Memory\Pages Input/sec"]


def collect(seconds: float = 30, progress=None) -> Sample:
    """Watches the system for `seconds` and returns everything the checks need.
    progress(fraction, phase) is called from this thread while it runs."""
    s = Sample(seconds=seconds, logical_cpus=os.cpu_count() or 1)
    report = progress or (lambda f, p: None)
    t0 = time.monotonic()
    procs0 = win.processes()
    tags0 = win.pool_tags()
    cpu0 = win.cpu_times()
    counters = win.Counters(COUNTERS)
    stalls = win.StallProbe(seconds)

    known = {(p.pid, p.created) for p in procs0}
    names = {p.pid: p.name for p in procs0}
    spawned: Counter = Counter()
    spawn_parent: dict[tuple[str, str], int] = {}
    hung_hits: Counter = Counter()
    hung_info = {}
    tick = 0
    while (elapsed := time.monotonic() - t0) < seconds:
        report(elapsed / seconds, "measure")
        time.sleep(0.5)
        for p in win.processes():
            if (p.pid, p.created) in known:
                continue
            known.add((p.pid, p.created))
            key = (names.get(p.ppid, f"pid {p.ppid}"), p.name)
            spawned[key] += 1
            spawn_parent[key] = p.ppid
            names[p.pid] = p.name
        tick += 1
        if tick % 4 == 0:
            for pid, title in win.hung_windows():
                hung_hits[pid] += 1
                hung_info[pid] = (names.get(pid, f"pid {pid}"), title)
    stalls.join()
    report(1.0, "analyze")

    minutes = (time.monotonic() - t0) / 60
    procs1 = win.processes()
    tags1 = win.pool_tags()
    cpu1 = win.cpu_times()
    pdh = counters.read()

    s.stall_probes, s.stall_slow, s.stall_worst_ms = stalls.probes, stalls.slow, stalls.worst
    s.hung = {pid: hung_info[pid] for pid, hits in hung_hits.items() if hits >= 2}

    window = minutes * 60 * 1e7
    cpu_before = {(p.pid, p.created): p.cpu for p in procs0}
    s.procs = [ProcUse(p.pid, p.name, (p.cpu - cpu_before[(p.pid, p.created)]) / window if (p.pid, p.created) in cpu_before else 0.0,
                       p.private, p.handles) for p in procs1 if p.pid]
    s.process_count = len(procs1)
    s.spawns = sorted((Spawn(parent, child, n / minutes, spawn_parent[(parent, child)]) for (parent, child), n in spawned.items()),
                      key=lambda x: -x.per_min)

    d = [b - a for a, b in zip(cpu0, cpu1)]  # idle, kernel (with idle), user, dpc, interrupt
    total = d[1] + d[2]
    if total > 0:
        s.cpu_busy_share = 1 - d[0] / total
        s.cpu_dpc_share = (d[3] + d[4]) / total

    s.mem = win.memory()
    s.pages_in_per_s = pdh.get(COUNTERS[2], 0.0)
    s.disk_ms = pdh.get(COUNTERS[0], 0.0) * 1000
    s.disk_idle = pdh.get(COUNTERS[1], 100.0)
    s.sys_drive = os.environ.get("SystemDrive", "C:")
    usage = shutil.disk_usage(s.sys_drive + "\\")
    s.sys_free, s.sys_total = usage.free, usage.total

    types = win.object_types()
    s.process_objects = next((t.objects for t in types.values() if t.name == "Process"), 0)
    candidates = {p.pid for p in procs1 if p.handles > 10_000} | {4}
    s.handle_stats = win.handle_stats(candidates)

    drivers = None
    for t in sorted(tags1.values(), key=lambda t: -t.bytes)[:12]:
        old = tags0.get(t.tag)
        tag = Tag(t.tag, t.bytes >> 20, t.live, round((t.live - old.live) / minutes) if old else 0)
        if t.bytes > 200 << 20 and not knowledge.windows_tag(t.tag):
            drivers = drivers if drivers is not None else win.running_drivers()
            tag.owner = win.find_tag_owner(t.tag, drivers)
        s.tags.append(tag)

    s.services = win.services()
    svc = defaultdict(list)
    for x in s.services:
        if x.running and x.pid:
            svc[x.pid].append(x.name)
    s.service_pids = dict(svc)

    s.events = win.events("System", 24) + win.events("Application", 24, max_level=2)
    s.uptime_days = win.uptime_days()
    s.reboot_pending = win.reboot_pending()
    s.power_scheme = win.active_power_scheme()
    s.cpu_max_mhz, s.cpu_limit_mhz = win.cpu_mhz()
    s.startup_count = win.startup_entries()
    s.temp_bytes = win.dir_size(os.environ.get("TEMP", ""))
    return s
