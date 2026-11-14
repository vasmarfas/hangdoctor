from collections import Counter
from dataclasses import dataclass, field

from . import knowledge, win
from .fixes import Fix, make
from .i18n import t
from .probe import Sample

GB = 1 << 30


@dataclass
class Finding:
    key: str
    severity: int  # 3 freezes it now, 2 piles up and will, 1 worth knowing
    title: str
    action: str
    tech: list[str] = field(default_factory=list)
    fixes: list[Fix] = field(default_factory=list)


def run(s: Sample) -> list[Finding]:
    out: list[Finding] = []
    for check in (stalls, hung, cpu, dpc, memory, disk, processes, spawns, handles, kernel, crashloops, event_log, system_state):
        check(s, out)
    if not any(f.key == "stalls" for f in out):
        # Without a measured hitch, nothing here is freezing the PC right now.
        for f in out:
            if f.key in ("cpu", "wmi", "spawn", "dpc", "disk_slow"):
                f.severity = min(f.severity, 2)
    return sorted(out, key=lambda f: -f.severity)


def verdict(findings: list[Finding]) -> int:
    worst = max((f.severity for f in findings), default=0)
    return worst if worst >= 2 else 0


def _app(name: str) -> str:
    return name[:-4] if name.lower().endswith(".exe") else name


def _app_fixes(pid: int, name: str) -> list[Fix]:
    """Restarting only makes sense for a program with a window or a known recipe; background ones just get closed."""
    close = make("end-process", str(pid), _app(name))
    if name.lower() in knowledge.RESTART_RECIPES or win.top_windows(pid):
        return [make("restart-app", str(pid), _app(name)), close]
    return [close]


def stalls(s: Sample, out: list) -> None:
    if s.stall_slow >= 3 or s.stall_worst_ms >= 500:
        out.append(Finding("stalls", 3, t("stalls.title", secs=s.seconds, slow=s.stall_slow, worst=s.stall_worst_ms), t("stalls.action"),
                           [f"taskbar ping: {s.stall_probes} probes, {s.stall_slow} over 100 ms, worst {s.stall_worst_ms} ms"],
                           [make("restart-explorer")]))


def hung(s: Sample, out: list) -> None:
    for pid, (name, title) in s.hung.items():
        if name.lower() in knowledge.CRITICAL:
            continue
        out.append(Finding("hung", 3, t("hung.title", app=_app(name)), t("hung.action"),
                           [f"{name} ({pid}) window \"{title}\" is hung (IsHungAppWindow)"],
                           [make("end-process", str(pid), _app(name), risk="danger")]))


def cpu(s: Sample, out: list) -> None:
    threshold = min(1.5, 0.5 * s.logical_cpus)
    wmi = sum(p.cores for p in s.procs if p.name.lower() == "wmiprvse.exe")
    if wmi >= 1:
        out.append(Finding("wmi", 3 if wmi >= 3 else 2, t("wmi.title"), t("wmi.action"),
                           [f"WmiPrvSE.exe uses {wmi:.1f} cores"], [make("restart-wmi")]))
    for p in sorted(s.procs, key=lambda p: -p.cores):
        if p.cores < 1:
            break
        low = p.name.lower()
        tech = [f"{p.name} ({p.pid}) used {p.cores:.1f} cores during the check"]
        if low == "msmpeng.exe":
            out.append(Finding("av", 1, t("av.title", cores=p.cores), t("av.action"), tech))
        elif low in ("searchindexer.exe", "searchprotocolhost.exe"):
            out.append(Finding("indexer", 1, t("indexer.title"), t("indexer.action"), tech))
        elif p.cores < threshold or low in ("wmiprvse.exe", "system", "registry", "memcompression", "idle"):
            continue
        elif low == "svchost.exe":
            svcs = s.service_pids.get(p.pid, [])
            name = ", ".join(svcs) or "svchost"
            fixes = [make("restart-service", svcs[0], svcs[0])] if len(svcs) == 1 else []
            out.append(Finding("cpu", 2, t("cpu_service.title", svc=name, cores=p.cores), t("cpu_service.action"), tech, fixes))
        elif low not in knowledge.CRITICAL:
            out.append(Finding("cpu", 2, t("cpu.title", app=_app(p.name), cores=p.cores), t("cpu.action"), tech, _app_fixes(p.pid, p.name)))


def dpc(s: Sample, out: list) -> None:
    if s.cpu_dpc_share >= 0.05:
        out.append(Finding("dpc", 2, t("dpc.title", share=s.cpu_dpc_share), t("dpc.action"),
                           [f"DPC + interrupt time {s.cpu_dpc_share:.1%} of all CPU time"]))


def memory(s: Sample, out: list) -> None:
    m = s.mem
    if not m:
        return
    load = 1 - m["phys_avail"] / m["phys_total"]
    top = sorted(s.procs, key=lambda p: -p.private)[:3]
    tech = [f"RAM {load:.0%} of {m['phys_total'] / GB:.0f} GB, hard faults {s.pages_in_per_s:.0f} pages/s; "
            f"largest: " + ", ".join(f"{p.name} {p.private / GB:.1f} GB" for p in top)]
    if load >= 0.92:
        fixes = [make("end-process", str(top[0].pid), _app(top[0].name))] if top and top[0].name.lower() not in knowledge.CRITICAL else []
        out.append(Finding("mem", 3 if s.pages_in_per_s > 500 else 2, t("mem.title", load=load), t("mem.action"), tech, fixes))
    commit = m["commit"] / m["commit_limit"] if m["commit_limit"] else 0
    if commit >= 0.9:
        out.append(Finding("commit", 3, t("commit.title", load=commit), t("commit.action"),
                           [f"commit {m['commit'] / GB:.0f} of {m['commit_limit'] / GB:.0f} GB"]))
    dwm = next((p for p in s.procs if p.name.lower() == "dwm.exe"), None)
    if dwm and dwm.private > 2 * GB:
        out.append(Finding("dwm", 1, t("dwm.title", gb=dwm.private / GB), t("dwm.action"), [f"dwm.exe private {dwm.private / GB:.1f} GB"]))


def disk(s: Sample, out: list) -> None:
    free_gb = s.sys_free / GB
    if s.sys_total and (free_gb < 5 or (s.sys_free / s.sys_total < 0.1 and free_gb < 20)):
        out.append(Finding("disk_space", 3 if free_gb < 2 else 2, t("disk_space.title", drive=s.sys_drive, free=f"{free_gb:.1f}"),
                           t("disk_space.action"), [f"{s.sys_drive} {free_gb:.1f} GB free of {s.sys_total / GB:.0f} GB"],
                           [make("clean-temp"), make("open-cleanmgr")]))
    if s.disk_ms >= 50 and s.disk_idle <= 20:
        out.append(Finding("disk_slow", 2, t("disk_slow.title", ms=s.disk_ms, idle=s.disk_idle), t("disk_slow.action"),
                           [f"PhysicalDisk(_Total): {s.disk_ms:.0f} ms/transfer, {s.disk_idle:.0f}% idle"]))
    if s.temp_bytes >= 5 * GB:
        out.append(Finding("temp", 1, t("temp.title", gb=s.temp_bytes / GB), t("temp.action"),
                           [f"%TEMP% holds {s.temp_bytes / GB:.1f} GB"], [make("clean-temp")]))


def processes(s: Sample, out: list) -> None:
    if s.process_count >= 800:
        names = Counter(p.name for p in s.procs).most_common(4)
        out.append(Finding("procs", 2, t("procs.title", count=s.process_count), t("procs.action"),
                           [f"{s.process_count} processes; most common: " + ", ".join(f"{n} x{c}" for n, c in names)]))


def spawns(s: Sample, out: list) -> None:
    for sp in s.spawns:
        if sp.per_min < 40:
            break
        low = sp.parent.lower()
        if low in knowledge.SHELLS or low in knowledge.CRITICAL or sp.parent.startswith("pid "):
            continue
        out.append(Finding("spawn", 2, t("spawn.title", parent=_app(sp.parent), child=_app(sp.child), rate=sp.per_min),
                           t("spawn.action", parent=_app(sp.parent)), [f"{sp.parent} ({sp.parent_pid}) -> {sp.child}: {sp.per_min:.0f}/min"],
                           _app_fixes(sp.parent_pid, sp.parent)))


def handles(s: Sample, out: list) -> None:
    names = {p.pid: p.name for p in s.procs}
    for pid, st in s.handle_stats.items():
        name = names.get(pid, "")
        if pid == 4 or not name or name.lower() in knowledge.CRITICAL:
            continue
        total = sum(st.by_type.values())
        top = ", ".join(f"{k} {v}" for k, v in sorted(st.by_type.items(), key=lambda kv: -kv[1])[:3])
        tech = [f"{name} ({pid}): {total} handles ({top}); dead own threads {st.dead_own_threads}, exited processes {st.dead_processes}"]
        restart = _app_fixes(pid, name)
        if st.dead_own_threads > 5000:
            out.append(Finding("leak", 2, t("leak_threads.title", app=_app(name)), t("leak_threads.action"), tech, restart))
        elif st.dead_processes > 2000:
            out.append(Finding("leak", 2, t("leak_procs.title", app=_app(name)), t("leak_procs.action"), tech, restart))
        elif total > 50_000:
            out.append(Finding("leak", 2, t("handles.title", app=_app(name)), t("handles.action"), tech, restart))


def kernel(s: Sample, out: list) -> None:
    garbage = []
    system = s.handle_stats.get(4)
    if system and sum(system.by_type.values()) > 50_000:
        top = ", ".join(f"{k} {v}" for k, v in sorted(system.by_type.items(), key=lambda kv: -kv[1])[:3])
        garbage.append(f"System holds {sum(system.by_type.values())} handles ({top})")
    zombies = s.process_objects - s.process_count
    if zombies > 3000:
        garbage.append(f"{zombies} exited processes are still held in memory")
    for tag in s.tags:
        mb = tag.mb
        if tag.tag in knowledge.LEAKY_DRIVERS:
            if mb >= 100:
                product, service, link = knowledge.LEAKY_DRIVERS[tag.tag]
                out.append(Finding("leaky_driver", 2, t("leaky_driver.title", product=product, mb=mb),
                                   t("leaky_driver.action", product=product, link=link),
                                   [f"pool tag {tag.tag}: {mb} MB, {tag.live} allocations, {tag.per_min:+d}/min"],
                                   [make("restart-service", service, service)]))
            continue
        cache = tag.tag in knowledge.CACHE_TAGS
        big = mb > (1536 if cache else 500) or (not cache and tag.live > 2_000_000)
        if knowledge.windows_tag(tag.tag):
            if big:
                garbage.append(f"pool tag {tag.tag} ({knowledge.WINDOWS_TAGS.get(tag.tag, 'Windows')}): {mb} MB, {tag.live} allocations")
        elif tag.owner and (big or (mb > 200 and tag.per_min > 300)):
            driver = tag.owner.rsplit("\\", 1)[-1]
            out.append(Finding("driver", 2, t("driver.title", driver=driver, mb=mb), t("driver.action"),
                               [f"pool tag {tag.tag}: {mb} MB, {tag.live} allocations, {tag.per_min:+d}/min, found in {tag.owner}"]))
    kernel_mb = (s.mem.get("kernel_paged", 0) + s.mem.get("kernel_nonpaged", 0)) >> 20 if s.mem else 0
    if garbage:
        garbage.append(f"kernel pools {kernel_mb} MB in total")
        out.append(Finding("kernel", 2, t("kernel.title"), t("kernel.action"), garbage, [make("reboot")]))


def crashloops(s: Sample, out: list) -> None:
    recent = [e for e in s.events if e.age_h <= 1]
    by_display = {x.display: x.name for x in s.services}
    crashed = Counter(e.data[0] for e in recent if e.provider == "Service Control Manager" and e.id in (7031, 7034) and e.data)
    nssm = Counter(e.data[0] for e in recent if e.provider == "nssm" and e.id == 1034 and e.data)
    for display, n in (crashed + nssm).items():
        if n < 3:
            continue
        name = by_display.get(display, display)
        out.append(Finding("crashloop", 2, t("crashloop.title", svc=display), t("crashloop.action"),
                           [f"service {name} crashed {n} times in the last hour"], [make("stop-service", name, display)]))


def event_log(s: Sample, out: list) -> None:
    ev = s.events
    whea = [e for e in ev if e.provider == "Microsoft-Windows-WHEA-Logger"]
    if whea:
        out.append(Finding("whea", 2, t("whea.title", count=len(whea)), t("whea.action"),
                           [f"WHEA-Logger events {sorted({e.id for e in whea})}"]))
    disk_ids = {"disk": {7, 51, 153}, "stornvme": {11, 129}, "storahci": {11, 129}, "Ntfs": {55, 98}, "Microsoft-Windows-Ntfs": {55, 98}}
    derr = [e for e in ev if e.id in disk_ids.get(e.provider, ())]
    if derr:
        out.append(Finding("disk_errors", 2, t("disk_errors.title", count=len(derr)), t("disk_errors.action"),
                           [f"{e.provider} {e.id}" for e in derr[:5]]))
    gpu = [e for e in ev if (e.provider == "Display" and e.id == 4101) or (e.provider in ("nvlddmkm", "amdkmdag", "amdwddmg") and e.level <= 2)]
    if gpu:
        out.append(Finding("gpu", 2, t("gpu.title", count=len(gpu)), t("gpu.action"), [f"{e.provider} {e.id}" for e in gpu[:5]]))
    hangs = Counter(e.data[0] for e in ev if e.provider == "Application Hang" and e.id == 1002 and e.data)
    for app, n in hangs.most_common(3):
        if n >= 2:
            out.append(Finding("app_hang", 2, t("app_hang.title", app=_app(app), count=n), t("app_hang.action"),
                               [f"Application Hang 1002 for {app}: {n} in 24 h"]))
    if any(e.provider == "Microsoft-Windows-Resource-Exhaustion-Detector" and e.id == 2004 for e in ev):
        out.append(Finding("exhaust", 3, t("exhaust.title"), t("exhaust.action"), ["Resource-Exhaustion-Detector 2004 in 24 h"]))
    ports = [e for e in ev if e.provider == "Tcpip" and e.id in (4227, 4231, 4266)]
    if ports:
        out.append(Finding("ports", 2, t("ports.title"), t("ports.action"), [f"Tcpip {e.id}" for e in ports[:5]], [make("reboot")]))
    power = [e for e in ev if e.provider == "Microsoft-Windows-Kernel-Power" and e.id == 41]
    if power:
        out.append(Finding("power_loss", 1, t("power_loss.title", count=len(power)), t("power_loss.action"), ["Kernel-Power 41"]))


def system_state(s: Sample, out: list) -> None:
    if s.reboot_pending:
        out.append(Finding("reboot_pending", 2 if s.uptime_days >= 3 else 1, t("reboot_pending.title"), t("reboot_pending.action"),
                           ["RebootPending / RebootRequired key present"], [make("reboot")]))
    elif s.uptime_days >= 7:
        out.append(Finding("uptime", 1, t("uptime.title", days=s.uptime_days), t("uptime.action"),
                           [f"uptime {s.uptime_days:.1f} days"], [make("reboot")]))
    if s.power_scheme == knowledge.POWER_SAVER:
        out.append(Finding("power_saver", 2, t("power_saver.title"), t("power_saver.action"), [f"active scheme {s.power_scheme}"],
                           [make("power-balanced")]))
    if s.cpu_max_mhz and s.cpu_limit_mhz < 0.85 * s.cpu_max_mhz:
        out.append(Finding("throttle", 2, t("throttle.title", limit=s.cpu_limit_mhz, max=s.cpu_max_mhz), t("throttle.action"),
                           [f"CallNtPowerInformation: MhzLimit {s.cpu_limit_mhz}, MaxMhz {s.cpu_max_mhz}"]))
    if s.startup_count >= 25:
        out.append(Finding("startup", 1, t("startup.title", count=s.startup_count), t("startup.action"),
                           [f"{s.startup_count} enabled Run entries and Startup folder items"], [make("open-startup")]))
