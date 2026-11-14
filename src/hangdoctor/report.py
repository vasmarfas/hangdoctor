from collections import Counter

from .checks import Finding, verdict
from .i18n import t
from .probe import Sample

COLORS = {3: "\033[91m", 2: "\033[93m", 1: "\033[96m", 0: "\033[92m"}
RISK_COLORS = {"safe": "\033[92m", "caution": "\033[93m", "danger": "\033[91m"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"


def summary(s: Sample) -> str:
    load = 1 - s.mem["phys_avail"] / s.mem["phys_total"] if s.mem else 0
    return t("summary", secs=s.seconds, slow=s.stall_slow, worst=s.stall_worst_ms, busy=s.cpu_busy_share, mem=load,
             procs=s.process_count, up=s.uptime_days)


def details(s: Sample) -> dict:
    names = {p.pid: p.name for p in s.procs}
    return {
        "cpu": [{"name": p.name, "pid": p.pid, "cores": round(p.cores, 2)} for p in sorted(s.procs, key=lambda p: -p.cores)[:10]],
        "memory": [{"name": p.name, "pid": p.pid, "mb": p.private >> 20} for p in sorted(s.procs, key=lambda p: -p.private)[:10]],
        "spawns": [{"parent": x.parent, "child": x.child, "per_min": round(x.per_min)} for x in s.spawns[:10]],
        "handles": [{"name": names.get(pid, "System" if pid == 4 else str(pid)), "pid": pid, "total": sum(st.by_type.values()),
                     "top": ", ".join(f"{k} {v}" for k, v in sorted(st.by_type.items(), key=lambda kv: -kv[1])[:3]),
                     "dead_threads": st.dead_own_threads, "dead_processes": st.dead_processes}
                    for pid, st in sorted(s.handle_stats.items(), key=lambda kv: -sum(kv[1].by_type.values()))],
        "kernel": [{"tag": x.tag, "mb": x.mb, "live": x.live, "per_min": x.per_min, "owner": x.owner} for x in s.tags],
        "events": [{"source": f"{p} {i}", "count": n} for (p, i), n in Counter((e.provider, e.id) for e in s.events).most_common(15)],
    }


def to_json(s: Sample, findings: list[Finding]) -> dict:
    sev = verdict(findings)
    return {
        "severity": sev, "verdict": t(f"verdict.{sev}"), "summary": summary(s),
        "findings": [{"key": f.key, "severity": f.severity, "title": f.title, "action": f.action, "tech": f.tech,
                      "fixes": [{"id": x.id, "label": x.label, "warning": x.warning, "risk": x.risk, "admin": x.admin} for x in f.fixes]}
                     for f in findings],
        "details": details(s),
    }


def all_fixes(findings: list[Finding]) -> dict:
    out = {}
    for f in findings:
        for x in f.fixes:
            out.setdefault(x.id, x)
    return out


def text(s: Sample, findings: list[Finding], color: bool = True) -> str:
    c = (lambda code: code) if color else (lambda code: "")
    sev = verdict(findings)
    lines = [f"\n== {t('cli.plain')}", f"  {c(BOLD)}{c(COLORS[sev])}{t(f'verdict.{sev}')}{c(RESET)}", f"  {c(DIM)}{summary(s)}{c(RESET)}"]
    for f in findings:
        lines.append(f"  {c(COLORS[f.severity])}● {t(f'sev.{f.severity}')}{c(RESET)}  {f.title}")
        lines.append(f"      {c(DIM)}{t('ui.what_to_do')}{c(RESET)} {f.action}")
    fixes = all_fixes(findings)
    if fixes:
        lines.append(f"\n== {t('cli.fixes')}")
        for x in fixes.values():
            admin = f" ({t('ui.admin')})" if x.admin else ""
            lines.append(f"  {c(RISK_COLORS[x.risk])}{t('risk.' + x.risk):<12}{c(RESET)} {x.id:<28} {x.label}{admin}")
        lines.append(f"  {c(DIM)}{t('cli.fix_hint')}{c(RESET)}")
    tech = [line for f in findings for line in f.tech]
    if tech:
        lines.append(f"\n== {t('cli.tech')}")
        lines += [f"  - {line}" for line in tech]
    d = details(s)
    lines.append(f"\n== CPU (cores)")
    lines += [f"  {x['name']:<30} {x['cores']:>6.2f}" for x in d["cpu"][:6]]
    lines.append(f"\n== Memory (MB)")
    lines += [f"  {x['name']:<30} {x['mb']:>6}" for x in d["memory"][:6]]
    if d["spawns"]:
        lines.append(f"\n== Launches per minute")
        lines += [f"  {x['per_min']:>5}  {x['parent']} -> {x['child']}" for x in d["spawns"][:5]]
    lines.append(f"\n== Kernel pool tags")
    lines += [f"  {x['tag']}  {x['mb']:>6} MB  {x['live']:>10}  {x['per_min']:>+7}/min  {x['owner']}" for x in d["kernel"][:10]]
    return "\n".join(lines)
