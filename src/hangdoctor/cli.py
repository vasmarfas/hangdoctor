import argparse
import json
import os
import sys

from . import __version__, checks, fixes, i18n, probe, report, win
from .i18n import t


def _check(seconds: float, quiet: bool):
    def progress(fraction, phase):
        if quiet:
            return
        if phase == "measure":
            print(f"\r  [{'#' * int(fraction * 30):<30}] {seconds * (1 - fraction):>3.0f} s ", end="", flush=True)
        else:
            print(f"\r  [{'#' * 30}]       \n{t('cli.analyzing')}", flush=True)

    if not quiet:
        print(t("cli.measuring", secs=seconds))
    sample = probe.collect(seconds, progress)
    return sample, checks.run(sample)


def _confirm(prompt: str, yes: bool) -> bool:
    if yes:
        return True
    try:
        return input(prompt).strip().lower() in ("y", "yes", "д", "да")
    except EOFError:
        return False


def _fix(args) -> int:
    sample, findings = _check(args.seconds, args.json)
    available = report.all_fixes(findings)
    if args.all:
        chosen = [x for x in available.values() if x.risk != "danger" or args.dangerous]
    else:
        missing = [i for i in args.ids if i not in available]
        for i in missing:
            print(t("cli.unknown_fix", id=i), file=sys.stderr)
        chosen = [available[i] for i in args.ids if i in available]
    if not chosen:
        print(t("cli.no_fixes"))
        return 0
    batch = [x for x in chosen if x.risk != "danger"]
    if batch and any(x.risk == "caution" for x in batch):
        items = "\n".join(f"  - {x.label}: {x.warning}" for x in batch)
        if not _confirm(t("cli.confirm_all", items=items), args.yes):
            batch = []
    results = []
    for x in batch + [x for x in chosen if x.risk == "danger"]:
        if x.risk == "danger" and not _confirm(t("cli.confirm", label=x.label, warn=x.warning), args.yes):
            results.append((x.id, t("fail.cancelled")))
            continue
        results.append((x.id, fixes.apply(x)))
    for fid, msg in results:
        print(f"  {fid}: {msg}")
    return 0


def main(argv=None) -> int:
    if os.name != "nt":
        print("hangdoctor runs on Windows only", file=sys.stderr)
        return 2
    win.enable_ansi()
    for stream in (sys.stdout, sys.stderr):
        if stream and not stream.isatty():
            stream.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(prog="hangdoctor", description="Finds out why Windows freezes and fixes what it can")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--lang", choices=["ru", "en"])
    p.add_argument("--seconds", type=float, default=30, help="how long to watch the system (default 30)")
    sub = p.add_subparsers(dest="cmd")
    c = sub.add_parser("check", help="check and print a report")
    c.add_argument("--json", action="store_true")
    c.add_argument("--no-color", action="store_true")
    f = sub.add_parser("fix", help="check, then apply fixes by id or all of them")
    f.add_argument("ids", nargs="*")
    f.add_argument("--all", action="store_true", help="every safe and cautious fix")
    f.add_argument("--dangerous", action="store_true", help="with --all, also restarts and closing frozen programs")
    f.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    f.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    a = sub.add_parser("apply", help=argparse.SUPPRESS)
    a.add_argument("--spec", required=True)
    a.add_argument("--out", required=True)
    args = p.parse_args(argv)
    if args.lang:
        i18n.set_lang(args.lang)

    if args.cmd == "apply":
        message = fixes.apply_here(fixes.from_spec(args.spec))
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"message": message}, fh)
        return 0
    if args.cmd == "fix":
        if not args.ids and not args.all:
            p.error("give fix ids or --all")
        return _fix(args)
    if args.cmd is None and sys.stdout.isatty():
        from .tui import run
        run(args.seconds)
        return 0
    sample, findings = _check(args.seconds, getattr(args, "json", False))
    if getattr(args, "json", False):
        print(json.dumps(report.to_json(sample, findings), ensure_ascii=False, indent=2))
    else:
        print(report.text(sample, findings, color=not getattr(args, "no_color", False) and sys.stdout.isatty()))
    return 0
