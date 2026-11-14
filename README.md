# HangDoctor

[Русская версия](README.ru.md)

Your PC has free CPU and RAM according to Task Manager, yet it freezes for a second when you switch windows. HangDoctor watches the system for 30 seconds, finds what is actually wrong, explains it in plain words and fixes what can be fixed without a reboot.

It was written after one such case: a phone-mirroring app launched `tasklist` every second, each call took 13 s because of a kernel handle leak, two dozen of them piled up in WMI, and Explorer kept waiting on RPC. Task Manager showed nothing unusual.

## Download and run

Download `hangdoctor.exe` from [Releases](https://github.com/vasmarfas/hangdoctor/releases) and double-click it. Nothing to install; Windows 10 and 11, x64. The build isn't code-signed yet, so SmartScreen may ask for confirmation.

With [uv](https://docs.astral.sh/uv/) installed you can run it straight from the repository:

```
uvx --from git+https://github.com/vasmarfas/hangdoctor hangdoctor
```

The window shows a verdict ("All good", "Worth fixing", "Your PC is unwell"), one card per problem with what to do, and fix buttons coloured by risk. **Fix all except dangerous** runs every green and yellow fix after one confirmation; red ones — a restart, closing a frozen program — only run one at a time, each with its own warning. Fixes that need administrator rights are marked with `*` and ask for elevation themselves. Tabs below hold the details: CPU, memory, frequent launches, handles, kernel memory, event log. `R` checks again, `Q` quits. The interface follows the Windows language (Russian or English); `--lang en` overrides it.

## What it checks

| Check | How |
| --- | --- |
| Hitches | pings the taskbar every 100 ms; a reply slower than 100 ms is a hitch you feel |
| Frozen programs | windows Windows itself marks as not responding |
| CPU hogs | per-process CPU time over the window, svchost mapped to its services |
| WMI overload | WmiPrvSE CPU: something is polling the process list non-stop |
| Driver interrupts | DPC and interrupt share of CPU time |
| Memory | physical memory load with hard faults, commit against the limit, compositor (dwm) memory |
| Disk | free space on the system drive, average latency and idle time, size of TEMP |
| Process storms | which program launches which child, per minute; shells and dev tools are ignored |
| Handle leaks | programs holding handles to their own exited threads or to exited processes |
| Kernel memory | pool tags by size and growth, owner driver found in the loaded drivers; known leaks named |
| Crash loops | services that crashed three or more times in the last hour |
| Event log, 24 h | hardware (WHEA), disk and graphics driver errors, app hangs, memory and port exhaustion, unexpected shutdowns |
| System state | uptime, pending restart after updates, Power saver plan, CPU throttling, number of startup programs |

## What it can fix

| Fix | Risk | Admin |
| --- | --- | --- |
| Delete TEMP files older than a day, open Disk Cleanup, open startup apps, switch to the Balanced plan | safe | no |
| Restart Explorer | caution | no |
| Restart a leaking or CPU-hungry program (graceful close, then start it again with the same command line) | caution | if it runs elevated |
| Close a program | caution | if it runs elevated |
| Restart or stop a service (known leaks such as the AmneziaVPN split tunnel driver, crash-looping services) | caution | yes |
| Restart WMI provider hosts | caution | yes |
| Close a frozen program | dangerous | if it runs elevated |
| Restart the computer (in one minute, cancel with `shutdown /a`) | dangerous | no |

System processes (csrss, lsass, svchost, dwm and the like) are never closed or restarted.

## Command line

```
hangdoctor                                  the window (in a terminal)
hangdoctor check                            text report
hangdoctor check --json                     the same for scripts
hangdoctor fix restart-app:1234 clean-temp  apply fixes by id from the report
hangdoctor fix --all                        every safe and cautious fix, after one confirmation
hangdoctor fix --all --dangerous --yes      including restarts, without asking
hangdoctor --seconds 10 --lang en check     shorter watch, English
```

## How it works

Everything is read through native Windows APIs: `NtQuerySystemInformation` for processes, handles, pool tags and CPU times, the Service Control Manager for services and loaded drivers, PDH counters by their English names, and `wevtutil` for the event log. HangDoctor deliberately never enumerates processes through WMI — that is one of the things that freezes Windows. Nothing is sent anywhere: no network access, no telemetry.

## Build from source

```
uv run --no-project --with pytest --with textual python -m pytest -q tests        # with PYTHONPATH=src
uv run --no-project --with pyinstaller --with textual pyinstaller --onefile --console --name hangdoctor --paths src --collect-all textual --collect-submodules rich packaging/entry.py
```

GitHub Actions runs the tests and builds `hangdoctor.exe` on every push; a `v*` tag publishes it to Releases.

## License

The source code is public under the [PolyForm Noncommercial License 1.0.0](LICENSE): free for personal and noncommercial use, commercial use needs a separate agreement. See [NOTICE.md](NOTICE.md) for the plain-language summary and the rules about forks and the name. Ways to support the project are in [SUPPORT.md](SUPPORT.md).
