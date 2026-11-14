# hangdoctor

Windows freeze diagnostics with fixes: Python 3.10+, ctypes, Textual. Layout and the reasoning behind it are in `README.ru.md` («Как устроено»).

- Never enumerate processes through WMI (`Win32_Process`, `tasklist`, `Get-CimInstance`): it freezes exactly the machines this tool is for. Use `win.py`.
- A new check: a function in `checks.py`, its strings under the same keys in both `ru` and `en` in `i18n.py`, and a test in `tests/test_checks.py` on a synthetic `Sample`. Technical details (`Finding.tech`) stay English.
- Every fix declares its risk (`safe`, `caution`, `danger`). Anything that loses user data or restarts the machine is `danger` and only runs one at a time after its own confirmation. Fixes never touch processes in `knowledge.CRITICAL`.
- Fixes that need administrator rights run through an elevated copy (`hangdoctor --lang xx apply --spec ... --out ...`); global options go before the subcommand.
- Tests: `uv run --no-project --with pytest --with textual env PYTHONPATH=src python -m pytest -q tests`.
- Exe: the PyInstaller line in `.github/workflows/release.yml`; check it with `dist/hangdoctor.exe --lang en --seconds 5 check`.
- The project is source-available under PolyForm Noncommercial; never call it "open source" anywhere.
- Git in this folder belongs to the owner: prepare changes and give him the commands.
