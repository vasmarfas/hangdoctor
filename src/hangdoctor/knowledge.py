"""What hangdoctor knows about specific programs, drivers and pool tags."""

# Pool tags that belong to Windows itself. A huge one is garbage only a reboot returns.
WINDOWS_TAGS = {
    "Luaf": "luafv.sys", "Thre": "threads", "Toke": "security tokens", "SeAt": "token attributes",
    "Proc": "processes", "File": "file objects", "IoFE": "file object extensions", "MmSt": "mapped file cache",
    "FMfn": "fltmgr.sys", "FMwi": "fltmgr.sys", "FMsl": "fltmgr.sys", "FMfc": "fltmgr.sys",
    "NtFC": "ntfs.sys", "NtfF": "ntfs.sys", "NtfC": "ntfs.sys", "Ntff": "ntfs.sys", "NtFs": "ntfs.sys",
    "smNp": "memory compression", "smCB": "memory compression", "Obtb": "handle tables", "Key ": "registry",
    "CM31": "registry", "CM25": "registry", "Gpbm": "graphics", "DxgK": "dxgkrnl.sys", "Vi54": "graphics",
}
# Tags that are normally big and only matter when they are enormous.
CACHE_TAGS = {"MmSt", "smNp", "smCB", "FMfn", "NtfF", "File", "CM31", "CM25", "Gpbm"}


def windows_tag(tag: str) -> bool:
    return tag in WINDOWS_TAGS or tag.startswith("WC") or tag.startswith("Nt") or tag.startswith("Mm")


# Third-party drivers with known pool leaks: tag -> (product, service to restart, link)
LEAKY_DRIVERS = {
    "SPTU": ("AmneziaVPN", "AmneziaVPN-service", "https://github.com/amnezia-vpn/amnezia-client/issues/3216"),
}

# Programs that start children all the time as part of normal work; a storm from them is not news.
SHELLS = {
    "bash.exe", "sh.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "openconsole.exe",
    "windowsterminal.exe", "git.exe", "git-remote-https.exe", "git-credential-manager.exe", "ssh.exe",
    "wsl.exe", "wslhost.exe", "node.exe", "npm.exe", "python.exe", "pythonw.exe", "uv.exe", "uvx.exe", "dotnet.exe", "cargo.exe",
    "claude.exe", "codex.exe", "code.exe", "devenv.exe", "msbuild.exe", "java.exe", "gradle.exe",
    "services.exe", "svchost.exe", "explorer.exe", "taskhostw.exe", "wininit.exe", "smss.exe",
}

# Processes that must never be killed or "restarted" by a fix.
CRITICAL = {
    "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "memcompression", "secure system",
    "wudfhost.exe", "audiodg.exe", "spoolsv.exe",
}

# Graceful restart recipes: process name -> (arguments that close it, arguments to start it again)
RESTART_RECIPES = {
    "steam.exe": (["-shutdown"], ["-silent"]),
}

POWER_SAVER = "a1841308-3541-4fab-bc81-f71556f20b4a"
BALANCED = "381b4222-f694-41f0-9685-ff5bb260df2e"
