import pytest

from hangdoctor import checks, i18n, win
from hangdoctor.probe import ProcUse, Sample, Spawn, Tag

GB = 1 << 30


@pytest.fixture(autouse=True)
def english():
    i18n.set_lang("en")


def healthy(**kw) -> Sample:
    s = Sample(seconds=30, stall_probes=280, logical_cpus=8, process_count=250, process_objects=260, uptime_days=1,
               mem={"phys_total": 16 * GB, "phys_avail": 8 * GB, "commit": 10 * GB, "commit_limit": 24 * GB,
                    "kernel_paged": 400 << 20, "kernel_nonpaged": 200 << 20},
               sys_free=200 * GB, sys_total=500 * GB, cpu_max_mhz=3600, cpu_limit_mhz=3600,
               procs=[ProcUse(1000, "explorer.exe", 0.05, 100 << 20, 3000)])
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def keys(findings):
    return [f.key for f in findings]


def fix_ids(findings, key):
    return [x.id for f in findings if f.key == key for x in f.fixes]


def test_healthy_system_has_nothing():
    findings = checks.run(healthy())
    assert findings == []
    assert checks.verdict(findings) == 0


def test_hitches_are_bad_and_offer_explorer_restart():
    findings = checks.run(healthy(stall_slow=12, stall_worst_ms=2400))
    assert findings[0].key == "stalls" and findings[0].severity == 3
    assert fix_ids(findings, "stalls") == ["restart-explorer"]


def test_busy_wmi_is_not_called_a_freeze_without_hitches():
    s = healthy(procs=[ProcUse(50, "WmiPrvSE.exe", 4.0, 50 << 20, 900)])
    findings = checks.run(s)
    assert keys(findings) == ["wmi"]
    assert findings[0].severity == 2


def test_spawn_storm_from_an_app_counts_but_shells_do_not():
    storms = [Spawn("bash.exe", "git.exe", 300, 11), Spawn("scrcpygui.exe", "tasklist.exe", 60, 22)]
    findings = checks.run(healthy(spawns=storms))
    assert keys(findings) == ["spawn"]
    assert "scrcpygui" in findings[0].title
    assert [x.kind for x in findings[0].fixes] == ["end-process"]  # no window, so no restart


def test_known_amnezia_leak_offers_service_restart():
    findings = checks.run(healthy(tags=[Tag("SPTU", 1350, 11_700_000, 635)]))
    assert keys(findings) == ["leaky_driver"]
    assert fix_ids(findings, "leaky_driver") == ["restart-service:AmneziaVPN-service"]
    assert findings[0].fixes[0].admin


def test_dead_thread_handles_mean_a_leaking_app():
    stats = win.HandleStats({"Thread": 133_000, "Event": 300}, dead_own_threads=133_000)
    s = healthy(procs=[ProcUse(64060, "steam.exe", 0.1, 200 << 20, 133_300)], handle_stats={64060: stats})
    findings = checks.run(s)
    assert keys(findings) == ["leak"]
    assert "steam" in findings[0].title
    assert fix_ids(findings, "leak")[0] == "restart-app:64060"  # steam has a restart recipe


def test_kernel_garbage_needs_a_reboot_which_is_dangerous():
    system = win.HandleStats({"File": 405_000, "Process": 5000})
    s = healthy(handle_stats={4: system}, tags=[Tag("Luaf", 727, 4_900_000, 12), Tag("MmSt", 300, 120_000, -9000)])
    findings = checks.run(s)
    assert keys(findings) == ["kernel"]
    reboot = findings[0].fixes[0]
    assert reboot.kind == "reboot" and reboot.risk == "danger"
    assert not any("MmSt" in line for line in findings[0].tech)  # a cache tag of normal size is not garbage


def test_service_crash_loop_in_the_last_hour():
    ev = [win.Event("System", "Service Control Manager", 7031, 2, ["Foo Updater"], 0.2) for _ in range(4)]
    s = healthy(events=ev, services=[win.Service("FooUpd", "Foo Updater", False, 0)])
    findings = checks.run(s)
    assert keys(findings) == ["crashloop"]
    assert fix_ids(findings, "crashloop") == ["stop-service:FooUpd"]


def test_old_crashes_are_not_a_loop():
    ev = [win.Event("System", "Service Control Manager", 7031, 2, ["Foo Updater"], 5.0) for _ in range(10)]
    assert "crashloop" not in keys(checks.run(healthy(events=ev)))


def test_hung_window_close_is_dangerous():
    findings = checks.run(healthy(hung={4242: ("editor.exe", "Untitled - Editor")}))
    assert findings[0].key == "hung" and findings[0].severity == 3
    assert findings[0].fixes[0].risk == "danger"


def test_power_saver_is_fixed_safely():
    findings = checks.run(healthy(power_scheme="a1841308-3541-4fab-bc81-f71556f20b4a"))
    assert fix_ids(findings, "power_saver") == ["power-balanced"]
    assert findings[0].fixes[0].risk == "safe"


def test_both_languages_have_the_same_keys():
    assert set(i18n.STRINGS["ru"]) == set(i18n.STRINGS["en"])
