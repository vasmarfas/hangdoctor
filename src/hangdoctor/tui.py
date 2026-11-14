import time

from rich.markup import escape
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, ProgressBar, Static, TabbedContent, TabPane

from . import checks, fixes, probe, report
from .i18n import t

SEV = {3: ("bad", "red"), 2: ("warn", "yellow"), 1: ("info", "cyan"), 0: ("ok", "green")}
VARIANT = {"safe": "success", "caution": "warning", "danger": "error"}


class Confirm(ModalScreen[bool]):
    CSS = """
    Confirm { align: center middle; }
    #box { width: 80; height: auto; padding: 1 2; border: thick $warning; background: $surface; }
    #box.danger { border: thick $error; }
    #buttons { height: auto; margin-top: 1; align-horizontal: right; }
    #buttons Button { margin-left: 2; }
    """

    def __init__(self, text: str, danger: bool):
        super().__init__()
        self.text, self.danger = text, danger

    def compose(self) -> ComposeResult:
        with Vertical(id="box", classes="danger" if self.danger else ""):
            yield Static(self.text)
            with Horizontal(id="buttons"):
                yield Button(t("ui.no"), id="no")
                yield Button(t("ui.yes"), id="yes", variant="error" if self.danger else "warning")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class HangDoctor(App):
    TITLE = "HangDoctor"
    BINDINGS = [("r", "recheck", t("ui.key.recheck")), ("a", "fix_all", t("ui.key.fixall")), ("q", "quit", t("ui.key.quit"))]
    CSS = """
    #status { height: auto; padding: 1 2 0 2; }
    #progress { margin: 0 2 1 2; }
    #top { height: auto; margin: 0 2; }
    #verdict { width: 1fr; height: auto; padding: 0 2; border: round $primary; text-style: bold; }
    #verdict.bad { border: round $error; color: $error; }
    #verdict.warn { border: round $warning; color: $warning; }
    #verdict.ok, #verdict.info { border: round $success; color: $success; }
    #fixall { margin-left: 2; height: 3; }
    #summary { height: auto; padding: 0 3; color: $text-muted; }
    #cards { height: auto; max-height: 60%; margin: 1 2 0 2; }
    .card { height: auto; padding: 0 1; border: round $primary; }
    .card.bad { border: round $error; }
    .card.warn { border: round $warning; }
    .card.info { border: round $accent; }
    .card .text { width: 1fr; }
    .card .fixes { width: auto; height: auto; }
    .card Button { min-width: 18; margin-left: 1; }
    #details { margin: 0 2; height: 1fr; min-height: 8; }
    .result { display: none; }
    """

    def __init__(self, seconds: float):
        super().__init__()
        self.seconds = seconds
        self.busy = False
        self.fix_by_id: dict[str, fixes.Fix] = {}
        self.sub_title = t("ui.subtitle")

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="status")
        yield ProgressBar(id="progress", show_eta=False)
        with Horizontal(id="top", classes="result"):
            yield Static(id="verdict")
            yield Button("", id="fixall", variant="success")
        yield Static(id="summary", classes="result")
        yield VerticalScroll(id="cards", classes="result")
        with TabbedContent(id="details", classes="result"):
            for key, table in (("cpu", "cpu"), ("memory", "memory"), ("spawns", "spawns"), ("handles", "handles"),
                               ("kernel", "kernel"), ("events", "events")):
                with TabPane(t(f"ui.tab.{key}")):
                    yield DataTable(id=table, zebra_stripes=True)
            with TabPane(t("ui.tab.tech")):
                yield VerticalScroll(Static(id="tech"))
        yield Footer()

    def on_mount(self) -> None:
        self.action_recheck()

    def _status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)

    def action_recheck(self) -> None:
        if self.busy:
            return
        self.busy = True
        for w in self.query(".result"):
            w.display = False
        bar = self.query_one("#progress", ProgressBar)
        bar.display = True
        bar.update(total=100, progress=0)
        self._status(t("ui.measuring", left=self.seconds))
        self.check()

    def progress(self, fraction: float, phase: str) -> None:
        bar = self.query_one("#progress", ProgressBar)
        if phase == "measure":
            bar.update(progress=fraction * 100)
            self._status(t("ui.measuring", left=self.seconds * (1 - fraction)))
        else:
            bar.update(total=None)
            self._status(t("ui.analyzing"))

    @work(thread=True, exclusive=True)
    def check(self) -> None:
        try:
            sample = probe.collect(self.seconds, lambda f, p: self.call_from_thread(self.progress, f, p))
            findings = checks.run(sample)
            self.call_from_thread(self.show, sample, findings)
        except Exception as e:
            self.call_from_thread(self.fail, str(e))

    def fail(self, error: str) -> None:
        self.busy = False
        self.query_one("#progress").display = False
        self._status(f"[red]{escape(t('ui.failed', error=error))}[/]")

    def show(self, s: probe.Sample, findings: list[checks.Finding]) -> None:
        self.busy = False
        self.query_one("#progress").display = False
        self._status(t("ui.checked", time=time.strftime("%H:%M")))
        for w in self.query(".result"):
            w.display = True
        sev = checks.verdict(findings)
        verdict = self.query_one("#verdict", Static)
        verdict.set_classes(SEV[sev][0])
        verdict.update(escape(t(f"verdict.{sev}")))
        self.query_one("#summary", Static).update(escape(report.summary(s)))

        self.fix_by_id = report.all_fixes(findings)
        batch = [f for f in self.fix_by_id.values() if f.risk != "danger"]
        fixall = self.query_one("#fixall", Button)
        fixall.label = t("ui.fix_all", n=len(batch))
        fixall.display = bool(batch)
        fixall.disabled = False

        cards = self.query_one("#cards", VerticalScroll)
        cards.remove_children()
        if not findings:
            cards.mount(Horizontal(Static(f"[green]●[/] {escape(t('ui.nothing'))}", classes="text"), classes="card"))
        for f in findings:
            cls, color = SEV[f.severity]
            text = f"[{color}]● {t(f'sev.{f.severity}')}[/]  [b]{escape(f.title)}[/]\n[dim]{t('ui.what_to_do')}[/] {escape(f.action)}"
            buttons = []
            for x in f.fixes:
                b = Button(x.label + (" *" if x.admin else ""), name=x.id, variant=VARIANT[x.risk])
                b.tooltip = f"{t('risk.' + x.risk)}. {x.warning}" + (f" ({t('ui.admin')})" if x.admin else "")
                buttons.append(b)
            cards.mount(Horizontal(Static(text, classes="text"), Vertical(*buttons, classes="fixes"), classes=f"card {cls}"))

        d = report.details(s)
        c = lambda *keys: [t(f"col.{k}") if k != "pid" else "PID" for k in keys]
        self.fill("#cpu", c("program", "pid", "cores"), [(x["name"], x["pid"], f"{x['cores']:.2f}") for x in d["cpu"]])
        self.fill("#memory", c("program", "pid", "mb"), [(x["name"], x["pid"], x["mb"]) for x in d["memory"]])
        self.fill("#spawns", c("parent", "child", "per_min"), [(x["parent"], x["child"], x["per_min"]) for x in d["spawns"]])
        self.fill("#handles", c("program", "pid", "handles", "most", "dead_threads", "exited"),
                  [(x["name"], x["pid"], x["total"], x["top"], x["dead_threads"], x["dead_processes"]) for x in d["handles"]])
        self.fill("#kernel", c("tag", "mb", "count", "per_min", "driver"), [(x["tag"], x["mb"], x["live"], x["per_min"], x["owner"]) for x in d["kernel"]])
        self.fill("#events", c("source", "day"), [(x["source"], x["count"]) for x in d["events"]])
        tech = [f"• {escape(line)}" for f in findings for line in f.tech]
        self.query_one("#tech", Static).update("\n".join(tech) or "—")

    def fill(self, selector: str, columns: list, rows: list) -> None:
        table = self.query_one(selector, DataTable)
        table.clear(columns=True)
        table.add_columns(*columns)
        table.add_rows([[str(v) for v in row] for row in rows])

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "fixall":
            self.action_fix_all()
        elif event.button.name in self.fix_by_id:
            self.ask_and_fix([self.fix_by_id[event.button.name]])

    def action_fix_all(self) -> None:
        batch = [f for f in self.fix_by_id.values() if f.risk != "danger"]
        if batch and not self.busy:
            self.ask_and_fix(batch)

    def ask_and_fix(self, batch: list[fixes.Fix]) -> None:
        if self.busy:
            return
        if all(f.risk == "safe" for f in batch):
            self.run_fixes(batch)
            return
        danger = any(f.risk == "danger" for f in batch)
        if len(batch) == 1:
            f = batch[0]
            text = f"[b]{escape(f.label)}[/]\n\n{escape(f.warning)}"
        else:
            items = "\n".join(f"• [b]{escape(f.label)}[/] — {escape(f.warning) or t('risk.' + f.risk)}" for f in batch)
            text = f"{t('ui.confirm_all')}\n\n{items}\n\n[dim]{t('ui.danger_note')}[/]"
        if any(f.admin for f in batch):
            text += f"\n\n[dim]* {t('ui.admin')}[/]"
        self.push_screen(Confirm(text, danger), lambda ok: self.run_fixes(batch) if ok else None)

    def run_fixes(self, batch: list[fixes.Fix]) -> None:
        self.busy = True
        for b in self.query(Button):
            b.disabled = True
        self._status(t("ui.fixing", what=", ".join(f.label for f in batch)))
        self.apply(batch)

    @work(thread=True)
    def apply(self, batch: list[fixes.Fix]) -> None:
        messages = [fixes.apply(f) for f in batch]
        self.call_from_thread(self.fixed, messages, any(f.kind == "reboot" for f in batch))

    def fixed(self, messages: list[str], rebooting: bool) -> None:
        for m in messages:
            self.notify(m, timeout=10)
        self.busy = False
        if rebooting:
            for b in self.query(Button):
                b.disabled = False
            self._status(messages[-1])
            return
        self.action_recheck()


def run(seconds: float) -> None:
    HangDoctor(seconds).run()
