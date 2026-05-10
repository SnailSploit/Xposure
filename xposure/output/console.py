"""X-POSURE console output and live dashboard."""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from ..config import Config
    from ..core.models import ScanStats
    from ..state import ScanState


# Shared console used by the dashboard. Other modules can `from .console import console`
# and call `console.print(...)` to get markup-aware, color-safe output that interleaves
# correctly with the Live region.
console = Console()


_PHASE_ORDER = [
    "initializing",
    "discovery",
    "extraction",
    "correlation",
    "verification",
    "enrichment",
    "done",
]


def _fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def _mask(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return value[:keep] + "…"
    return f"{value[:keep]}…{value[-keep:]}"


class LiveDashboard:
    """Rich-based live dashboard for X-POSURE scans.

    Reads from ``stats``, ``state``, and the engine's own ``findings`` /
    ``all_candidates`` lists by reference, so it stays in sync without the
    engine having to push events explicitly.
    """

    def __init__(
        self,
        config: "Config",
        state: "ScanState",
        stats: "ScanStats",
        findings_ref: Optional[list] = None,
        candidates_ref: Optional[list] = None,
    ):
        self.config = config
        self.state = state
        self.stats = stats
        self.findings_ref = findings_ref if findings_ref is not None else []
        self.candidates_ref = candidates_ref if candidates_ref is not None else []

        self.current_phase: str = "initializing"
        self.phase_detail: str = ""
        self.log_buffer: deque[tuple[str, str]] = deque(maxlen=12)
        self.running = False

        self._live: Optional[Live] = None
        self._refresh_task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    # ----- public API used by the engine ---------------------------------

    def set_phase(self, phase: str, detail: str = "") -> None:
        self.current_phase = phase
        self.phase_detail = detail

    def log(self, message: str, level: str = "info") -> None:
        """Append a styled log line to the rolling buffer."""
        self.log_buffer.append((level, message))

    # ----- lifecycle ------------------------------------------------------

    async def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._stop.clear()
        self._live = Live(
            self._render(),
            console=console,
            refresh_per_second=8,
            screen=False,
            transient=False,
            redirect_stdout=True,
            redirect_stderr=True,
        )
        self._live.start()
        self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def _refresh_loop(self) -> None:
        try:
            while not self._stop.is_set():
                if self._live is not None:
                    self._live.update(self._render())
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=0.2)
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            pass

    def stop(self) -> None:
        if not self.running:
            return
        self.running = False
        self._stop.set()
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
        if self._live is not None:
            try:
                self._live.update(self._render(final=True))
            except Exception:
                pass
            self._live.stop()
            self._live = None

    # ----- rendering ------------------------------------------------------

    def _render(self, final: bool = False) -> Layout:
        layout = Layout(name="root")
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="logs", size=10),
        )
        layout["body"].split_row(
            Layout(name="stats", ratio=1),
            Layout(name="findings", ratio=2),
        )

        layout["header"].update(self._render_header(final))
        layout["stats"].update(self._render_stats())
        layout["findings"].update(self._render_findings())
        layout["logs"].update(self._render_logs())
        return layout

    def _render_header(self, final: bool) -> Panel:
        elapsed = (datetime.now() - self.stats.start_time).total_seconds()
        phase = self.current_phase.upper()
        if final:
            phase = "DONE"
        phase_color = {
            "INITIALIZING": "grey70",
            "DISCOVERY": "cyan",
            "EXTRACTION": "magenta",
            "CORRELATION": "blue",
            "VERIFICATION": "yellow",
            "ENRICHMENT": "green",
            "DONE": "bold green",
        }.get(phase, "white")

        head = Text()
        head.append("X-POSURE ", style="bold red")
        head.append(f"› {self.config.target}", style="bold white")
        head.append("   ")
        head.append(f"[{phase}]", style=f"bold {phase_color}")
        if self.phase_detail:
            head.append(f" {self.phase_detail}", style="grey70")
        head.append("   ")
        head.append(f"⏱ {_fmt_duration(elapsed)}", style="grey70")
        return Panel(Align.left(head), border_style="red", padding=(0, 1))

    def _render_stats(self) -> Panel:
        s = self.stats
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(style="grey70", no_wrap=True)
        table.add_column(justify="right", style="bold white")

        sections: list[tuple[str, list[tuple[str, str]]]] = [
            (
                "discovery",
                [
                    ("subdomains", str(s.subdomains_found)),
                    ("js files", str(s.js_files_found)),
                    ("urls seen", str(len(self.state.seen_urls))),
                ],
            ),
            (
                "extract",
                [
                    ("candidates", str(s.candidates_found)),
                    ("decoded", str(s.decoded_blobs)),
                    ("paired", str(s.paired_credentials)),
                ],
            ),
            (
                "verify",
                [
                    ("verified", f"[bold green]{s.verified_findings}[/]"),
                    ("invalid", f"[red]{s.invalid_findings}[/]"),
                    ("unverified", str(s.unverified_findings)),
                ],
            ),
        ]

        if s.crawl_pages or s.crawl_urls_found or s.trufflehog_findings:
            sections.append(
                (
                    "crawl",
                    [
                        ("pages", str(s.crawl_pages)),
                        ("urls", str(s.crawl_urls_found)),
                        ("trufflehog", str(s.trufflehog_findings)),
                    ],
                )
            )

        for i, (header, rows) in enumerate(sections):
            if i:
                table.add_row("", "")
            table.add_row(f"[bold cyan]{header}[/]", "")
            for k, v in rows:
                table.add_row(f"  {k}", v)

        return Panel(table, title="[bold]stats[/]", border_style="cyan", padding=(0, 1))

    def _render_findings(self) -> Panel:
        table = Table(expand=True, show_lines=False, show_header=True, header_style="bold")
        table.add_column("type", style="yellow", no_wrap=True)
        table.add_column("value", style="white", overflow="ellipsis", no_wrap=True)
        table.add_column("source", style="grey70", overflow="ellipsis", no_wrap=True)
        table.add_column("conf", style="bold", justify="right", width=5)
        table.add_column("status", justify="center", width=10)

        # Prefer correlated findings; fall back to raw candidates while extraction is running.
        rows: list = list(self.findings_ref)
        if not rows:
            rows = list(self.candidates_ref)

        # Show the most recent N
        display = rows[-12:]
        for item in reversed(display):
            ftype = getattr(item, "credential_type", None) or getattr(item, "type", "?")
            value = getattr(item, "masked_value", None) or _mask(getattr(item, "value", ""))
            source = ""
            sources = getattr(item, "sources", None)
            if sources:
                source = sources[0].url
            else:
                src = getattr(item, "source", None)
                if src is not None:
                    source = getattr(src, "url", "") or ""
            confidence = getattr(item, "confidence", 0.0) or 0.0
            status = getattr(item, "status", None)
            status_str = ""
            status_style = "grey70"
            if status is not None:
                status_str = getattr(status, "value", str(status))
                status_style = {
                    "verified": "bold green",
                    "likely_valid": "green",
                    "unverified": "grey70",
                    "invalid": "red",
                    "error": "yellow",
                }.get(status_str, "grey70")
            table.add_row(
                str(ftype),
                str(value),
                str(source),
                f"{confidence:.0%}" if confidence else "-",
                Text(status_str or "-", style=status_style),
            )

        if not display:
            empty = Align.center(
                Text("waiting for findings…", style="dim italic"),
                vertical="middle",
            )
            return Panel(empty, title="[bold]findings[/]", border_style="magenta")

        return Panel(table, title=f"[bold]findings[/] ({len(rows)})", border_style="magenta")

    def _render_logs(self) -> Panel:
        if not self.log_buffer:
            body: Group | Text = Text("idle", style="dim italic")
        else:
            lines = []
            for level, msg in self.log_buffer:
                style = {
                    "info": "white",
                    "ok": "green",
                    "warn": "yellow",
                    "error": "bold red",
                    "debug": "grey50",
                }.get(level, "white")
                lines.append(Text(msg, style=style))
            body = Group(*lines)
        return Panel(body, title="[bold]activity[/]", border_style="grey42", padding=(0, 1))


def print_summary(stats: "ScanStats", findings: list) -> None:
    """Print a tidy summary table after the scan ends."""
    duration = (
        (stats.end_time - stats.start_time).total_seconds()
        if stats.end_time
        else 0
    )

    summary = Table(title=f"[bold red]X-POSURE[/] › {stats.target}", expand=False)
    summary.add_column("metric", style="cyan")
    summary.add_column("value", style="bold white", justify="right")
    summary.add_row("duration", _fmt_duration(duration))
    summary.add_row("subdomains", str(stats.subdomains_found))
    summary.add_row("js files", str(stats.js_files_found))
    summary.add_row("candidates", str(stats.candidates_found))
    summary.add_row("findings", str(len(findings)))
    summary.add_row("verified", f"[green]{stats.verified_findings}[/]")
    summary.add_row("invalid", f"[red]{stats.invalid_findings}[/]")
    console.print()
    console.print(summary)

    verified = [f for f in findings if getattr(f.status, "value", str(f.status)) == "verified"]
    if verified:
        ftable = Table(title="[bold green]verified credentials[/]", expand=True)
        ftable.add_column("type", style="yellow")
        ftable.add_column("value", style="white", overflow="ellipsis")
        ftable.add_column("identity", style="cyan", overflow="ellipsis")
        ftable.add_column("blast", style="red")
        for f in verified:
            ftable.add_row(
                f.credential_type,
                f.masked_value or _mask(f.value),
                f.identity or "-",
                getattr(f.blast_radius, "value", str(f.blast_radius)),
            )
        console.print(ftable)
