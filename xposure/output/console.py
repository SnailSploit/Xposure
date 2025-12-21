"""X-POSURE console output and live dashboard."""

import asyncio
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from rich import box
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from ..ui.colors import COLORS
from ..ui.banners import BANNER_COMPACT

if TYPE_CHECKING:
    from ..config import Config
    from ..state import ScanState
    from ..core.models import ScanStats


class LiveDashboard:
    """Rich-powered live dashboard with a neon Mr. Robot vibe."""

    def __init__(self, config: "Config", state: "ScanState", stats: "ScanStats"):
        """Initialize dashboard."""
        self.config = config
        self.state = state
        self.stats = stats
        self.running = False
        self.phase: str = "initializing"
        self.phase_detail: str = "Booting up nodes..."
        self.recent_events: list[str] = []
        self._live: Optional[Live] = None
        self._refresh_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

        theme = Theme(
            {
                "mrrobot.primary": COLORS["toxic"],
                "mrrobot.alert": COLORS["blood"],
                "mrrobot.dim": COLORS["smoke"],
                "mrrobot.banner": "bold " + COLORS["toxic"],
            }
        )
        self.console = Console(theme=theme)

    async def start(self):
        """Start the live dashboard."""
        self.running = True
        self._stop_event.clear()

        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=6,
            screen=True,
        )
        self._live.start()
        self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def stop(self):
        """Stop the live dashboard."""
        self.running = False
        self._stop_event.set()
        if self._refresh_task:
            await asyncio.wait({self._refresh_task}, return_when=asyncio.ALL_COMPLETED)
        if self._live:
            self._live.stop()
            self._live = None

    def set_phase(self, phase: str, detail: str = ""):
        """Update the current phase and detail message."""
        self.phase = phase
        if detail:
            self.phase_detail = detail
        self._push_event(f"[{phase.upper()}] {detail or '...'}")

    def _push_event(self, message: str):
        """Append an event to the ticker."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.recent_events.append(f"{timestamp}  {message}")
        self.recent_events = self.recent_events[-6:]

    async def _refresh_loop(self):
        """Continuously refresh the dashboard while running."""
        while not self._stop_event.is_set():
            if self._live:
                self._live.update(self._render())
            await asyncio.sleep(0.4)

    def _render(self) -> Layout:
        """Build the Rich layout for the dashboard."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="body"),
            Layout(name="footer", size=6),
        )

        layout["body"].split_row(
            Layout(name="phase", ratio=2),
            Layout(name="stats", ratio=3),
            Layout(name="events", ratio=2),
        )

        layout["header"].update(self._render_header())
        layout["phase"].update(self._render_phase())
        layout["stats"].update(self._render_stats())
        layout["events"].update(self._render_events())
        layout["footer"].update(self._render_footer())

        return layout

    def _render_header(self) -> Panel:
        """Render the ASCII banner."""
        banner_text = Text.from_ansi(BANNER_COMPACT)
        banner = Align.center(banner_text, vertical="middle")
        return Panel(
            banner,
            box=box.SQUARE,
            border_style="mrrobot.primary",
            subtitle="live // infiltration dashboard",
        )

    def _render_phase(self) -> Panel:
        """Render current phase info."""
        glitch = Text("▌ X-POSURE : OPERATION ▐", style="mrrobot.primary")
        phase_text = Text(self.phase.upper(), style="bold " + COLORS["blood"])
        detail_text = Text(self.phase_detail or "Running...", style="mrrobot.dim")

        table = Table.grid(expand=True)
        table.add_row(glitch)
        table.add_row("")
        table.add_row(Text("phase", style="mrrobot.dim"), phase_text)
        table.add_row(Text("detail", style="mrrobot.dim"), detail_text)
        table.add_row(Text("target", style="mrrobot.dim"), Text(self.config.target, style="mrrobot.primary"))

        return Panel(
            table,
            title="mr.robot // status",
            border_style="mrrobot.primary",
            box=box.ROUNDED,
        )

    def _render_stats(self) -> Panel:
        """Render stats snapshot."""
        stats_table = Table.grid(padding=(0, 1))
        stats_table.add_column("metric", style="mrrobot.dim", justify="right")
        stats_table.add_column("value", style="mrrobot.primary")

        stats_table.add_row("subdomains", str(self.stats.subdomains_found))
        stats_table.add_row("js files", str(self.stats.js_files_found))
        stats_table.add_row("paths", str(len(getattr(self.state, 'seen_urls', []))))
        stats_table.add_row("candidates", str(self.stats.candidates_found))
        stats_table.add_row("paired", str(self.stats.paired_credentials))
        stats_table.add_row("verified", str(self.stats.verified_findings))
        stats_table.add_row("errors", str(self.stats.error_findings))

        return Panel(
            stats_table,
            title="signal // telemetry",
            border_style="mrrobot.primary",
            box=box.ROUNDED,
        )

    def _render_events(self) -> Panel:
        """Render recent events ticker."""
        table = Table.grid(expand=True)
        for event in reversed(self.recent_events):
            table.add_row(Text(event, style="mrrobot.dim"))

        if not self.recent_events:
            table.add_row(Text("listening for leaks...", style="mrrobot.dim"))

        return Panel(
            table,
            title="ticker // operations",
            border_style="mrrobot.primary",
            box=box.ROUNDED,
        )

    def _render_footer(self) -> Panel:
        """Render footer with friendly reminder."""
        footer_text = Text(
            "root@fsociety:~$  reality is insecure — exploit responsibly",
            style="mrrobot.primary",
        )
        return Panel(
            Align.center(footer_text, vertical="middle"),
            border_style="mrrobot.primary",
            box=box.SQUARE,
        )
