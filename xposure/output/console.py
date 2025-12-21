"""X-POSURE console output and live dashboard."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import Config
    from ..state import ScanState
    from ..core.models import ScanStats


class LiveDashboard:
    """Live dashboard using Rich (placeholder for now)."""

    def __init__(self, config: 'Config', state: 'ScanState', stats: 'ScanStats'):
        """Initialize dashboard."""
        self.config = config
        self.state = state
        self.stats = stats
        self.running = False

    async def start(self):
        """Start the live dashboard."""
        self.running = True
        # Will be implemented in session 7 with Rich

    def stop(self):
        """Stop the live dashboard."""
        self.running = False

    def update(self):
        """Update the dashboard display."""
        # Will be implemented in session 7
        pass
