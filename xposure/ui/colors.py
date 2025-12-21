"""X-POSURE color palette and theme."""

COLORS = {
    "blood": "#FF0055",       # verified/critical
    "toxic": "#00FF88",       # success/live
    "ice": "#00D4FF",         # info/progress
    "gold": "#FFD93D",        # warning/high value
    "void": "#1A1A2E",        # background
    "clean": "#FFFFFF",       # primary text
    "smoke": "#666666",       # dimmed text
    "ghost": "#333333",       # borders/subtle
}


def get_severity_color(severity: str) -> str:
    """Get color for severity level."""
    severity_map = {
        "critical": COLORS["blood"],
        "high": COLORS["gold"],
        "medium": COLORS["ice"],
        "low": COLORS["toxic"],
        "info": COLORS["smoke"],
    }
    return severity_map.get(severity.lower(), COLORS["clean"])


def get_status_color(status: str) -> str:
    """Get color for verification status."""
    status_map = {
        "verified": COLORS["toxic"],
        "unverified": COLORS["ice"],
        "invalid": COLORS["smoke"],
        "error": COLORS["blood"],
    }
    return status_map.get(status.lower(), COLORS["clean"])
