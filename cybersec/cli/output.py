from enum import Enum

from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme

console = Console(
    theme=Theme({
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "dim green",
        "info": "cyan",
        "success": "bold green",
        "error": "bold red",
    })
)


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


def risk_style(score: float) -> str:
    """Return Rich style string for a risk score."""
    if score >= 0.8:
        return "bold red"
    elif score >= 0.5:
        return "yellow"
    else:
        return "dim green"


def risk_color(score: float) -> str:
    """Return a color name for a risk score."""
    if score >= 0.8:
        return "red"
    elif score >= 0.5:
        return "yellow"
    else:
        return "green"


def risk_level(score: float) -> RiskLevel:
    """Return RiskLevel enum for a score."""
    if score >= 0.8:
        return RiskLevel.CRITICAL
    elif score >= 0.5:
        return RiskLevel.HIGH
    else:
        return RiskLevel.LOW


def error_panel(message: str, title: str = "Error") -> None:
    """Print a styled error panel."""
    panel = Panel(
        f"  {message}",
        title=f"[bold red]{title}[/]",
        border_style="red",
        padding=(1, 2),
    )
    console.print(panel)


def success_panel(title: str, message: str) -> None:
    """Print a styled success panel."""
    panel = Panel(
        f"  {message}",
        title=f"[bold green]{title}[/]",
        border_style="green",
        padding=(1, 2),
    )
    console.print(panel)


def warning_panel(message: str, title: str = "Warning") -> None:
    """Print a styled warning panel."""
    panel = Panel(
        f"  {message}",
        title=f"[bold yellow]{title}[/]",
        border_style="yellow",
        padding=(1, 2),
    )
    console.print(panel)


def info_panel(message: str, title: str = "Info") -> None:
    """Print a styled info panel."""
    panel = Panel(
        f"  {message}",
        title=f"[bold cyan]{title}[/]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)
