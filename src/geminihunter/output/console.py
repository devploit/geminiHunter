"""Rich terminal output for scan results."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from geminihunter.config import Config
from geminihunter.models import KeyIntelligence, KeyStatus, ScanResult

console = Console(stderr=True)

STATUS_STYLES = {
    KeyStatus.VALID: ("VALID", "bold green"),
    KeyStatus.BYPASSED: ("BYPASSED", "bold yellow"),
    KeyStatus.FORBIDDEN: ("403", "red"),
    KeyStatus.INVALID: ("INVALID", "dim"),
    KeyStatus.UNKNOWN: ("ERR", "dim red"),
}


def render_table(result: ScanResult, config: Config) -> str:
    """Render scan results as a rich table."""
    if not result.results:
        console.print("  [dim]No results to display.[/dim]")
        return ""

    # Summary line
    console.print(
        f"  [bold]Results[/bold]  "
        f"[green]{result.keys_valid} valid[/green]  "
        f"[yellow]{result.keys_bypassed} bypassed[/yellow]  "
        f"[red]{result.keys_forbidden} forbidden[/red]  "
        f"[dim]{result.keys_invalid} invalid[/dim]  "
        f"[dim]({result.duration_seconds}s)[/dim]\n"
    )

    # Results table
    table = Table(
        show_header=True,
        header_style="bold",
        border_style="dim",
        pad_edge=False,
        box=None,
        padding=(0, 2),
    )
    table.add_column("Status", justify="center", width=10)
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Domain", style="blue")
    table.add_column("Models", justify="right", style="green")
    table.add_column("Billing", justify="center")
    table.add_column("Bypass", style="yellow")

    for r in result.results:
        # Key display
        key_display = f"{r.key[:10]}...{r.key[-6:]}"

        # Status
        label, style = STATUS_STYLES.get(r.status, ("?", "dim"))
        status_text = Text(label, style=style)

        # Models
        models_str = str(len(r.available_models)) if r.available_models else "-"

        # Billing
        if r.billing_enabled is True:
            billing_str = Text("YES", style="bold green")
        elif r.billing_enabled is False:
            billing_str = Text("NO", style="red")
        else:
            billing_str = Text("-", style="dim")

        # Bypass
        bypass_str = r.bypass.technique.split(":")[-1] if r.bypass else "-"

        table.add_row(
            status_text,
            key_display,
            r.target_domain or "-",
            models_str,
            billing_str,
            bypass_str,
        )

    console.print(table)
    console.print()

    # Detail panels for valid/bypassed keys only
    working = [r for r in result.results if r.status in (KeyStatus.VALID, KeyStatus.BYPASSED)]
    for r in working:
        _print_key_detail(r, config)

    return ""


def _print_key_detail(r: KeyIntelligence, config: Config) -> None:
    """Print detailed panel for a working key."""
    lines: list[str] = []

    lines.append(f"  [bold cyan]Key[/bold cyan]      {r.key}")

    if r.target_domain and r.target_domain != "direct":
        lines.append(f"  [bold cyan]Domain[/bold cyan]   {r.target_domain}")

    if r.sources and r.sources != ["direct_input"]:
        lines.append(f"  [bold cyan]Source[/bold cyan]   {r.sources[0]}")
        for src in r.sources[1:3]:
            lines.append(f"           {src}")
        if len(r.sources) > 3:
            lines.append(f"           [dim]+{len(r.sources) - 3} more[/dim]")

    if r.bypass:
        lines.append(f"  [bold cyan]Bypass[/bold cyan]   {r.bypass.technique}")
        for k, v in r.bypass.headers.items():
            lines.append(f"           [dim]{k}: {v}[/dim]")

    if r.project_id:
        lines.append(f"  [bold cyan]Project[/bold cyan]  {r.project_id}")

    if r.billing_enabled is not None:
        billing = "[green]Active[/green]" if r.billing_enabled else "[red]Inactive[/red]"
        lines.append(f"  [bold cyan]Billing[/bold cyan]  {billing}")

    if r.available_models:
        lines.append(f"  [bold cyan]Models[/bold cyan]   {len(r.available_models)} available")
        for m in r.available_models[:5]:
            lines.append(f"           [dim]{m}[/dim]")
        if len(r.available_models) > 5:
            lines.append(f"           [dim]+{len(r.available_models) - 5} more[/dim]")

    if r.quota_remaining is not None:
        lines.append(f"  [bold cyan]Quota[/bold cyan]    {r.quota_remaining}/{r.quota_limit or '?'}")

    if config.evidence and r.curl_commands:
        lines.append(f"  [bold cyan]PoC[/bold cyan]")
        for cmd in r.curl_commands:
            lines.append(f"    [dim]$ {cmd}[/dim]")

    panel_content = "\n".join(lines)
    border = "green" if r.status == KeyStatus.VALID else "yellow"
    label = f"[bold {border}]{r.status.value.upper()}[/bold {border}]"
    console.print(Panel(panel_content, title=label, border_style=border, padding=(1, 1)))
