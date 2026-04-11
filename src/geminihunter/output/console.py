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

BYPASS_CODE_LABEL = {
    200: ("200 OK", "bold green"),
    429: ("429 Rate-limited", "bold yellow"),
}


def render_table(result: ScanResult, config: Config) -> str:
    """Render scan results as a rich table."""
    if not result.results:
        console.print("  [dim]No results to display.[/dim]")
        return ""

    # Summary line
    timing_parts = [f"{result.duration_seconds}s total"]
    for phase, secs in result.phase_timings.items():
        timing_parts.append(f"{phase}: {secs}s")
    timing_str = " | ".join(timing_parts)

    console.print(
        f"  [bold]Results[/bold]  "
        f"[green]{result.keys_valid} valid[/green]  "
        f"[yellow]{result.keys_bypassed} bypassed[/yellow]  "
        f"[red]{result.keys_forbidden} forbidden[/red]  "
        f"[dim]{result.keys_invalid} invalid[/dim]  "
        f"[dim]({timing_str})[/dim]\n"
    )

    # Print header
    console.print(
        f"  {'Status':<10}  {'Key':<22}  {'Models':>6}  {'Billing':^7}  {'Bypass'}",
        style="bold",
    )

    for r in result.results:
        key_display = f"{r.key[:10]}...{r.key[-6:]}"

        label, style = STATUS_STYLES.get(r.status, ("?", "dim"))

        models_str = str(len(r.available_models)) if r.available_models else "-"

        if r.billing_enabled is True:
            billing = "[bold green]YES[/bold green]"
        elif r.billing_enabled is False:
            billing = "[red]NO[/red]"
        else:
            billing = "[dim]-[/dim]"

        if r.bypass:
            code = r.bypass.bypass_status_code
            code_label, code_style = BYPASS_CODE_LABEL.get(code, (str(code), "yellow"))
            bypass = f"[{code_style}]{code_label}[/{code_style}]"
        else:
            bypass = "[dim]-[/dim]"

        console.print(
            f"  [{style}]{label:<10}[/{style}]  [cyan]{key_display:<22}[/cyan]  [green]{models_str:>6}[/green]  {billing:^7}  {bypass}"
        )

        # Source URLs (full, never truncated)
        sources = [s for s in r.sources if s != "direct_input"]
        if sources:
            console.print(f"  [dim]found in:[/dim] [blue]{sources[0]}[/blue]")
            for s in sources[1:3]:
                console.print(f"           [dim]{s}[/dim]")
            if len(sources) > 3:
                console.print(f"           [dim]+{len(sources) - 3} more[/dim]")

        console.print()  # Blank line between entries


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
        code = r.bypass.bypass_status_code
        code_label, code_style = BYPASS_CODE_LABEL.get(code, (str(code), "yellow"))
        lines.append(f"  [bold cyan]Bypass[/bold cyan]   {r.bypass.technique}")
        lines.append(f"  [bold cyan]Status[/bold cyan]   403 → [{code_style}]{code_label}[/{code_style}]")
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

    panel_content = "\n".join(lines)
    border = "green" if r.status == KeyStatus.VALID else "yellow"
    label = f"[bold {border}]{r.status.value.upper()}[/bold {border}]"
    console.print(Panel(panel_content, title=label, border_style=border, padding=(1, 1)))

    # Print curls OUTSIDE the panel so they're easy to copy
    if config.evidence and r.curl_commands:
        console.print(f"  [bold cyan]PoC curls:[/bold cyan]")
        for cmd in r.curl_commands:
            console.print(f"  [dim]{cmd}[/dim]\n")
