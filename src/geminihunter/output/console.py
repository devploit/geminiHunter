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
    KeyStatus.FORBIDDEN: ("FORBIDDEN", "bold red"),
    KeyStatus.INVALID: ("INVALID", "dim"),
    KeyStatus.UNKNOWN: ("UNKNOWN", "dim red"),
}


def render_table(result: ScanResult, config: Config) -> str:
    """Render scan results as a rich table to stderr and return summary string."""

    if not result.results:
        console.print("[dim]No results to display.[/dim]")
        return ""

    # Summary panel
    summary = (
        f"[green]{result.keys_valid} valid[/green] | "
        f"[yellow]{result.keys_bypassed} bypassed[/yellow] | "
        f"[red]{result.keys_forbidden} forbidden[/red] | "
        f"[dim]{result.keys_invalid} invalid[/dim] | "
        f"[dim]{result.duration_seconds}s[/dim]"
    )
    console.print(Panel(summary, title="Scan Summary", border_style="blue"))

    # Results table
    table = Table(show_header=True, header_style="bold", border_style="dim")
    table.add_column("#", style="dim", width=3)
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Domain", style="blue")
    table.add_column("Models", style="green")
    table.add_column("Billing", justify="center")
    table.add_column("Bypass", style="yellow")

    for i, r in enumerate(result.results, 1):
        # Key: show first 10 + last 8 chars
        key_display = f"{r.key[:10]}...{r.key[-8:]}" if len(r.key) > 20 else r.key

        # Status
        label, style = STATUS_STYLES.get(r.status, ("?", "dim"))
        status_text = Text(label, style=style)

        # Models count
        models_str = str(len(r.available_models)) if r.available_models else "-"

        # Billing
        if r.billing_enabled is True:
            billing_str = Text("YES", style="bold green")
        elif r.billing_enabled is False:
            billing_str = Text("NO", style="red")
        else:
            billing_str = Text("-", style="dim")

        # Bypass technique
        bypass_str = r.bypass.technique if r.bypass else "-"

        table.add_row(
            str(i),
            key_display,
            status_text,
            r.target_domain or "-",
            models_str,
            billing_str,
            bypass_str,
        )

    console.print(table)

    # Detail panels for valid/bypassed keys
    for r in result.results:
        if r.status not in (KeyStatus.VALID, KeyStatus.BYPASSED):
            continue

        _print_key_detail(r, config)

    return ""


def _print_key_detail(r: KeyIntelligence, config: Config) -> None:
    """Print detailed info for a working key."""
    lines: list[str] = []
    lines.append(f"[cyan]Key:[/cyan] {r.key}")
    lines.append(f"[cyan]Status:[/cyan] {r.status.value}")
    lines.append(f"[cyan]Domain:[/cyan] {r.target_domain}")

    if r.sources:
        lines.append(f"[cyan]Sources:[/cyan]")
        for src in r.sources[:5]:
            lines.append(f"  - {src}")
        if len(r.sources) > 5:
            lines.append(f"  ... and {len(r.sources) - 5} more")

    if r.bypass:
        lines.append(f"[cyan]Bypass:[/cyan] {r.bypass.technique}")
        if r.bypass.headers:
            for k, v in r.bypass.headers.items():
                lines.append(f"  {k}: {v}")

    if r.available_models:
        lines.append(f"[cyan]Models ({len(r.available_models)}):[/cyan]")
        for m in r.available_models[:10]:
            lines.append(f"  - {m}")
        if len(r.available_models) > 10:
            lines.append(f"  ... and {len(r.available_models) - 10} more")

    if r.project_id:
        lines.append(f"[cyan]Project ID:[/cyan] {r.project_id}")

    if r.billing_enabled is not None:
        billing = "[green]Active[/green]" if r.billing_enabled else "[red]Inactive[/red]"
        lines.append(f"[cyan]Billing:[/cyan] {billing}")

    if r.quota_remaining is not None:
        lines.append(f"[cyan]Quota:[/cyan] {r.quota_remaining}/{r.quota_limit or '?'}")

    if config.evidence and r.curl_commands:
        lines.append(f"[cyan]Evidence:[/cyan]")
        for cmd in r.curl_commands:
            lines.append(f"  $ {cmd}")

    panel_content = "\n".join(lines)
    key_short = f"...{r.key[-8:]}"
    style = "green" if r.status == KeyStatus.VALID else "yellow"
    console.print(Panel(panel_content, title=f"Key {key_short}", border_style=style))
