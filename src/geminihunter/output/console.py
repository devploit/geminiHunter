"""Rich terminal output for scan results."""

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

from geminihunter.config import Config
from geminihunter.models import KeyIntelligence, KeyStatus, ScanResult

console = Console(stderr=True)

STATUS_STYLES = {
    KeyStatus.VALID: ("VALID", "bold green"),
    KeyStatus.BYPASSED: ("BYPASSED", "bold yellow"),
    KeyStatus.RATE_LIMITED: ("429", "bold yellow"),
    KeyStatus.FORBIDDEN: ("403", "red"),
    KeyStatus.INVALID: ("INVALID", "dim"),
    KeyStatus.UNKNOWN: ("ERR", "dim red"),
}

BYPASS_CODE_LABEL = {
    200: ("200 OK", "bold green"),
    403: ("403 Permission changed", "yellow"),
    429: ("429 Rate-limited", "bold yellow"),
}


def render_table(
    result: ScanResult,
    config: Config,
    out_console: Console | None = None,
) -> str:
    """Render scan results as a rich table."""
    target_console = out_console or console
    if not result.results:
        target_console.print("  [dim]No results to display.[/dim]")
        return target_console.export_text() if getattr(target_console, "record", False) else ""

    # Summary line
    timing_parts = [f"{result.duration_seconds}s total"]
    for phase, secs in result.phase_timings.items():
        timing_parts.append(f"{phase}: {secs}s")
    timing_str = " | ".join(timing_parts)

    target_console.print(
        f"  [bold]Results[/bold]  "
        f"[green]{result.keys_valid} valid[/green]  "
        f"[yellow]{result.keys_bypassed} bypassed[/yellow]  "
        f"[yellow]{result.keys_rate_limited} rate-limited[/yellow]  "
        f"[red]{result.keys_forbidden} forbidden[/red]  "
        f"[dim]{result.keys_invalid} invalid[/dim]  "
        f"[dim]({timing_str})[/dim]\n"
    )

    # Print header
    header = Text()
    header.append(f"  {'Status':<10}  {'Key':<22}  {'Models':>6}  {'Billing':^7}  Bypass", style="bold")
    target_console.print(header)

    for r in result.results:
        key_display = f"{r.key[:10]}...{r.key[-6:]}"

        label, style = STATUS_STYLES.get(r.status, ("?", "dim"))

        models_str = str(len(r.available_models)) if r.available_models else "-"

        if r.billing_enabled is True:
            billing_text, billing_style = "YES", "bold green"
        elif r.billing_enabled is False:
            billing_text, billing_style = "NO", "red"
        else:
            billing_text, billing_style = "-", "dim"

        if r.bypass:
            code = r.bypass.bypass_status_code
            bp_label, bp_style = BYPASS_CODE_LABEL.get(code, (str(code), "yellow"))
        else:
            bp_label, bp_style = "-", "dim"

        line = Text()
        line.append(f"  {label:<10}", style=style)
        line.append(f"  {key_display:<22}", style="cyan")
        line.append(f"  {models_str:>6}", style="green")
        line.append(f"  {billing_text:^7}", style=billing_style)
        line.append(f"  {bp_label}", style=bp_style)
        target_console.print(line)

        # Source URLs (full, never truncated)
        sources = [s for s in r.sources if s != "direct_input"]
        if sources:
            target_console.print(f"  [dim]found in:[/dim] [blue]{escape(sources[0])}[/blue]")
            for s in sources[1:3]:
                target_console.print(f"           [dim]{escape(s)}[/dim]")
            if len(sources) > 3:
                target_console.print(f"           [dim]+{len(sources) - 3} more[/dim]")

        target_console.print()  # Blank line between entries


    # Detail panels for working keys and permission-progress attempts.
    working = [
        r
        for r in result.results
        if r.status in (KeyStatus.VALID, KeyStatus.BYPASSED, KeyStatus.RATE_LIMITED)
        or r.bypass
    ]
    for r in working:
        _print_key_detail(r, config, target_console)

    return target_console.export_text() if getattr(target_console, "record", False) else ""


def _print_key_detail(
    r: KeyIntelligence,
    config: Config,
    target_console: Console,
) -> None:
    """Print detailed panel for a working key."""
    lines: list[str] = []

    lines.append(f"  [bold cyan]Key[/bold cyan]      {escape(r.key)}")

    if r.target_domain and r.target_domain != "direct":
        lines.append(f"  [bold cyan]Domain[/bold cyan]   {escape(r.target_domain)}")

    if r.sources and r.sources != ["direct_input"]:
        lines.append(f"  [bold cyan]Source[/bold cyan]   {escape(r.sources[0])}")
        for src in r.sources[1:3]:
            lines.append(f"           {escape(src)}")
        if len(r.sources) > 3:
            lines.append(f"           [dim]+{len(r.sources) - 3} more[/dim]")

    if r.bypass:
        code = r.bypass.bypass_status_code
        code_label, code_style = BYPASS_CODE_LABEL.get(code, (str(code), "yellow"))
        if code == 403 and r.bypass.error_reason == "SERVICE_DISABLED":
            code_label, code_style = "403 Service disabled", "yellow"
        lines.append(f"  [bold cyan]Bypass[/bold cyan]   {escape(r.bypass.technique)}")
        lines.append(f"  [bold cyan]Status[/bold cyan]   403 → [{code_style}]{code_label}[/{code_style}]")
        if r.bypass.error_reason:
            lines.append(f"  [bold cyan]Reason[/bold cyan]   {escape(r.bypass.error_reason)}")
        for k, v in r.bypass.headers.items():
            lines.append(f"           [dim]{escape(k)}: {escape(v)}[/dim]")

    if r.project_id or r.project_name:
        project_str = r.project_id or ""
        if r.project_name:
            project_str = f"{r.project_name} ({r.project_id})" if r.project_id else r.project_name
        lines.append(f"  [bold cyan]Project[/bold cyan]  {escape(project_str)}")

    if r.billing_enabled is not None:
        billing = "[green]Active[/green]" if r.billing_enabled else "[red]Inactive[/red]"
        lines.append(f"  [bold cyan]Billing[/bold cyan]  {billing}")

    if r.detail:
        lines.append(f"  [bold cyan]Detail[/bold cyan]   {escape(r.detail)}")

    if r.available_models:
        lines.append(f"  [bold cyan]Models[/bold cyan]   {len(r.available_models)} available")
        for m in r.available_models[:5]:
            lines.append(f"           [dim]{escape(m)}[/dim]")
        if len(r.available_models) > 5:
            lines.append(f"           [dim]+{len(r.available_models) - 5} more[/dim]")

    if r.tuned_models:
        lines.append(f"  [bold cyan]Tuned[/bold cyan]    [bold red]{len(r.tuned_models)} fine-tuned model(s)[/bold red]")
        for m in r.tuned_models[:5]:
            lines.append(f"           [red]{escape(m)}[/red]")
        if len(r.tuned_models) > 5:
            lines.append(f"           [dim]+{len(r.tuned_models) - 5} more[/dim]")

    if r.restrictions:
        rx = r.restrictions
        if rx.unrestricted:
            lines.append("  [bold cyan]Restrict[/bold cyan] [bold red]None (unrestricted key)[/bold red]")
        elif rx.referrer_restricted:
            lines.append("  [bold cyan]Restrict[/bold cyan] HTTP Referrer")
            if rx.referrer_pattern:
                lines.append(f"           [dim]pattern: {escape(rx.referrer_pattern)}[/dim]")
        elif rx.restriction_type == "application":
            lines.append("  [bold cyan]Restrict[/bold cyan] Application (query param blocked, header works)")
        elif rx.restriction_type == "no_referrer_restriction_observed":
            lines.append("  [bold cyan]Restrict[/bold cyan] No referrer restriction observed")
        elif rx.restriction_type:
            lines.append(f"  [bold cyan]Restrict[/bold cyan] {escape(rx.restriction_type)}")

    if r.quota_remaining is not None:
        lines.append(f"  [bold cyan]Quota[/bold cyan]    {r.quota_remaining}/{r.quota_limit or '?'}")

    panel_content = "\n".join(lines)
    border = (
        "green"
        if r.status == KeyStatus.VALID
        else "red"
        if r.status == KeyStatus.FORBIDDEN
        else "yellow"
    )
    label = f"[bold {border}]{r.status.value.upper()}[/bold {border}]"
    target_console.print(Panel(panel_content, title=label, border_style=border, padding=(1, 1)))

    # Print curls OUTSIDE the panel so they're easy to copy
    if config.evidence and r.curl_commands:
        target_console.print("  [bold cyan]PoC curls:[/bold cyan]")
        for cmd in r.curl_commands:
            target_console.print(f"  {cmd}\n", style="dim", markup=False, soft_wrap=True)
