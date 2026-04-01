import asyncio
import json
import sys

import click
from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from cybersec.core.scanner import AsyncPortScanner
from cybersec.core.utils import resolve_target
from cybersec.cli.output import (
    console,
    error_panel,
)

SCAN_GROUP = click.Group(name="scan", help="Port and vulnerability scanning commands")


@SCAN_GROUP.command(name="run")
@click.argument("target")
@click.option("--ports", default="common", help="Port range: common, all, 1-1024, or comma-separated")
@click.option("--protocol", default="tcp", type=click.Choice(["tcp", "udp", "both"]), help="Protocol to scan")
@click.option("--timeout", default=1.0, type=float, help="Connection timeout in seconds")
@click.option("--concurrency", default=500, type=int, help="Max parallel connections")
@click.option("--output", default="table", type=click.Choice(["table", "json", "csv"]), help="Output format")
@click.option("--save", type=click.Path(), help="Save results to file")
def scan_run(
    target: str,
    ports: str,
    protocol: str,
    timeout: float,
    concurrency: int,
    output: str,
    save: str | None,
) -> None:
    """Run a port scan on TARGET (IP or hostname)."""
    try:
        resolved_ip = resolve_target(target)
        console.print(f"[dim]Resolved {target} → {resolved_ip}[/dim]")
    except ValueError as e:
        error_panel(str(e))
        sys.exit(1)

    scanner = AsyncPortScanner()
    open_ports_found = 0

    def on_progress(port: int, state: str, service: str) -> None:
        nonlocal open_ports_found
        if state == "open":
            open_ports_found += 1

    console.print(f"\n[cyan]Starting scan on[/cyan] {target} [dim]({resolved_ip})[/dim]")
    console.print(f"[dim]Ports: {ports} | Protocol: {protocol} | Timeout: {timeout}s | Concurrency: {concurrency}[/dim]\n")

    try:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            scan_task = progress.add_task("[cyan]Scanning ports...", total=100)
            progress.update(scan_task, description=f"[cyan]Scanning {target}...")

            async def run_scan():
                report = await scanner.scan(
                    target=target,
                    ports=ports,
                    protocol=protocol,
                    timeout=timeout,
                    concurrency=concurrency,
                    on_progress=on_progress,
                )
                return report

            report = asyncio.run(run_scan())
            progress.update(scan_task, completed=100, description="[green]Scan complete!")

    except Exception as e:
        error_panel(f"Scan failed: {e}")
        sys.exit(1)

    open_ports = [p for p in report.open_ports if p.state == "open"]
    closed_ports = [p for p in report.open_ports if p.state == "closed"]
    filtered_ports = [p for p in report.open_ports if p.state == "filtered"]

    if output == "json":
        output_data = {
            "target": report.target,
            "ip": report.ip,
            "scan_type": report.scan_type,
            "duration": report.scan_duration,
            "timestamp": report.timestamp.isoformat(),
            "open_ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version,
                    "banner": p.banner,
                    "os_hint": p.os_hint,
                    "risk_score": p.risk_score,
                    "cves": [{"id": c.id, "cvss_score": c.cvss_score, "severity": c.severity} for c in p.cves],
                }
                for p in open_ports
            ],
            "summary": {
                "total_scanned": report.ports_scanned,
                "open": len(open_ports),
                "closed": len(closed_ports),
                "filtered": len(filtered_ports),
            },
        }
        json_str = json.dumps(output_data, indent=2)
        if save:
            with open(save, "w") as f:
                f.write(json_str)
            console.print(f"[green]Results saved to {save}[/green]")
        else:
            console.print(json_str)
        return

    if output == "csv":
        csv_lines = ["PORT,PROTOCOL,STATE,SERVICE,VERSION,RISK,TOP_CVE"]
        for p in open_ports:
            top_cve = p.cves[0].id if p.cves else ""
            csv_lines.append(f"{p.port},{p.protocol},{p.state},{p.service},{p.version or ''},{p.risk_score:.2f},{top_cve}")
        csv_str = "\n".join(csv_lines)
        if save:
            with open(save, "w") as f:
                f.write(csv_str)
            console.print(f"[green]Results saved to {save}[/green]")
        else:
            console.print(csv_str)
        return

    table = Table(title=f"Port Scan Results: {target}", show_header=True, header_style="bold cyan")
    table.add_column("PORT", style="bold", width=8)
    table.add_column("PROTO", width=6)
    table.add_column("STATE", width=10)
    table.add_column("SERVICE", width=15)
    table.add_column("VERSION", width=20)
    table.add_column("RISK", width=8)
    table.add_column("TOP CVE", width=20)

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for port in open_ports:
        state_str = f"[green]{port.state.upper()}[/green]"
        version_str = port.version or "-"
        top_cve_str = port.cves[0].id if port.cves else "-"

        risk = port.risk_score
        if risk >= 0.8:
            risk_str = "[bold red]CRITICAL[/]"
            critical_count += 1
        elif risk >= 0.5:
            risk_str = "[yellow]HIGH[/]"
            high_count += 1
        elif risk >= 0.3:
            risk_str = "[dim yellow]MEDIUM[/]"
            medium_count += 1
        else:
            risk_str = "[dim]LOW[/]"
            low_count += 1

        table.add_row(
            str(port.port),
            port.protocol,
            state_str,
            port.service,
            version_str,
            risk_str,
            top_cve_str,
        )

    console.print(table)

    summary_lines = [
        f"  Target:      {report.target} ({report.ip})",
        f"  Open:       {len(open_ports)}",
        f"  Closed:     {len(closed_ports)}",
        f"  Filtered:   {len(filtered_ports)}",
        f"  Duration:   {report.scan_duration:.2f}s",
        "",
        f"  [bold red]Critical:[/] {critical_count}   [yellow]High:[/] {high_count}   [dim yellow]Medium:[/] {medium_count}   [dim]Low:[/] {low_count}",
    ]

    summary_panel = Panel(
        "\n".join(summary_lines),
        title="[bold]Scan Summary[/]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(f"\n{summary_panel}")

    if save:
        output_data = {
            "target": report.target,
            "ip": report.ip,
            "duration": report.scan_duration,
            "open_ports": [
                {"port": p.port, "service": p.service, "risk_score": p.risk_score}
                for p in open_ports
            ],
        }
        with open(save, "w") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"\n[green]Results saved to {save}[/green]")


@SCAN_GROUP.command(name="history")
@click.option("--limit", default=10, type=int, help="Number of recent scans to show")
def scan_history(limit: int) -> None:
    """Show recent scan history."""
    console.print("[yellow]History feature requires database connection.[/yellow]")
    console.print(f"[dim]Showing last {limit} scans (not yet implemented)[/dim]")


@SCAN_GROUP.command(name="show")
@click.argument("scan_id")
@click.option("--format", default="table", type=click.Choice(["table", "json"]), help="Output format")
def scan_show(scan_id: str, format: str) -> None:
    """Show details of a previous scan."""
    console.print("[yellow]Scan details require database connection.[/yellow]")
    console.print(f"[dim]Scan ID: {scan_id} (not yet implemented)[/dim]")
