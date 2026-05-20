"""
CyberSec CLI — Click + Rich terminal interface.
Calls core engine directly, never the HTTP API.
"""
import asyncio
import csv
import json
import sys
from datetime import datetime, timezone
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich import print as rprint

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "white",
}


def _risk_color(level: str) -> str:
    return RISK_COLORS.get(str(level).upper(), "white")


def _report_to_dict(report) -> dict:
    return {
        "target": report.target,
        "ip": report.ip,
        "total_ports_scanned": report.total_ports_scanned,
        "scan_duration": report.scan_duration,
        "open_ports": [
            {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service.name if p.service else None,
                "version": p.service.version if p.service else None,
                "banner": p.banner,
                "risk_level": p.risk.risk_level if p.risk else "INFO",
                "risk_score": p.risk.risk_score if p.risk else 0.0,
                "cves": [
                    {"id": c.id, "severity": c.severity, "cvss_score": c.cvss_score, "description": c.description}
                    for c in (p.cves or [])
                ],
            }
            for p in report.open_ports
        ],
    }


def _render_scan_table(report) -> None:
    table = Table(title=f"Scan Results — {report.target} ({report.ip})", show_lines=True)
    table.add_column("Port", style="bold cyan", justify="right")
    table.add_column("Protocol", justify="center")
    table.add_column("Service", style="cyan")
    table.add_column("Version")
    table.add_column("State", justify="center")
    table.add_column("Risk", justify="center")
    table.add_column("CVEs", justify="right")

    for p in report.open_ports:
        risk_level = p.risk.risk_level if p.risk else "INFO"
        color = _risk_color(risk_level)
        cve_count = str(len(p.cves)) if p.cves else "0"
        table.add_row(
            str(p.port),
            p.protocol or "tcp",
            (p.service.name if p.service else "unknown") or "unknown",
            (p.service.version if p.service else "") or "",
            p.state or "open",
            Text(risk_level, style=color),
            cve_count,
        )

    console.print(table)

    # Highest risk
    risk_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    highest = "INFO"
    for p in report.open_ports:
        rl = p.risk.risk_level if p.risk else "INFO"
        if risk_order.index(rl) > risk_order.index(highest):
            highest = rl

    summary = (
        f"[bold]Total scanned:[/bold] {report.total_ports_scanned}   "
        f"[bold]Open ports:[/bold] {len(report.open_ports)}   "
        f"[bold]Duration:[/bold] {report.scan_duration:.2f}s   "
        f"[bold]Highest risk:[/bold] [{_risk_color(highest)}]{highest}[/{_risk_color(highest)}]"
    )
    console.print(Panel(summary, title="Summary", border_style="dim"))


# ─────────────────────────────────────────────────────────────────────────────
# CLI Root
# ─────────────────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version="1.0.0", prog_name="CyberSec")
def cli():
    """⚡ CyberSec — Async Network Security Toolkit"""
    pass


# ─────────────────────────────────────────────────────────────────────────────
# scan group
# ─────────────────────────────────────────────────────────────────────────────

@cli.group()
def scan():
    """Port scanning commands"""
    pass


@scan.command("run")
@click.argument("target")
@click.option("--ports", default="quick", help="Scan profile (quick, web-audit, database, remote-access, full-tcp, stealth) or port range (common, top1000, 1-1000, 80,443)")
@click.option("--timeout", default=3.0, type=float, help="Connection timeout in seconds")
@click.option("--concurrency", default=500, type=int, help="Max concurrent connections")
@click.option("--rate", default="normal", type=click.Choice(["stealth", "normal", "aggressive"]), help="Rate preset: stealth (100 pps), normal (1000 pps), aggressive (5000 pps)")
@click.option("--rate-pps", type=float, help="Custom rate in packets per second")
@click.option("--ip-version", default="auto", type=click.Choice(["auto", "ipv4", "ipv6"]), help="IP version: auto (prefer v4), ipv4, or ipv6")
@click.option("--output", default="table", type=click.Choice(["table", "json", "csv"]), help="Output format")
@click.option("--save-file", is_flag=True, help="Save results to file with auto-generated filename")
@click.option("--save", is_flag=True, help="Save results to database")
def scan_run(target, ports, timeout, concurrency, rate, rate_pps, ip_version, output, save, save_file):
    """Run a port scan against TARGET"""
    from cybersec.core.scanner import AsyncPortScanner

    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] {target}   "
        f"[bold cyan]Ports:[/bold cyan] {ports}   "
        f"[bold cyan]Concurrency:[/bold cyan] {concurrency}",
        title="[bold]⚡ CyberSec Port Scanner[/bold]",
        border_style="purple"
    ))

    report = None
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("Initializing scanner...", total=None)
        try:
            scanner = AsyncPortScanner(
                timeout=timeout, 
                enable_connection_pool=True,
                rate_preset=rate,
                rate_pps=rate_pps
            )
            progress.update(task, description=f"Scanning {target}...")
            report = asyncio.run(scanner.scan(target, ports, ip_version=ip_version))
            progress.update(task, description="Scan complete.")
        except Exception as e:
            console.print(f"[bold red]✗ Scan failed:[/bold red] {e}")
            raise SystemExit(1)

    if output == "table":
        _render_scan_table(report)
    elif output == "json":
        print(json.dumps(_report_to_dict(report), indent=2))
        if save_file:
            filepath = report.save_to_file("json")
            console.print(f"[bold green]✓ Saved to:[/bold green] {filepath}")
    elif output == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(["port", "protocol", "service", "version", "state", "risk_score", "cve_count"])
        for p in report.open_ports:
            writer.writerow([
                p.port,
                p.protocol or "tcp",
                (p.service.name if p.service else "") or "unknown",
                (p.service.version if p.service else "") or "",
                p.state or "open",
                p.risk.risk_score if p.risk else 0.0,
                len(p.cves) if p.cves else 0,
            ])
        if save_file:
            filepath = report.save_to_file("csv")
            console.print(f"[bold green]✓ Saved to:[/bold green] {filepath}")

    if save:
        async def _save():
            from cybersec.database.session import async_session_maker
            from cybersec.database.models import Scan, ScanResult

            async with async_session_maker() as db:
                scan_row = Scan(
                    target=target,
                    scan_type="port",
                    status="completed",
                    port_range=ports,
                    started_at=report.started_at,
                    completed_at=report.completed_at,
                )
                db.add(scan_row)
                await db.flush()

                for p in report.open_ports:
                    db.add(ScanResult(
                        scan_id=scan_row.id,
                        port=p.port,
                        protocol=p.protocol or "tcp",
                        state=p.state or "open",
                        service=(p.service.name if p.service else None),
                        version=(p.service.version if p.service else None),
                        banner=p.banner,
                        cves=[{"id": c.id, "severity": c.severity, "cvss_score": c.cvss_score} for c in (p.cves or [])],
                    ))

                await db.commit()
                console.print(f"[bold green]✓ Saved to database with ID:[/bold green] {scan_row.id}")

        try:
            asyncio.run(_save())
        except Exception as e:
            console.print(f"[bold red]✗ Failed to save to database:[/bold red] {e}")


@scan.command("history")
@click.option("--limit", default=10, type=int, help="Number of recent scans to show")
def scan_history(limit):
    """Show recent scan history from database"""
    async def _fetch():
        from cybersec.database.session import async_session_maker
        from cybersec.database.models import Scan
        from sqlalchemy import select

        async with async_session_maker() as db:
            result = await db.execute(
                select(Scan).order_by(Scan.created_at.desc()).limit(limit)
            )
            return result.scalars().all()

    try:
        scans = asyncio.run(_fetch())
    except Exception as e:
        console.print(f"[bold red]✗ Database error:[/bold red] {e}")
        raise SystemExit(1)

    if not scans:
        console.print("[dim]No scan history found.[/dim]")
        return

    table = Table(title="Recent Scan History", show_lines=True)
    table.add_column("ID", style="dim")
    table.add_column("Target", style="cyan")
    table.add_column("Type", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Ports")
    table.add_column("Created At")
    table.add_column("Duration", justify="right")

    STATUS_COLORS = {"completed": "green", "failed": "red", "running": "yellow", "pending": "white"}

    for s in scans:
        color = STATUS_COLORS.get(s.status, "white")
        duration = ""
        if s.started_at and s.completed_at:
            dur = (s.completed_at - s.started_at).total_seconds()
            duration = f"{dur:.1f}s"
        created = s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else ""
        table.add_row(
            str(s.id)[:8],
            s.target,
            s.scan_type or "port",
            Text(s.status or "?", style=color),
            s.port_range or "—",
            created,
            duration,
        )

    console.print(table)


@scan.command("show")
@click.argument("scan_id")
def scan_show(scan_id):
    """Show full results for a scan by ID"""
    async def _fetch():
        from cybersec.database.session import async_session_maker
        from cybersec.database.models import Scan, ScanResult
        from sqlalchemy import select

        async with async_session_maker() as db:
            s = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
            if not s:
                return None, []
            results = (await db.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))).scalars().all()
            return s, results

    try:
        scan_obj, results = asyncio.run(_fetch())
    except Exception as e:
        console.print(f"[bold red]✗ Database error:[/bold red] {e}")
        raise SystemExit(1)

    if scan_obj is None:
        console.print(f"[bold red]✗ Scan not found:[/bold red] {scan_id}")
        raise SystemExit(1)

    console.print(Panel(
        f"[bold]Target:[/bold] {scan_obj.target}\n"
        f"[bold]Status:[/bold] {scan_obj.status}\n"
        f"[bold]Port Range:[/bold] {scan_obj.port_range or '—'}\n"
        f"[bold]Started:[/bold] {scan_obj.started_at}\n"
        f"[bold]Completed:[/bold] {scan_obj.completed_at}",
        title=f"Scan {str(scan_obj.id)[:8]}",
        border_style="purple",
    ))

    table = Table(show_lines=True)
    table.add_column("Port", justify="right", style="bold cyan")
    table.add_column("Protocol")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("State")
    table.add_column("CVEs", justify="right")

    for r in results:
        cves = r.cves or []
        table.add_row(
            str(r.port) if r.port else "—",
            r.protocol or "tcp",
            r.service or "unknown",
            r.version or "",
            r.state or "open",
            str(len(cves)),
        )

    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# tools group
# ─────────────────────────────────────────────────────────────────────────────

@cli.group()
def tools():
    """Network reconnaissance tools"""
    pass


# ── DNS ──────────────────────────────────────────────────────────────────────

def _render_dns(result) -> None:
    if result.error:
        console.print(f"[bold red]✗ DNS Error:[/bold red] {result.error}")
        return
    table = Table(title=f"DNS Records — {result.target} ({result.record_type})", show_lines=True)
    table.add_column("Type", style="cyan", justify="center")
    table.add_column("Value")
    table.add_column("TTL", justify="right")
    for rec in result.records:
        table.add_row(rec.get("type", "?"), str(rec.get("value", "")), str(rec.get("ttl", "")))
    console.print(table)
    console.print(f"[dim]Query time: {result.query_time_ms:.1f} ms[/dim]")


@tools.command("dns")
@click.argument("domain")
@click.option("--type", "record_type", default="ALL",
              type=click.Choice(["ALL", "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]))
def tools_dns(domain, record_type):
    """DNS record enumeration"""
    from cybersec.core.tools.dns import dns_lookup
    try:
        result = asyncio.run(dns_lookup(domain, record_type))
        _render_dns(result)
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


# ── WHOIS ─────────────────────────────────────────────────────────────────────

def _render_whois(result) -> None:
    if result.error:
        console.print(f"[bold red]✗ WHOIS Error:[/bold red] {result.error}")
        return
    ns = "\n".join(result.name_servers) if result.name_servers else "—"
    body = (
        f"[bold]Registrar:[/bold] {result.registrar or '—'}\n"
        f"[bold]Creation:[/bold] {result.creation_date or '—'}\n"
        f"[bold]Expiration:[/bold] {result.expiration_date or '—'}\n"
        f"[bold]Updated:[/bold] {result.updated_date or '—'}\n"
        f"[bold]Org:[/bold] {result.org or '—'}\n"
        f"[bold]Country:[/bold] {result.country or '—'}\n"
        f"[bold]Nameservers:[/bold]\n{ns}"
    )
    console.print(Panel(body, title=f"WHOIS — {result.domain}", border_style="cyan"))


@tools.command("whois")
@click.argument("domain")
def tools_whois(domain):
    """WHOIS domain registration lookup"""
    from cybersec.core.tools.whois import whois_lookup
    try:
        result = asyncio.run(whois_lookup(domain))
        _render_whois(result)
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


# ── PING ──────────────────────────────────────────────────────────────────────

def _render_ping(result) -> None:
    if result.error:
        console.print(f"[bold red]✗ Ping Error:[/bold red] {result.error}")
        return
    body = (
        f"[bold]Host:[/bold] {result.target}\n"
        f"[bold]IP:[/bold] {result.ip or '—'}\n"
        f"[bold]Packets Sent:[/bold] {result.packets_sent}\n"
        f"[bold]Received:[/bold] {result.packets_received}\n"
        f"[bold]Loss:[/bold] {result.packet_loss_pct:.1f}%\n"
        f"[bold]RTT Min/Avg/Max:[/bold] "
        f"{result.min_ms or 0:.1f} / {result.avg_ms or 0:.1f} / {result.max_ms or 0:.1f} ms"
    )
    reachable = result.packets_received > 0
    reachable_color = "green" if reachable else "red"
    console.print(Panel(body, title=f"[{reachable_color}]Ping — {result.target}[/{reachable_color}]", border_style=reachable_color))


@tools.command("ping")
@click.argument("host")
@click.option("--count", default=4, type=int, help="Number of ping packets")
def tools_ping(host, count):
    """ICMP ping a host"""
    from cybersec.core.tools.ping import ping_host
    try:
        result = asyncio.run(ping_host(host, count))
        _render_ping(result)
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


# ── TRACEROUTE ────────────────────────────────────────────────────────────────

def _render_traceroute(result) -> None:
    if result.error:
        console.print(f"[bold red]✗ Traceroute Error:[/bold red] {result.error}")
        return
    table = Table(title=f"Traceroute — {result.target}", show_lines=True)
    table.add_column("Hop", justify="right", style="cyan")
    table.add_column("IP")
    table.add_column("Hostname")
    table.add_column("RTT (ms)", justify="right")
    for hop in result.hops:
        # hops are TracerouteHop dataclass objects
        ip = getattr(hop, 'ip', None) or "*"
        hostname = getattr(hop, 'hostname', None) or "*"
        rtt = getattr(hop, 'rtt_ms', None)
        hop_num = getattr(hop, 'hop', '?')
        table.add_row(
            str(hop_num),
            ip,
            hostname,
            f"{rtt:.1f}" if rtt else "*",
        )
    console.print(table)


@tools.command("traceroute")
@click.argument("host")
@click.option("--max-hops", default=30, type=int)
def tools_traceroute(host, max_hops):
    """Trace packet route to host"""
    from cybersec.core.tools.traceroute import traceroute
    try:
        result = asyncio.run(traceroute(host, max_hops))
        _render_traceroute(result)
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


# ── SSL ───────────────────────────────────────────────────────────────────────

def _render_ssl(result) -> None:
    if result.error:
        console.print(f"[bold red]✗ SSL Error:[/bold red] {result.error}")
        return
    cert = result.cert
    days = cert.days_remaining if cert else None
    days_colored = (
        f"[bold red]{days} days[/bold red]" if days is not None and days < 30
        else f"[green]{days} days[/green]" if days is not None
        else "—"
    )
    subject = str(cert.subject) if cert else "—"
    issuer = str(cert.issuer) if cert else "—"
    valid_from = cert.valid_from if cert else "—"
    valid_until = cert.valid_until if cert else "—"
    san_list = cert.san[:5] if cert and cert.san else []

    body = (
        f"[bold]Subject:[/bold] {subject}\n"
        f"[bold]Issuer:[/bold] {issuer}\n"
        f"[bold]Valid From:[/bold] {valid_from}\n"
        f"[bold]Expires:[/bold] {valid_until} ({days_colored})\n"
        f"[bold]TLS Version:[/bold] {result.tls_version or '—'}\n"
        f"[bold]Cipher:[/bold] {result.cipher_suite or '—'}\n"
        f"[bold]TLS 1.2:[/bold] {'✓' if result.supports_tls12 else '✗'}   "
        f"[bold]TLS 1.3:[/bold] {'✓' if result.supports_tls13 else '✗'}\n"
        f"[bold]Self-Signed:[/bold] {'yes' if result.is_self_signed else 'no'}\n"
        f"[bold]SANs:[/bold] {', '.join(san_list) if san_list else '—'}"
    )
    console.print(Panel(body, title=f"SSL Certificate — {result.host}:{result.port}", border_style="cyan"))


@tools.command("ssl")
@click.argument("host")
@click.option("--port", default=443, type=int)
def tools_ssl(host, port):
    """Inspect SSL/TLS certificate"""
    from cybersec.core.tools.ssl import ssl_audit
    try:
        result = asyncio.run(ssl_audit(host, port))
        _render_ssl(result)
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


# ── HTTP HEADERS ──────────────────────────────────────────────────────────────

def _render_headers(result) -> None:
    if result.error:
        console.print(f"[bold red]✗ Headers Error:[/bold red] {result.error}")
        return
    table = Table(title=f"Security Headers — {result.target}", show_lines=True)
    table.add_column("Header", style="cyan")
    table.add_column("Present", justify="center")
    table.add_column("Value")
    table.add_column("Severity", justify="center")

    SEV_COLORS = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "blue", "NONE": "green"}

    for h in result.security_analysis:
        # h is a SecurityHeaderAnalysis dataclass
        present_text = Text("✓", style="green") if h.present else Text("✗", style="red")
        sev = h.severity if hasattr(h, 'severity') else "NONE"
        sev_color = SEV_COLORS.get(sev, "white")
        table.add_row(
            h.header,
            present_text,
            (h.value or "")[:60],
            Text(sev, style=sev_color),
        )
    console.print(table)
    console.print(f"[dim]Status: {result.status_code}[/dim]")


@tools.command("headers")
@click.argument("url")
@click.option("--path", default="/")
def tools_headers(url, path):
    """Inspect HTTP security headers"""
    from cybersec.core.tools.http_headers import check_http_headers
    try:
        result = asyncio.run(check_http_headers(url, path))
        _render_headers(result)
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


# ── SUBDOMAINS ────────────────────────────────────────────────────────────────

def _format_records(records: dict) -> str:
    parts = []
    for rtype in ("A", "AAAA", "CNAME", "MX", "TXT", "NS"):
        vals = records.get(rtype, [])
        if vals:
            if rtype == "TXT":
                parts.append(f"[yellow]TXT[/yellow]: {len(vals)}")
            else:
                items = ", ".join(v.replace(",", "\\,") for v in vals)
                parts.append(f"[yellow]{rtype}[/yellow]: {items}")
    return " | ".join(parts) if parts else "[dim]—[/dim]"


def _format_http(http: dict) -> str:
    if not http or not http.get("alive"):
        return "[dim]not responding[/dim]"
    parts = []
    parts.append(f"[green]{http.get('status', '?')}[/green]")
    if t := http.get("title"):
        parts.append(f"[white]{t}[/white]")
    if s := http.get("server"):
        parts.append(f"[cyan]{s}[/cyan]")
    if r := http.get("redirect_to"):
        parts.append(f"[yellow]→ {r}[/yellow]")
    if rt := http.get("response_time_ms"):
        parts.append(f"[dim]{rt}ms[/dim]")
    if techs := http.get("technologies"):
        parts.append(f"[magenta]{', '.join(techs)}[/magenta]")
    return " | ".join(parts)


def _format_risk(risk: dict | None) -> str:
    if not risk:
        return "[dim]—[/dim]"
    level = risk.get("level", "LOW")
    color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(level, "dim")
    return f"[{color}]{level}[/{color}]"


def _render_subdomains(result) -> None:
    if result.error:
        console.print(f"[bold red]✗ Subdomain Error:[/bold red] {result.error}")
        return

    if result.wildcard_detected:
        ips = ", ".join(result.wildcard_ips)
        console.print(f"[yellow]⚠ Wildcard DNS detected[/yellow] — resolves random subdomains to [bold]{ips}[/bold]")
        console.print("[dim]Results matching wildcard IPs were excluded (use --strictness low to include all)[/dim]")
        console.print()

    table = Table(title=f"Subdomains — {result.domain}", show_lines=True)
    table.add_column("Subdomain", style="cyan")
    table.add_column("A Record")
    table.add_column("Records")
    table.add_column("HTTP")
    table.add_column("Risk")
    table.add_column("Status")
    for sub in result.found:
        records = sub.get("records", {})
        a_recs = ", ".join(records.get("A", [])) or "[dim]—[/dim]"
        other = _format_records(records)
        http_str = _format_http(sub.get("http"))
        risk_str = _format_risk(sub.get("risk"))
        status = "[green]OK[/green]" if sub.get("resolved") else f"[red]{sub.get('error', 'unknown')}[/red]"
        table.add_row(sub.get("subdomain", ""), a_recs, other, http_str, risk_str, status)
    console.print(table)
    resolved = sum(1 for s in result.found if s.get("resolved"))
    failed = len(result.found) - resolved
    console.print(f"[dim]Resolved {resolved} / {result.total_checked} checked ({failed} failed)[/dim]")
    if result.scan_time_ms:
        parts = [f"[dim]Total [bold]{result.scan_time_ms}ms[/bold][/dim]"]
        if result.dns_time_ms:
            parts.append(f"[dim]DNS {result.dns_time_ms}ms[/dim]")
        if result.http_time_ms:
            parts.append(f"[dim]HTTP {result.http_time_ms}ms[/dim]")
        console.print(" ┃ ".join(parts))


@tools.command("subdomains")
@click.argument("domain")
@click.option("--size", default="small", type=click.Choice(["small", "medium", "large"]))
@click.option("--strictness", default="medium", type=click.Choice(["off", "low", "medium", "high"]))
def tools_subdomains(domain, size, strictness):
    """Enumerate subdomains via DNS brute-force"""
    from cybersec.core.tools.subdomain import find_subdomains
    try:
        result = asyncio.run(find_subdomains(domain, size, strictness))
        _render_subdomains(result)
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


# ── GEOIP ─────────────────────────────────────────────────────────────────────

def _render_geo(result) -> None:
    if result.error:
        console.print(f"[bold red]✗ GeoIP Error:[/bold red] {result.error}")
        return
    body = (
        f"[bold]Country:[/bold] {result.country or '—'} ({result.country_code or '?'})\n"
        f"[bold]Region:[/bold] {result.region or '—'}\n"
        f"[bold]City:[/bold] {result.city or '—'}\n"
        f"[bold]ISP:[/bold] {result.isp or '—'}\n"
        f"[bold]ASN:[/bold] {result.as_number or '—'}\n"
        f"[bold]Organization:[/bold] {result.org or '—'}\n"
        f"[bold]Lat/Lon:[/bold] {result.latitude}, {result.longitude}\n"
        f"[bold]Timezone:[/bold] {result.timezone or '—'}"
    )
    console.print(Panel(body, title=f"GeoIP — {result.target}", border_style="cyan"))


@tools.command("geo")
@click.argument("ip")
def tools_geo(ip):
    """GeoIP lookup for an IP address"""
    from cybersec.core.tools.geoip import geoip_lookup
    try:
        result = asyncio.run(geoip_lookup(ip))
        _render_geo(result)
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
