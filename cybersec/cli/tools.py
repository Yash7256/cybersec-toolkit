import asyncio
import ipaddress
import sys
from datetime import datetime

import click
from rich.table import Table
from rich.panel import Panel

from cybersec.cli.output import console, error_panel

TOOLS_GROUP = click.Group(name="tools", help="Network reconnaissance tools")


@TOOLS_GROUP.command(name="dns")
@click.argument("target")
@click.option("--type", "record_type", default="ALL", help="DNS record type (A, AAAA, MX, TXT, NS, CNAME, SOA, ALL)")
def tools_dns(target: str, record_type: str) -> None:
    """Query DNS records for TARGET (domain or IP)."""
    from cybersec.core.tools import DNSTool

    console.print(f"[cyan]Querying DNS records for[/cyan] {target} [dim](type: {record_type})[/dim]")

    try:
        tool = DNSTool()
        result = tool.lookup(target, record_type=record_type)
        result = asyncio.run(result) if asyncio.iscoroutine(result) else result
    except ValueError as e:
        error_panel(str(e))
        sys.exit(1)
    except Exception as e:
        error_panel(f"DNS lookup failed: {e}")
        sys.exit(1)

    if result.error:
        error_panel(f"DNS query failed: {result.error}")
        sys.exit(1)

    record_map = {
        "A": result.a_records,
        "AAAA": result.aaaa_records,
        "MX": result.mx_records,
        "NS": result.ns_records,
        "TXT": result.txt_records,
        "CNAME": result.cname_records,
        "SOA": [result.soa_record] if result.soa_record else [],
    }

    if record_type != "ALL":
        record_map = {record_type: record_map.get(record_type, [])}

    has_records = False
    for rtype, records in record_map.items():
        if records:
            has_records = True
            table = Table(
                title=f"DNS {rtype} Records: {target}",
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("Type", width=10)
            table.add_column("Value", style="bold green")
            for record in records:
                table.add_row(rtype, str(record))
            console.print(f"\n{table}")

    if not has_records:
        console.print(f"[yellow]No {record_type} records found for {target}[/yellow]")
        return

    total = sum(len(r) for r in record_map.values())
    console.print(f"\n[green]✓[/green] [dim]{total} record(s) found[/dim]")


@TOOLS_GROUP.command(name="whois")
@click.argument("target")
def tools_whois(target: str) -> None:
    """Get WHOIS information for TARGET (domain or IP)."""
    from cybersec.core.tools import WhoisTool

    console.print(f"[cyan]Looking up WHOIS for[/cyan] {target}")

    try:
        tool = WhoisTool()
        result = tool.lookup(target)
        result = asyncio.run(result) if asyncio.iscoroutine(result) else result
    except PermissionError:
        error_panel("Permission denied. WHOIS may require elevated privileges.")
        sys.exit(1)
    except ValueError as e:
        error_panel(str(e))
        sys.exit(1)
    except Exception as e:
        error_panel(f"WHOIS lookup failed: {e}")
        sys.exit(1)

    if result.error:
        error_panel(f"WHOIS lookup failed: {result.error}")
        sys.exit(1)

    rows = []
    if result.domain_name:
        rows.append(f"  [cyan]Domain Name:[/] {result.domain_name}")
    if result.registrar:
        rows.append(f"  [cyan]Registrar:[/] {result.registrar}")
    if result.creation_date:
        rows.append(f"  [cyan]Created:[/] {result.creation_date}")
    if result.expiration_date:
        exp_val = result.expiration_date
        try:
            exp_date = datetime.fromisoformat(str(exp_val).replace("Z", "+00:00"))
            days_left = (exp_date - datetime.now()).days
            if days_left < 30:
                exp_val = f"[red]{exp_val} (expires in {days_left} days!)[/red]"
            elif days_left < 90:
                exp_val = f"[yellow]{exp_val} ({days_left} days)[/yellow]"
            else:
                exp_val = f"[green]{exp_val}[/green]"
        except (ValueError, TypeError):
            pass
        rows.append(f"  [cyan]Expires:[/] {exp_val}")
    if result.updated_date:
        rows.append(f"  [cyan]Updated:[/] {result.updated_date}")
    if result.name_servers:
        ns_str = "\n                  ".join(str(ns) for ns in result.name_servers[:5])
        rows.append(f"  [cyan]Name Servers:[/] {ns_str}")
    if result.status:
        rows.append(f"  [cyan]Status:[/] {result.status}")
    if result.emails:
        rows.append(f"  [cyan]Emails:[/] {', '.join(str(e) for e in result.emails[:3])}")
    if result.org:
        rows.append(f"  [cyan]Org:[/] {result.org}")

    panel = Panel(
        "\n".join(rows) if rows else "  No WHOIS data available",
        title=f"[bold]WHOIS: {target}[/]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(f"\n{panel}")


@TOOLS_GROUP.command(name="ping")
@click.argument("target")
@click.option("--count", default=4, type=int, help="Number of pings to send")
def tools_ping(target: str, count: int) -> None:
    """Ping TARGET and measure round-trip time."""
    from cybersec.core.tools import PingTool

    console.print(f"[cyan]Pinging[/cyan] {target} [dim]({count} packets)[/dim]")

    try:
        tool = PingTool()
        result = tool.ping(target, count=count)
        result = asyncio.run(result) if asyncio.iscoroutine(result) else result
    except PermissionError:
        error_panel("Permission denied. Ping may require elevated privileges (try sudo).")
        sys.exit(1)
    except ValueError as e:
        error_panel(str(e))
        sys.exit(1)
    except Exception as e:
        error_panel(f"Ping failed: {e}")
        sys.exit(1)

    if result.error:
        error_panel(f"Ping failed: {result.error}")
        sys.exit(1)

    loss_pct = result.packet_loss_pct
    min_rtt = result.min_rtt_ms
    avg_rtt = result.avg_rtt_ms
    max_rtt = result.max_rtt_ms

    console.print("\n[bold]Ping Statistics:[/bold]")
    console.print(f"  Sent:     {result.packets_sent}")
    console.print(f"  Received: {result.packets_received}")
    console.print(f"  Loss:     {loss_pct:.1f}%")

    if min_rtt is not None:
        console.print("\n[bold]RTT (ms):[/bold]")
        console.print(f"  Min:  {min_rtt}")
        console.print(f"  Avg:  {avg_rtt}")
        console.print(f"  Max:  {max_rtt}")

        max_display = max(max_rtt or 1, 1)
        bar_width = 40
        min_bar = int((min_rtt / max_display) * bar_width) if max_rtt else 0
        avg_bar = int((avg_rtt / max_display) * bar_width) if max_rtt else 0

        console.print("\n[bold]RTT Bar:[/bold]")
        console.print(f"  Min [{'█' * min_bar}{'░' * (bar_width - min_bar)}] {min_rtt}ms")
        console.print(f"  Avg [{'█' * avg_bar}{'░' * (bar_width - avg_bar)}] {avg_rtt}ms")
        console.print(f"  Max [{'█' * bar_width}] {max_rtt}ms")

    if result.raw_output:
        console.print("\n[dim]Raw output:[/dim]")
        console.print(f"[dim]{result.raw_output[:500]}[/dim]")


@TOOLS_GROUP.command(name="traceroute")
@click.argument("target")
@click.option("--max-hops", default=30, type=int, help="Maximum number of hops")
def tools_traceroute(target: str, max_hops: int) -> None:
    """Trace the route to TARGET."""
    from cybersec.core.tools import TracerouteTool

    console.print(f"[cyan]Tracing route to[/cyan] {target} [dim](max {max_hops} hops)[/dim]\n")

    try:
        tool = TracerouteTool()
        result = tool.trace(target, max_hops=max_hops)
        result = asyncio.run(result) if asyncio.iscoroutine(result) else result
    except PermissionError:
        error_panel("Permission denied. Traceroute may require elevated privileges (try sudo).")
        sys.exit(1)
    except ValueError as e:
        error_panel(str(e))
        sys.exit(1)
    except Exception as e:
        error_panel(f"Traceroute failed: {e}")
        sys.exit(1)

    if result.error:
        error_panel(f"Traceroute failed: {result.error}")
        sys.exit(1)

    table = Table(
        title=f"Traceroute to {target}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("HOP", width=6, style="bold")
    table.add_column("IP", width=18)
    table.add_column("HOSTNAME", width=30)
    table.add_column("RTT (ms)", width=12)

    for hop in result.hops:
        ip_str = hop.ip or "[dim]*[/dim]"
        hostname_str = hop.hostname or ""
        rtt_str = f"{hop.rtt_ms}" if hop.rtt_ms is not None else "-"
        table.add_row(str(hop.hop_number), ip_str, hostname_str, rtt_str)

    console.print(table)
    console.print(f"\n[dim]Trace complete. {result.total_hops} hops observed.[/dim]")


@TOOLS_GROUP.command(name="ssl")
@click.argument("host")
@click.option("--port", default=443, type=int, help="SSL port to check")
def tools_ssl(host: str, port: int) -> None:
    """Inspect SSL certificate for HOST."""
    from cybersec.core.tools import SSLTool

    console.print(f"[cyan]Inspecting SSL certificate for[/cyan] {host}:{port}")

    try:
        tool = SSLTool()
        result = tool.inspect(host, port=port)
        result = asyncio.run(result) if asyncio.iscoroutine(result) else result
    except ValueError as e:
        error_panel(str(e))
        sys.exit(1)
    except Exception as e:
        error_panel(f"SSL inspection failed: {e}")
        sys.exit(1)

    if result.error:
        error_panel(f"SSL error: {result.error}")
        sys.exit(1)

    days_left = result.days_until_expiry
    if result.is_expired:
        cert_status = "[bold red]EXPIRED[/bold red]"
    elif days_left < 30:
        cert_status = f"[yellow]EXPIRES IN {days_left} DAYS[/yellow]"
    elif days_left < 90:
        cert_status = f"[dim yellow]Expires in {days_left} days[/dim yellow]"
    else:
        cert_status = f"[green]Valid ({days_left} days)[/green]"

    tls_versions = result.tls_versions or []
    protocol = tls_versions[0] if tls_versions else "Unknown"
    if "1.0" in protocol or "1.1" in protocol:
        proto_style = "[red]"
    elif "1.2" in protocol:
        proto_style = "[yellow]"
    else:
        proto_style = "[green]"
    tls_badge = f"{proto_style}{protocol}[/]"

    rows = f"""
  [bold]Certificate Status:[/bold] {cert_status}
  
  [cyan]Subject (CN):[/] {result.cn or 'Unknown'}
  [cyan]Issuer:[/] {result.issuer or 'Unknown'}
  
  [cyan]Protocol:[/] {tls_badge}
  [cyan]Cipher Suite:[/] {result.cipher_suite or 'Unknown'}
  
  [cyan]Valid From:[/] {result.valid_from or 'Unknown'}
  [cyan]Expires:[/] {result.valid_to or 'Unknown'}
"""
    if result.is_self_signed:
        rows += "  [yellow]Self-signed certificate[/yellow]\n"
    if result.sans:
        rows += f"  [dim]SANs:[/dim] {', '.join(result.sans[:3])}"

    panel = Panel(
        rows,
        title=f"[bold]SSL Certificate: {host}:{port}[/]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(f"\n{panel}")


@TOOLS_GROUP.command(name="headers")
@click.argument("url")
def tools_headers(url: str) -> None:
    """Check HTTP security headers for URL."""
    from cybersec.core.tools import HTTPHeadersTool

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    console.print(f"[cyan]Checking HTTP headers for[/cyan] {url}")

    try:
        tool = HTTPHeadersTool()
        result = tool.inspect(url)
        result = asyncio.run(result) if asyncio.iscoroutine(result) else result
    except ValueError as e:
        error_panel(str(e))
        sys.exit(1)
    except Exception as e:
        error_panel(f"HTTP headers check failed: {e}")
        sys.exit(1)

    if result.error:
        error_panel(f"Request failed: {result.error}")
        sys.exit(1)

    security_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-content-type-options": "X-Content-Type",
        "x-frame-options": "X-Frame-Options",
        "x-xss-protection": "X-XSS-Protection",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "x-permitted-cross-domain-policies": "Cross-Domain",
    }

    table = Table(
        title=f"Security Headers: {url}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Header", width=28, style="bold")
    table.add_column("Status", width=8)
    table.add_column("Value", width=40)

    present_count = 0
    missing_count = 0

    for header_key, header_name in security_headers.items():
        found_value = None
        for k, v in result.headers.items():
            if k.lower() == header_key.lower():
                found_value = v
                break

        if found_value:
            table.add_row(header_name, "[green]✓[/green]", found_value[:60])
            present_count += 1
        else:
            table.add_row(header_name, "[red]✗[/red]", "[dim]Not set[/dim]")
            missing_count += 1

    console.print(f"\n[bold]Status Code:[/bold] {result.status_code or 'Unknown'}")
    console.print(f"\n{table}")
    console.print(f"\n  Present: [green]{present_count}[/green]   Missing: [red]{missing_count}[/red]")


@TOOLS_GROUP.command(name="subdomains")
@click.argument("domain")
@click.option("--size", default="small", type=click.Choice(["small", "medium", "large"]), help="Wordlist size")
def tools_subdomains(domain: str, size: str) -> None:
    """Find subdomains for DOMAIN."""
    from cybersec.core.tools import SubdomainTool

    console.print(f"[cyan]Enumerating subdomains for[/cyan] {domain} [dim]({size} wordlist)[/dim]")

    try:
        tool = SubdomainTool()
        result = tool.find(domain, wordlist_size=size)
        result = asyncio.run(result) if asyncio.iscoroutine(result) else result
    except ValueError as e:
        error_panel(str(e))
        sys.exit(1)
    except Exception as e:
        error_panel(f"Subdomain enumeration failed: {e}")
        sys.exit(1)

    if result.error:
        error_panel(f"Subdomain enumeration failed: {result.error}")
        sys.exit(1)

    found = result.found
    if not found:
        console.print(f"[yellow]No subdomains found for {domain}[/yellow]")
        return

    table = Table(
        title=f"Subdomains for {domain}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#", width=5, style="bold")
    table.add_column("Subdomain", style="bold green")
    table.add_column("IP(s)", width=25)
    table.add_column("CNAME", width=25)

    for i, entry in enumerate(found, 1):
        ips = ", ".join(entry.ip_addresses[:2]) if entry.ip_addresses else "-"
        cname = entry.cname or "-"
        table.add_row(str(i), entry.subdomain, ips[:25], cname[:25])

    console.print(f"\n{table}")
    console.print(
        f"\n[green]✓[/green] [bold]{len(found)}[/bold] subdomains found "
        f"[dim]({result.total_checked} checked, {result.scan_time_ms:.0f}ms)[/dim]"
    )


@TOOLS_GROUP.command(name="geo")
@click.argument("ip")
def tools_geo(ip: str) -> None:
    """Get geolocation information for IP address."""
    from cybersec.core.tools import GeoTool

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            console.print(f"[yellow]Private IP address: {ip}[/yellow]")
            console.print("[dim]Geolocation is only available for public IP addresses.[/dim]")
            sys.exit(0)
    except ValueError:
        pass

    console.print(f"[cyan]Looking up geolocation for[/cyan] {ip}")

    try:
        tool = GeoTool()
        result = tool.lookup(ip)
        result = asyncio.run(result) if asyncio.iscoroutine(result) else result
    except ValueError as e:
        error_panel(str(e))
        sys.exit(1)
    except Exception as e:
        error_panel(f"Geolocation lookup failed: {e}")
        sys.exit(1)

    if result.error:
        error_panel(f"Geolocation lookup failed: {result.error}")
        sys.exit(1)

    location = ""
    if result.city and result.city != "Unknown":
        location += result.city + ", "
    if result.region and result.region != "Unknown":
        location += result.region + ", "
    location += result.country or "Unknown"

    rows = f"""
  [cyan]IP Address:[/] {result.ip}
  [cyan]Location:[/] {location}
  
  [cyan]ISP:[/] {result.isp or 'Unknown'}
  [cyan]Organization:[/] {result.org or 'Unknown'}
  [cyan]ASN:[/] {result.asn or 'Unknown'}
"""
    if result.lat is not None and result.lon is not None:
        rows += f"  [cyan]Coordinates:[/] {result.lat}, {result.lon}\n"
    if result.timezone:
        rows += f"  [cyan]Timezone:[/] {result.timezone}\n"

    panel = Panel(
        rows,
        title=f"[bold]Geolocation: {ip}[/]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(f"\n{panel}")
