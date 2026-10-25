#!/usr/bin/env python3
"""headerprobe — inspect auth-related response headers of endpoints you own."""

from __future__ import annotations

import json
import sys

import click
import requests
from rich.console import Console
from rich.table import Table

from .analysis import SEVERITIES, worst
from .probe import DEFAULT_TIMEOUT, probe

console = Console()


def _severity_rank(name: str) -> int:
    return SEVERITIES.index(name)


@click.group()
@click.version_option()
def main():
    """Inspect WWW-Authenticate, session cookie and CORS response headers."""


@main.command()
@click.option("--url", required=True, help="Target URL (http or https).")
@click.option("--timeout", default=DEFAULT_TIMEOUT, show_default=True,
              type=float, help="Request timeout in seconds.")
@click.option("--insecure", is_flag=True,
              help="Do not verify the TLS certificate (testing only).")
@click.option("--no-redirects", is_flag=True, help="Do not follow redirects.")
@click.option("--fail-on", type=click.Choice(list(SEVERITIES)), default="medium",
              show_default=True,
              help="Exit 1 when a finding at or above this severity exists.")
@click.option("--json-out", is_flag=True, help="Print the report as JSON.")
def check(url, timeout, insecure, no_redirects, fail_on, json_out):
    """Probe URL and report auth-header findings."""
    try:
        report = probe(url, timeout=timeout, verify=not insecure,
                       redirects=not no_redirects)
    except ValueError as exc:
        console.print(f"[red]error:[/red] {exc}")
        sys.exit(2)
    except requests.exceptions.Timeout:
        console.print(f"[red]error:[/red] request to {url} timed out after {timeout}s")
        sys.exit(2)
    except requests.exceptions.RequestException as exc:
        console.print(f"[red]error:[/red] request failed: {exc}")
        sys.exit(2)

    if json_out:
        click.echo(json.dumps(report, indent=2))
    else:
        console.print(f"[bold]{report['url']}[/bold]  status {report['status']}")
        findings = report["findings"]
        if not findings:
            console.print("[green]no findings[/green]")
        else:
            table = Table(title="Findings")
            table.add_column("Severity")
            table.add_column("Check")
            table.add_column("Message")
            colour = {"high": "red", "medium": "yellow", "low": "cyan", "info": "white"}
            for f in findings:
                table.add_row(
                    f"[{colour[f['severity']]}]{f['severity'].upper()}[/]",
                    f["check"], f["message"])
            console.print(table)
        counts = report["counts"]
        console.print(
            "  ".join(f"{sev}: {counts[sev]}" for sev in SEVERITIES))

    threshold = _severity_rank(fail_on)
    hit = worst(report["findings"])
    if hit is not None and _severity_rank(hit) <= threshold:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
