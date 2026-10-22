#!/usr/bin/env python3
import click, json
from rich.console import Console
from .probe import probe
console = Console()
@click.group()
@click.version_option()
def main(): pass
@main.command()
@click.option('--url', required=True)
def check(url):
    res = probe(url)
    console.print(f"Status: {res['status']}")
    for f in res['headers']:
        console.print(f"  {f['header']}: {f['value']}")
    for i in res['issues']:
        console.print(f"[red]ISSUE: {i}[/red]")
if __name__ == '__main__': main()
