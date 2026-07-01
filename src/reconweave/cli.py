"""reconweave command-line interface (typer).

Commands: scan, graph, report, watch, export, serve, collectors.
Everything runs offline by default; ``--live`` enables real collectors.
"""

from __future__ import annotations

import json
import os
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__, collectors as collectors_pkg
from .config import load_config
from .engine import Engine
from .exporters import available_formats, export
from .monitoring import WatchStore
from .report import write_report
from .seeds import detect

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="reconweave — offline-first OSINT correlation platform.")
console = Console()


def _engine(live: bool, config_path: Optional[str], no_cache: bool) -> Engine:
    cfg = load_config(config_path)
    cfg.live = live or cfg.live
    return Engine(cfg, use_cache=not no_cache)


def _print_summary(result) -> None:
    seed = result.seed
    stats = result.graph.stats()
    console.print(Panel.fit(
        f"[bold]{seed.value}[/bold]  ([cyan]{seed.type.value}[/cyan])\n"
        f"collectors: {', '.join(result.collectors_run) or 'none'}\n"
        f"nodes: [bold]{stats['nodes']}[/bold]   edges: [bold]{stats['edges']}[/bold]   "
        f"correlations: [bold]{len(result.correlations)}[/bold]   "
        f"{'[red]LIVE[/red]' if result.live else '[green]OFFLINE[/green]'}",
        title="reconweave scan", border_style="cyan"))

    band_color = {"critical": "red", "high": "orange3", "medium": "yellow",
                  "low": "green", "minimal": "cyan"}.get(result.risk.band, "white")
    rtable = Table(title=f"Exposure risk: {result.risk.score}/100 "
                        f"[{result.risk.band.upper()}]", show_header=True,
                   header_style="bold", title_style=band_color)
    rtable.add_column("Factor")
    rtable.add_column("Points", justify="right")
    rtable.add_column("Detail")
    for f in result.risk.factors:
        rtable.add_row(f.name, f"+{f.points:.0f}", f.detail)
    if not result.risk.factors:
        rtable.add_row("—", "0", "no exposure detected")
    console.print(rtable)


@app.command()
def scan(
    seed: str = typer.Argument(..., help="Seed value (domain, email, username, ip, ...)."),
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Force seed type."),
    live: bool = typer.Option(False, "--live", help="Enable real network collectors."),
    json_out: Optional[str] = typer.Option(None, "--json", help="Write full JSON here."),
    report_out: Optional[str] = typer.Option(None, "--report", help="Write HTML report here."),
    config: Optional[str] = typer.Option(None, "--config", help="Path to reconweave.toml."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable sqlite cache."),
) -> None:
    """Scan a seed: run collectors, correlate, score, and summarize."""
    eng = _engine(live, config, no_cache)
    result = eng.scan(seed, type)
    _print_summary(result)
    if json_out:
        with open(json_out, "w", encoding="utf-8") as fh:
            fh.write(export(result, "json"))
        console.print(f"[green]wrote[/green] {json_out}")
    if report_out:
        write_report(result, report_out)
        console.print(f"[green]wrote[/green] {report_out}")
    eng.close()


@app.command()
def graph(
    seed: str = typer.Argument(...),
    type: Optional[str] = typer.Option(None, "--type", "-t"),
    live: bool = typer.Option(False, "--live"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Print the entity graph (nodes + edges) as JSON."""
    eng = _engine(live, config, no_cache=False)
    result = eng.scan(seed, type)
    console.print_json(json.dumps({"nodes": result.graph.nodes(),
                                   "edges": result.graph.edges()}))
    eng.close()


@app.command()
def report(
    seed: str = typer.Argument(...),
    out: str = typer.Option("report.html", "--out", "-o", help="Output HTML path."),
    type: Optional[str] = typer.Option(None, "--type", "-t"),
    live: bool = typer.Option(False, "--live"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Generate a self-contained offline HTML report."""
    eng = _engine(live, config, no_cache=False)
    result = eng.scan(seed, type)
    write_report(result, out)
    console.print(f"[green]report written[/green] -> {out}")
    eng.close()


def export_cmd(
    seed: str = typer.Argument(...),
    format: str = typer.Option("json", "--format", "-f",
                              help=f"One of: {', '.join(available_formats())}."),
    out: Optional[str] = typer.Option(None, "--out", "-o", help="Output file (else stdout)."),
    type: Optional[str] = typer.Option(None, "--type", "-t"),
    live: bool = typer.Option(False, "--live"),
    config: Optional[str] = typer.Option(None, "--config"),
) -> None:
    """Export a scan to json / csv / graphml / maltego / stix / misp."""
    eng = _engine(live, config, no_cache=False)
    result = eng.scan(seed, type)
    data = export(result, format)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(data)
        console.print(f"[green]wrote[/green] {out} ({format})")
    else:
        typer.echo(data)
    eng.close()


# Register the export command explicitly (avoids underscore in command name).
app.command(name="export")(export_cmd)


watch_app = typer.Typer(help="Manage the monitoring watchlist.")
app.add_typer(watch_app, name="watch")


@watch_app.command("add")
def watch_add(seed: str, config: Optional[str] = typer.Option(None, "--config")) -> None:
    """Add a seed to the watchlist and take a baseline snapshot."""
    cfg = load_config(config)
    store = WatchStore(cfg.watch_db)
    store.add(seed, detect(seed).value)
    diff = store.check(seed)
    console.print(f"[green]watching[/green] {seed} — {', '.join(diff.alerts)}")
    store.close()


@watch_app.command("check")
def watch_check(seed: str, config: Optional[str] = typer.Option(None, "--config")) -> None:
    """Rescan a watched seed and print the diff / alerts."""
    cfg = load_config(config)
    store = WatchStore(cfg.watch_db)
    diff = store.check(seed)
    console.print_json(json.dumps(diff.to_dict()))
    store.close()


@watch_app.command("list")
def watch_list(config: Optional[str] = typer.Option(None, "--config")) -> None:
    """List watched seeds."""
    cfg = load_config(config)
    store = WatchStore(cfg.watch_db)
    for w in store.list_watches():
        console.print(f"- {w['seed']} ({w['seed_type']})")
    store.close()


@app.command()
def collectors() -> None:
    """List all registered collectors."""
    table = Table(title=f"reconweave collectors ({len(collectors_pkg.all_collectors())})",
                  show_header=True, header_style="bold cyan")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Accepts")
    table.add_column("Mode")
    table.add_column("Description")
    for row in collectors_pkg.catalog():
        table.add_row(row["name"], row["category"], ", ".join(row["accepts"]),
                      "live" if row["live"] else "offline", row["description"])
    console.print(table)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    """Start the FastAPI server (OpenAPI at /docs)."""
    import uvicorn

    console.print(f"[cyan]reconweave API[/cyan] on http://{host}:{port}  "
                  f"(docs at /docs)")
    uvicorn.run("reconweave.api:app", host=host, port=port, log_level="info")


@app.command()
def version() -> None:
    """Print the reconweave version."""
    console.print(f"reconweave {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
