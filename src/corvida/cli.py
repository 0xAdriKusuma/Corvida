"""
cli.py — Corvida command-line interface (Typer).

Entry point: `corvida <binary> [options]`

All option defaults match sensible CTF-player experience:
  * Terminal output by default (human-readable)
  * JSON output on --json (machine-readable for AI agents)
  * --verbose reveals extra details
  * --no-color for terminal piping / CI
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from corvida import __version__

app = typer.Typer(
    name="corvida",
    help="CTF binary triage tool -- one command, curated summary.",
    add_completion=False,
    rich_markup_mode="rich",
    pretty_exceptions_enable=False,
)

_err_console = Console(stderr=True, highlight=False)


@app.command()
def analyse(
    binary: Annotated[
        Path,
        typer.Argument(
            help="Path to the binary to analyse.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    json_out: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output structured JSON (for AI agents / scripting).",
        ),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option(
            "--no-color",
            help="Disable colour output.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose", "-v",
            help="Show extra details (stack traces, more evidence).",
        ),
    ] = False,
    max_strings: Annotated[
        int,
        typer.Option(
            "--max-strings",
            help="Maximum number of interesting strings to display.",
        ),
    ] = 20,
) -> None:
    """
    Analyse a binary and print a curated triage summary.

    \b
    Examples
    --------
      corvida ./vuln              # terminal summary
      corvida ./vuln --json       # JSON output for AI agents
      corvida ./vuln --verbose    # extra detail
    """
    from corvida.core.config import Config
    from corvida.core.pipeline import run
    from corvida.core.registry import reporter_registry

    cfg = Config(
        verbose=verbose,
        no_color=no_color,
        output_format="json" if json_out else "terminal",
        max_strings=max_strings,
    )

    t0 = time.monotonic()

    try:
        report = run(binary, cfg)
    except KeyboardInterrupt:
        _err_console.print("\n[yellow]Interrupted.[/yellow]")
        raise typer.Exit(code=1)
    except Exception as exc:   # noqa: BLE001
        _err_console.print(f"[red]Fatal error:[/red] {exc}")
        if verbose:
            import traceback
            _err_console.print(traceback.format_exc())
        raise typer.Exit(code=2)

    elapsed = time.monotonic() - t0
    report.metadata["analysis_time_s"] = round(elapsed, 3)
    report.metadata["corvida_version"] = __version__

    reporter_name = "json" if json_out else "terminal"
    reporter_cls = reporter_registry.get(reporter_name)
    if reporter_cls is None:
        _err_console.print(
            f"[red]Reporter '{reporter_name}' not found.[/red] "
            "This is a bug — please report it."
        )
        raise typer.Exit(code=3)

    reporter = reporter_cls()
    reporter.render(report, cfg)

    if report.errors and not json_out:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print Corvida version and exit."""
    typer.echo(f"Corvida {__version__}")


def main() -> None:
    app()
