"""
cli.py — Corvida command-line interface (Typer).

Entry point: `corvida <binary> [options]`

All option defaults match sensible CTF-player experience:
  * Terminal output by default (human-readable)
  * JSON output on --json (machine-readable for AI agents)
  * --verbose reveals extra details
  * --no-color for terminal piping / CI
  * --ai enables the optional AI summarisation layer
  * --ai-debug enables verbose AI debug logging
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from corvida import __version__

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from typer.core import TyperGroup


class _DefaultCommandGroup(TyperGroup):
    """Allows `corvida <binary> [options]` directly while still supporting subcommands."""
    default_cmd_name = "analyse"

    def parse_args(self, ctx: typer.Context, args: list[str]) -> list[str]:
        if args:
            first = args[0]
            if first not in self.commands and first not in ("-h", "--help", "--version") and not first.startswith("-"):
                args = [self.default_cmd_name] + args
        return super().parse_args(ctx, args)


app = typer.Typer(
    cls=_DefaultCommandGroup,
    name="corvida",
    help="CTF binary triage tool -- one command, curated summary.",
    add_completion=False,
    rich_markup_mode="rich",
    pretty_exceptions_enable=False,
)

# Sub-app for `corvida ai` commands
_ai_app = typer.Typer(name="ai", help="AI layer utilities.", add_completion=False)
app.add_typer(_ai_app, name="ai")

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
    # ------------------------------------------------------------------ AI flags
    ai: Annotated[
        bool,
        typer.Option(
            "--ai",
            help="Run the AI summarisation layer after rule-based analysis.",
        ),
    ] = False,
    ai_config: Annotated[
        Optional[Path],
        typer.Option(
            "--ai-config",
            help="Path to corvida.yaml (default: auto-discover).",
            exists=False,
        ),
    ] = None,
    local_only: Annotated[
        bool,
        typer.Option(
            "--local-only",
            help="Restrict AI to local providers only (no cloud).",
        ),
    ] = False,
    no_cache: Annotated[
        bool,
        typer.Option(
            "--no-cache",
            help="Bypass the AI response cache.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Skip cloud-send confirmation prompt.",
        ),
    ] = False,
    ai_exclude_strings: Annotated[
        bool,
        typer.Option(
            "--ai-exclude-strings",
            help="Do not include interesting strings in the AI context.",
        ),
    ] = False,
    ai_debug: Annotated[
        bool,
        typer.Option(
            "--ai-debug",
            help="Emit verbose AI HTTP debug logs (shows error details, never secrets).",
        ),
    ] = False,
) -> None:
    """
    Analyse a binary and print a curated triage summary.

    \\b
    Examples
    --------
      corvida ./vuln              # terminal summary
      corvida ./vuln --json       # JSON output for AI agents
      corvida ./vuln --verbose    # extra detail
      corvida ./vuln --ai         # include AI summary layer
      corvida ./vuln --ai --local-only  # AI with local models only
      corvida ./vuln --ai --ai-debug    # verbose AI diagnostics
    """
    import logging

    if ai_debug:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    from corvida.core.config import Config
    from corvida.core.pipeline import run
    from corvida.core.registry import _import_all, reporter_registry

    _import_all()

    cfg = Config(
        verbose=verbose,
        no_color=no_color,
        output_format="json" if json_out else "terminal",
        max_strings=max_strings,
        # AI
        ai_enabled=ai,
        ai_config_path=ai_config,
        ai_local_only=local_only,
        ai_no_cache=no_cache,
        ai_yes=yes,
        ai_exclude_strings=ai_exclude_strings,
        ai_debug=ai_debug,
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

    # ------------------------------------------------------------------ Render rule-based first
    # Task C: Rule-based report is ALWAYS shown before AI analysis begins.
    if not json_out:
        reporter_name = "terminal"
        reporter_cls = reporter_registry.get(reporter_name)
        if reporter_cls is None:
            _err_console.print(f"[red]Reporter '{reporter_name}' not found.[/red]")
            raise typer.Exit(code=3)
        reporter_cls().render(report, cfg)

    # ------------------------------------------------------------------ AI layer
    if ai:
        try:
            from corvida.model import run_ai
            ai_result = run_ai(report, cfg)
            if ai_result is not None:
                report.metadata["ai"] = ai_result.to_dict()
            else:
                report.metadata["ai"] = None
        except Exception as exc:  # noqa: BLE001
            _err_console.print(f"[yellow]AI layer error:[/yellow] {exc}")
            if ai_debug:
                import traceback
                _err_console.print(traceback.format_exc())
            report.metadata["ai"] = None

    # ------------------------------------------------------------------ Render final output
    if json_out:
        # JSON always rendered once at the end (includes AI if present)
        reporter_name = "json"
        reporter_cls = reporter_registry.get(reporter_name)
        if reporter_cls is None:
            _err_console.print(f"[red]Reporter 'json' not found.[/red]")
            raise typer.Exit(code=3)
        reporter_cls().render(report, cfg)
    elif ai and report.metadata.get("ai"):
        # Re-render the AI section only (terminal)
        _render_ai_section(report.metadata["ai"], no_color=no_color)

    if report.errors and not json_out:
        raise typer.Exit(code=1)


def _render_ai_section(ai_data: dict, no_color: bool = False) -> None:
    """Print AI results section to stdout after the rule-based report."""
    from rich.console import Console
    from corvida.reporters.terminal import TerminalReporter

    console = Console(highlight=False, no_color=no_color, markup=True)
    TerminalReporter()._render_ai_section(console, ai_data)
    console.rule(style="dim", characters="-")


@app.command()
def version() -> None:
    """Print Corvida version and exit."""
    typer.echo(f"Corvida {__version__}")


# ---------------------------------------------------------------------------
# corvida ai doctor
# ---------------------------------------------------------------------------

@_ai_app.command("doctor")
def ai_doctor(
    ai_config: Annotated[
        Optional[Path],
        typer.Option(
            "--ai-config",
            help="Path to corvida.yaml (default: auto-discover).",
            exists=False,
        ),
    ] = None,
    list_models_provider: Annotated[
        Optional[str],
        typer.Option(
            "--list-models",
            help="List all models available from the given provider name (requires key).",
            metavar="PROVIDER",
        ),
    ] = None,
) -> None:
    """
    Check AI configuration, key availability, and model availability.

    Queries each provider's /models endpoint to verify both connectivity
    AND that the configured model is actually available.

    Status codes:
      OK            — key set, server reachable, model exists
      MODEL MISSING — key set and server reachable, but model not in /models
      KEY MISSING   — env var not set (will get 401 at runtime)
      UNREACHABLE   — server TCP unreachable
      LOCAL         — no key needed (local provider)
    """
    from rich.console import Console
    from rich.table import Table
    from rich import box
    import os

    console = Console(highlight=False, safe_box=True)
    console.rule("[bold]CORVIDA AI Doctor[/bold]")

    # Load config
    try:
        from corvida.model.config import load_ai_config, get_used_providers
        ai_cfg = load_ai_config(ai_config)
        console.print("[green][OK][/green] corvida.yaml loaded\n")
    except Exception as exc:
        console.print(f"[red][ERR] Config error:[/red] {exc}")
        raise typer.Exit(code=1)

    used_providers = get_used_providers(ai_cfg)

    # ------------------------------------------------------------------
    # --list-models shortcut
    # ------------------------------------------------------------------
    if list_models_provider:
        pcfg = ai_cfg.providers.get(list_models_provider)
        if pcfg is None:
            console.print(f"[red]Provider '{list_models_provider}' not found in config.[/red]")
            console.print(f"Available: {', '.join(ai_cfg.providers.keys())}")
            raise typer.Exit(code=1)
        console.print(f"[bold]Fetching models from '{list_models_provider}'...[/bold]")
        models = _fetch_models(pcfg)
        if models:
            for m in sorted(models):
                console.print(f"  • {m}")
        else:
            console.print("[dim]  (no models returned or /models endpoint not supported)[/dim]")
        raise typer.Exit(code=0)

    # ------------------------------------------------------------------
    # Provider status table
    # ------------------------------------------------------------------
    prov_table = Table(title="Providers", box=box.ASCII, padding=(0, 1))
    prov_table.add_column("Name",     style="bold",  width=14)
    prov_table.add_column("Base URL", width=42)
    prov_table.add_column("Key Env",  width=22)
    prov_table.add_column("Key",      width=6)
    prov_table.add_column("Reach",    width=7)
    prov_table.add_column("Status",   width=20)

    provider_model_cache: dict[str, tuple[list[str], str | None]] = {}  # cache /models results

    for name, pcfg in ai_cfg.providers.items():
        is_used = name in used_providers

        # Key status
        if not pcfg.key_env:
            key_col = "[dim]N/A[/dim]"
        elif os.environ.get(pcfg.key_env):
            key_col = "[green]SET[/green]"
        else:
            key_col = "[red]NO[/red]"

        # Connectivity
        reach_ok = _check_connectivity(pcfg.base_url)
        reach_col = "[green]OK[/green]" if reach_ok else "[red]FAIL[/red]"

        # Overall status
        if not pcfg.key_env:
            status_col = "[dim]LOCAL[/dim]"
        elif not os.environ.get(pcfg.key_env):
            hint = f"export {pcfg.key_env}=..."
            if is_used:
                status_col = f"[red]KEY MISSING[/red]\n[dim]{hint}[/dim]"
            else:
                status_col = f"[dim]KEY MISSING (unused)[/dim]"
        elif not reach_ok:
            status_col = "[red]UNREACHABLE[/red]"
        else:
            # Attempt model list
            models, err = _fetch_models_result(pcfg)
            provider_model_cache[name] = (models, err)
            if err == "AUTH_FAILED":
                status_col = "[red]AUTH FAILED[/red]\n[dim](invalid key)[/dim]"
            elif err == "TIMEOUT":
                status_col = "[yellow]TIMEOUT[/yellow]"
            elif err and "NET_ERR" in err:
                status_col = "[red]NETWORK ERROR[/red]"
            elif models:
                status_col = "[green]OK[/green]"
            elif err:
                status_col = f"[red]{err}[/red]"
            else:
                status_col = "[green]OK[/green] [dim](no /models)[/dim]"

        prov_table.add_row(name, pcfg.base_url, pcfg.key_env or "-", key_col, reach_col, status_col)

    console.print(prov_table)
    console.print()

    # ------------------------------------------------------------------
    # Role chain status table
    # ------------------------------------------------------------------
    role_table = Table(title="Role Chains", box=box.ASCII, padding=(0, 1))
    role_table.add_column("Role",     style="bold", width=16)
    role_table.add_column("Provider/Model",         width=36)
    role_table.add_column("Model Status",           width=24)

    for role_name, chain in ai_cfg.roles.items():
        for i, ref in enumerate(chain):
            pcfg = ai_cfg.providers.get(ref.provider)
            role_label = role_name if i == 0 else ""

            if pcfg is None:
                model_status = "[red]PROVIDER MISSING[/red]"
            elif not pcfg.key_env:
                # Local — check Ollama model pull status
                model_status = _check_local_model(pcfg, ref.model)
            elif not os.environ.get(pcfg.key_env or ""):
                model_status = "[red]KEY MISSING[/red]"
            else:
                # Check via /models list
                cached = provider_model_cache.get(ref.provider)
                if cached is None:
                    cached = _fetch_models_result(pcfg)
                    provider_model_cache[ref.provider] = cached
                models, err = cached

                if err == "AUTH_FAILED":
                    model_status = "[red]AUTH FAILED[/red]"
                elif err == "TIMEOUT":
                    model_status = "[yellow]TIMEOUT[/yellow]"
                elif err and "NET_ERR" in err:
                    model_status = "[red]NETWORK ERROR[/red]"
                elif not models and not err:
                    model_status = "[dim]UNKNOWN (no /models)[/dim]"
                elif _model_in_list(ref.model, models):
                    model_status = "[green]OK[/green]"
                else:
                    model_status = (
                        f"[red]MODEL MISSING[/red]\n"
                        f"[dim]'{ref.model}' not in /models[/dim]"
                    )

            role_table.add_row(role_label, f"{ref.provider}/{ref.model}", model_status)

    console.print(role_table)
    console.print()

    # ------------------------------------------------------------------
    # Policy summary
    # ------------------------------------------------------------------
    pol = ai_cfg.policy
    console.print(
        f"[bold]Policy:[/bold] cache={pol.cache}  "
        f"local_only={pol.sensitive_local_only}  "
        f"max_tokens={pol.max_context_tokens}  "
        f"temperature={pol.temperature}"
    )

    # Per-provider rate limits (only show if any are set)
    rate_limited = [(n, p) for n, p in ai_cfg.providers.items() if p.rpm or p.tpm or p.rpd]
    if rate_limited:
        console.print()
        console.print("[bold]Per-provider rate limits:[/bold]")
        for n, p in rate_limited:
            parts = []
            if p.rpm: parts.append(f"rpm={p.rpm}")
            if p.tpm: parts.append(f"tpm={p.tpm}")
            if p.rpd: parts.append(f"rpd={p.rpd}")
            console.print(f"  {n}: {', '.join(parts)}")

    console.rule(characters="-")


def _fetch_models_result(pcfg) -> tuple[list[str], str | None]:
    """
    Query the provider /models endpoint.
    Returns (models_list, error_summary).
    error_summary is None on success (or on 404 endpoint not found).
    """
    try:
        from corvida.model.client import build_provider
        provider = build_provider(pcfg)
        return provider.list_models(timeout=8), None
    except Exception as exc:
        from corvida.model.client import ProviderHTTPError, ProviderTimeoutError
        if isinstance(exc, ProviderHTTPError):
            if exc.kind == "auth_failed" or exc.status in (401, 403):
                return [], "AUTH_FAILED"
            if exc.kind == "network_error":
                return [], f"NET_ERR: {exc}"
            return [], f"HTTP_{exc.status}"
        if isinstance(exc, ProviderTimeoutError):
            return [], "TIMEOUT"
        return [], str(exc)


def _fetch_models(pcfg) -> list[str]:
    """Backward-compatible helper returning list of models."""
    models, _ = _fetch_models_result(pcfg)
    return models


def _check_local_model(pcfg, model_name: str) -> str:
    """
    Check if a local (Ollama-style) model is pulled.
    Returns a Rich-markup status string.
    """
    models = _fetch_models(pcfg)
    if not models:
        return "[dim]LOCAL (cannot verify)[/dim]"
    if _model_in_list(model_name, models):
        return "[green]LOCAL OK[/green]"
    return (
        f"[red]NOT PULLED[/red]\n"
        f"[dim]Run: ollama pull {model_name}[/dim]"
    )


def _model_in_list(model_name: str, available: list[str]) -> bool:
    """
    Check if model_name matches any entry in available.
    Handles prefix matches (e.g. "llama3" matches "llama3:8b") and
    provider-prefixed models (e.g. "models/gemini-3.5-flash").
    """
    if not available:
        return False
    target = model_name.lower().removeprefix("models/")
    for m in available:
        clean = m.lower().removeprefix("models/")
        if clean == target:
            return True
        # Prefix match: "llama3" matches "llama3:8b"
        if clean.startswith(target + ":") or target.startswith(clean + ":"):
            return True
    return False


def _check_connectivity(base_url: str) -> bool:
    """Quick TCP connectivity check — returns True on success."""
    import socket
    from urllib.parse import urlparse
    try:
        parsed = urlparse(base_url)
        host   = parsed.hostname or ""
        port   = parsed.port or (443 if parsed.scheme == "https" else 80)
        sock   = socket.create_connection((host, port), timeout=4)
        sock.close()
        return True
    except Exception:
        return False


def main() -> None:
    app()
