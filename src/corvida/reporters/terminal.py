"""
reporters/terminal.py — Rich terminal reporter.

Renders the Report as a curated, color-coded one-screen summary.
Layout:
  ┌─ Header (file info) ─────────────────────────────────────────────┐
  │ Binary Info table                                                 │
  │ Protections table                                                 │
  │ Dangerous Functions panel                                         │
  │ Interesting Strings panel                                         │
  │ Advisory panel (attack path suggestions)                          │
  │ Errors panel (if any)                                             │
  └───────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from corvida.core.config import Config
from corvida.core.models import (
    Category, Confidence, Finding, Report, Severity,
)
from corvida.core.registry import register_reporter
from corvida.reporters.base import BaseReporter


# ---------------------------------------------------------------------------
# Color / style helpers
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "dim yellow",
    Severity.INFO:     "dim",
}

_CONF_COLOR = {
    Confidence.CERTAIN: "green",
    Confidence.HIGH:    "cyan",
    Confidence.MEDIUM:  "blue",
    Confidence.LOW:     "dim",
}

_BOOL_STYLE = {
    True:  ("[green]✓[/green]", "green"),
    False: ("[red]✗[/red]",    "red"),
    None:  ("?",               "dim"),
}


def _sev_badge(sev: Severity) -> str:
    label = sev.value.upper()
    colors = {
        Severity.CRITICAL: "bold white on red",
        Severity.HIGH:     "bold red",
        Severity.MEDIUM:   "bold yellow",
        Severity.LOW:      "dim yellow",
        Severity.INFO:     "dim",
    }
    return f"[{colors[sev]}]{label}[/{colors[sev]}]"


def _conf_badge(conf: Confidence) -> str:
    colors = {
        Confidence.CERTAIN: "green",
        Confidence.HIGH:    "cyan",
        Confidence.MEDIUM:  "blue",
        Confidence.LOW:     "dim",
    }
    return f"[{colors[conf]}]{conf.value}[/{colors[conf]}]"


def _tick(value: bool | None) -> str:
    return _BOOL_STYLE.get(value, ("?", "dim"))[0]


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

@register_reporter
class TerminalReporter(BaseReporter):
    """Renders a Rich terminal summary of the analysis report."""

    name = "terminal"

    def render(self, report: Report, config: Config) -> None:
        console = Console(
            highlight=False,
            no_color=config.no_color,
            markup=True,
        )

        target = report.target

        # ---- Header --------------------------------------------------------
        console.rule(
            f"[bold cyan]CORVIDA[/bold cyan]  [bold]{escape(target.name)}[/bold]",
            style="cyan",
        )
        console.print(
            f"  [dim]sha256:[/dim] [dim white]{target.sha256}[/dim white]  "
            f"[dim]size:[/dim] [dim white]{target.size:,} bytes[/dim white]",
        )
        console.print()

        # ---- Binary Info ---------------------------------------------------
        self._render_binary_info(console, report)

        # ---- Protections ---------------------------------------------------
        self._render_protections(console, report)

        # ---- Dangerous Functions -------------------------------------------
        self._render_dangerous_funcs(console, report, config)

        # ---- Interesting Strings -------------------------------------------
        self._render_strings(console, report, config)

        # ---- Advisories ----------------------------------------------------
        self._render_advisories(console, report)

        # ---- Errors --------------------------------------------------------
        if report.errors:
            self._render_errors(console, report)

        console.rule(style="dim")

    # ------------------------------------------------------------------
    # Section renderers
    # ------------------------------------------------------------------

    def _render_binary_info(self, console: Console, report: Report) -> None:
        t = report.target
        table = Table(
            box=box.SIMPLE,
            show_header=False,
            padding=(0, 2),
            expand=False,
        )
        table.add_column("Key",   style="dim cyan", no_wrap=True)
        table.add_column("Value", style="bold")

        table.add_row("Format",     t.file_type or "unknown")
        table.add_row("Arch",       f"{t.arch or '?'}  {t.bits or '?'}-bit  {t.endian or '?'}-endian")
        table.add_row("Stripped",   f"{'[red]YES[/red]' if t.is_stripped else '[green]no[/green]'}")
        table.add_row("Type",       "PIE (ET_DYN)" if t.is_pie else "executable (ET_EXEC)")
        table.add_row("Linker",     t.interpreter or "[dim]statically linked[/dim]")

        console.print(Panel(table, title="[bold]Binary Info[/bold]", border_style="cyan"))

    def _render_protections(self, console: Console, report: Report) -> None:
        prot = report.by_category(Category.PROTECTIONS)
        if not prot:
            return

        table = Table(box=box.ROUNDED, padding=(0, 1))
        table.add_column("Mitigation",  style="bold", width=18)
        table.add_column("Status",      width=22)
        table.add_column("Confidence",  width=10)
        table.add_column("Note",        style="dim", overflow="fold")

        for f in prot:
            key = f.extra.get("key", "")
            val = f.extra.get("value")

            # Format value
            if key == "relro":
                val_str = {
                    "full":    "[green]FULL[/green]",
                    "partial": "[yellow]PARTIAL[/yellow]",
                    "none":    "[red]NONE[/red]",
                }.get(str(val), str(val))
            elif isinstance(val, bool):
                val_str = "[green]ON[/green]" if val else "[red]OFF[/red]"
            else:
                val_str = str(val) if val is not None else "?"

            # Mitigation name from title
            title_clean = f.title.split(":")[0].strip()
            note = (f.advice or "")[: 80]

            table.add_row(title_clean, val_str, _conf_badge(f.confidence), note)

        console.print(Panel(table, title="[bold]Protections[/bold]", border_style="blue"))

    def _render_dangerous_funcs(
        self, console: Console, report: Report, config: Config
    ) -> None:
        findings = sorted(
            report.by_category(Category.DANGEROUS_FUNC),
            key=lambda f: f.score,
            reverse=True,
        )
        if not findings:
            console.print(Panel(
                "[dim]No dangerous imports detected.[/dim]",
                title="[bold]Dangerous Functions[/bold]",
                border_style="yellow",
            ))
            return

        table = Table(box=box.ROUNDED, padding=(0, 1))
        table.add_column("Function",    style="bold red", width=24, no_wrap=True)
        table.add_column("Severity",    width=10)
        table.add_column("Confidence",  width=10)
        table.add_column("Location",    width=20, no_wrap=True)
        table.add_column("Callers",     style="dim", overflow="fold")

        for f in findings:
            callers = f.extra.get("callers", [])
            caller_str = "\n".join(callers[:3]) or "[dim]unknown[/dim]"
            table.add_row(
                escape(f.extra.get("func_name", f.title)),
                _sev_badge(f.severity),
                _conf_badge(f.confidence),
                escape(f.location or ""),
                caller_str,
            )

        # Advice panel below table
        advice_lines: list[str] = []
        for f in findings:
            if f.advice:
                advice_lines.append(f"[dim]•[/dim] {escape(f.advice)}")

        body = table
        if advice_lines and config.verbose:
            from rich.console import Group
            advice_text = "\n".join(advice_lines[:5])
            body = Group(table, Text.from_markup(f"\n[bold]Advice:[/bold]\n{advice_text}"))

        console.print(Panel(body, title="[bold]Dangerous Functions[/bold]", border_style="yellow"))

    def _render_strings(
        self, console: Console, report: Report, config: Config
    ) -> None:
        findings = sorted(
            report.by_category(Category.STRINGS),
            key=lambda f: f.score,
            reverse=True,
        )
        if not findings:
            console.print(Panel(
                "[dim]No interesting strings found.[/dim]",
                title="[bold]Interesting Strings[/bold]",
                border_style="magenta",
            ))
            return

        table = Table(box=box.ROUNDED, padding=(0, 1))
        table.add_column("String",    style="green", overflow="fold", max_width=55)
        table.add_column("Type",      width=22)
        table.add_column("Severity",  width=10)
        table.add_column("Location",  style="dim", width=20, no_wrap=True)

        for f in findings:
            s = f.extra.get("string", f.title)
            label = f.title.split(":")[0].strip()
            table.add_row(
                escape(s[:60]),
                escape(label),
                _sev_badge(f.severity),
                escape(f.location or ""),
            )

        console.print(Panel(table, title="[bold]Interesting Strings[/bold]", border_style="magenta"))

    def _render_advisories(self, console: Console, report: Report) -> None:
        findings = report.by_category(Category.ADVISORY)
        if not findings:
            return

        lines: list[str] = []
        for f in sorted(findings, key=lambda x: x.score, reverse=True):
            sev  = _sev_badge(f.severity)
            conf = _conf_badge(f.confidence)
            lines.append(f"{sev} {conf}  [bold]{escape(f.title)}[/bold]")
            if f.advice:
                # Wrap advice at ~90 chars
                for part in _wrap(f.advice, 88):
                    lines.append(f"  [dim]{escape(part)}[/dim]")
            lines.append("")

        console.print(Panel(
            "\n".join(lines).strip(),
            title="[bold]Attack Path Suggestions[/bold]",
            border_style="red",
        ))

    def _render_errors(self, console: Console, report: Report) -> None:
        lines = "\n".join(f"[yellow]⚠[/yellow]  {escape(e)}" for e in report.errors)
        console.print(Panel(lines, title="[bold yellow]Warnings / Errors[/bold yellow]", border_style="yellow"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wrap(text: str, width: int) -> list[str]:
    """Very simple word-wrap."""
    import textwrap
    return textwrap.wrap(text, width=width)
