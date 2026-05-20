#!/usr/bin/env python3
"""
Security Incident Timeline Analyzer
Parses security logs, detects attack patterns, and generates interactive HTML timeline reports.
"""

import argparse
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
import time

from core.parsers import AuthLogParser
from core.engine import IncidentEngine
from core.reporter import TimelineReporter


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze security logs and generate incident timeline reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --log-file /var/log/auth.log
  %(prog)s --log-file data/sample_auth.log --output reports/incident.html
  %(prog)s --log-file data/sample_auth.log --no-geolocation  # Skip geolocation enrichment
        """,
    )

    parser.add_argument(
        "--log-file",
        required=True,
        help="Path to the log file to analyze",
    )

    parser.add_argument(
        "--parser-type",
        choices=["auth-log", "nginx", "auto"],
        default="auto",
        help="Type of log file (default: auto-detect from extension)",
    )

    parser.add_argument(
        "--output",
        default="data/output_timeline.html",
        help="Output HTML file path (default: data/output_timeline.html)",
    )

    parser.add_argument(
        "--no-geolocation",
        action="store_true",
        help="Disable geolocation enrichment (faster processing)",
    )

    args = parser.parse_args()

    console = Console()

    # Print banner
    console.print(
        Panel(
            "[bold cyan]Security Incident Timeline Analyzer[/bold cyan]\n"
            "[dim]Parse logs, detect threats, visualize incidents[/dim]",
            expand=False,
        )
    )

    # Validate input file
    log_file = Path(args.log_file)
    if not log_file.exists():
        console.print(f"[red]✗ Log file not found: {args.log_file}[/red]")
        sys.exit(1)

    console.print(f"[dim]Log file:[/dim] {args.log_file}")
    console.print(f"[dim]Output:[/dim] {args.output}")
    console.print()

    try:
        with Progress() as progress:
            # Step 1: Parse logs
            parse_task = progress.add_task("[cyan]Parsing logs...", total=100)
            with open(log_file, "r") as f:
                lines = f.readlines()

            parser_obj = AuthLogParser()
            events = parser_obj.parse(lines)
            progress.update(parse_task, completed=100)

            console.print(
                f"[green]✓[/green] Parsed {len(events)} events from {len(lines)} lines"
            )

            # Step 2: Detect threats
            detect_task = progress.add_task("[cyan]Detecting threats...", total=100)
            engine = IncidentEngine(enable_geolocation=not args.no_geolocation)
            events_df = engine.process(events)
            progress.update(detect_task, completed=100)

            alert_count = len(events_df[events_df["event_type"].str.startswith("ALERT_", na=False)])
            console.print(f"[green]✓[/green] Detected {alert_count} security alerts")

            # Step 3: Generate report
            report_task = progress.add_task("[cyan]Generating report...", total=100)
            reporter = TimelineReporter()
            reporter.render(events_df, args.output)
            progress.update(report_task, completed=100)

        # Print summary
        console.print()
        summary_table = Table(title="Incident Summary", show_header=False)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")

        total_events = len(events_df)
        failed_logins = len(events_df[events_df["event_type"] == "AUTH_FAILURE"])
        successful_logins = len(events_df[events_df["event_type"] == "AUTH_SUCCESS"])
        brute_force_alerts = len(
            events_df[events_df["event_type"] == "ALERT_BRUTE_FORCE_SUCCESS"]
        )
        impossible_travel_alerts = len(
            events_df[events_df["event_type"] == "ALERT_IMPOSSIBLE_TRAVEL"]
        )
        critical_alerts = len(events_df[events_df["severity"] == "CRITICAL"])
        high_alerts = len(events_df[events_df["severity"] == "HIGH"])

        summary_table.add_row("Total Events", str(total_events))
        summary_table.add_row("Failed Logins", str(failed_logins))
        summary_table.add_row("Successful Logins", str(successful_logins))
        summary_table.add_row("Brute Force Alerts", str(brute_force_alerts))
        summary_table.add_row("Impossible Travel Alerts", str(impossible_travel_alerts))
        summary_table.add_row("Critical Severity", str(critical_alerts))
        summary_table.add_row("High Severity", str(high_alerts))

        console.print(summary_table)
        console.print()
        console.print(
            f"[green bold]✓ Report generated successfully![/green bold]\n"
            f"  Open in browser: {args.output}"
        )

    except Exception as e:
        console.print(f"[red]✗ Error: {str(e)}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
