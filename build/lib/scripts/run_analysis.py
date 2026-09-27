"""Command line entry point.

`python -m scripts.run_analysis --demo` is the shortest path from a clone to
seeing the project work: no API key, no tenant, no database setup.

The CLI exists so the pipeline is demonstrable without starting a web server.
It calls the same functions the API does, so there is no second code path to
keep in sync.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from app.collect.graph import GraphCollectionError
from app.config import (
    Settings,
    configure_logging,
    missing_graph_env_vars,
)
from app.database.repository import Repository
from app.pipeline import analyze_demo, analyze_live, investigate_incident

logger = logging.getLogger("run_analysis")


def _print_incidents(repository: Repository) -> None:
    incidents = repository.list_incidents(limit=20)
    if not incidents:
        print("\nNo incidents. Nothing matched a detection rule.")
        print(
            "That is a real result, not an error: a clean run means the "
            "telemetry did not match,\nnot that the telemetry was "
            "inspected. See 'What this cannot show' in the README."
        )
        return

    print(f"\n{len(incidents)} incident(s):\n")
    for incident in incidents:
        print(f"  [{incident['severity']:>2}] {incident['title']}")
        print(f"       id       {incident['incident_uid']}")
        print(f"       type     {incident['attack_type']}  ({incident['status']})")
        print(f"       events   {incident['event_count']}")
        print(
            f"       window   {incident['first_seen'][:19]} -> "
            f"{incident['last_seen'][:19]}"
        )
        if incident.get("decision"):
            decision = incident["decision"]
            print(
                f"       decision {decision['attack_type']} sev="
                f"{decision['severity']} band={decision['band']} "
                f"by={decision['source']}"
            )
        if incident.get("decision_error"):
            print(f"       note     model layer failed: {incident['decision_error']}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_analysis",
        description=(
            "Analyze Microsoft Entra ID telemetry for identity attack signals. "
            "Every result is a detected signal, not a confirmed attack."
        ),
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="analyze the bundled synthetic sample data (default, needs no credentials)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="collect from Microsoft Graph (needs graph credentials)",
    )
    parser.add_argument(
        "--investigate",
        metavar="INCIDENT_ID",
        help="write an investigation report for one incident id",
    )
    parser.add_argument(
        "--all-investigations",
        action="store_true",
        help="write investigation reports for every incident found (costs a model call each)",
    )
    parser.add_argument("--json", action="store_true", help="print the run summary as JSON")
    parser.add_argument("--db", help="override the database path for this run")
    args = parser.parse_args(argv)

    configure_logging()
    settings = Settings()
    if args.db:
        settings = Settings(database_path=args.db)
    settings.ensure_directories()

    if args.investigate:
        repository = Repository(settings.database_path)
        try:
            report = investigate_incident(args.investigate, settings, repository)
        except Exception as error:
            print(f"investigation failed: {error}", file=sys.stderr)
            return 1
        if report is None:
            print(f"no incident with id {args.investigate}", file=sys.stderr)
            return 1
        print(json.dumps(report, indent=2))
        return 0

    if args.live:
        missing = missing_graph_env_vars()
        if missing:
            print(
                f"live mode needs these environment variables: {', '.join(missing)}",
                file=sys.stderr,
            )
            print("Run with --demo instead; it needs no credentials.", file=sys.stderr)
            return 2
        runner, label = analyze_live, "live"
    else:
        runner, label = analyze_demo, "demo"

    try:
        result = runner(settings, run_investigation=args.all_investigations)
    except FileNotFoundError as error:
        # A run over no data would report zero findings, which reads as a clean
        # tenant. That is the one conclusion this tool must not reach, so missing
        # sample data is an error rather than an empty result.
        print(f"cannot analyze: {error}", file=sys.stderr)
        return 3
    except GraphCollectionError as error:
        print(f"Microsoft Graph collection failed: {error}", file=sys.stderr)
        return 4

    if args.json:
        print(json.dumps(result.summary(), indent=2))
    else:
        summary = result.summary()
        print(f"\n{label} analysis complete in {summary['duration_seconds']}s")
        print(
            f"  events       {summary['events_ingested']} read, "
            f"{summary['events_new']} new"
        )
        print(f"  findings     {summary['findings']}")
        print(f"  incidents    {summary['incidents']}")
        print(
            f"  decisions    {summary['decisions_made']} made, "
            f"{summary['decisions_fallback']} fell back to rules"
        )
        if result.degraded:
            print("\n  stages that did not complete:")
            for stage, reason in result.degraded.items():
                print(f"    {stage}: {reason}")

    _print_incidents(Repository(settings.database_path))

    if not args.json:
        print(
            "\nReminder: these are detected signals from heuristics, not "
            "confirmed attacks.\nSee docs/adr/0002-signal-not-proof.md."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
