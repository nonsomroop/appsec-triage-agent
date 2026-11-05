import argparse
import asyncio
import logging
import os
from pathlib import Path

from appsec_triage.config import Settings
from appsec_triage.reporting.json_reporter import write_report
from appsec_triage.scanners.semgrep import SemgrepScanner
from appsec_triage.services.pipeline import Pipeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan repositories and optionally assess findings")
    commands = parser.add_subparsers(dest="command", required=True)
    ui = commands.add_parser("ui", help="Open the local report viewer and scan controls")
    ui.add_argument("--port", type=int, default=8765)
    for name in ("scan", "triage"):
        command = commands.add_parser(name)
        command.add_argument("target", type=Path)
        command.add_argument("--output", type=Path, help="JSON file; defaults to stdout")
        command.add_argument("--config", type=Path, help="Application TOML configuration")
        command.add_argument("--max-findings", type=int, help="Limit assessments, never scan findings; 0 disables assessment")
        command.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "ui":
        from appsec_triage.web import serve
        return serve(args.port)
    logger = logging.getLogger("appsec_triage")
    try:
        settings = Settings.load(args.config)
        limit = args.max_findings if args.max_findings is not None else settings.max_findings
        if limit < 0:
            raise ValueError("max-findings must be non-negative")
        level = "DEBUG" if args.verbose else settings.log_level.upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("Invalid log level")
        # Keep provider HTTP/payload logging disabled, including in verbose mode.
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
        logger.setLevel(level)
        triage = None
        if args.command == "triage":
            if not os.environ.get("OPENAI_API_KEY", "").strip() or not settings.openai_model.strip():
                parser.error("triage requires OPENAI_API_KEY and OPENAI_MODEL; scan requires neither")
            from appsec_triage.services.triage import TriageService
            from appsec_triage.utils.source_reader import SourceReader

            triage = TriageService(SourceReader(args.target), settings.openai_model)
        logger.info("Starting %s", args.command)
        report = asyncio.run(Pipeline(
            SemgrepScanner(settings.semgrep_config, settings.scan_timeout), triage,
        ).run(args.target, limit))
        if args.output:
            write_report(report, args.output)
        else:
            print(report.model_dump_json(indent=2))
        logger.info("Scan %s: %d findings, %d assessments", report.scan.status,
                    len(report.scan.findings), len(report.assessments))
        return 1 if report.scan.errors or report.failed_assessments else 0
    except (OSError, ValueError):
        # Validation errors can include supplied configuration values.
        logger.error("Invalid configuration, inaccessible target, or report output failure")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
