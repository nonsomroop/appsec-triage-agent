import argparse
import asyncio
import logging
import os
import signal
import threading
from pathlib import Path

from appsec_triage.config import Settings
from appsec_triage.progress import Progress, TrackedScanner
from appsec_triage.secrets_store import KeyStore, Preferences, resolve_key
from appsec_triage.services.providers import PROVIDERS
from appsec_triage.reporting.json_reporter import write_report
from appsec_triage.scanners.semgrep import SemgrepScanner
from appsec_triage.services.pipeline import Pipeline
from appsec_triage.scanners.trivy import TrivyScanner
from appsec_triage.scanners.combined import CombinedScanner
from appsec_triage.scanners.gitleaks import GitleaksScanner

from appsec_triage.scanners.base import SCAN_LABELS, parse_scanners, scanner_spec


def stop_on_sigterm(signum, frame):
    raise SystemExit(128 + signum)


def scanner_argument(value):
    try:
        return scanner_spec(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


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
        command.add_argument("--scanner", type=scanner_argument, default="semgrep", metavar="SCANNERS",
                             help="semgrep, trivy, gitleaks-files or gitleaks-history; combine with '+', "
                                  "e.g. semgrep+trivy+gitleaks-files ('all' = semgrep+trivy)")
        command.add_argument("--provider", choices=tuple(PROVIDERS), help="AI provider for triage; defaults to AI_PROVIDER or openai")
        command.add_argument("--model", help="Model ID; defaults to the provider's *_MODEL setting")
        command.add_argument("--verbose", action="store_true")
        command.add_argument("--progress", type=Path, help=argparse.SUPPRESS)  # JSON-lines events for the dashboard
    args = parser.parse_args(argv)
    if args.command == "ui":
        from appsec_triage.web import serve
        return serve(args.port)
    if args.command == "triage" and all(name.startswith("gitleaks-") for name in parse_scanners(args.scanner)):
        parser.error("Use the scan command for Gitleaks. Secret findings stay out of AI review.")
    # Stopping a scan sends SIGTERM. Exit through normal cleanup so scanners started in
    # their own process groups (Semgrep) or by subprocess.run (Trivy) are stopped too.
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, stop_on_sigterm)
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
        progress = Progress(args.progress)
        scanner_names = parse_scanners(args.scanner)
        plan = [{"id": f"scan:{name}", "label": SCAN_LABELS[name]} for name in scanner_names]
        if args.command == "triage":
            plan.append({"id": "triage", "label": "AI review"})
        progress.emit("plan", "plan", steps=plan + [{"id": "report", "label": "Write report"}])
        triage = None
        if args.command == "triage":
            preferences = Preferences()
            saved = preferences.load()
            provider = PROVIDERS[args.provider or settings.ai_provider or saved["provider"] or "openai"]
            model = (args.model or getattr(settings, f"{provider.name}_model")
                     or saved["models"].get(provider.name) or provider.default_model).strip()
            key, source = resolve_key(provider, KeyStore())
            if not key or not model:
                progress.emit("triage", "failed", detail=f"No {provider.label} API key or model is configured")
                parser.error(f"triage with {provider.label} requires an API key ({' or '.join(provider.key_env)}, "
                             f"or save one in the dashboard Settings) and a model ({provider.model_env} or --model); "
                             "scan requires neither")
            if source != "environment":
                # The SDK clients read keys from the environment of this process only.
                os.environ[provider.key_env[0]] = key
            from appsec_triage.services.triage import TriageService, create_backend
            from appsec_triage.utils.source_reader import SourceReader

            triage = TriageService(SourceReader(args.target), f"{provider.name}/{model}",
                                   create_backend(provider.name, model), timeout=settings.ai_timeout)
            progress.emit("plan", "plan", steps=[{"id": "triage", "label": f"AI review with {provider.label} ({model})"}])
        logger.info("Starting %s", args.command)
        scanners = {"semgrep": lambda: SemgrepScanner(settings.semgrep_config, settings.scan_timeout),
                    "trivy": lambda: TrivyScanner(settings.scan_timeout),
                    "gitleaks-files": lambda: GitleaksScanner("files", settings.scan_timeout),
                    "gitleaks-history": lambda: GitleaksScanner("history", settings.scan_timeout)}
        tracked = [TrackedScanner(scanners[name](), f"scan:{name}", progress) for name in scanner_names]
        scanner = CombinedScanner(tracked) if len(tracked) > 1 else tracked[0]
        report = asyncio.run(Pipeline(scanner, triage, progress).run(args.target, limit))
        progress.emit("report", "start")
        if args.output:
            write_report(report, args.output)
        else:
            print(report.model_dump_json(indent=2))
        progress.emit("report", "done", detail=f"{len(report.scan.findings)} findings, {len(report.assessments)} AI reviews")
        logger.info("Scan %s: %d findings, %d assessments", report.scan.status,
                    len(report.scan.findings), len(report.assessments))
        return 1 if report.scan.errors or report.failed_assessments else 0
    except (OSError, ValueError):
        # Validation errors can include supplied configuration values.
        logger.error("Invalid configuration, inaccessible target, or report output failure")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
