"""Step-by-step progress events from the CLI, read by the dashboard.

Events are JSON lines with step names, counts, rule IDs and file locations only:
never source code, AI output or credentials.
"""
import json
import time
from pathlib import Path

MAX_LOG = 200


class Progress:
    """Append progress events to a file; a no-op without one."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else None

    def emit(self, step: str, status: str, **fields) -> None:
        if not self.path:
            return
        event = {"time": round(time.time(), 3), "step": step, "status": status,
                 **{key: value for key, value in fields.items() if value is not None}}
        try:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event) + "\n")
        except OSError:
            pass  # Progress is best effort and must never fail a scan.


class TrackedScanner:
    """Report when a wrapped scanner starts and finishes."""

    def __init__(self, scanner, step: str, progress: Progress):
        self.scanner, self.step, self.progress = scanner, step, progress

    def scan(self, target):
        self.progress.emit(self.step, "start")
        try:
            result = self.scanner.scan(target)
        except Exception:
            self.progress.emit(self.step, "failed", detail="Scanner crashed")
            raise
        errors, warnings = len(result.errors), len(result.warnings)
        status = ("failed" if result.status == "failed" else
                  "warning" if result.status != "completed" or warnings else "done")
        notes = [f"{errors} scanner error{'s' * (errors != 1)}" if errors else None,
                 f"{warnings} file{'s' * (warnings != 1)} not fully analysed" if warnings else None]
        self.progress.emit(self.step, status, count=len(result.findings),
                           detail="; ".join(note for note in notes if note) or None)
        return result


def short_rule(rule_id: str) -> str:
    return rule_id.rsplit(".", 1)[-1][:120]


def location(finding) -> str:
    return f"{finding.file_path}:{finding.start_line}" if finding.start_line else finding.file_path


class ProgressState:
    """Fold progress events into steps and a readable activity log."""

    def __init__(self, steps: list[dict] | None = None):
        self.steps = [dict(step, status="pending") for step in steps or []]
        self.log = []

    def step(self, step_id: str) -> dict:
        for step in self.steps:
            if step["id"] == step_id:
                return step
        step = {"id": step_id, "label": step_id, "status": "pending"}
        self.steps.append(step)
        return step

    def add_log(self, when: float, message: str, level: str = "info") -> None:
        self.log.append({"time": when, "message": message, "level": level})
        del self.log[:-MAX_LOG]

    def apply(self, event: dict) -> None:
        when, status = event.get("time") or time.time(), event.get("status")
        if event.get("step") == "plan":
            for planned in event.get("steps", []):
                if isinstance(planned, dict) and isinstance(planned.get("id"), str):
                    self.step(planned["id"])["label"] = str(planned.get("label", planned["id"]))[:200]
            return
        step = self.step(str(event.get("step", "unknown")))
        label = step["label"]
        for key in ("detail", "count", "current", "total"):
            if key in event:
                step[key] = event[key]
        if status == "start":
            step.update(status="running", started=when)
            self.add_log(when, f"{label} started")
        elif status == "progress":
            step.update(status="running")
            step.setdefault("started", when)
        elif status == "item":
            result = event.get("result", "")
            self.add_log(when, f"{label} {event.get('current')}/{event.get('total')}: {event.get('detail', '')} → "
                               f"{result.replace('_', ' ')}", "error" if result.startswith("failed") else "info")
        elif status in ("done", "warning", "failed", "skipped"):
            step.update(status=status, finished=when)
            step.setdefault("started", when)
            parts = [f"{event['count']} found" if "count" in event and step["id"].startswith("scan:") else None,
                     event.get("detail")]
            summary = "; ".join(part for part in parts if part)
            verb = {"done": "finished", "warning": "finished with warnings", "failed": "failed", "skipped": "skipped"}[status]
            self.add_log(when, f"{label} {verb}" + (f": {summary}" if summary else ""),
                         {"failed": "error", "warning": "warning"}.get(status, "info"))

    def current(self) -> dict | None:
        return next((step for step in self.steps if step["status"] == "running"), None)

    def snapshot(self) -> dict:
        running = self.current()
        return {"steps": [dict(step) for step in self.steps], "log": list(self.log),
                "phase": running["label"] if running else None}
