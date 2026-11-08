import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace

from appsec_triage.models.scan import Scan
from appsec_triage.progress import Progress, ProgressState, TrackedScanner
from appsec_triage.services.pipeline import Pipeline


def events(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def test_state_builds_steps_and_log():
    state = ProgressState([{"id": "prepare", "label": "Check repository folder"}])
    state.apply({"step": "plan", "status": "plan", "steps": [{"id": "scan:semgrep", "label": "Semgrep code scan"},
                                                             {"id": "triage", "label": "AI review"}]})
    state.apply({"step": "plan", "status": "plan", "steps": [{"id": "triage", "label": "AI review with Claude"}]})
    state.apply({"step": "scan:semgrep", "status": "start", "time": 1})
    assert state.snapshot()["phase"] == "Semgrep code scan"
    state.apply({"step": "scan:semgrep", "status": "done", "time": 3, "count": 4})
    state.apply({"step": "triage", "status": "start", "time": 4, "current": 0, "total": 2})
    state.apply({"step": "triage", "status": "item", "time": 5, "current": 1, "total": 2,
                 "detail": "sql · app.py:1", "result": "likely_true_positive"})
    snapshot = state.snapshot()
    assert [s["id"] for s in snapshot["steps"]] == ["prepare", "scan:semgrep", "triage"]
    semgrep = snapshot["steps"][1]
    assert semgrep["status"] == "done" and semgrep["count"] == 4 and semgrep["finished"] - semgrep["started"] == 2
    assert snapshot["steps"][2]["label"] == "AI review with Claude" and snapshot["phase"] == "AI review with Claude"
    assert [entry["message"] for entry in snapshot["log"]] == [
        "Semgrep code scan started", "Semgrep code scan finished: 4 found",
        "AI review with Claude started", "AI review with Claude 1/2: sql · app.py:1 → likely true positive"]


def test_pipeline_reports_each_review(tmp_path, finding):
    path = tmp_path / "progress.jsonl"
    progress = Progress(path)
    scan = Scan(target=str(tmp_path), scanner="semgrep", status="completed", findings=[finding])
    scanner = TrackedScanner(SimpleNamespace(scan=lambda target: scan), "scan:semgrep", progress)

    class Triage:
        async def assess(self, f):
            raise RuntimeError("provider text with secret code")

    report = asyncio.run(Pipeline(scanner, Triage(), progress).run(tmp_path))
    assert len(report.failed_assessments) == 1
    recorded = events(path)
    assert [(e["step"], e["status"]) for e in recorded] == [
        ("scan:semgrep", "start"), ("scan:semgrep", "done"), ("triage", "start"),
        ("triage", "progress"), ("triage", "item"), ("triage", "warning")]
    assert recorded[1]["count"] == 1 and recorded[4]["result"] == "failed (RuntimeError)"
    assert "secret code" not in path.read_text()


def test_progress_without_file_is_noop(tmp_path):
    Progress().emit("x", "start")
    Progress(tmp_path / "missing" / "dir.jsonl").emit("x", "start")  # unwritable path is ignored


def test_cli_writes_plan_and_steps(monkeypatch, tmp_path, semgrep_payload):
    from appsec_triage.cli import main
    from appsec_triage.scanners import semgrep
    monkeypatch.setattr(semgrep, "run_semgrep", lambda *args: (0, json.dumps(semgrep_payload)))
    progress = tmp_path / "progress.jsonl"
    assert main(["scan", str(tmp_path), "--progress", str(progress), "--output", str(tmp_path / "r.json")]) == 0
    recorded = events(progress)
    assert recorded[0]["step"] == "plan"
    assert [s["id"] for s in recorded[0]["steps"]] == ["scan:semgrep", "report"]
    assert ("report", "done") in [(e["step"], e["status"]) for e in recorded]


def test_dashboard_publishes_live_steps(monkeypatch, tmp_path):
    from appsec_triage.web import LocalServer
    snapshots = []

    def fake_run(args, **kwargs):
        progress = Path(args[args.index("--progress") + 1])
        write = lambda **event: progress.open("a").write(json.dumps({"time": time.time(), **event}) + "\n")
        write(step="plan", status="plan", steps=[{"id": "scan:semgrep", "label": "Semgrep code scan"},
                                                 {"id": "report", "label": "Write report"}])
        write(step="scan:semgrep", status="start")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and server.job.get("phase") != "Semgrep code scan":
            time.sleep(0.05)
        snapshots.append(json.loads(json.dumps(server.job)))
        write(step="scan:semgrep", status="done", count=2)
        Path(args[-1]).write_text('{"scan":{"status":"completed"}}')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("appsec_triage.web.run_scan_process", fake_run)
    with LocalServer(0) as server:
        server.scan(str(tmp_path), "scan", 0)
        final = server.job
    live = snapshots[0]
    assert live["status"] == "running" and live["phase"] == "Semgrep code scan"
    assert [s["status"] for s in live["steps"]] == ["done", "running", "pending"]
    assert final["status"] == "completed"
    assert [s["status"] for s in final["steps"]] == ["done", "done", "pending"]
    assert final["steps"][1]["count"] == 2 and final["finished"] >= final["started"]
    assert any("Semgrep code scan finished: 2 found" == entry["message"] for entry in final["log"])


def test_failed_scan_names_the_step(monkeypatch, tmp_path):
    from appsec_triage.web import LocalServer

    def fake_run(args, **kwargs):
        progress = Path(args[args.index("--progress") + 1])
        progress.write_text(json.dumps({"time": time.time(), "step": "triage", "status": "failed",
                                        "detail": "No Anthropic Claude API key or model is configured"}) + "\n")
        return SimpleNamespace(returncode=2)

    monkeypatch.setattr("appsec_triage.web.run_scan_process", fake_run)
    with LocalServer(0) as server:
        server.scan(str(tmp_path), "scan", 0)
        assert "during “triage”: No Anthropic Claude API key" in server.job["error"]


def test_failure_reasons_are_readable_and_safe():
    from pydantic import ValidationError
    from appsec_triage.models.assessment import AssessmentContent
    from appsec_triage.services.pipeline import failure_reason
    server_error = type("ServerError", (Exception,), {"code": 503})("details with secret source")
    assert failure_reason(TimeoutError(), 240) == "timed out after 240 s"
    assert failure_reason(server_error) == "provider server error, HTTP 503"
    assert failure_reason(type("RateLimitError", (Exception,), {"status_code": 429})()) == "rate limited, HTTP 429"
    try:
        AssessmentContent.model_validate({"verdict": "safe"})
    except ValidationError as exc:
        assert failure_reason(exc) == "the model's answer did not match the required format"


def test_warnings_show_as_amber_step_and_merge_in_combined_scan(tmp_path):
    from appsec_triage.scanners.combined import CombinedScanner
    path = tmp_path / "p.jsonl"
    progress = Progress(path)
    semgrep = Scan(target="t", scanner="semgrep", status="completed", warnings=["a.tsx was only partly parsed", "b.json could not be parsed"])
    trivy = Scan(target="t", scanner="trivy", status="completed")
    combined = CombinedScanner([TrackedScanner(SimpleNamespace(scan=lambda t: semgrep), "scan:semgrep", progress),
                                TrackedScanner(SimpleNamespace(scan=lambda t: trivy), "scan:trivy", progress)]).scan("t")
    assert combined.status == "completed" and combined.errors == []
    assert combined.warnings == ["semgrep: a.tsx was only partly parsed", "semgrep: b.json could not be parsed"]
    done = [e for e in events(path) if e["status"] != "start"]
    assert (done[0]["status"], done[0]["detail"]) == ("warning", "2 files not fully analysed")
    assert done[1]["status"] == "done"
