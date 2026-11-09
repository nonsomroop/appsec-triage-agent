import json

import pytest

from appsec_triage.models.finding import Finding
from appsec_triage.models.scan import Scan
from appsec_triage.reporting import pdf_report
from appsec_triage.reporting.json_reporter import Report


def make_report(*findings):
    return json.loads(Report(scan=Scan(target="/repo", scanner="semgrep+trivy", status="completed",
                                       findings=list(findings))).model_dump_json())


def finding(id, category="sast", severity="high", **extra):
    return Finding(id=id, scanner="trivy" if category == "sca" else "semgrep", rule_id=f"rule.{id}", title="t",
                   severity=severity, message=extra.pop("message", "message"), file_path=f"src/{id}.py",
                   category=category, **extra)



@pytest.mark.parametrize("group", pdf_report.GROUPINGS)
def test_every_grouping_builds_a_pdf(group):
    report = make_report(finding("a"), finding("b", "sca", "critical", package_name="flask",
                                               installed_version="1", fixed_version="2"))
    pdf = pdf_report.build_pdf(report, {"a": {"verdict": "confirmed", "comments": []}}, {"project": "Demo"},
                               {"group": group}, compress=False)
    assert pdf.startswith(b"%PDF") and b"/Outlines" in pdf


def test_untrusted_markup_is_escaped():
    hostile = '<font name="x"><img src="/etc/passwd"/></font><b>unclosed & <link href="javascript:x">'
    report = make_report(finding("a", message=hostile, source_snippet=hostile))
    reviews = {"a": {"verdict": "confirmed", "reviewer": hostile[:60],
                     "comments": [{"kind": "comment", "author": "<i>", "body": hostile, "created": "2026"}]}}
    assert pdf_report.build_pdf(report, reviews, {"project": hostile}).startswith(b"%PDF")


def test_markup_falls_back_per_character(monkeypatch):
    fonts = {"body": "Main", "bold": "Main-Bold", "mono": "Mono", "fallbacks": [("Thai", "Thai-Bold")],
             "coverage": {"Main": frozenset(range(256)), "Main-Bold": frozenset(range(256)),
                          "Mono": frozenset(range(256)), "Thai": frozenset(range(0x0E00, 0x0E80)),
                          "Thai-Bold": frozenset(range(0x0E00, 0x0E80))}}
    monkeypatch.setattr(pdf_report, "_fonts", fonts)
    assert pdf_report.markup("Fix ด่วน <now>") == 'Fix <font name="Thai">ด่วน</font> &lt;now&gt;'
    assert pdf_report.markup("a\nb") == "a<br/>b"


def test_false_positives_can_be_left_out():
    report = make_report(finding("a"), finding("b"))
    reviews = {"b": {"verdict": "false_positive", "comments": []}}
    data = pdf_report.ReportData(report, reviews, {"include_false_positives": False, "group": "category"})
    assert [item["f"]["id"] for item in data.items] == ["a"] and len(data.hidden) == 1
    assert pdf_report.agreement("likely_true_positive", "false_positive") == "Human overrides AI"
    assert pdf_report.agreement("likely_true_positive", "confirmed") == "Human agrees with AI"
    assert pdf_report.agreement("unassessed", "confirmed") is None
    with pytest.raises(ValueError):
        pdf_report.build_pdf(report, options={"group": "colour"})


def test_whitespace_that_fonts_cannot_draw_is_normalised():
    text = "if x:\r\n\treturn\u200b 1\u00a0\u2003# ok\x07"
    assert pdf_report.plain(text) == "if x:\n    return 1  # ok"
    assert "\t" not in pdf_report.plain("a\tb") and "\r" not in pdf_report.plain("a\rb")


def test_explicit_font_wraps_text(monkeypatch):
    fonts = {"body": "Main", "bold": "Main-Bold", "mono": "Mono", "fallbacks": [],
             "coverage": {"Main": frozenset(range(256)), "Main-Bold": frozenset(range(256)), "Mono": frozenset(range(256))}}
    monkeypatch.setattr(pdf_report, "_fonts", fonts)
    assert pdf_report.markup("app.py:1", primary="Mono") == '<font name="Mono">app.py:1</font>'
