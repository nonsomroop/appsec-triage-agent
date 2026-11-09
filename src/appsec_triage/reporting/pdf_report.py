"""A formal, A4 portrait PDF assessment report for one scan.

Structure: title page, contents, 1 Executive summary, 2 Scope and methodology,
3 Findings overview, 4 Detailed findings, Appendix A finding index.

Report content (rule IDs, messages, comments, code) is untrusted: every string is
normalised and escaped before it reaches ReportLab's paragraph markup.
"""
import hashlib
import unicodedata
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, HRFlowable, KeepTogether, NextPageTemplate,
                                PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle, XPreformatted)
from reportlab.platypus.tableofcontents import TableOfContents

GROUPINGS = ("category", "severity", "file", "review")
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
CATEGORIES = {"sast": "Code issues (SAST)", "sca": "Vulnerable dependencies (SCA)", "secret": "Exposed secrets"}
CATEGORY_SHORT = {"sast": "Code (SAST)", "sca": "Dependency (SCA)", "secret": "Secret"}
AI_LABELS = {"likely_true_positive": "Likely real", "likely_false_positive": "Likely false alarm",
             "needs_review": "Needs review", "failed": "Review failed", "unassessed": "Not reviewed"}
HUMAN_LABELS = {"confirmed": "Confirmed", "false_positive": "False positive", "accepted_risk": "Accepted risk",
                "fixed": "Fixed", None: "Not reviewed"}
REVIEW_ORDER = ("confirmed", "accepted_risk", None, "fixed", "false_positive")

# A restrained palette: one navy accent, greys, and muted severity colours.
NAVY, INK, MUTED = colors.HexColor("#1b2a4a"), colors.HexColor("#1a1a1a"), colors.HexColor("#5a6270")
RULE, FILL = colors.HexColor("#c9ced8"), colors.HexColor("#f3f4f7")
CONFIDENTIAL = "#8b1a1a"
SEVERITY_COLORS = {"critical": "#8b1a1a", "high": "#b4410c", "medium": "#9a6b12", "low": "#2b5f9e",
                   "info": "#4a5568", "unknown": "#6b7280"}
HUMAN_COLORS = {"confirmed": "#8b1a1a", "false_positive": "#2f6b3f", "accepted_risk": "#9a6b12",
                "fixed": "#2b5f9e", None: "#6b7280"}
SEVERITY_MEANING = {
    "critical": "Exploitable with severe impact; fix immediately.",
    "high": "Likely exploitable with significant impact; fix in the current cycle.",
    "medium": "Exploitable under specific conditions; plan a fix.",
    "low": "Limited impact or hard to exploit; fix when convenient.",
    "info": "Informational or hardening advice.",
}
HUMAN_MEANING = {
    "confirmed": "A reviewer verified the issue is real.",
    "false_positive": "A reviewer determined the finding is not a real issue.",
    "accepted_risk": "Real, but the risk is knowingly accepted.",
    "fixed": "The issue has been remediated.",
}

# ---------- fonts ----------

ASSETS = Path(__file__).resolve().parent.parent / "assets" / "fonts"
SERIF_SETS = [  # (regular, bold, italic, bold italic): Times New Roman, else its metric-compatible twin.
    tuple(f"/System/Library/Fonts/Supplemental/Times New Roman{s}.ttf" for s in ("", " Bold", " Italic", " Bold Italic")),
    tuple(f"/Library/Fonts/Times New Roman{s}.ttf" for s in ("", " Bold", " Italic", " Bold Italic")),
    tuple(f"/usr/share/fonts/truetype/msttcorefonts/Times_New_Roman{s}.ttf" for s in ("", "_Bold", "_Italic", "_Bold_Italic")),
    tuple(f"C:/Windows/Fonts/{n}.ttf" for n in ("times", "timesbd", "timesi", "timesbi")),
    tuple(f"/usr/share/fonts/truetype/liberation2/LiberationSerif-{s}.ttf" for s in ("Regular", "Bold", "Italic", "BoldItalic")),
    tuple(f"/usr/share/fonts/truetype/liberation/LiberationSerif-{s}.ttf" for s in ("Regular", "Bold", "Italic", "BoldItalic")),
]
MONO_SET = (ASSETS / "UbuntuMono-Regular.ttf", ASSETS / "UbuntuMono-Bold.ttf")
# Used per character when the main font lacks a glyph, e.g. Thai comments or code.
FALLBACK_FONTS = [
    ("/usr/share/fonts/truetype/tlwg/Loma.ttf", "/usr/share/fonts/truetype/tlwg/Loma-Bold.ttf"),
    ("/System/Library/Fonts/Supplemental/Tahoma.ttf", "/System/Library/Fonts/Supplemental/Tahoma Bold.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", None),
    ("/Library/Fonts/Arial Unicode.ttf", None),
    ("C:/Windows/Fonts/tahoma.ttf", "C:/Windows/Fonts/tahomabd.ttf"),
]
LATIN1 = frozenset(range(256))
_fonts = None


def _register_family(name, regular, bold=None, italic=None, bold_italic=None):
    names = {}
    for style, path in (("normal", regular), ("bold", bold), ("italic", italic), ("boldItalic", bold_italic)):
        if path and Path(path).is_file():
            font = name if style == "normal" else f"{name}-{style}"
            pdfmetrics.registerFont(TTFont(font, str(path)))
            names[style] = font
    names.setdefault("bold", names["normal"])
    names.setdefault("italic", names["normal"])
    names.setdefault("boldItalic", names["bold"])
    pdfmetrics.registerFontFamily(name, **names)
    return names


def fonts():
    """Times New Roman (or Liberation Serif) for text, bundled Ubuntu Mono for code, base-14 as a last resort."""
    global _fonts
    if _fonts is not None:
        return _fonts
    found = {"body": "Times-Roman", "bold": "Times-Bold", "italic": "Times-Italic", "mono": "Courier",
             "mono_bold": "Courier-Bold", "fallbacks": [], "coverage": {}}
    for paths in SERIF_SETS:
        if all(Path(p).is_file() for p in paths[:2]):
            try:
                names = _register_family("ReportSerif", *paths)
                found.update(body=names["normal"], bold=names["bold"], italic=names["italic"])
                break
            except Exception:
                continue
    try:
        if MONO_SET[0].is_file():
            names = _register_family("ReportMono", MONO_SET[0], MONO_SET[1])
            found.update(mono=names["normal"], mono_bold=names["bold"])
    except Exception:
        pass
    for index, (regular, bold) in enumerate(FALLBACK_FONTS):
        if Path(regular).is_file():
            try:
                names = _register_family(f"ReportFallback{index}", regular, bold)
                found["fallbacks"].append((names["normal"], names["bold"]))
            except Exception:
                continue
    for name in {found[k] for k in ("body", "bold", "italic", "mono", "mono_bold")} | \
            {n for pair in found["fallbacks"] for n in pair}:
        face = getattr(pdfmetrics.getFont(name), "face", None)
        found["coverage"][name] = frozenset(face.charToGlyph) if hasattr(face, "charToGlyph") else LATIN1
    _fonts = found
    return found


# ---------- text ----------

def plain(value, limit=4000):
    """Normalise untrusted text so every character has something sensible to render.

    Tabs, carriage returns, exotic spaces and invisible format characters have no glyph
    in most fonts and would otherwise print as boxes.
    """
    text = str(value if value is not None else "").replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.expandtabs(4) for line in text.split("\n"))
    out = []
    for char in text:
        kind = unicodedata.category(char)
        if char == "\n":
            out.append(char)
        elif kind == "Zs":
            out.append(" ")
        elif kind in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            continue
        else:
            out.append(char)
    text = "".join(out)
    return text[:limit].rstrip() + "…" if len(text) > limit else text


def _font_for(char, primary, bold=False):
    f = fonts()
    if char in "\n " or ord(char) in f["coverage"].get(primary, LATIN1):
        return primary
    for regular, bold_name in f["fallbacks"]:
        name = bold_name if bold else regular
        if ord(char) in f["coverage"][name]:
            return name
    return primary


def runs(text, primary, bold=False):
    """Split text into [font, chunk] runs so each character uses a font that has it."""
    result = []
    for char in text:
        font = _font_for(char, primary, bold)
        if result and result[-1][0] == font:
            result[-1][1] += char
        else:
            result.append([font, char])
    return result


def markup(value, limit=4000, primary=None, bold=False):
    """Escape untrusted text for Paragraph markup, adding font fallback and line breaks.

    An explicit primary font (e.g. mono inside a serif paragraph) wraps the whole text.
    """
    explicit = primary is not None
    primary = primary or (fonts()["bold"] if bold else fonts()["body"])
    out = []
    for font, chunk in runs(plain(value, limit), primary, bold):
        chunk = escape(chunk).replace("\n", "<br/>")
        out.append(chunk if font == primary else f'<font name="{font}">{chunk}</font>')
    text = "".join(out)
    return f'<font name="{primary}">{text}</font>' if explicit and text else text


def draw_text(canvas, x, y, text, font, size, align="left"):
    """drawString with per-character font fallback."""
    pieces = runs(plain(text, 300).replace("\n", " "), font)
    total = sum(pdfmetrics.stringWidth(chunk, name, size) for name, chunk in pieces)
    x = x - total if align == "right" else x
    for name, chunk in pieces:
        canvas.setFont(name, size)
        canvas.drawString(x, y, chunk)
        x += pdfmetrics.stringWidth(chunk, name, size)


# ---------- data ----------

def category(finding):
    return finding.get("category") or ("sca" if finding.get("scanner") == "trivy" else "sast")


def finding_title(finding):
    if category(finding) == "sca":
        return f"{finding.get('package_name') or 'Dependency'} {finding.get('vulnerability_id') or finding.get('rule_id')}"
    last = str(finding.get("rule_id", "")).split(".")[-1].replace("-", " ").replace("_", " ")
    return last[:1].upper() + last[1:] if last else "Finding"


def location(finding):
    where = finding.get("file_path") or ""
    start, end = finding.get("start_line"), finding.get("end_line")
    if start:
        where += f":{start}" + (f"–{end}" if end and end != start else "")
    return where


def agreement(ai, human):
    if human is None or ai in (None, "unassessed", "failed"):
        return None
    if ai == "needs_review":
        return "AI was unsure; human decided"
    real = human in ("confirmed", "accepted_risk", "fixed")
    if (ai == "likely_true_positive") == real:
        return "Human agrees with AI"
    return "Human overrides AI"


class ReportData:
    def __init__(self, report, reviews, options):
        self.report = report
        self.scan = report.get("scan") or {}
        self.reviews = reviews or {}
        self.options = options
        assessments = {a.get("finding_id"): a for a in report.get("assessments") or [] if isinstance(a, dict)}
        failed = {a.get("finding_id") for a in report.get("failed_assessments") or [] if isinstance(a, dict)}
        self.all = []
        for finding in self.scan.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            review = self.reviews.get(finding.get("id")) or {}
            ai = assessments.get(finding.get("id"))
            self.all.append({"f": finding, "ai": ai, "review": review,
                             "ai_verdict": ai.get("verdict") if ai else ("failed" if finding.get("id") in failed else "unassessed"),
                             "human": review.get("verdict")})
        self.hidden = [item for item in self.all if item["human"] == "false_positive"] \
            if not options.get("include_false_positives", True) else []
        self.items = [item for item in self.all if item not in self.hidden]
        self.models = sorted({a.get("model_name") for a in assessments.values() if a.get("model_name")})

    def groups(self):
        mode = self.options.get("group", "category")
        order = {"category": list(CATEGORIES), "severity": list(SEVERITIES), "review": list(REVIEW_ORDER)}.get(mode)
        keyfunc = {"category": lambda i: category(i["f"]), "severity": lambda i: i["f"].get("severity", "unknown"),
                   "file": lambda i: i["f"].get("file_path") or "(no file)", "review": lambda i: i["human"]}[mode]
        buckets = {}
        for item in self.items:
            buckets.setdefault(keyfunc(item), []).append(item)
        keys = ([k for k in order if k in buckets] + [k for k in buckets if k not in order]) if order \
            else sorted(buckets, key=str)

        def label(key):
            if mode == "category":
                return CATEGORIES.get(key, str(key).title())
            if mode == "severity":
                return f"{str(key).title()} severity"
            if mode == "review":
                return HUMAN_LABELS.get(key, str(key))
            return key

        sev = lambda i: SEVERITIES.index(i["f"].get("severity")) if i["f"].get("severity") in SEVERITIES else 9
        return [(label(k), k, sorted(buckets[k], key=lambda i: (sev(i), i["f"].get("file_path") or ""))) for k in keys]


# ---------- layout helpers ----------

def styles():
    f = fonts()
    base = dict(fontName=f["body"], textColor=INK, fontSize=10.5, leading=14.5)
    return {
        "body": ParagraphStyle("body", **base, alignment=TA_JUSTIFY, spaceAfter=6),
        "left": ParagraphStyle("left", **base),
        "cell": ParagraphStyle("cell", **{**base, "fontSize": 9.5, "leading": 12.5}),
        "cell_head": ParagraphStyle("cell_head", **{**base, "fontName": f["bold"], "fontSize": 9.5, "leading": 12.5,
                                                     "textColor": colors.white}),
        "label": ParagraphStyle("label", **{**base, "fontName": f["bold"], "fontSize": 9.5, "leading": 12.5,
                                            "textColor": NAVY}),
        "caption": ParagraphStyle("caption", **{**base, "fontName": f["italic"], "fontSize": 9, "leading": 12,
                                                "textColor": MUTED, "spaceBefore": 3, "spaceAfter": 10}),
        "small": ParagraphStyle("small", **{**base, "fontSize": 8.5, "leading": 11, "textColor": MUTED}),
        "h1": ParagraphStyle("h1", **{**base, "fontName": f["bold"], "fontSize": 17, "leading": 22,
                                      "textColor": NAVY, "spaceBefore": 4, "spaceAfter": 10}),
        "h2": ParagraphStyle("h2", **{**base, "fontName": f["bold"], "fontSize": 13, "leading": 17,
                                      "textColor": NAVY, "spaceBefore": 12, "spaceAfter": 6, "keepWithNext": 1}),
        "h3": ParagraphStyle("h3", **{**base, "fontName": f["bold"], "fontSize": 11.5, "leading": 15,
                                      "spaceBefore": 4, "spaceAfter": 6, "keepWithNext": 1}),
        "h4": ParagraphStyle("h4", **{**base, "fontName": f["bold"], "fontSize": 10.5, "leading": 14,
                                      "spaceBefore": 6, "spaceAfter": 2, "keepWithNext": 1}),
        "code": ParagraphStyle("code", fontName=f["mono"], fontSize=8.6, leading=11, textColor=INK),
        "bullet": ParagraphStyle("bullet", **base, leftIndent=14, bulletIndent=3, spaceAfter=3),
        "toc0": ParagraphStyle("toc0", **{**base, "fontName": f["bold"], "fontSize": 11, "leading": 18}),
        "toc1": ParagraphStyle("toc1", **{**base, "fontSize": 10.5, "leading": 16, "leftIndent": 18}),
    }


def sev_markup(severity):
    color = SEVERITY_COLORS.get(severity, "#6b7280")
    return f'<font color="{color}"><b>{escape(str(severity).upper())}</b></font>'


def human_markup(verdict):
    return f'<font color="{HUMAN_COLORS.get(verdict, "#6b7280")}"><b>{escape(HUMAN_LABELS.get(verdict, str(verdict)))}</b></font>'


def cells(values, style):
    return [Paragraph(str(v), style) if isinstance(v, (str, int, float)) else v for v in values]


def grid_table(rows, widths, header=True, align_right=()):
    """A consistent ruled table: navy header row, light zebra rows, thin grey rules."""
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
             ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
             ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, FILL])]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("LINEBELOW", (0, -1), (-1, -1), 0.8, NAVY)]
    for col in align_right:
        style.append(("ALIGN", (col, 1), (col, -1), "RIGHT"))
    table.setStyle(TableStyle(style))
    return table


class ReportTemplate(BaseDocTemplate):
    """Feeds section headings to the table of contents and the PDF outline."""

    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph) or flowable.style.name not in ("h1", "h2"):
            return
        level = 0 if flowable.style.name == "h1" else 1
        text = flowable.getPlainText()
        key = f"heading-{self.seq.nextf('heading')}"
        self.canv.bookmarkPage(key)
        self.canv.addOutlineEntry(text, key, level=level, closed=level > 0)
        self.notify("TOCEntry", (level, escape(text), self.page, key))


def numbered_canvas(header_text, footer_text):
    """A canvas that knows the page count, for running headers and 'Page X of Y'."""

    class NumberedCanvas(Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved = []

        def showPage(self):
            self._saved.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._saved)
            for state in self._saved:
                self.__dict__.update(state)
                self.decorate(total)
                super().showPage()
            super().save()

        def decorate(self, total):
            f = fonts()
            width, height = A4
            left, right = 22 * mm, width - 22 * mm
            self.saveState()
            if self._pageNumber == 1:
                self.setFillColor(NAVY)
                self.rect(0, height - 9 * mm, width, 9 * mm, fill=1, stroke=0)
            else:
                self.setStrokeColor(RULE)
                self.setLineWidth(0.5)
                self.line(left, height - 15 * mm, right, height - 15 * mm)
                self.setFillColor(MUTED)
                draw_text(self, left, height - 13 * mm, header_text, f["italic"], 8.5)
                self.setFillColor(colors.HexColor(CONFIDENTIAL))
                draw_text(self, right, height - 13 * mm, "CONFIDENTIAL", f["bold"], 8.5, "right")
            self.setStrokeColor(RULE)
            self.setLineWidth(0.5)
            self.line(left, 15 * mm, right, 15 * mm)
            self.setFillColor(MUTED)
            draw_text(self, left, 10.5 * mm, footer_text, f["body"], 8.5)
            draw_text(self, right, 10.5 * mm, f"Page {self._pageNumber} of {total}", f["body"], 8.5, "right")
            self.restoreState()

    return NumberedCanvas


def counts(items, key, values):
    return {value: sum(1 for item in items if key(item) == value) for value in values}


def plural(n, word):
    return f"{n} {word}{'s' * (n != 1)}"


# ---------- document ----------

def build_pdf(report: dict, reviews: dict | None = None, meta: dict | None = None,
              options: dict | None = None, compress: bool = True) -> bytes:
    options = {"group": "category", "include_false_positives": True, "include_code": True,
               "include_comments": True, **(options or {})}
    if options["group"] not in GROUPINGS:
        raise ValueError("Unknown grouping")
    meta = meta or {}
    s = styles()
    data = ReportData(report, reviews, options)
    scan = data.scan
    width, height = A4
    margin_x = 22 * mm
    content = width - 2 * margin_x
    project = plain(meta.get("project") or scan.get("target") or "Scan report", 90).replace("\n", " ")
    now = datetime.now(timezone.utc)
    generated = now.strftime("%d %B %Y, %H:%M UTC")
    scanned = str(scan.get("completed_at") or scan.get("started_at") or "")[:16].replace("T", " ") or "Not recorded"
    digest = hashlib.sha256(f"{project}|{scan.get('id')}|{scanned}".encode()).hexdigest()[:6].upper()
    report_id = f"AST-{now.strftime('%Y%m%d')}-{digest}"

    groups = data.groups()
    numbering, number = {}, 0
    for _, _, items in groups:
        for item in items:
            number += 1
            numbering[id(item)] = f"F-{number:03d}"

    buffer = BytesIO()
    doc = ReportTemplate(buffer, pagesize=A4, leftMargin=margin_x, rightMargin=margin_x, topMargin=24 * mm,
                         bottomMargin=22 * mm, title=f"Application Security Assessment: {project}",
                         author="AppSec Triage", subject="Application security assessment report",
                         pageCompression=1 if compress else 0)
    frame = Frame(margin_x, 22 * mm, content, height - 46 * mm, id="main", leftPadding=0, rightPadding=0,
                  topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate("title", [frame]), PageTemplate("body", [frame])])

    story = title_page(s, data, project, scanned, generated, report_id, content, meta)
    story += [NextPageTemplate("body"), PageBreak(), Paragraph("Contents", ParagraphStyle("contents", parent=s["h1"])), Spacer(1, 4),
              TableOfContents(dotsMinLevel=0, levelStyles=[s["toc0"], s["toc1"]]), PageBreak()]
    story += executive_summary(s, data, project, scan, scanned, content)
    story += scope_and_methodology(s, data, scan, scanned, generated, content, meta)
    story += findings_overview(s, data, content)
    story += detailed_findings(s, data, groups, numbering, options, content)
    story += appendix(s, groups, numbering, content)

    header = f"Application Security Assessment: {project}"
    footer = f"{report_id} · Generated by AppSec Triage on {now.strftime('%d %b %Y')}"
    doc.multiBuild(story, canvasmaker=numbered_canvas(header, footer))
    return buffer.getvalue()


# ---------- sections ----------

def title_page(s, data, project, scanned, generated, report_id, content, meta):
    f = fonts()
    scan = data.scan
    title = ParagraphStyle("title", parent=s["left"], fontName=f["bold"], fontSize=30, leading=36, textColor=NAVY)
    subtitle = ParagraphStyle("subtitle", parent=s["left"], fontName=f["italic"], fontSize=15, leading=20,
                              textColor=MUTED)
    kicker = ParagraphStyle("kicker", parent=s["label"], fontSize=10, textColor=colors.HexColor(CONFIDENTIAL))
    control = [
        ("Report ID", escape(report_id)), ("Project", markup(project, 120)),
        ("Target", markup(scan.get("target"), 300)), ("Branch", markup(meta.get("branch") or "Default", 120)),
        ("Scanners", markup(scan.get("scanner") or "Not recorded", 120)),
        ("Scan status", markup(str(scan.get("status") or "Not recorded").title())),
        ("Scan date", markup(scanned)), ("Report generated", markup(generated)),
        ("Classification", f'<font color="{CONFIDENTIAL}"><b>CONFIDENTIAL</b></font>'),
    ]
    rows = [[Paragraph(label, s["label"]), Paragraph(value, s["cell"])] for label, value in control]
    table = Table(rows, colWidths=[content * 0.3, content * 0.7], hAlign="LEFT")
    table.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, 0), 1, NAVY), ("LINEBELOW", (0, -1), (-1, -1), 1, NAVY),
                               ("LINEBELOW", (0, 0), (-1, -2), 0.4, RULE), ("BACKGROUND", (0, 0), (0, -1), FILL),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 5),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 5), ("LEFTPADDING", (0, 0), (-1, -1), 7)]))
    notice = ("This document contains security findings and may contain excerpts of source code. Distribute it "
              "only to people authorised to see this information. Automated findings and AI assessments are "
              "suggestions; verdicts marked as human review were recorded by a named reviewer.")
    return [Spacer(1, 30 * mm), Paragraph("SECURITY ASSESSMENT · CONFIDENTIAL", kicker), Spacer(1, 8),
            Paragraph("Application Security<br/>Assessment Report", title),
            HRFlowable(width="100%", thickness=1.5, color=NAVY, spaceBefore=10, spaceAfter=10),
            Paragraph(markup(project, 120), subtitle), Spacer(1, 26 * mm),
            Paragraph("Document control", s["h4"]), Spacer(1, 4), table, Spacer(1, 14 * mm),
            Paragraph(escape(notice), s["small"])]


def executive_summary(s, data, project, scan, scanned, content):
    items = data.all
    sev = counts(items, lambda i: i["f"].get("severity"), SEVERITIES)
    human = counts(items, lambda i: i["human"], list(HUMAN_LABELS))
    reviewed = len(items) - human[None]
    open_items = [i for i in items if i["human"] not in ("false_positive", "fixed")]
    highest = next((name for name in SEVERITIES if any(i["f"].get("severity") == name for i in open_items)), None)
    rating = highest if highest in ("critical", "high", "medium", "low") else "low"
    ai_items = [i for i in items if i["ai"]]
    both = [i for i in items if i["human"] and i["ai_verdict"] not in ("unassessed", "failed")]
    overrides = sum(1 for i in both if agreement(i["ai_verdict"], i["human"]) == "Human overrides AI")
    severity_text = ", ".join(f"{sev[name]} {name}" for name in SEVERITIES[:5] if sev[name]) or "none"

    paras = [
        f"This report presents the results of an automated application security assessment of "
        f"<b>{markup(project, 120)}</b>, performed on {markup(scanned)} using "
        f"{markup(scan.get('scanner') or 'the configured scanners')}.",
        f"The assessment identified <b>{plural(len(items), 'finding')}</b> ({escape(severity_text)}).",
    ]
    if reviewed:
        paras.append(f"Human reviewers assessed {plural(reviewed, 'finding')}: {human['confirmed']} confirmed, "
                     f"{plural(human['false_positive'], 'false positive')}, "
                     f"{plural(human['accepted_risk'], 'accepted risk')} and {human['fixed']} fixed. "
                     f"After review, <b>{plural(len(open_items), 'finding')}</b> remain open.")
    else:
        paras.append("No findings have been reviewed by a person yet, so all findings are treated as open.")
    if ai_items:
        models = f" ({markup(', '.join(data.models), 200)})" if data.models else ""
        paras.append(f"{plural(len(ai_items), 'code finding')} received an AI assessment{models}"
                     + (f"; reviewers overrode the AI verdict on {overrides}." if both else "."))
    story = [Paragraph("1. Executive Summary", s["h1"])] + [Paragraph(p, s["body"]) for p in paras]
    rating_table = Table([[Paragraph("Overall risk rating", s["label"]),
                           Paragraph(f'<font color="{SEVERITY_COLORS[rating]}" size="13"><b>{rating.upper()}</b></font>', s["cell"]),
                           Paragraph("Based on the most severe finding that is still open after human review.", s["small"])]],
                         colWidths=[content * 0.27, content * 0.18, content * 0.55], hAlign="LEFT")
    rating_table.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 1, NAVY), ("BACKGROUND", (0, 0), (0, 0), FILL),
                                      ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 8),
                                      ("BOTTOMPADDING", (0, 0), (-1, -1), 8), ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    figures = [("Total findings", len(items)), ("Critical and high", sev["critical"] + sev["high"]),
               ("Reviewed by a person", f"{reviewed} of {len(items)}"), ("Open after review", len(open_items)),
               ("False positives (human review)", human["false_positive"]), ("AI-assessed findings", len(ai_items))]
    rows = [cells(["Metric", "Value"], s["cell_head"])] + [cells([escape(k), str(v)], s["cell"]) for k, v in figures]
    story += [Spacer(1, 4), rating_table, Spacer(1, 12), Paragraph("Key figures", s["h4"]),
              grid_table(rows, [content * 0.65, content * 0.35], align_right=(1,)),
              Paragraph("Table 1. Key figures.", s["caption"])]
    return story


def scope_and_methodology(s, data, scan, scanned, generated, content, meta):
    detail = [("Target", markup(scan.get("target"), 300)), ("Branch", markup(meta.get("branch") or "Default", 120)),
              ("Scanners", markup(scan.get("scanner") or "Not recorded", 120)),
              ("Scanner version", markup(scan.get("scanner_version") or "Not recorded", 120)),
              ("Scan completed", markup(scanned)), ("AI assessment", markup(", ".join(data.models) or "Not used", 200)),
              ("Report generated", markup(generated))]
    rows = [cells(["Item", "Detail"], s["cell_head"])]
    rows += [[Paragraph(label, s["label"]), Paragraph(value, s["cell"])] for label, value in detail]
    story = [PageBreak(), Paragraph("2. Scope and Methodology", s["h1"]), Paragraph("2.1 Scope", s["h2"]),
             grid_table(rows, [content * 0.3, content * 0.7]), Paragraph("Table 2. Assessment scope.", s["caption"]),
             Paragraph("2.2 Methodology", s["h2"]),
             Paragraph("The assessment combined automated scanning with optional AI and human review:", s["body"])]
    for text in ("<b>Static analysis (SAST)</b> finds insecure code patterns such as injection or unsafe APIs.",
                 "<b>Software composition analysis (SCA)</b> matches dependencies against known vulnerability databases.",
                 "<b>Secret scanning</b> flags credentials committed to files or history; matched values are not stored.",
                 "<b>AI assessment</b> reviews code findings with the surrounding source and suggests a verdict. It is advisory.",
                 "<b>Human review</b> records a named reviewer's verdict and notes. Human verdicts take precedence in this report."):
        story.append(Paragraph(text, s["bullet"], bulletText="•"))
    rows = [cells(["Term", "Meaning"], s["cell_head"])]
    rows += [[Paragraph(sev_markup(name), s["cell"]), Paragraph(escape(text), s["cell"])] for name, text in SEVERITY_MEANING.items()]
    rows += [[Paragraph(human_markup(name), s["cell"]), Paragraph(escape(text), s["cell"])] for name, text in HUMAN_MEANING.items()]
    story += [Paragraph("2.3 Severity and Verdict Definitions", s["h2"]), grid_table(rows, [content * 0.3, content * 0.7]),
              Paragraph("Table 3. Definitions.", s["caption"]), Paragraph("2.4 Limitations", s["h2"]),
              Paragraph("Automated scanning cannot prove the absence of vulnerabilities. Coverage depends on the "
                        "rulesets and databases used, and on the languages and files the scanners support.", s["body"])]
    notes = [n for n in (scan.get("warnings") or []) + (scan.get("errors") or []) if isinstance(n, str)]
    for text in notes[:25]:
        story.append(Paragraph(markup(text, 400), s["bullet"], bulletText="•"))
    if len(notes) > 25:
        story.append(Paragraph(f"… and {len(notes) - 25} more scanner notes.", s["small"]))
    return story


def findings_overview(s, data, content):
    items, total = data.all, len(data.all) or 1
    rows = [cells(["Severity", "Count", "Share", "Open after review"], s["cell_head"])]
    for name in SEVERITIES:
        group = [i for i in items if i["f"].get("severity") == name]
        if not group and name == "unknown":
            continue
        still_open = sum(1 for i in group if i["human"] not in ("false_positive", "fixed"))
        rows.append(cells([sev_markup(name), len(group), f"{100 * len(group) / total:.0f}%", still_open], s["cell"]))
    story = [PageBreak(), Paragraph("3. Findings Overview", s["h1"]), Paragraph("3.1 Findings by Severity", s["h2"]),
             grid_table(rows, [content * 0.34, content * 0.22, content * 0.22, content * 0.22], align_right=(1, 2, 3)),
             Paragraph("Table 4. Findings by severity.", s["caption"])]
    rows = [cells(["Category", "Total", "Crit.", "High", "Med.", "Low", "Info"], s["cell_head"])]
    for key, label in CATEGORIES.items():
        group = [i for i in items if category(i["f"]) == key]
        if group:
            c = counts(group, lambda i: i["f"].get("severity"), SEVERITIES)
            rows.append(cells([escape(label), len(group), c["critical"], c["high"], c["medium"], c["low"],
                               c["info"] + c["unknown"]], s["cell"]))
    if len(rows) == 1:
        rows.append(cells(["No findings", 0, 0, 0, 0, 0, 0], s["cell"]))
    story += [Paragraph("3.2 Findings by Category", s["h2"]),
              grid_table(rows, [content * 0.4] + [content * 0.1] * 6, align_right=range(1, 7)),
              Paragraph("Table 5. Findings by category and severity.", s["caption"])]
    human = counts(items, lambda i: i["human"], list(HUMAN_LABELS))
    after = len(items) - human["false_positive"] - human["fixed"]
    rows = [cells(["Stage", "Findings", "Note"], s["cell_head"]),
            cells(["Raw scanner output", len(items), "Every finding reported by the scanners."], s["cell"]),
            cells(["Marked false positive", f"−{human['false_positive']}", "Removed: not a real issue."], s["cell"]),
            cells(["Marked fixed", f"−{human['fixed']}", "Removed: already remediated."], s["cell"]),
            cells(["<b>Open after review</b>", f"<b>{after}</b>",
                   f"{human['confirmed']} confirmed, {human['accepted_risk']} accepted risk, "
                   f"{human[None]} not yet reviewed."], s["cell"])]
    story += [Paragraph("3.3 Scanner Results Compared with Human Review", s["h2"]),
              grid_table(rows, [content * 0.34, content * 0.16, content * 0.5], align_right=(1,)),
              Paragraph("Table 6. Effect of human review on the scanner result.", s["caption"])]
    both = [i for i in items if i["human"] and i["ai_verdict"] not in ("unassessed", "failed")]
    if both:
        agree = sum(1 for i in both if agreement(i["ai_verdict"], i["human"]) == "Human agrees with AI")
        override = sum(1 for i in both if agreement(i["ai_verdict"], i["human"]) == "Human overrides AI")
        story.append(Paragraph(f"Of {plural(len(both), 'finding')} assessed by both AI and a person, the reviewer "
                               f"agreed with the AI on {agree} and overrode it on {override}.", s["body"]))
    return story


def attribute_table(s, item, content):
    f, ai, review = item["f"], item["ai"], item["review"]
    cat = category(f)
    mono = fonts()["mono"]
    ai_text = "Not applicable" if cat != "sast" else AI_LABELS.get(item["ai_verdict"], item["ai_verdict"]) + (
        f" ({round(ai['confidence'] * 100)}% confidence)" if ai and isinstance(ai.get("confidence"), (int, float)) else "")
    human = human_markup(item["human"])
    if item["human"] and review.get("reviewer"):
        human += f" by {markup(review.get('reviewer'), 60)}"
    if item["human"] and review.get("updated"):
        human += f", {markup(str(review.get('updated'))[:10])}"
    if cat == "sca":
        extra = [("Package", markup(f"{f.get('package_name') or '—'} {f.get('installed_version') or ''}", 160)),
                 ("Fixed in", markup(f.get("fixed_version") or "No fix published", 120))]
    else:
        extra = [("CWE", markup(", ".join(str(c) for c in f.get("cwe") or []) or "—", 200)),
                 ("Scanner", markup(f.get("scanner"), 60))]
    label = lambda t: Paragraph(t, s["label"])
    cell = lambda t: Paragraph(t, s["cell"])
    rows = [[label("Severity"), cell(sev_markup(f.get("severity", "unknown"))), label("Category"),
             cell(escape(CATEGORY_SHORT.get(cat, cat)))],
            [label("Rule"), cell(markup(f.get("rule_id"), 200, mono)), "", ""],
            [label("Location"), cell(markup(location(f), 300, mono)), "", ""],
            [label(extra[0][0]), cell(extra[0][1]), label(extra[1][0]), cell(extra[1][1])],
            [label("AI verdict"), cell(escape(ai_text)), label("Human review"), cell(human)]]
    table = Table(rows, colWidths=[content * 0.16, content * 0.34, content * 0.16, content * 0.34], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("SPAN", (1, 1), (3, 1)), ("SPAN", (1, 2), (3, 2)), ("BACKGROUND", (0, 0), (0, -1), FILL),
        ("BACKGROUND", (2, 0), (2, 0), FILL), ("BACKGROUND", (2, 3), (2, 4), FILL),
        ("BOX", (0, 0), (-1, -1), 0.6, RULE), ("INNERGRID", (0, 0), (-1, -1), 0.4, RULE),
        ("LINEABOVE", (0, 0), (-1, 0), 1.2, NAVY), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6)]))
    return table


def code_block(snippet, s, width):
    """Source evidence in Ubuntu Mono. Whitespace is normalised so no character prints as a box."""
    f = fonts()
    lines = plain(snippet, 8000).split("\n")[:45]
    chars = max(int((width - 18) / pdfmetrics.stringWidth("M", f["mono"], 8.6)), 20)
    wrapped = []
    for line in lines:
        while len(line) > chars:
            wrapped.append(line[:chars])
            line = "    " + line[chars:]
        wrapped.append(line)
    code = markup("\n".join(wrapped), 12000, f["mono"]).replace("<br/>", "\n")
    table = Table([[XPreformatted(code, s["code"])]], colWidths=[width], hAlign="LEFT")
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), FILL), ("LINEBEFORE", (0, 0), (0, -1), 2, NAVY),
                               ("BOX", (0, 0), (-1, -1), 0.4, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 9),
                               ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    return table


def finding_section(s, item, identifier, options, content):
    f, ai, review = item["f"], item["ai"], item["review"]
    cat = category(f)
    title = f"{identifier}&nbsp;&nbsp;{markup(finding_title(f), 200, bold=True)}"
    if item["human"] in ("false_positive", "fixed"):
        title += (f' <font size="9.5" color="{HUMAN_COLORS[item["human"]]}">'
                  f'[{escape(HUMAN_LABELS[item["human"]])}]</font>')
    story = [KeepTogether([Paragraph(title, s["h3"]), attribute_table(s, item, content)])]
    story.append(Paragraph("Description", s["h4"]))
    story.append(Paragraph("Gitleaks flagged a possible credential at this location. The matched value is not stored "
                           "in the report." if cat == "secret" else markup(f.get("message"), 2000), s["body"]))
    if ai:
        text = markup(ai.get("reasoning_summary"), 2000)
        if ai.get("impact"):
            text += f"<br/><i>Impact:</i> {markup(ai.get('impact'), 800)}"
        note = agreement(item["ai_verdict"], item["human"])
        if note:
            text += f'<br/><font color="{"#8b1a1a" if "overrides" in note else "#2f6b3f"}"><i>{escape(note)}.</i></font>'
        story += [Paragraph("AI Assessment", s["h4"]), Paragraph(text, s["body"])]
    comments = [c for c in review.get("comments") or [] if isinstance(c, dict)]
    if item["human"] or (options.get("include_comments", True) and comments):
        story.append(Paragraph("Human Review", s["h4"]))
        story.append(Paragraph(f"Verdict: {human_markup(item['human'])}" +
                               (f" by {markup(review.get('reviewer'), 60)}" if review.get("reviewer") else ""), s["left"]))
        if options.get("include_comments", True) and comments:
            rows = [cells(["Date", "Reviewer", "Note"], s["cell_head"])]
            for comment in comments[-15:]:
                body = markup(comment.get("body"), 1000)
                rows.append(cells([markup(str(comment.get("created", ""))[:16].replace("T", " ")),
                                   markup(comment.get("author") or "—", 60),
                                   f"<i>{body}</i>" if comment.get("kind") == "event" else body], s["cell"]))
            story += [Spacer(1, 4), grid_table(rows, [content * 0.2, content * 0.18, content * 0.62])]
    if cat == "sca":
        fix = (f"Upgrade <b>{markup(f.get('package_name'), 120)}</b> from {markup(f.get('installed_version'), 60)} to "
               f"<b>{markup(f.get('fixed_version'), 120)}</b> or later, then rebuild the lockfile." if f.get("fixed_version")
               else "No fixed version is published. Consider a workaround, an alternative package, or formally accepting the risk.")
    elif cat == "secret":
        fix = "If this is a real credential, revoke or rotate it, then remove it from the source and the Git history."
    else:
        fix = markup(ai.get("remediation"), 2000) if ai and ai.get("remediation") else \
            "Follow the scanner guidance above and confirm the fix with a new scan."
    story += [Paragraph("Recommendation", s["h4"]), Paragraph(fix, s["body"])]
    if options.get("include_code", True) and cat == "sast" and isinstance(f.get("source_snippet"), str) and f["source_snippet"]:
        story += [Paragraph("Evidence", s["h4"]), code_block(f["source_snippet"], s, content)]
    story.append(HRFlowable(width="100%", thickness=0.4, color=RULE, spaceBefore=10, spaceAfter=10))
    return story


def detailed_findings(s, data, groups, numbering, options, content):
    grouping = {"category": "category", "severity": "severity", "file": "file", "review": "human review status"}
    intro = (f"Findings are grouped by {grouping[options['group']]} and ordered by severity. Each finding has an "
             "identifier that is also listed in Appendix A.")
    if data.hidden:
        intro += (f" {plural(len(data.hidden), 'finding')} marked as false positive by a reviewer "
                  f"{'is' if len(data.hidden) == 1 else 'are'} excluded from this report.")
    story = [PageBreak(), Paragraph("4. Detailed Findings", s["h1"]), Paragraph(escape(intro), s["body"])]
    if not groups:
        story.append(Paragraph("The scan reported no findings.", s["body"]))
    for index, (label, _, items) in enumerate(groups, start=1):
        story += [CondPageBreak(70 * mm), Paragraph(f"4.{index} {markup(label, 120)} ({len(items)})", s["h2"])]
        for item in items:
            story.append(CondPageBreak(60 * mm))
            story += finding_section(s, item, numbering[id(item)], options, content)
    return story


def appendix(s, groups, numbering, content):
    mono = fonts()["mono"]
    rows = [cells(["ID", "Finding", "Severity", "Location", "Human review"], s["cell_head"])]
    for _, _, items in groups:
        for item in items:
            f = item["f"]
            rows.append(cells([numbering[id(item)], markup(finding_title(f), 120), sev_markup(f.get("severity", "unknown")),
                               markup(location(f), 160, mono), human_markup(item["human"])], s["cell"]))
    if len(rows) == 1:
        rows.append(cells(["—", "No findings", "", "", ""], s["cell"]))
    return [PageBreak(), Paragraph("Appendix A. Finding Index", s["h1"]),
            Paragraph("All findings in this report with their identifiers and human review status.", s["body"]),
            grid_table(rows, [content * 0.1, content * 0.32, content * 0.13, content * 0.27, content * 0.18])]
