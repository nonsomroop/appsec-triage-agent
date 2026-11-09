"""A formal, A4 portrait PDF assessment report for one scan.

Structure: title page, contents, 1 Executive summary, 2 Scope and methodology,
3 Findings overview, 4 Detailed findings, Appendix A finding index.

Typography uses fonts the operating system already has (no bundled assets):
a serif for running text, a sans-serif for headings, labels and tables, and the
platform's coding font for evidence, each with a base-14 PDF fallback.

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
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, KeepTogether, NextPageTemplate, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table, TableStyle, XPreformatted)
from reportlab.platypus.tableofcontents import TableOfContents

GROUPINGS = ("category", "severity", "file", "review")
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
CATEGORIES = {"sast": "Code issues (SAST)", "sca": "Vulnerable dependencies (SCA)", "secret": "Exposed secrets"}
CATEGORY_SHORT = {"sast": "Code", "sca": "Dependency", "secret": "Secret"}
AI_LABELS = {"likely_true_positive": "Likely real", "likely_false_positive": "Likely false alarm",
             "needs_review": "Needs review", "failed": "Review failed", "unassessed": "Not reviewed"}
HUMAN_LABELS = {"confirmed": "Confirmed", "false_positive": "False positive", "accepted_risk": "Accepted risk",
                "fixed": "Fixed", None: "Not reviewed"}
REVIEW_ORDER = ("confirmed", "accepted_risk", None, "fixed", "false_positive")

# ---------- theme ----------
# Minimal theme: near-black text, greys, one indigo accent; colour only where it carries meaning.
INDIGO = colors.HexColor("#231C66")
GRID = colors.HexColor("#d1d5db")
INK, MUTED, RULE = colors.HexColor("#111827"), colors.HexColor("#6b7280"), colors.HexColor("#e5e7eb")
ROW_TINT, HEAD_FILL = colors.HexColor("#fafafa"), colors.HexColor("#f3f4f6")
SEVERITY_COLORS = {"critical": "#dc1e1e", "high": "#e86b05", "medium": "#edea35", "low": "#66afeb",
                   "info": "#6b7280", "unknown": "#9ca3af"}
HUMAN_COLORS = {"confirmed": "#dc1e1e", "false_positive": "#052E96", "accepted_risk": "#e65d02",
                "fixed": "#27bb20", None: "#9ca3af"}
AI_COLORS = {"likely_true_positive": "#dc1e1e", "likely_false_positive": "#052E96", "needs_review": "#e65d02",
             "failed": "#94a3b8", "unassessed": "#94a3b8"}
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

# ---------- fonts (all from the operating system; base-14 PDF fonts as the last resort) ----------
# Each entry: (regular, bold, italic, bold italic); a path may be (file, index) for font collections.
SERIF_SETS = [  # running text: Times New Roman, else its metric-compatible twin
    tuple(f"/System/Library/Fonts/Supplemental/Times New Roman{s}.ttf" for s in ("", " Bold", " Italic", " Bold Italic")),
    tuple(f"C:/Windows/Fonts/{n}.ttf" for n in ("times", "timesbd", "timesi", "timesbi")),
    tuple(f"/usr/share/fonts/truetype/liberation2/LiberationSerif-{s}.ttf" for s in ("Regular", "Bold", "Italic", "BoldItalic")),
    tuple(f"/usr/share/fonts/truetype/liberation/LiberationSerif-{s}.ttf" for s in ("Regular", "Bold", "Italic", "BoldItalic")),
]
SANS_SETS = [  # headings, labels and tables: Arial, else Liberation Sans or DejaVu Sans
    tuple(f"/System/Library/Fonts/Supplemental/Arial{s}.ttf" for s in ("", " Bold", " Italic", " Bold Italic")),
    tuple(f"C:/Windows/Fonts/{n}.ttf" for n in ("arial", "arialbd", "ariali", "arialbi")),
    tuple(f"/usr/share/fonts/truetype/liberation2/LiberationSans-{s}.ttf" for s in ("Regular", "Bold", "Italic", "BoldItalic")),
    tuple(f"/usr/share/fonts/truetype/liberation/LiberationSans-{s}.ttf" for s in ("Regular", "Bold", "Italic", "BoldItalic")),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", None, None),
]
MONO_SETS = [  # code: each platform's own coding font
    ("C:/Windows/Fonts/consola.ttf", "C:/Windows/Fonts/consolab.ttf", None, None),  # Consolas
    (("/System/Library/Fonts/Menlo.ttc", 0), ("/System/Library/Fonts/Menlo.ttc", 1), None, None),  # Menlo
    ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", None, None),
    tuple(f"/usr/share/fonts/truetype/liberation/LiberationMono-{s}.ttf" for s in ("Regular", "Bold", "Italic", "BoldItalic")),
]
FALLBACK_FONTS = [  # per character, when the main font lacks a glyph (e.g. Thai)
    ("/usr/share/fonts/truetype/tlwg/Loma.ttf", "/usr/share/fonts/truetype/tlwg/Loma-Bold.ttf"),
    ("/System/Library/Fonts/Supplemental/Tahoma.ttf", "/System/Library/Fonts/Supplemental/Tahoma Bold.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", None),
    ("C:/Windows/Fonts/tahoma.ttf", "C:/Windows/Fonts/tahomabd.ttf"),
]
BASE14 = {"serif": ("Times-Roman", "Times-Bold", "Times-Italic"),
          "sans": ("Helvetica", "Helvetica-Bold", "Helvetica-Oblique"),
          "mono": ("Courier", "Courier-Bold", "Courier-Oblique")}
LATIN1 = frozenset(range(256))
_fonts = None


def _exists(path):
    return path is not None and Path(path[0] if isinstance(path, tuple) else path).is_file()


def _register_family(name, regular, bold=None, italic=None, bold_italic=None):
    names = {}
    for style, path in (("normal", regular), ("bold", bold), ("italic", italic), ("boldItalic", bold_italic)):
        if _exists(path):
            font = name if style == "normal" else f"{name}-{style}"
            file, index = path if isinstance(path, tuple) else (path, 0)
            pdfmetrics.registerFont(TTFont(font, file, subfontIndex=index))
            names[style] = font
    names.setdefault("bold", names["normal"])
    names.setdefault("italic", names["normal"])
    names.setdefault("boldItalic", names["bold"])
    pdfmetrics.registerFontFamily(name, **names)
    return names


def fonts():
    global _fonts
    if _fonts is not None:
        return _fonts
    found = {"fallbacks": [], "coverage": {}}
    for role, sets in (("serif", SERIF_SETS), ("sans", SANS_SETS), ("mono", MONO_SETS)):
        regular, bold, italic = BASE14[role]
        for paths in sets:
            if _exists(paths[0]) and _exists(paths[1]):
                try:
                    names = _register_family(f"Report{role.title()}", *paths)
                    regular, bold, italic = names["normal"], names["bold"], names["italic"]
                    break
                except Exception:
                    continue
        found.update({role: regular, f"{role}_bold": bold, f"{role}_italic": italic})
    for index, (regular, bold) in enumerate(FALLBACK_FONTS):
        if _exists(regular):
            try:
                names = _register_family(f"ReportFallback{index}", regular, bold)
                found["fallbacks"].append((names["normal"], names["bold"]))
            except Exception:
                continue
    names = {v for k, v in found.items() if k not in ("fallbacks", "coverage")}
    for name in names | {n for pair in found["fallbacks"] for n in pair}:
        face = getattr(pdfmetrics.getFont(name), "face", None)
        found["coverage"][name] = frozenset(face.charToGlyph) if hasattr(face, "charToGlyph") else LATIN1
    # Backwards-compatible aliases.
    found.update(body=found["serif"], bold=found["serif_bold"], italic=found["serif_italic"])
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


# ---------- styles and building blocks ----------

def styles():
    f = fonts()
    body = dict(fontName=f["serif"], textColor=INK, fontSize=11, leading=16)
    sans = dict(fontName=f["sans"], textColor=INK, fontSize=9.2, leading=12.8)
    return {
        "body": ParagraphStyle("body", **body, spaceAfter=7),
        "left": ParagraphStyle("left", **body),
        "cell": ParagraphStyle("cell", **sans),
        "cell_center": ParagraphStyle("cell_center", **sans, alignment=TA_CENTER),
        "cell_head": ParagraphStyle("cell_head", **{**sans, "fontName": f["sans_bold"], "textColor": INK}),
        "label": ParagraphStyle("label", **{**sans, "fontName": f["sans_bold"], "fontSize": 8, "leading": 11,
                                            "textColor": INDIGO}),
        "chip": ParagraphStyle("chip", **{**sans, "fontName": f["sans_bold"], "fontSize": 8, "leading": 10}),
        "caption": ParagraphStyle("caption", **{**sans, "fontName": f["sans_italic"], "fontSize": 8.2, "leading": 11,
                                                "textColor": MUTED, "spaceBefore": 4, "spaceAfter": 12}),
        "small": ParagraphStyle("small", **{**sans, "fontSize": 8.2, "leading": 11.5, "textColor": MUTED}),
        # Section headings are coloured bands; the band colour is set per section.
        "h1": ParagraphStyle("h1", fontName=f["sans_bold"], fontSize=19, leading=24, textColor=INK,
                             spaceBefore=4, spaceAfter=14),
        "h2": ParagraphStyle("h2", fontName=f["sans_bold"], fontSize=12.5, leading=16, textColor=INK,
                             spaceBefore=16, spaceAfter=7, keepWithNext=1),
        "h3": ParagraphStyle("h3", fontName=f["sans_bold"], fontSize=11.5, leading=15, textColor=INK, keepWithNext=1),
        "h4": ParagraphStyle("h4", fontName=f["sans_bold"], fontSize=9, leading=12, textColor=INDIGO,
                             spaceBefore=12, spaceAfter=4, keepWithNext=1),
        "code": ParagraphStyle("code", fontName=f["mono"], fontSize=8.3, leading=11.2, textColor=colors.HexColor("#1e293b")),
        "bullet": ParagraphStyle("bullet", **body, leftIndent=15, bulletIndent=3, spaceAfter=4),
        "toc0": ParagraphStyle("toc0", fontName=f["sans_bold"], fontSize=11, leading=20, textColor=INK),
        "toc1": ParagraphStyle("toc1", fontName=f["sans"], fontSize=10, leading=17, leftIndent=18, textColor=INK),
    }


def section_heading(s, text, index):
    return Paragraph(text, s["h1"])


def sev_text(severity):
    color = SEVERITY_COLORS.get(severity, "#94a3b8")
    return f'<font color="{color}"><b>{escape(str(severity).title())}</b></font>'


def human_text(verdict):
    return f'<font color="{HUMAN_COLORS.get(verdict, "#94a3b8")}"><b>{escape(HUMAN_LABELS.get(verdict, str(verdict)))}</b></font>'


def chip(text, color, s, width=None):
    """A quiet label: a coloured dot followed by the text."""
    return Paragraph(f'<font color="{color}">●</font>&nbsp;{escape(str(text).title())}', s["chip"])


def cells(values, style):
    return [Paragraph(str(v), style) if isinstance(v, (str, int, float)) else v for v in values]


def grid_table(rows, widths, header=True, align_right=()):
    """A ruled table: light grey header row, faint zebra rows, hairline rules."""
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
             ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
             ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
             ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, ROW_TINT])]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), HEAD_FILL), ("LINEBELOW", (0, 0), (-1, 0), 0.8, MUTED)]
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
            left, right = 20 * mm, width - 20 * mm
            self.saveState()
            if self._pageNumber > 1:  # the title page draws its own artwork as a background
                self.setStrokeColor(RULE)
                self.setLineWidth(0.5)
                self.line(left, height - 12 * mm, right, height - 12 * mm)
                self.setFillColor(MUTED)
                draw_text(self, left, height - 10 * mm, header_text, f["sans"], 8)
                draw_text(self, right, height - 10 * mm, "Confidential", f["sans_bold"], 8, "right")
                self.setStrokeColor(RULE)
                self.setLineWidth(0.5)
                self.line(left, 14 * mm, right, 14 * mm)
                self.setFillColor(MUTED)
                draw_text(self, left, 9.5 * mm, footer_text, f["sans"], 7.8)
                draw_text(self, right, 9.5 * mm, f"Page {self._pageNumber} of {total}", f["sans"], 8, "right")
            self.restoreState()

    return NumberedCanvas


def title_page_art(canvas, width, height):
    """A single accent rule; the title page is otherwise typographic."""
    canvas.setFillColor(INDIGO)
    canvas.rect(20 * mm, height - 62 * mm, 18 * mm, 1.6 * mm, fill=1, stroke=0)


def keep_captions(story):
    """Never let a caption start a page on its own: bind it to the table or figure above."""
    result = []
    for flowable in story:
        if isinstance(flowable, Paragraph) and flowable.style.name == "caption" and result:
            result[-1] = KeepTogether([result[-1], flowable])
        else:
            result.append(flowable)
    return result


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
    margin_x = 20 * mm
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
    doc = ReportTemplate(buffer, pagesize=A4, leftMargin=margin_x, rightMargin=margin_x, topMargin=20 * mm,
                         bottomMargin=20 * mm, title=f"Application Security Assessment: {project}",
                         author="AppSec Triage", subject="Application security assessment report",
                         pageCompression=1 if compress else 0)
    frame = Frame(margin_x, 20 * mm, content, height - 40 * mm, id="main", leftPadding=0, rightPadding=0,
                  topPadding=0, bottomPadding=0)
    title_art = lambda canvas, _doc: title_page_art(canvas, width, height)
    doc.addPageTemplates([PageTemplate("title", [frame], onPage=title_art), PageTemplate("body", [frame])])

    contents_style = ParagraphStyle("contents", parent=s["h1"])
    story = title_page(s, data, project, scanned, generated, report_id, content, meta)
    story += [NextPageTemplate("body"), PageBreak(), Paragraph("Contents", contents_style), Spacer(1, 4),
              TableOfContents(dotsMinLevel=0, levelStyles=[s["toc0"], s["toc1"]]), PageBreak()]
    story += executive_summary(s, data, project, scan, scanned, content)
    story += scope_and_methodology(s, data, scan, scanned, generated, content, meta)
    story += findings_overview(s, data, content)
    story += detailed_findings(s, data, groups, numbering, options, content)
    story += appendix(s, groups, numbering, content)

    story = keep_captions(story)
    header = f"Application Security Assessment  ·  {project}"
    footer = f"{report_id}  ·  Generated by AppSec Triage on {now.strftime('%d %b %Y')}"
    doc.multiBuild(story, canvasmaker=numbered_canvas(header, footer))
    return buffer.getvalue()


# ---------- sections ----------

def title_page(s, data, project, scanned, generated, report_id, content, meta):
    f = fonts()
    scan = data.scan
    kicker = ParagraphStyle("kicker", fontName=f["sans_bold"], fontSize=9, leading=12, textColor=MUTED)
    title = ParagraphStyle("title", fontName=f["sans_bold"], fontSize=30, leading=36, textColor=INK)
    subtitle = ParagraphStyle("subtitle", fontName=f["serif_italic"], fontSize=16, leading=21, textColor=MUTED)
    control = [
        ("Report ID", escape(report_id)), ("Project", markup(project, 120)),
        ("Target", markup(scan.get("target"), 300, f["mono"])), ("Branch", markup(meta.get("branch") or "Default", 120)),
        ("Scanners", markup(scan.get("scanner") or "Not recorded", 120)),
        ("Scan status", markup(str(scan.get("status") or "Not recorded").title())),
        ("Scan date", markup(scanned)), ("Report generated", markup(generated)),
        ("Classification", "<b>Confidential</b>"),
    ]
    rows = [[Paragraph(label.upper(), s["label"]), Paragraph(value, s["cell"])] for label, value in control]
    table = Table(rows, colWidths=[content * 0.28, content * 0.72], hAlign="LEFT")
    table.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, 0), 0.8, INK), ("LINEBELOW", (0, -1), (-1, -1), 0.8, INK),
                               ("LINEBELOW", (0, 0), (-1, -2), 0.4, GRID), ("BACKGROUND", (0, 0), (0, -1), HEAD_FILL),
                               ("LINEAFTER", (0, 0), (0, -1), 0.5, GRID),
                               ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 6),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    notice = ("This document contains security findings and may contain excerpts of source code. Distribute it "
              "only to people authorised to see this information. Automated findings and AI assessments are "
              "suggestions; verdicts marked as human review were recorded by a named reviewer.")
    return [Spacer(1, 48 * mm), Paragraph("SECURITY ASSESSMENT", kicker), Spacer(1, 10),
            Paragraph("Application Security<br/>Assessment Report", title), Spacer(1, 12),
            Paragraph(markup(project, 120), subtitle), Spacer(1, 40 * mm),
            Paragraph("Document control", ParagraphStyle("doc-control", parent=s["h2"])), table, Spacer(1, 12 * mm),
            Paragraph(escape(notice), s["small"])]


def stat_tiles(s, tiles, content):
    """Coloured key-figure tiles: big number over a label."""
    big = ParagraphStyle("big", fontName=fonts()["sans_bold"], fontSize=22, leading=26, alignment=TA_CENTER)
    row = []
    for label, value, color in tiles:
        row.append([Paragraph(escape(str(value)), big),
                    Paragraph(escape(label), ParagraphStyle("tl", parent=s["small"], alignment=TA_CENTER))])
    table = Table([row], colWidths=[content / len(tiles)] * len(tiles), hAlign="LEFT")
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 10),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 10), ("BOX", (0, 0), (-1, -1), 0.5, RULE),
             ("LINEAFTER", (0, 0), (-2, -1), 0.5, RULE)]
    table.setStyle(TableStyle(style))
    return table


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

    rating_color = SEVERITY_COLORS[rating]
    rating_table = Table([[Paragraph("OVERALL RISK", s["label"]),
                           Paragraph(f'<font color="{rating_color}"><b>{rating.upper()}</b></font>',
                                     ParagraphStyle("rv", fontName=fonts()["sans_bold"], fontSize=17, leading=21)),
                           Paragraph("Based on the most severe finding still open after human review.", s["small"])]],
                         colWidths=[content * 0.2, content * 0.24, content * 0.56], hAlign="LEFT")
    rating_table.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, 0), 0.8, INK), ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK),
                                      ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 9),
                                      ("BOTTOMPADDING", (0, 0), (-1, -1), 9), ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
    tiles = [("Total findings", len(items), "#4338ca"), ("Critical + high", sev["critical"] + sev["high"], "#be123c"),
             ("Reviewed by a person", f"{reviewed}/{len(items)}", "#0d9488"), ("Open after review", len(open_items), "#d97706"),
             ("False positives", human["false_positive"], "#059669")]
    story = [section_heading(s, "1. Executive Summary", 0)] + [Paragraph(p, s["body"]) for p in paras]
    story += [Spacer(1, 6), rating_table, Spacer(1, 14), stat_tiles(s, tiles, content),
              Paragraph("Figure 1. Key figures.", s["caption"])]
    return story


def scope_and_methodology(s, data, scan, scanned, generated, content, meta):
    detail = [("Target", markup(scan.get("target"), 300, fonts()["mono"])),
              ("Branch", markup(meta.get("branch") or "Default", 120)),
              ("Scanners", markup(scan.get("scanner") or "Not recorded", 120)),
              ("Scanner version", markup(scan.get("scanner_version") or "Not recorded", 120)),
              ("Scan completed", markup(scanned)), ("AI assessment", markup(", ".join(data.models) or "Not used", 200)),
              ("Report generated", markup(generated))]
    rows = [cells(["Item", "Detail"], s["cell_head"])]
    rows += [[Paragraph(f"<b>{label}</b>", s["cell"]), Paragraph(value, s["cell"])] for label, value in detail]
    story = [PageBreak(), section_heading(s, "2. Scope and Methodology", 1), Paragraph("2.1 Scope", s["h2"]),
             grid_table(rows, [content * 0.28, content * 0.72]),
             Paragraph("Table 1. Assessment scope.", s["caption"]), Paragraph("2.2 Methodology", s["h2"]),
             Paragraph("The assessment combined automated scanning with optional AI and human review:", s["body"])]
    methods = [("#4338ca", "Static analysis (SAST)", "finds insecure code patterns such as injection or unsafe APIs."),
               ("#0d9488", "Software composition analysis (SCA)", "matches dependencies against known vulnerability databases."),
               ("#e11d48", "Secret scanning", "flags credentials committed to files or history; matched values are not stored."),
               ("#7c3aed", "AI assessment", "reviews code findings with the surrounding source and suggests a verdict. It is advisory."),
               ("#d97706", "Human review", "records a named reviewer's verdict and notes. Human verdicts take precedence in this report.")]
    for color, name, text in methods:
        story.append(Paragraph(f"<b>{name}</b> {text}", s["bullet"], bulletText="•"))
    rows = [cells(["Term", "Meaning"], s["cell_head"])]
    chip_cells = []
    for name, text in SEVERITY_MEANING.items():
        rows.append([chip(name, SEVERITY_COLORS[name], s, 30 * mm), Paragraph(escape(text), s["cell"])])
    for name, text in HUMAN_MEANING.items():
        rows.append([chip(HUMAN_LABELS[name], HUMAN_COLORS[name], s, 30 * mm), Paragraph(escape(text), s["cell"])])
    story += [Paragraph("2.3 Severity and Verdict Definitions", s["h2"]),
              grid_table(rows, [content * 0.28, content * 0.72]),
              Paragraph("Table 2. Definitions.", s["caption"]), Paragraph("2.4 Limitations", s["h2"]),
              Paragraph("Automated scanning cannot prove the absence of vulnerabilities. Coverage depends on the "
                        "rulesets and databases used, and on the languages and files the scanners support.", s["body"])]
    notes = [n for n in (scan.get("warnings") or []) + (scan.get("errors") or []) if isinstance(n, str)]
    for text in notes[:25]:
        story.append(Paragraph(markup(text, 400), s["bullet"], bulletText="•"))
    if len(notes) > 25:
        story.append(Paragraph(f"… and {len(notes) - 25} more scanner notes.", s["small"]))
    return story


def severity_bars(s, items, content):
    """A horizontal bar per severity, drawn as table cells for crisp printing."""
    total = len(items) or 1
    bar_width = content * 0.5
    rows = []
    for name in SEVERITIES[:5]:
        n = sum(1 for i in items if i["f"].get("severity") == name or (name == "info" and i["f"].get("severity") == "unknown"))
        filled = max(bar_width * n / total, 0.1)
        bar = Table([["", ""]], colWidths=[filled, max(bar_width - filled, 0.1)], rowHeights=[6])
        bar.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#374151")),
                                 ("BACKGROUND", (1, 0), (1, 0), HEAD_FILL),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                 ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
        rows.append([chip(name, SEVERITY_COLORS[name], s, 24 * mm), bar,
                     Paragraph(f"<b>{n}</b>  <font color='#6b7280'>({100 * n / total:.0f}%)</font>", s["cell"])])
    table = Table(rows, colWidths=[content * 0.2, bar_width + 6, content * 0.3 - 6], hAlign="LEFT")
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 4),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("LEFTPADDING", (0, 0), (-1, -1), 3)]))
    return table


def findings_overview(s, data, content):
    items = data.all
    story = [PageBreak(), section_heading(s, "3. Findings Overview", 2), Paragraph("3.1 Findings by Severity", s["h2"]),
             severity_bars(s, items, content), Paragraph("Figure 2. Distribution of findings by severity.", s["caption"])]
    rows = [cells(["Category", "Total", "Critical", "High", "Medium", "Low", "Info"], s["cell_head"])]
    for key, label in CATEGORIES.items():
        group = [i for i in items if category(i["f"]) == key]
        if group:
            c = counts(group, lambda i: i["f"].get("severity"), SEVERITIES)
            rows.append(cells([escape(label), f"<b>{len(group)}</b>",
                               c["critical"], c["high"], c["medium"], c["low"], c["info"] + c["unknown"]], s["cell"]))
    if len(rows) == 1:
        rows.append(cells(["No findings", 0, 0, 0, 0, 0, 0], s["cell"]))
    table = grid_table(rows, [content * 0.37] + [content * 0.105] * 6, align_right=range(1, 7))
    story += [Paragraph("3.2 Findings by Category", s["h2"]), table,
              Paragraph("Table 3. Findings by category and severity.", s["caption"])]
    human = counts(items, lambda i: i["human"], list(HUMAN_LABELS))
    after = len(items) - human["false_positive"] - human["fixed"]
    rows = [cells(["Stage", "Findings", "Note"], s["cell_head"]),
            cells(["Raw scanner output", f"<b>{len(items)}</b>", "Every finding reported by the scanners."], s["cell"]),
            cells([human_text("false_positive"), f"−{human['false_positive']}", "Removed: not a real issue."], s["cell"]),
            cells([human_text("fixed"), f"−{human['fixed']}", "Removed: already remediated."], s["cell"]),
            cells(["<b>Open after review</b>", f"<b>{after}</b>",
                   f"{human['confirmed']} confirmed, {human['accepted_risk']} accepted risk, "
                   f"{human[None]} not yet reviewed."], s["cell"])]
    story += [Paragraph("3.3 Scanner Results Compared with Human Review", s["h2"]),
              grid_table(rows, [content * 0.34, content * 0.16, content * 0.5], align_right=(1,)),
              Paragraph("Table 4. Effect of human review on the scanner result.", s["caption"])]
    both = [i for i in items if i["human"] and i["ai_verdict"] not in ("unassessed", "failed")]
    if both:
        agree = sum(1 for i in both if agreement(i["ai_verdict"], i["human"]) == "Human agrees with AI")
        override = sum(1 for i in both if agreement(i["ai_verdict"], i["human"]) == "Human overrides AI")
        story.append(Paragraph(f"Of {plural(len(both), 'finding')} assessed by both AI and a person, the reviewer "
                               f"agreed with the AI on <b>{agree}</b> and overrode it on <b>{override}</b>.", s["body"]))
    return story


def finding_header(s, item, identifier, content):
    """A severity-tinted band: ID, title, then severity and category chips."""
    f = item["f"]
    sev, cat = f.get("severity", "unknown"), category(f)
    title = f'<font color="#6b7280">{identifier}</font>&nbsp;&nbsp;{markup(finding_title(f), 200, bold=True)}'
    if item["human"] in ("false_positive", "fixed"):
        title += f' <font size="9" color="{HUMAN_COLORS[item["human"]]}">({escape(HUMAN_LABELS[item["human"]])})</font>'
    heading = Paragraph(title, ParagraphStyle("fh", parent=s["h3"], fontName=fonts()["sans_bold"]))
    table = Table([[heading, chip(sev, SEVERITY_COLORS.get(sev, "#94a3b8"), s, 22 * mm),
                    chip(CATEGORY_SHORT.get(cat, cat), "#9ca3af", s, 24 * mm)]],
                  colWidths=[content - 50 * mm, 25 * mm, 25 * mm], hAlign="LEFT")
    table.setStyle(TableStyle([("LINEBEFORE", (0, 0), (0, -1), 2, colors.HexColor(SEVERITY_COLORS.get(sev, "#9ca3af"))),
                               ("LINEBELOW", (0, 0), (-1, -1), 0.5, RULE),
                               ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 8),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 8), ("LEFTPADDING", (0, 0), (0, 0), 10),
                               ("LEFTPADDING", (1, 0), (-1, 0), 2), ("RIGHTPADDING", (-1, 0), (-1, 0), 8)]))
    return table


def attribute_table(s, item, content):
    f, ai, review = item["f"], item["ai"], item["review"]
    cat, mono = category(f), fonts()["mono"]
    ai_color = AI_COLORS.get(item["ai_verdict"], "#94a3b8")
    ai_label = "Not applicable" if cat != "sast" else AI_LABELS.get(item["ai_verdict"], item["ai_verdict"])
    ai_text = f'<font color="{ai_color if cat == "sast" else "#94a3b8"}"><b>{escape(ai_label)}</b></font>'
    if cat == "sast" and ai and isinstance(ai.get("confidence"), (int, float)):
        ai_text += f" · {round(ai['confidence'] * 100)}% confidence"
    human = human_text(item["human"])
    if item["human"] and review.get("reviewer"):
        human += f" · {markup(review.get('reviewer'), 60)}"
    if item["human"] and review.get("updated"):
        human += f" · {markup(str(review.get('updated'))[:10])}"
    if cat == "sca":
        extra = [("PACKAGE", markup(f"{f.get('package_name') or '—'} {f.get('installed_version') or ''}", 160, mono)),
                 ("FIXED IN", markup(f.get("fixed_version") or "No fix published", 120, mono))]
    else:
        extra = [("CWE", markup(", ".join(str(c) for c in f.get("cwe") or []) or "—", 200)),
                 ("SCANNER", markup(f.get("scanner"), 60))]
    label = lambda t: Paragraph(t, s["label"])
    cell = lambda t: Paragraph(t, s["cell"])
    rows = [[label("RULE"), cell(markup(f.get("rule_id"), 200, mono)), "", ""],
            [label("LOCATION"), cell(markup(location(f), 300, mono)), "", ""],
            [label(extra[0][0]), cell(extra[0][1]), label(extra[1][0]), cell(extra[1][1])],
            [label("AI VERDICT"), cell(ai_text), label("HUMAN REVIEW"), cell(human)]]
    table = Table(rows, colWidths=[content * 0.15, content * 0.35, content * 0.15, content * 0.35], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("SPAN", (1, 0), (3, 0)), ("SPAN", (1, 1), (3, 1)),
        ("BOX", (0, 0), (-1, -1), 0.6, GRID), ("INNERGRID", (0, 0), (-1, -1), 0.5, GRID),
        ("BACKGROUND", (0, 0), (0, -1), HEAD_FILL), ("BACKGROUND", (2, 2), (2, 3), HEAD_FILL),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 6)]))
    return table


def code_block(snippet, s, width):
    """Source evidence in the platform coding font. Whitespace is normalised so nothing prints as a box."""
    f = fonts()
    lines = plain(snippet, 8000).split("\n")[:45]
    chars = max(int((width - 20) / pdfmetrics.stringWidth("M", f["mono"], 8.3)), 20)
    wrapped = []
    for line in lines:
        while len(line) > chars:
            wrapped.append(line[:chars])
            line = "    " + line[chars:]
        wrapped.append(line)
    code = markup("\n".join(wrapped), 12000, f["mono"]).replace("<br/>", "\n")
    table = Table([[XPreformatted(code, s["code"])]], colWidths=[width], hAlign="LEFT")
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f7f7f8")),
                               ("BOX", (0, 0), (-1, -1), 0.5, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 10),
                               ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    return table


def finding_section(s, item, identifier, options, content):
    f, ai, review = item["f"], item["ai"], item["review"]
    cat = category(f)
    story = [KeepTogether([finding_header(s, item, identifier, content), attribute_table(s, item, content)])]
    story.append(Paragraph("DESCRIPTION", s["h4"]))
    story.append(Paragraph("Gitleaks flagged a possible credential at this location. The matched value is not stored "
                           "in the report." if cat == "secret" else markup(f.get("message"), 2000), s["body"]))
    if ai:
        text = markup(ai.get("reasoning_summary"), 2000)
        if ai.get("impact"):
            text += f"<br/><i>Impact:</i> {markup(ai.get('impact'), 800)}"
        note = agreement(item["ai_verdict"], item["human"])
        if note:
            text += f'<br/><font color="{"#be123c" if "overrides" in note else "#059669"}"><i>{escape(note)}.</i></font>'
        story += [Paragraph("AI ASSESSMENT", s["h4"]), Paragraph(text, s["body"])]
    comments = [c for c in review.get("comments") or [] if isinstance(c, dict)]
    if item["human"] or (options.get("include_comments", True) and comments):
        story.append(Paragraph("HUMAN REVIEW", s["h4"]))
        story.append(Paragraph(f"Verdict: {human_text(item['human'])}" +
                               (f" by {markup(review.get('reviewer'), 60)}" if review.get("reviewer") else ""), s["left"]))
        if options.get("include_comments", True) and comments:
            rows = [cells(["Date", "Reviewer", "Note"], s["cell_head"])]
            for comment in comments[-15:]:
                body = markup(comment.get("body"), 1000, fonts()["sans"])
                rows.append(cells([markup(str(comment.get("created", ""))[:16].replace("T", " ")),
                                   f"<b>{markup(comment.get('author') or '—', 60)}</b>",
                                   f"<i>{body}</i>" if comment.get("kind") == "event" else body], s["cell"]))
            story += [Spacer(1, 5), grid_table(rows, [content * 0.2, content * 0.17, content * 0.63])]
    if cat == "sca":
        fix = (f"Upgrade <b>{markup(f.get('package_name'), 120)}</b> from {markup(f.get('installed_version'), 60)} to "
               f"<b>{markup(f.get('fixed_version'), 120)}</b> or later, then rebuild the lockfile." if f.get("fixed_version")
               else "No fixed version is published. Consider a workaround, an alternative package, or formally accepting the risk.")
    elif cat == "secret":
        fix = "If this is a real credential, revoke or rotate it, then remove it from the source and the Git history."
    else:
        fix = markup(ai.get("remediation"), 2000) if ai and ai.get("remediation") else \
            "Follow the scanner guidance above and confirm the fix with a new scan."
    story += [Paragraph("RECOMMENDATION", s["h4"]), Paragraph(fix, s["body"])]
    if options.get("include_code", True) and cat == "sast" and isinstance(f.get("source_snippet"), str) and f["source_snippet"]:
        story += [Paragraph("EVIDENCE", s["h4"]), code_block(f["source_snippet"], s, content)]
    story.append(Spacer(1, 20))
    return story


def detailed_findings(s, data, groups, numbering, options, content):
    grouping = {"category": "category", "severity": "severity", "file": "file", "review": "human review status"}
    intro = (f"Findings are grouped by {grouping[options['group']]} and ordered by severity. Each finding has an "
             "identifier that is also listed in Appendix A.")
    if data.hidden:
        intro += (f" {plural(len(data.hidden), 'finding')} marked as false positive by a reviewer "
                  f"{'is' if len(data.hidden) == 1 else 'are'} excluded from this report.")
    story = [PageBreak(), section_heading(s, "4. Detailed Findings", 3), Paragraph(escape(intro), s["body"])]
    if not groups:
        story.append(Paragraph("The scan reported no findings.", s["body"]))
    for index, (label, _, items) in enumerate(groups, start=1):
        heading = Paragraph(f"4.{index} {markup(label, 120, fonts()['sans_bold'])} "
                            f'<font color="#6b7280" size="10">({plural(len(items), "finding")})</font>',
                            s["h2"])
        story += [CondPageBreak(80 * mm), heading]
        for item in items:
            story.append(CondPageBreak(65 * mm))
            story += finding_section(s, item, numbering[id(item)], options, content)
    return story


def appendix(s, groups, numbering, content):
    mono = fonts()["mono"]
    rows = [cells(["ID", "Finding", "Severity", "Location", "Human review"], s["cell_head"])]
    for _, _, items in groups:
        for item in items:
            f = item["f"]
            sev = f.get("severity", "unknown")
            rows.append([Paragraph(f"<b>{numbering[id(item)]}</b>", s["cell"]), Paragraph(markup(finding_title(f), 120), s["cell"]),
                         chip(sev, SEVERITY_COLORS.get(sev, "#94a3b8"), s, 20 * mm),
                         Paragraph(markup(location(f), 160, mono), s["cell"]), Paragraph(human_text(item["human"]), s["cell"])])
    if len(rows) == 1:
        rows.append(cells(["—", "No findings", "", "", ""], s["cell"]))
    return [PageBreak(), section_heading(s, "Appendix A. Finding Index", 4),
            Paragraph("All findings in this report with their identifiers and human review status.", s["body"]),
            grid_table(rows, [content * 0.1, content * 0.32, content * 0.14, content * 0.26, content * 0.18])]
