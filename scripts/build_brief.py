#!/usr/bin/env python
"""Render docs/BRIEF.md to the two-page PDF the brief asks for.

    python scripts/build_brief.py            # writes docs/yugaantar-astra-brief.pdf

The brief's own template says "keep each page to about 350 words" and "keep each page to
one page" -- which Markdown viewers do not enforce. So this renderer enforces it: the PDF
has exactly two pages, and the build **fails** if either page's text would overflow. A
document that silently becomes three pages fails a stated requirement, and the failure
should be loud at build time rather than discovered by a reviewer.

Page furniture is deliberately plain: no logos, no colour blocks. The subject is a
security claim, and the document should read as evidence rather than marketing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Flowable, Frame, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.lib import colors

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "BRIEF.md"
TARGET = ROOT / "docs" / "yugaantar-astra-brief.pdf"

MARGIN = 16 * mm

# A4 is 210x297mm; at 16mm margins with 9pt body text this fits ~430 words comfortably.
STYLES = {
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.9, leading=13.0,
                           alignment=TA_JUSTIFY, spaceAfter=3.2, textColor=colors.black),
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=19, leading=22,
                            spaceAfter=2),
    "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=12.4, leading=14.6,
                         spaceBefore=8, spaceAfter=3.5),
    "h3": ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=10.4, leading=12.4,
                         spaceBefore=7.5, spaceAfter=2.5),
    "meta": ParagraphStyle("meta", fontName="Helvetica", fontSize=9.0, leading=12.2,
                           spaceAfter=0.6),
    "mono": ParagraphStyle("mono", fontName="Courier", fontSize=8.1, leading=10.4),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8.3, leading=10.4),
    "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=8.3, leading=10.4),
}


def inline(text: str) -> str:
    """Markdown inline -> reportlab mini-HTML, escaping anything we do not handle."""
    text = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    # _placeholder_ -> italic; placeholders should read as blanks to fill in, not as
    # literal underscores.
    text = re.sub(r"(?<![A-Za-z0-9_])_(?!\s)(.+?)(?<!\s)_(?![A-Za-z0-9_])",
                  r"<i>\1</i>", text)
    text = re.sub(r"(?<!\*)\*(?!\s)(.+?)(?<!\s)\*(?!\*)", r"<i>\1</i>", text)
    text = re.sub(r"`([^`]+)`", r'<font name="Courier" size="8">\1</font>', text)
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r'<link href="\2" color="#0b4f9c">\1</link>', text)
    return text


def parse(markdown: str) -> list:
    """A deliberately small Markdown subset: headings, paragraphs, tables, lists."""
    story: list = []
    lines = markdown.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()

        if not line.strip():
            i += 1
            continue

        if line.startswith('<!-- page break -->') or "page-break" in line:
            story.append(PageBreak())
            i += 1
            continue

        if line.startswith("# "):
            story.append(Paragraph(inline(line[2:]), STYLES["title"]))
            i += 1
            continue
        if line.startswith("## "):
            story.append(Paragraph(inline(line[3:]), STYLES["h2"]))
            i += 1
            continue
        if line.startswith("### "):
            story.append(Paragraph(inline(line[4:]), STYLES["h3"]))
            i += 1
            continue

        # table: header row, separator, body rows
        if line.startswith("|") and i + 1 < len(lines) and set(lines[i + 1]) <= set("|-: "):
            header = [c.strip() for c in line.strip("|").split("|")]
            rows = []
            i += 2
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip("|").split("|")])
                i += 1
            data = [[Paragraph(inline(c), STYLES["cellb"]) for c in header]]
            for row in rows:
                data.append([Paragraph(inline(c), STYLES["cell"])
                             for c in (row + [""] * len(header))[:len(header)]])
            # Prose columns get the room; the Evidence column stays narrow.
            widths = ([46 * mm, 46 * mm, 86 * mm] if len(header) == 3
                      else [(178 * mm) / len(header)] * len(header))
            table = Table(data, colWidths=widths, repeatRows=1)
            table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9aa4ae")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f4")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2.2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2),
            ]))
            story.append(Spacer(1, 2))
            story.append(table)
            story.append(Spacer(1, 3))
            continue

        # Meta line: "**Field:** value" on its own line stays on its own line.
        # Joining these would run Project/Team/Repo/Demo together into one unreadable
        # block at the top of page 1 -- which is what the first build did.
        if re.match(r"^\*\*[^:*]+:\*\*", line) and line.rstrip().endswith(("`", ")", ".")) \
                or re.match(r"^\*\*[A-Z][^:]{2,30}:\*\*", line):
            story.append(Paragraph(inline(line), STYLES["meta"]))
            i += 1
            continue

        if DIAGRAM_MARKER in line:
            story.append(ArchitectureDiagram())
            i += 1
            continue

        # paragraph: gather until a blank line or a block marker
        block = []
        while i < len(lines) and lines[i].strip() and not (
            lines[i].startswith(("#", "|")) or "page-break" in lines[i]
            or DIAGRAM_MARKER in lines[i]
            or re.match(r"^\*\*[A-Z][^:]{2,30}:\*\*", lines[i])
        ):
            block.append(lines[i].strip())
            i += 1
        story.append(Paragraph(inline(" ".join(block)), STYLES["body"]))
    return story


DIAGRAM_MARKER = "<!-- diagram: request path -->"

INK = colors.HexColor("#1b222b")
LINE = colors.HexColor("#7d8894")
FILL = colors.HexColor("#eef2f6")
WARN = colors.HexColor("#fdf1e2")


class ArchitectureDiagram(Flowable):
    """The request path and the state directory, drawn rather than described.

    Deliberately vector and label-only: it stays legible printed in greyscale, and every
    label is a real component name from the repository.

    ``wrap()`` is overridden explicitly. The framework's default returns the class
    attributes, and a Flowable that reports the wrong height does not get its space
    reserved -- the first build of this diagram drew itself over the paragraph above it.
    """

    def __init__(self) -> None:
        super().__init__()
        self.width = 178 * mm
        self.height = 48 * mm

    def wrap(self, availWidth, availHeight):
        return self.width, self.height

    def draw(self) -> None:
        canvas = self.canv
        W = self.width

        def box(x, y, w, h, label, sub=None, fill=FILL, bold=7.2):
            canvas.setFillColor(fill)
            canvas.setStrokeColor(LINE)
            canvas.setLineWidth(0.6)
            canvas.roundRect(x, y, w, h, 2.2, stroke=1, fill=1)
            canvas.setFillColor(INK)
            canvas.setFont("Helvetica-Bold", bold)
            canvas.drawCentredString(x + w / 2, y + h / 2 + (2.2 if sub else -2.4), label)
            if sub:
                canvas.setFont("Helvetica", 6.1)
                canvas.setFillColor(colors.HexColor("#5a636e"))
                canvas.drawCentredString(x + w / 2, y + h / 2 - 5.2, sub)

        def arrow(x1, y, x2):
            canvas.setStrokeColor(LINE)
            canvas.setLineWidth(0.6)
            canvas.line(x1, y, x2, y)
            canvas.setFillColor(LINE)
            path = canvas.beginPath()
            path.moveTo(x2, y)
            path.lineTo(x2 - 3.2, y + 1.8)
            path.lineTo(x2 - 3.2, y - 1.8)
            path.close()
            canvas.drawPath(path, stroke=0, fill=1)

        # --- the request path, left to right, sitting above the state directory
        row_y, row_h = 23 * mm, 15 * mm
        mid = row_y + row_h / 2
        widths = [22 * mm, 24 * mm, 26 * mm, 30 * mm, 26 * mm]
        gap = 4.2 * mm
        labels = [
            ("caller", "untrusted JSON"),
            ("adapter", "closed op set"),
            ("identity", "exact bytes"),
            ("authorize + audit", "one lock"),
            ("AEAD open", "AAD = asset,owner"),
        ]
        x = 0.0
        for index, (label, sub) in enumerate(labels):
            box(x, row_y, widths[index], row_h, label, sub)
            if index < len(labels) - 1:
                arrow(x + widths[index] + 0.9, mid, x + widths[index] + gap - 0.9)
            x += widths[index] + gap

        # outcome: one box, both answers, because a deny must look like an allow
        arrow(x - gap + 0.9, mid, x + 2.4)
        box(x + 3.4, row_y, W - x - 3.4, row_h, "deny  /  allow",
            "silent on failure")

        # --- the state directory, and the one boundary that matters
        dir_y, dir_h = 1.5 * mm, 12.5 * mm
        canvas.setFillColor(colors.HexColor("#f7f9fb"))
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.6)
        canvas.setDash(3, 2)
        canvas.roundRect(0, dir_y, W, dir_h, 2.5, stroke=1, fill=1)
        canvas.setDash()
        canvas.setFillColor(INK)
        canvas.setFont("Helvetica-Bold", 7.0)
        canvas.drawString(4, dir_y + dir_h - 5.6, "state directory — the trust boundary")
        canvas.setFont("Helvetica", 6.3)
        canvas.setFillColor(colors.HexColor("#5a636e"))
        canvas.drawString(4, dir_y + 2.4,
                          "state.json (policy + log anchor)    keyring.json    "
                          "sealed envelopes    audit.jsonl    key-events.jsonl")

        # everything above this line is untrusted; everything below it is trusted
        canvas.setStrokeColor(colors.HexColor("#b9c3cd"))
        canvas.setLineWidth(0.5)
        canvas.setDash(1.2, 2.2)
        canvas.line(0, dir_y + dir_h + 2.6 * mm, W, dir_y + dir_h + 2.6 * mm)
        canvas.setDash()
        canvas.setFont("Helvetica-Oblique", 6.2)
        canvas.setFillColor(colors.HexColor("#5a636e"))
        canvas.drawString(0, dir_y + dir_h + 3.4 * mm,
                          "untrusted: the attacker controls every field")
        canvas.drawRightString(W, dir_y + dir_h + 3.4 * mm,
                               "trusted: its integrity is the whole security property")

        # the operator does not touch request data
        canvas.setFont("Helvetica", 6.3)
        canvas.setFillColor(colors.HexColor("#5a636e"))
        canvas.drawRightString(W, self.height - 3.6 * mm,
                               "operator: rotate · revoke · verify log "
                               "(a separate principal)")


def footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#6b7480"))
    canvas.drawString(MARGIN, 9 * mm,
                      "yugaantar-astra · Trust, but verify · Track 4")
    canvas.drawRightString(A4[0] - MARGIN, 9 * mm, f"{doc.page} of 2")
    canvas.restoreState()


def main() -> int:
    markdown = SOURCE.read_text(encoding="utf-8")

    doc = BaseDocTemplate(
        str(TARGET), pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=14 * mm,
        title="Trust, but verify — yugaantar-astra",
        author="yugaantar-astra", subject="Track 4 submission brief",
    )
    frame = Frame(MARGIN, 14 * mm, A4[0] - 2 * MARGIN, A4[1] - MARGIN - 14 * mm,
                  id="page", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id="two", frames=[frame], onPage=footer)])

    story = parse(markdown)
    doc.build(story)

    # Verify the enforced requirement: exactly two pages.
    from pypdf import PdfReader  # optional; fall back to a byte scan if absent
    try:
        pages = len(PdfReader(str(TARGET)).pages)
    except Exception:
        pages = TARGET.read_bytes().count(b"/Type /Page\n")
    size = TARGET.stat().st_size
    print(f"wrote {TARGET.relative_to(ROOT)}  {size:,} bytes, {pages} page(s)")
    if pages != 2:
        print(f"FAIL: the brief must be exactly two pages, this is {pages}.",
              file=sys.stderr)
        return 1
    print("two-page requirement satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
