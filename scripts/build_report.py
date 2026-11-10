"""Render report/REPORT.md and vector diagrams into the submission PDF.

Optional dependency: pip install -r requirements-docs.txt
"""
from html import escape
import os
from pathlib import Path
import re
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle

ROOT = Path(__file__).resolve().parents[1]
FONT_DIR = Path(os.environ.get('REPORT_FONT_DIR', r'C:/Windows/Fonts'))
REGULAR = FONT_DIR / ('arial.ttf' if (FONT_DIR / 'arial.ttf').exists() else 'DejaVuSans.ttf')
BOLD = FONT_DIR / ('arialbd.ttf' if (FONT_DIR / 'arialbd.ttf').exists() else 'DejaVuSans-Bold.ttf')
pdfmetrics.registerFont(TTFont('Report', str(REGULAR)))
pdfmetrics.registerFont(TTFont('ReportBold', str(BOLD)))
BLUE = colors.HexColor('#233e67')
styles = {
    'body': ParagraphStyle('body', fontName='Report', fontSize=10, leading=15, spaceAfter=9),
    'title': ParagraphStyle('title', fontName='ReportBold', fontSize=19, leading=25, textColor=BLUE, spaceAfter=14),
    'section': ParagraphStyle('section', fontName='ReportBold', fontSize=15, leading=21, textColor=BLUE, spaceAfter=14),
    'cell': ParagraphStyle('cell', fontName='Report', fontSize=8.5, leading=12),
}


def label(drawing, x, y, text, size=9, anchor='middle'):
    drawing.add(String(x, y, text, fontName='Report', fontSize=size, textAnchor=anchor, fillColor=BLUE))


def arrow(drawing, x1, y1, x2, y2, text='', dashed=False):
    line = Line(x1, y1, x2, y2, strokeColor=BLUE, strokeWidth=1)
    if dashed:
        line.strokeDashArray = [3, 3]
    drawing.add(line)
    direction = 1 if x2 > x1 else -1
    drawing.add(Polygon([x2, y2, x2 - 6 * direction, y2 + 3,
                         x2 - 6 * direction, y2 - 3], fillColor=BLUE, strokeColor=BLUE))
    if text:
        label(drawing, (x1 + x2) / 2, (y1 + y2) / 2 + 7, text, size=8)


def architecture():
    drawing = Drawing(490, 210)
    for x, y, width, name, detail in [(0, 145, 100, 'Browser A', 'HTML + JavaScript'),
                                     (155, 145, 130, 'Local bridge A', 'Client / RPC / UDP'),
                                     (0, 30, 100, 'Browser B', 'HTML + JavaScript'),
                                     (155, 30, 130, 'Local bridge B', 'Client / RPC / UDP'),
                                     (355, 87, 135, 'Server', 'Registry / Router')]:
        drawing.add(Rect(x, y, width, 48, fillColor=colors.HexColor('#eef3fa'), strokeColor=BLUE, rx=5))
        label(drawing, x + width / 2, y + 29, name, size=10)
        label(drawing, x + width / 2, y + 12, detail, size=8)
    arrow(drawing, 100, 168, 155, 168, 'HTTP')
    arrow(drawing, 100, 53, 155, 53, 'HTTP')
    arrow(drawing, 285, 164, 355, 122, 'TLS / UDP')
    arrow(drawing, 355, 100, 285, 58, 'TLS / UDP')
    return drawing


def sequence(kind):
    steps = ([('A', 'S', 'STREAM_DATA: chat', False), ('S', 'A', 'ACK chunk', True),
              ('S', 'B', 'Forward chat', False), ('B', 'S', 'ACK chunk', True),
              ('B', 'S', 'Result: accepted', False), ('S', 'A', 'Result: delivered', False)]
             if kind == 'chat' else
             [('A', 'S', 'file_begin + metadata', False), ('S', 'B', 'file_begin / ready', False),
              ('A', 'S', 'file_block(offset)', False), ('S', 'B', 'chunk #2: lost', True),
              ('S', 'B', 'RTO: resend #2', False), ('B', 'S', 'ACK + block result', True),
              ('A', 'S', 'file_end + SHA-256', False), ('S', 'B', 'Verify / publish / result', False),
              ('S', 'A', 'Result: completed', False)])
    height = 40 + 27 * len(steps)
    drawing = Drawing(490, height)
    positions = {'A': 35, 'S': 245, 'B': 455}
    for key, x in positions.items():
        label(drawing, x, height - 12, {'A': 'Client A', 'S': 'Server', 'B': 'Client B'}[key], size=10)
        drawing.add(Line(x, 5, x, height - 20, strokeColor=colors.HexColor('#a9b6c9')))
    for i, (sender, target, text, dashed) in enumerate(steps):
        y = height - 40 - i * 27
        arrow(drawing, positions[sender], y, positions[target], y, text, dashed)
    return drawing


def markup(text):
    return re.sub(r'`([^`]+)`', r'<font name="ReportBold">\1</font>', escape(text))


def footer(canvas, doc):
    canvas.setFont('Report', 8)
    canvas.setFillColor(colors.HexColor('#637083'))
    canvas.drawString(42, 25, 'BTL1-MMT | Backend v2 + Web UI | 10/11/2026')
    canvas.drawRightString(A4[0] - 42, 25, str(doc.page))


def build():
    lines = (ROOT / 'report/REPORT.md').read_text(encoding='utf-8').splitlines()
    story = []
    paragraph = []
    def flush():
        if paragraph:
            story.append(Paragraph(markup(' '.join(paragraph)), styles['body']))
            paragraph.clear()
    i = 0
    section = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith('# '):
            flush()
            story.append(Paragraph(markup(line[2:]), styles['title']))
        elif line.startswith('## '):
            flush()
            if section:
                story.append(PageBreak())
            section += 1
            story.append(Paragraph(markup(line[3:]), styles['section']))
        elif line.startswith('<!-- diagram:'):
            flush()
            kind = line.split(':')[1].split()[0]
            story.append(architecture() if kind == 'architecture' else sequence(kind))
            story.append(Spacer(1, 10))
        elif line.startswith('|'):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith('|'):
                if not re.fullmatch(r'[| :\-]+', lines[i]):
                    rows.append([Paragraph(markup(cell.strip()), styles['cell'])
                                 for cell in lines[i].strip('|').split('|')])
                i += 1
            table = Table(rows, colWidths=[95, 45, A4[0] - 84 - 140], repeatRows=1)
            table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e6edf7')),
                                       ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#b8c5d7')),
                                       ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                                       ('TOPPADDING', (0, 0), (-1, -1), 5),
                                       ('BOTTOMPADDING', (0, 0), (-1, -1), 5)]))
            story.extend([table, Spacer(1, 12)])
            continue
        elif not line.strip():
            flush()
        else:
            paragraph.append(line)
        i += 1
    flush()
    target = ROOT / 'report/Technical_Report.pdf'
    SimpleDocTemplate(str(target), pagesize=A4, rightMargin=42, leftMargin=42,
                      topMargin=38, bottomMargin=42, title='Distributed Streaming Collaboration - Technical Report').build(
                          story, onFirstPage=footer, onLaterPages=footer)
    print(target)


if __name__ == '__main__':
    build()
