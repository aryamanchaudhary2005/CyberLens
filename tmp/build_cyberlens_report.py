from __future__ import annotations

import json
import sys
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_TAB_ALIGNMENT, WD_TAB_LEADER
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "tmp" / "report-work"
OUT = ROOT / "CyberLens_Minor_Project_Report.docx"
PAGE_MAP_PATH = WORK / "page-map.json"
WORK.mkdir(parents=True, exist_ok=True)

NAVY = "#13284B"
BLUE = "#4F73E8"
PALE = "#EFF3FC"
TEAL = "#2A8C9B"
INK = "#20242B"
MUTED = "#596579"
WHITE = "#FFFFFF"
LINE = "#C9D2E3"


def font(size: int, bold: bool = False):
    candidates = [
        Path("C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf"),
        Path("C:/Windows/Fonts/calibrib.ttf" if bold else "C:/Windows/Fonts/calibri.ttf"),
    ]
    for path in candidates:
        if path.exists():
            return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default()


def centered_text(draw, xy, text, fnt, fill=INK, anchor="mm"):
    draw.text(xy, text, font=fnt, fill=fill, anchor=anchor)


def draw_box(draw, box, title, subtitle="", fill=PALE, border=BLUE, title_size=34, body_size=25):
    draw.rounded_rectangle(box, radius=22, fill=fill, outline=border, width=4)
    x1, y1, x2, y2 = box
    compact = (y2 - y1) <= 125
    title_y = y1 + (31 if compact else 52)
    centered_text(draw, ((x1 + x2) // 2, title_y), title, font(title_size, True), NAVY)
    if subtitle:
        lines = subtitle.split("\n")
        if compact:
            start = y1 + 75 - (len(lines) - 1) * 11
            line_step = 25
        else:
            start = (y1 + y2) // 2 + (len(lines) - 1) * 14
            line_step = 34
        for i, line in enumerate(lines):
            centered_text(draw, ((x1 + x2) // 2, start + i * line_step), line, font(body_size), MUTED)


def arrow(draw, start, end, color=TEAL, width=6):
    draw.line([start, end], fill=color, width=width)
    import math
    angle = math.atan2(end[1] - start[1], end[0] - start[0])
    size = 18
    left = (end[0] - size * math.cos(angle - 0.45), end[1] - size * math.sin(angle - 0.45))
    right = (end[0] - size * math.cos(angle + 0.45), end[1] - size * math.sin(angle + 0.45))
    draw.polygon([end, left, right], fill=color)


def make_architecture():
    image = Image.new("RGB", (1800, 1050), WHITE)
    d = ImageDraw.Draw(image)
    draw_box(d, (80, 90, 510, 270), "Analyst browser", "React + TypeScript\nAccessible workspace")
    draw_box(d, (650, 90, 1080, 270), "Caddy gateway", "Local HTTPS\nLoopback only", fill="#F0F4FF")
    draw_box(d, (1220, 90, 1660, 270), "Nginx frontend", "Serves the built\nsingle-page interface")
    arrow(d, (510, 180), (650, 180))
    arrow(d, (1080, 180), (1220, 180))
    draw_box(d, (650, 370, 1080, 550), "FastAPI service", "Authentication, API,\nhealth and reports", fill="#EEF8F8", border=TEAL)
    arrow(d, (865, 270), (865, 370))
    draw_box(d, (130, 700, 530, 880), "PostgreSQL", "Assets, attempts,\nevidence and findings")
    draw_box(d, (700, 700, 1100, 880), "Dispatcher + Redis/RQ", "Outbox delivery and\nbackground job queue", fill="#F0F4FF")
    draw_box(d, (1270, 700, 1670, 880), "Worker + collectors", "Bounded checks against\nconfigured providers", fill="#EEF8F8", border=TEAL)
    arrow(d, (700, 480), (400, 700))
    arrow(d, (860, 550), (900, 700))
    arrow(d, (1100, 790), (1270, 790))
    d.line([(1470, 880), (1470, 930), (330, 930), (330, 880)], fill=BLUE, width=6)
    arrow(d, (330, 930), (330, 880), color=BLUE)
    centered_text(d, (900, 985), "Evidence and investigation results return to PostgreSQL; the browser reads them through the API.", font(25), MUTED)
    image.save(WORK / "fig_architecture.png")


def make_workflow():
    image = Image.new("RGB", (1600, 1120), WHITE)
    d = ImageDraw.Draw(image)
    items = [
        ("1  Register asset", "Type, scope and inventory context"),
        ("2  Submit investigation", "API stores request, attempt and outbox event"),
        ("3  Dispatch job", "Dispatcher publishes a stable RQ job"),
        ("4  Collect evidence", "Worker runs selected bounded collectors"),
        ("5  Save observations", "Evidence, findings and source status are persisted"),
        ("6  Analyst review", "Applicability and case decisions remain human-led"),
        ("7  Report and follow-up", "Snapshots, remediation and comparisons"),
    ]
    y = 55
    for i, (title, detail) in enumerate(items):
        draw_box(d, (210, y, 1390, y + 112), title, detail, fill=PALE if i % 2 == 0 else "#EEF8F8", border=BLUE if i % 2 == 0 else TEAL, title_size=29, body_size=22)
        if i < len(items) - 1:
            arrow(d, (800, y + 112), (800, y + 142))
        y += 150
    image.save(WORK / "fig_workflow.png")


def make_data_model():
    image = Image.new("RGB", (1800, 1100), WHITE)
    d = ImageDraw.Draw(image)
    draw_box(d, (80, 80, 520, 250), "Users and sessions", "Roles, authentication,\naudit actor", fill="#F0F4FF")
    draw_box(d, (680, 80, 1120, 250), "Assets", "Domains, IPs, URLs,\nemails, applications")
    draw_box(d, (1280, 80, 1720, 250), "Investigations", "Attempts, outbox,\ncollector runs")
    draw_box(d, (1280, 390, 1720, 560), "Evidence snapshots", "Source, time, status,\nchecksum")
    draw_box(d, (680, 390, 1120, 560), "Findings and risk", "Applicability, assessments,\nimmutable revisions")
    draw_box(d, (80, 390, 520, 560), "Evidence graph", "Relationships linked to\nevidence records")
    draw_box(d, (80, 760, 520, 930), "Incidents", "Events, tasks and\ncase state")
    draw_box(d, (680, 760, 1120, 930), "Remediation", "Plans, actions and\ncontrol mappings")
    draw_box(d, (1280, 760, 1720, 930), "Reports and audit", "Point-in-time exports,\nappend-only audit chain")
    arrow(d, (520, 165), (680, 165))
    arrow(d, (1120, 165), (1280, 165))
    arrow(d, (1500, 250), (1500, 390))
    arrow(d, (1280, 475), (1120, 475))
    arrow(d, (680, 475), (520, 475))
    arrow(d, (900, 560), (300, 760))
    arrow(d, (900, 560), (900, 760))
    arrow(d, (1120, 845), (1280, 845))
    centered_text(d, (900, 1040), "The evidence graph is a PostgreSQL projection; the application does not require a separate graph database.", font(23), MUTED)
    image.save(WORK / "fig_data_model.png")


def set_cell_shading(cell, fill: str):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill.replace("#", ""))


def set_cell_border(cell, color=LINE, size="6"):
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    borders = tc_pr.first_child_found_in("w:tcBorders")
    if borders is None:
        borders = OxmlElement("w:tcBorders")
        tc_pr.append(borders)
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        tag = "w:" + edge
        element = borders.find(qn(tag))
        if element is None:
            element = OxmlElement(tag)
            borders.append(element)
        element.set(qn("w:val"), "single")
        element.set(qn("w:sz"), size)
        element.set(qn("w:color"), color.replace("#", ""))


def set_repeat_table_header(row):
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


def prevent_table_row_split(row):
    tr_pr = row._tr.get_or_add_trPr()
    cant_split = OxmlElement("w:cantSplit")
    tr_pr.append(cant_split)


def set_run_font(run, name="Times New Roman", size=12, bold=None, italic=None, color=INK):
    run.font.name = name
    run._element.get_or_add_rPr().rFonts.set(qn("w:ascii"), name)
    run._element.get_or_add_rPr().rFonts.set(qn("w:hAnsi"), name)
    run.font.size = Pt(size)
    run.font.color.rgb = RGBColor.from_string(color.replace("#", ""))
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic


def set_paragraph_spacing(p, before=0, after=6, line=1.5):
    p.paragraph_format.space_before = Pt(before)
    p.paragraph_format.space_after = Pt(after)
    p.paragraph_format.line_spacing = line


def add_page_field(paragraph):
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = paragraph.add_run()
    set_run_font(run, size=9, color=MUTED)
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = " PAGE "
    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    text = OxmlElement("w:t")
    text.text = "1"
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.extend([begin, instr, separate, text, end])


def set_page_number_format(section, fmt, start=1):
    pg = section._sectPr.find(qn("w:pgNumType"))
    if pg is None:
        pg = OxmlElement("w:pgNumType")
        section._sectPr.append(pg)
    pg.set(qn("w:fmt"), fmt)
    pg.set(qn("w:start"), str(start))


def configure_document(doc):
    for section in doc.sections:
        section.page_width = Inches(8.27)
        section.page_height = Inches(11.69)
        section.left_margin = Inches(1.15)
        section.right_margin = Inches(1.0)
        section.top_margin = Inches(0.9)
        section.bottom_margin = Inches(0.85)
        section.footer_distance = Inches(0.4)
    normal = doc.styles["Normal"]
    normal.font.name = "Times New Roman"
    normal._element.rPr.rFonts.set(qn("w:ascii"), "Times New Roman")
    normal._element.rPr.rFonts.set(qn("w:hAnsi"), "Times New Roman")
    normal.font.size = Pt(12)
    normal.font.color.rgb = RGBColor.from_string(INK.replace("#", ""))
    normal.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    normal.paragraph_format.line_spacing = 1.5
    normal.paragraph_format.space_after = Pt(7)
    normal.paragraph_format.first_line_indent = Inches(0.28)
    title = doc.styles["Title"]
    title.font.name = "Times New Roman"
    title._element.rPr.rFonts.set(qn("w:ascii"), "Times New Roman")
    title._element.rPr.rFonts.set(qn("w:hAnsi"), "Times New Roman")
    title.font.size = Pt(22)
    title.font.bold = True
    title.font.color.rgb = RGBColor.from_string(NAVY.replace("#", ""))
    title.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.paragraph_format.space_after = Pt(10)
    for name, size, color in (("Heading 1", 16, NAVY), ("Heading 2", 13, INK), ("Heading 3", 12, MUTED)):
        style = doc.styles[name]
        style.font.name = "Times New Roman"
        style._element.rPr.rFonts.set(qn("w:ascii"), "Times New Roman")
        style._element.rPr.rFonts.set(qn("w:hAnsi"), "Times New Roman")
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor.from_string(color.replace("#", ""))
        style.paragraph_format.keep_with_next = True
        style.paragraph_format.space_before = Pt(10 if name != "Heading 1" else 0)
        style.paragraph_format.space_after = Pt(6)
        style.paragraph_format.line_spacing = 1.15


def format_footer(section):
    section.footer.is_linked_to_previous = False
    p = section.footer.paragraphs[0]
    p.clear()
    add_page_field(p)


def add_body_paragraph(doc, text, indent=True, keep=False):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.first_line_indent = Inches(0.28) if indent else Inches(0)
    p.paragraph_format.keep_together = keep
    set_paragraph_spacing(p, after=7, line=1.5)
    r = p.add_run(text)
    set_run_font(r)
    return p


def add_bullet(doc, text):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.left_indent = Inches(0.32)
    p.paragraph_format.first_line_indent = Inches(-0.18)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.25
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    set_run_font(p.add_run(text), size=11.5)
    return p


def add_numbered(doc, text):
    p = doc.add_paragraph(style="List Number")
    p.paragraph_format.left_indent = Inches(0.34)
    p.paragraph_format.first_line_indent = Inches(-0.20)
    p.paragraph_format.space_after = Pt(5)
    p.paragraph_format.line_spacing = 1.3
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    set_run_font(p.add_run(text), size=11.5)
    return p


def add_section(doc, heading, paragraphs, level=2):
    p = doc.add_paragraph(style=f"Heading {level}")
    p.paragraph_format.keep_with_next = True
    set_run_font(p.add_run(heading), size={1: 16, 2: 13, 3: 12}[level], bold=True,
                 color={1: NAVY, 2: INK, 3: MUTED}[level])
    for text in paragraphs:
        add_body_paragraph(doc, text)


def add_table(doc, headers, rows, widths=None, font_size=9.5):
    table = doc.add_table(rows=1, cols=len(headers))
    table.autofit = False
    table.style = "Table Grid"
    if widths:
        for cell, width in zip(table.rows[0].cells, widths):
            cell.width = Inches(width)
    for j, text in enumerate(headers):
        cell = table.rows[0].cells[j]
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        set_cell_shading(cell, NAVY)
        set_cell_border(cell, color=NAVY)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.line_spacing = 1.0
        set_run_font(p.add_run(str(text)), size=font_size, bold=True, color=WHITE)
    set_repeat_table_header(table.rows[0])
    prevent_table_row_split(table.rows[0])
    for i, row in enumerate(rows):
        table_row = table.add_row()
        prevent_table_row_split(table_row)
        cells = table_row.cells
        for j, text in enumerate(row):
            cell = cells[j]
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            if widths:
                cell.width = Inches(widths[j])
            if i % 2 == 1:
                set_cell_shading(cell, "#F6F8FC")
            set_cell_border(cell)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.space_before = Pt(3)
            p.paragraph_format.line_spacing = 1.05
            p.paragraph_format.first_line_indent = Inches(0)
            set_run_font(p.add_run(str(text)), size=font_size, color=INK)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return table


def add_caption(doc, text):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(7)
    set_run_font(p.add_run(text), size=10, italic=True, color=MUTED)
    return p


def add_figure(doc, path, width, caption):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(2)
    p.add_run().add_picture(str(path), width=Inches(width))
    add_caption(doc, caption)


def add_chapter(doc, number, title):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.keep_with_next = True
    set_run_font(p.add_run(f"CHAPTER {number}"), size=15, bold=True, color=NAVY)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(22)
    p.paragraph_format.keep_with_next = True
    set_run_font(p.add_run(title.upper()), size=15, bold=True, color=INK)


def add_front_title(doc, title):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(20)
    p.paragraph_format.keep_with_next = True
    set_run_font(p.add_run(title.upper()), size=15, bold=True, color=NAVY)


def add_toc_line(doc, key, label, level=0):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.28 if level else 0)
    p.paragraph_format.first_line_indent = Inches(0)
    p.paragraph_format.space_after = Pt(3 if level else 5)
    p.paragraph_format.line_spacing = 1.05
    p.paragraph_format.tab_stops.add_tab_stop(Inches(6.0), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS)
    r = p.add_run(f"@@TOC|{key}|{label}@@\t")
    set_run_font(r, size=10.5 if level else 11, bold=(level == 0), color=INK)
    r = p.add_run("??")
    set_run_font(r, size=10.5 if level else 11, bold=(level == 0), color=INK)


def add_list_line(doc, key, label):
    p = doc.add_paragraph()
    p.paragraph_format.first_line_indent = Inches(0)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.0
    p.paragraph_format.tab_stops.add_tab_stop(Inches(6.0), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS)
    set_run_font(p.add_run(f"@@LIST|{key}|{label}@@\t"), size=10.5, color=INK)
    set_run_font(p.add_run("??"), size=10.5, color=INK)


def add_toc_body(doc):
    add_front_title(doc, "Table of Contents")
    entries = [
        ("abstract", "ABSTRACT", 0),
        ("abbreviations", "ABBREVIATIONS", 0),
        ("ch1", "CHAPTER 1  INTRODUCTION", 0),
        ("1.1", "1.1  Background", 1),
        ("1.2", "1.2  Problem Statement", 1),
        ("1.3", "1.3  Aim and Objectives", 1),
        ("1.4", "1.4  Scope and Boundaries", 1),
        ("1.5", "1.5  Project Contributions", 1),
        ("ch2", "CHAPTER 2  TECHNICAL BACKGROUND AND RELATED WORK", 0),
        ("2.1", "2.1  Cyber Threat Intelligence and Asset Context", 1),
        ("2.2", "2.2  Vulnerability Sources and Prioritization Signals", 1),
        ("2.3", "2.3  ATT&CK and Structured Threat Knowledge", 1),
        ("2.4", "2.4  Background Processing and Evidence", 1),
        ("2.5", "2.5  Design Opportunity", 1),
        ("ch3", "CHAPTER 3  REQUIREMENTS AND SYSTEM DESIGN", 0),
        ("3.1", "3.1  Requirements", 1),
        ("3.2", "3.2  Architecture", 1),
        ("3.3", "3.3  Investigation Workflow", 1),
        ("3.4", "3.4  Data Model", 1),
        ("3.5", "3.5  Risk Assessment Method", 1),
        ("3.6", "3.6  Security and Privacy Design", 1),
        ("3.7", "3.7  Operating Modes", 1),
        ("ch4", "CHAPTER 4  IMPLEMENTATION AND EVALUATION", 0),
        ("4.1", "4.1  Technology Stack", 1),
        ("4.2", "4.2  Core Modules", 1),
        ("4.3", "4.3  Durable Investigation Orchestration", 1),
        ("4.4", "4.4  Evidence, Findings and Change Radar", 1),
        ("4.5", "4.5  Case Management and Reports", 1),
        ("4.6", "4.6  Verification and Observed Results", 1),
        ("4.7", "4.7  Limitations", 1),
        ("ch5", "CHAPTER 5  CONCLUSION AND FUTURE WORK", 0),
        ("5.1", "5.1  Conclusion", 1),
        ("5.2", "5.2  Future Work", 1),
        ("references", "REFERENCES", 0),
        ("appendixa", "APPENDIX A  API RESOURCE SUMMARY", 0),
        ("appendixb", "APPENDIX B  LOCAL RUN AND SHOWCASE NOTES", 0),
    ]
    for key, label, level in entries:
        add_toc_line(doc, key, label, level)


def set_page_map():
    if not PAGE_MAP_PATH.exists():
        return {}
    try:
        return json.loads(PAGE_MAP_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def fill_markers(doc, page_map):
    for p in doc.paragraphs:
        text = p.text
        if text.startswith("@@TOC|") or text.startswith("@@LIST|"):
            marker = text.split("\t", 1)[0]
            parts = marker[2:-2].split("|", 2) if marker.endswith("@@") else []
            if len(parts) == 3:
                _, key, label = parts
                number = str(page_map.get(key, ""))
                p.clear()
                p.paragraph_format.left_indent = Inches(0.28 if key[:1].isdigit() and key[1:2] == "." else 0)
                p.paragraph_format.first_line_indent = Inches(0)
                p.paragraph_format.tab_stops.add_tab_stop(Inches(6.0), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS)
                p.paragraph_format.space_after = Pt(3 if key[:1].isdigit() and key[1:2] == "." else 5)
                p.paragraph_format.line_spacing = 1.05
                is_major = key in {"abstract", "abbreviations", "ch1", "ch2", "ch3", "ch4", "ch5", "references", "appendixa", "appendixb"}
                set_run_font(p.add_run(label + "\t"), size=10.5 if not is_major else 11, bold=is_major, color=INK)
                set_run_font(p.add_run(number if number else " "), size=10.5 if not is_major else 11, bold=is_major, color=INK)
    return doc


def build():
    make_architecture()
    make_workflow()
    make_data_model()
    doc = Document()
    configure_document(doc)
    doc.core_properties.title = "CyberLens Minor Project Report"
    doc.core_properties.subject = "Cyber threat intelligence and incident response workspace"
    doc.core_properties.author = "[Student Name]"
    doc.core_properties.keywords = "CyberLens, cyber threat intelligence, incident response, FastAPI, React"
    front = doc.sections[0]
    set_page_number_format(front, "lowerRoman", 1)
    format_footer(front)

    logo = ROOT / "frontend" / "public" / "brand" / "cyberlens-180.png"
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(20)
    p.add_run().add_picture(str(logo), width=Inches(0.82))
    p = doc.add_paragraph(style="Title")
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(8)
    p.add_run("CyberLens")
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(22)
    set_run_font(p.add_run("A Local Cyber Threat Intelligence and Incident Response Workspace"), size=17, bold=True, color=INK)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(22)
    set_run_font(p.add_run("MINOR PROJECT REPORT"), size=14, bold=True, color=NAVY)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(6)
    set_run_font(p.add_run("Submitted by"), size=12, italic=True)
    for line in ("[Student Name]", "[Register Number]"):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after = Pt(3)
        set_run_font(p.add_run(line), size=12, bold=True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(16)
    p.paragraph_format.space_after = Pt(5)
    set_run_font(p.add_run("Under the guidance of"), size=12, italic=True)
    for line in ("[Supervisor Name]", "[Designation]"):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after = Pt(3)
        set_run_font(p.add_run(line), size=12)
    for line in (
        "in partial fulfillment of the requirements for the degree of",
        "[Degree Program]",
        "[Department Name]",
        "[College or Institute Name]",
        "[City, State]",
        "[Month Year]",
    ):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(8 if line.startswith("in partial") else 0)
        p.paragraph_format.space_after = Pt(3)
        set_run_font(p.add_run(line), size=12, bold=line.startswith("[Degree") or line.startswith("[Department"))

    doc.add_page_break()
    add_front_title(doc, "Declaration")
    add_body_paragraph(doc, "I hereby declare that this minor project report entitled “CyberLens: A Local Cyber Threat Intelligence and Incident Response Workspace” describes the project work submitted by me in partial fulfillment of the requirements for [Degree Program] at [College or Institute Name]. The implementation and written report are presented for academic evaluation. Any external standards, provider documentation, and software documentation used to explain the design are cited in the references.", indent=False)
    add_body_paragraph(doc, "I understand that the institution’s own declaration and originality requirements take precedence. I will review this report, replace the editable student and institution details, verify the implementation claims against my final project build, and sign this statement only if it is accurate.", indent=False)
    doc.add_paragraph()
    doc.add_paragraph()
    add_table(doc, ["Student Details", "To be completed"], [
        ("Name", "[Student Name]"),
        ("Register number", "[Register Number]"),
        ("Signature", "________________________________"),
        ("Date", "________________________________"),
    ], widths=[2.3, 4.2], font_size=10.5)

    doc.add_page_break()
    add_front_title(doc, "Bonafide Certificate")
    add_body_paragraph(doc, "This is to certify that the project report entitled “CyberLens: A Local Cyber Threat Intelligence and Incident Response Workspace” is submitted by [Student Name], [Register Number], in partial fulfillment of the requirements for [Degree Program] at [College or Institute Name]. The project work was carried out under the guidance of [Supervisor Name], [Designation], [Department Name].", indent=False)
    add_body_paragraph(doc, "The final wording, institutional seal, signatures, and date must be completed by the authorized supervisor and department in accordance with the institution’s report format.", indent=False)
    doc.add_paragraph()
    doc.add_paragraph()
    add_table(doc, ["Role", "Name and signature", "Date"], [
        ("Project supervisor", "[Supervisor Name]  __________________", "____________"),
        ("Head of department", "[HOD Name]  ______________________", "____________"),
        ("External examiner", "______________________________", "____________"),
    ], widths=[1.6, 3.6, 1.2], font_size=9.5)

    doc.add_page_break()
    add_front_title(doc, "Acknowledgements")
    add_body_paragraph(doc, "I express my sincere gratitude to [Supervisor Name] for guidance, feedback, and support during the development of CyberLens. The discussions helped shape the project scope and kept the implementation focused on evidence review, analyst decisions, and safe investigation workflows.")
    add_body_paragraph(doc, "I thank the faculty and staff of [Department Name], [College or Institute Name], for providing the academic environment and resources required to complete this project. I also acknowledge the maintainers of the open-source software and public cybersecurity data sources cited in this report.")
    add_body_paragraph(doc, "Finally, I thank my family and peers for their encouragement throughout the project.")
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    p.paragraph_format.space_before = Pt(30)
    set_run_font(p.add_run("[Student Name]"), size=12, bold=True)

    doc.add_page_break()
    add_front_title(doc, "Abstract")
    abstract = (
        "CyberLens is a browser-based workspace for organizing cyber threat intelligence, security observations, and incident-response records for assets that an analyst is authorized to assess. It combines an inventory of domains, IP addresses, URLs, email addresses, applications, and software components with background investigations that collect selected evidence from configured sources. Each investigation records collector status, observation time, source provenance, and evidence checksums. Vulnerability matches remain review candidates until an analyst evaluates applicability, while a documented academic prioritization method explains which reviewed evidence contributes to risk."
    )
    add_body_paragraph(doc, abstract)
    add_body_paragraph(doc, "The application uses a React and TypeScript interface, a FastAPI service, PostgreSQL for durable records, Redis with RQ for background processing, a separate dispatcher for reliable queue delivery, and Docker Compose for local operation. Analysts can review evidence relationships, compare investigation history, create incident cases, track remediation plans, and export PDF or JSON report snapshots. Security controls include role-based access, cookie-backed sessions, CSRF checks, password hashing, shared login throttling, scoped authorization records, bounded outbound requests, and backend-only provider credentials.")
    add_body_paragraph(doc, "CyberLens has a separate offline Demo mode that uses synthetic fixtures. The normal Live mode can use real provider data when the required configuration, access, and authorization are available. The project is designed as a local single-workspace showcase and does not perform exploitation, network-wide scanning, automatic containment, or automatic remediation. The risk score is an explainable academic prioritization aid and has not been calibrated against incident outcomes.")
    p = doc.add_paragraph()
    p.paragraph_format.first_line_indent = Inches(0)
    set_run_font(p.add_run("Keywords: "), size=11, bold=True, color=NAVY)
    set_run_font(p.add_run("cyber threat intelligence, incident response, evidence provenance, vulnerability applicability, risk prioritization, background jobs"), size=11)

    doc.add_page_break()
    add_toc_body(doc)
    doc.add_page_break()
    add_front_title(doc, "List of Figures")
    for key, label in [
        ("fig31", "Fig. 3.1  CyberLens service architecture"),
        ("fig32", "Fig. 3.2  Investigation processing and analyst review workflow"),
        ("fig33", "Fig. 3.3  Core data relationships"),
    ]:
        add_list_line(doc, key, label)

    doc.add_page_break()
    add_front_title(doc, "List of Tables")
    for key, label in [
        ("tab31", "Table 3.1  Functional requirements"),
        ("tab32", "Table 3.2  Non-functional requirements"),
        ("tab33", "Table 3.3  Core data entities"),
        ("tab41", "Table 4.1  Technology stack"),
        ("tab42", "Table 4.2  Selected evidence sources and interpretation"),
        ("tab43", "Table 4.3  Documented verification evidence"),
        ("tab44", "Table 4.4  Limitations and proposed extensions"),
    ]:
        add_list_line(doc, key, label)

    doc.add_page_break()
    add_front_title(doc, "Abbreviations")
    add_table(doc, ["Abbreviation", "Meaning"], [
        ("API", "Application Programming Interface"),
        ("ATT&CK", "Adversarial Tactics, Techniques, and Common Knowledge"),
        ("CISA", "Cybersecurity and Infrastructure Security Agency"),
        ("CPE", "Common Platform Enumeration"),
        ("CVE", "Common Vulnerabilities and Exposures"),
        ("CVSS", "Common Vulnerability Scoring System"),
        ("CSRF", "Cross-Site Request Forgery"),
        ("CTI", "Cyber Threat Intelligence"),
        ("DNS", "Domain Name System"),
        ("EPSS", "Exploit Prediction Scoring System"),
        ("HIBP", "Have I Been Pwned"),
        ("HTTP(S)", "Hypertext Transfer Protocol (Secure)"),
        ("JSON", "JavaScript Object Notation"),
        ("KEV", "Known Exploited Vulnerabilities"),
        ("NVD", "National Vulnerability Database"),
        ("OSV", "Open Source Vulnerabilities"),
        ("RQ", "Redis Queue"),
        ("SSRF", "Server-Side Request Forgery"),
        ("STIX", "Structured Threat Information Expression"),
        ("TLS", "Transport Layer Security"),
    ], widths=[1.45, 5.05], font_size=10)

    body = doc.add_section(WD_SECTION.NEW_PAGE)
    body.page_width = Inches(8.27)
    body.page_height = Inches(11.69)
    body.left_margin = Inches(1.15)
    body.right_margin = Inches(1.0)
    body.top_margin = Inches(0.9)
    body.bottom_margin = Inches(0.85)
    body.footer_distance = Inches(0.4)
    set_page_number_format(body, "decimal", 1)
    format_footer(body)
    page_map = set_page_map()
    fill_markers(doc, page_map)

    add_chapter(doc, 1, "Introduction")
    add_section(doc, "1.1 Background", [
        "Organizations use public vulnerability databases, threat feeds, asset inventories, and incident records to understand security exposure. The information is distributed across providers and differs in scope, freshness, and confidence. A CVE record can describe a product weakness without proving that the affected version is installed. A threat-feed match can be stale or incomplete. A historical email-breach record does not establish current account compromise. Analysts therefore need a workspace that preserves what each source observed and makes uncertainty visible.",
        "CyberLens brings asset context, selected source observations, evidence, findings, and response records into one local browser application. The system uses asynchronous investigations so the web request can return while the worker performs provider checks. The analyst reviews the stored results and determines how they apply to the organization."
    ])
    add_section(doc, "1.2 Problem Statement", [
        "Security information often arrives as separate API responses, spreadsheets, and incident notes. When these records are not connected to the asset and the observation that produced them, analysts can lose source provenance, repeat work, or overstate what a result means. A vulnerability candidate may be treated as present without checking the installed version. A provider outage may be mistaken for an absence of risk. Risk scores can also appear authoritative even when the scoring method is not calibrated against real incident outcomes.",
        "The project addresses the need for a single analyst workflow that records authorized assets, runs bounded investigations, preserves source status and evidence, separates candidate detection from applicability decisions, and supports case tracking and report generation without automating disruptive response actions."
    ])
    add_section(doc, "1.3 Aim and Objectives", [
        "The aim of CyberLens is to provide a local workspace that helps analysts collect, review, and document security evidence for authorized assets."
    ])
    for item in [
        "Provide inventory records for domains, IP addresses, URLs, email addresses, applications, and software components.",
        "Run selected Live-mode collectors as background work and record success, partial coverage, failure, freshness, and provenance.",
        "Preserve evidence snapshots and connect findings and relationships to their supporting evidence.",
        "Require analyst review of vulnerability applicability before candidate findings affect vulnerability risk.",
        "Explain the project’s academic prioritization score and preserve changes as assessment revisions.",
        "Support incidents, response tasks, remediation plans, control mappings, monitoring history, and saved PDF or JSON reports.",
        "Use role-based authorization, CSRF protection, session management, audit records, and bounded outbound networking.",
        "Provide an isolated offline Demo mode for repeatable workflows without real provider requests."
    ]:
        add_bullet(doc, item)
    add_section(doc, "1.4 Scope and Boundaries", [
        "CyberLens supports analyst-led assessment and incident documentation. Depending on configuration and provider access, collectors can use DNS and RDAP context, bounded website and TLS observations, existing VirusTotal reports, explicit email-breach lookups, vulnerability information from NVD and OSV, CISA KEV and FIRST EPSS context, and locally matched threat-feed snapshots. Optional community sources have separate consent or permitted-use restrictions. The Integrations view reports source status; a configured API key does not guarantee quota, availability, or a useful result.",
        "The system does not exploit vulnerabilities, guess passwords, scan arbitrary network ranges, automatically block traffic, disable accounts, remediate software, or send external incident notifications. Website checks are bounded and require a current authorization record. Live mode is a local single-workspace operation profile, not a public internet production deployment."
    ])
    add_section(doc, "1.5 Project Contributions", [
        "The project combines provider observations with a durable evidence model and analyst workflow. Its main contribution is the connection between each finding or relationship and the saved evidence that supports it. Collector failure and missing coverage are represented explicitly so the interface can distinguish unknown from no match.",
        "A transactional outbox and separate dispatcher reduce the chance that an investigation is saved in PostgreSQL but never delivered to the worker queue. Stable job identifiers make repeated delivery idempotent. The workflow also keeps technical evidence separate from analyst decisions, response tasks, remediation plans, and immutable report snapshots."
    ])
    add_section(doc, "1.6 Organization of the Report", [
        "Chapter 1 introduces the project and its scope. Chapter 2 describes the technical background and source models. Chapter 3 presents requirements, architecture, data relationships, risk methodology, and security design. Chapter 4 explains the implementation and documented verification evidence. Chapter 5 concludes the report and identifies future work."
    ])

    doc.add_page_break()
    add_chapter(doc, 2, "Technical Background and Related Work")
    add_section(doc, "2.1 Cyber Threat Intelligence and Asset Context", [
        "Cyber threat intelligence (CTI) is useful when an observation can be connected to a specific asset and interpreted with its source, time, and limitations. CyberLens treats provider data as evidence to review, rather than as a command to act. A finding retains its source attribution and observation context. The system’s evidence graph projects stored relationships from PostgreSQL records and links each edge to the evidence snapshot that supports it.",
        "Asset context matters because a provider match alone does not determine organizational impact. The same CVE may be irrelevant to an asset that does not run the affected component, while a lower-severity observation may matter for a critical exposed service. CyberLens records inventory attributes and analyst applicability decisions to keep these questions visible."
    ])
    add_section(doc, "2.2 Vulnerability Sources and Prioritization Signals", [
        "The National Vulnerability Database (NVD) provides machine-readable vulnerability and product data through its API. CyberLens uses CPE and CVE information to surface candidate matches for inventoried software. Product-name and version matching can be ambiguous, so a returned candidate remains in a review state until an analyst decides whether it applies [7].",
        "CISA’s Known Exploited Vulnerabilities catalog identifies vulnerabilities that CISA lists as known exploited [8]. FIRST EPSS provides a separate estimate of exploitation probability over the next 30 days [9]. These signals answer different questions: CVSS describes technical severity, KEV indicates catalog membership, and EPSS estimates observed exploitation likelihood at a population level. CyberLens stores and displays these concepts separately; none proves that a specific asset has been compromised.",
        "For package-level analysis, CyberLens can query OSV for an explicitly inventoried npm or PyPI package and version. It does not upload a software bill of materials or discover dependencies automatically. A package advisory is a candidate, and aliases are retained for provenance while duplicate scoring against an NVD CVE is avoided."
    ])
    add_section(doc, "2.3 ATT&CK and Structured Threat Knowledge", [
        "MITRE ATT&CK organizes adversary tactics and techniques based on observed behavior. CyberLens stores a locally versioned Enterprise subset and supports an administrator-queued synchronization of official STIX 2.1 data outside Demo mode [10]. A technique suggestion is contextual and requires analyst review. It does not establish that an attacker used the technique.",
        "Versioned catalog snapshots help preserve the meaning of existing mappings when the upstream knowledge base changes. A mapping keeps its catalog version and saved technique text. Existing reports are snapshots and are not silently rewritten when a newer catalog is activated."
    ])
    add_section(doc, "2.4 Background Processing and Evidence", [
        "Provider requests can be slow, rate-limited, or temporarily unavailable. A background queue separates the user-facing API from the work performed by collectors. RQ represents Python functions as jobs executed by worker processes using Redis [4, 5]. CyberLens adds a PostgreSQL outbox and dispatcher around this queue so the accepted investigation and its delivery event are recorded together.",
        "Evidence provenance includes the source, provider or version where available, observation time, freshness, status, schema version, and a checksum. Hashes help detect changes to stored bytes. They do not independently prove collection authenticity or establish forensic chain of custody."
    ])
    add_section(doc, "2.5 Design Opportunity", [
        "The design opportunity is to make the analyst workflow as important as the external lookup. CyberLens joins source collection to inventory, evidence, applicability review, prioritization, incident management, remediation tracking, and report snapshots. This approach is intended to reduce context switching and preserve uncertainty. It does not replace the source providers, a dedicated vulnerability scanner, a SIEM, or a calibrated enterprise risk model."
    ])

    doc.add_page_break()
    add_chapter(doc, 3, "Requirements and System Design")
    add_section(doc, "3.1 Requirements", [
        "The system requirements focus on a local, authenticated analyst workspace with durable records and controlled provider interaction. Functional requirements describe what the workspace supports; non-functional requirements describe the reliability, safety, and usability expected from those workflows."
    ])
    add_caption(doc, "Table 3.1. Functional requirements")
    add_table(doc, ["ID", "Requirement", "Expected behavior"], [
        ("FR-01", "Asset inventory", "Create and maintain scoped domain, IP, URL, email, application, and component records."),
        ("FR-02", "Investigation", "Queue an investigation and show its attempts, collectors, evidence, and findings."),
        ("FR-03", "Analyst review", "Record applicability decisions with a reason and preserve review history."),
        ("FR-04", "Incident response", "Create cases, events, playbook tasks, remediation actions, and control mappings."),
        ("FR-05", "Reporting", "Save immutable PDF or JSON snapshots from current workspace records."),
        ("FR-06", "Monitoring", "Schedule authorized website checks and compare saved investigation history."),
        ("FR-07", "Administration", "Manage roles and inspect audit, integrity, provider, and health status."),
    ], widths=[0.62, 1.52, 4.68], font_size=9)
    add_caption(doc, "Table 3.2. Non-functional requirements")
    add_table(doc, ["Area", "Requirement"], [
        ("Security", "Protect credentials, enforce role checks and CSRF validation, and restrict outbound network requests."),
        ("Reliability", "Persist investigation delivery events, use stable job identifiers, and separate attempts from the parent investigation."),
        ("Traceability", "Attach evidence, source status, observation time, and immutable report snapshots to analyst decisions."),
        ("Usability", "Present unavailable, stale, unassessed, no-match, and synthetic states distinctly."),
        ("Portability", "Run the application components together using Docker Compose on a local machine."),
        ("Privacy", "Keep provider secrets on the backend and require explicit, scoped authorization for protected lookups."),
    ], widths=[1.3, 5.52], font_size=9.2)
    add_section(doc, "3.2 Architecture", [
        "The browser serves as the analyst interface. Caddy terminates local HTTPS and routes requests to the static frontend and API. The FastAPI service validates requests and persists operational records to PostgreSQL. When an investigation is accepted, the API also records an outbox event in the same transaction. The dispatcher publishes pending events to RQ in Redis, and a worker executes collectors and persists the results."
    ])
    add_figure(doc, WORK / "fig_architecture.png", 6.55, "Fig. 3.1. CyberLens service architecture.")
    add_body_paragraph(doc, "PostgreSQL is the durable source of truth for assets, investigations, evidence, findings, risk revisions, incidents, remediation, reports, and audit records. Redis is used for job delivery and shared short-lived state such as throttling and worker heartbeat. The evidence graph is a projection of the stored relational records; the application does not depend on a separate graph database.", indent=False)
    add_section(doc, "3.3 Investigation Workflow", [
        "The workflow begins when an authenticated Analyst or Admin submits an investigation for an asset in scope. The API stores the investigation, its first attempt, and a delivery event transactionally. The dispatcher publishes a stable job identifier to the Redis-backed RQ queue. A worker claims the attempt, checks its lease and any required authorization, executes the selected collectors, then saves collector status, evidence snapshots, findings, and risk assessment revisions. The frontend reads the persisted state and updates the investigation view."
    ])
    add_figure(doc, WORK / "fig_workflow.png", 6.45, "Fig. 3.2. Investigation processing and analyst review workflow.")
    add_body_paragraph(doc, "A transient provider failure can receive a limited automatic retry. Each retry is a distinct attempt so the record shows what happened on each execution. Stable job identifiers make delivery idempotent; a reconciler can recover old queued or stale work. A failed collector produces unknown coverage rather than evidence that the asset is safe.", indent=False)
    add_section(doc, "3.4 Data Model", [
        "The schema uses relational entities with explicit identifiers and foreign keys. Users and sessions represent authenticated access. Assets define the scope of investigations. An investigation has attempts and collector runs; each collector run can create evidence snapshots and findings. Risk assessments preserve a current projection, while risk revision records retain the earlier score explanations. Incidents link findings and response events. Remediation plans, actions, and control mappings track analyst work. Reports store point-in-time content. Audit events record important changes."
    ])
    add_caption(doc, "Table 3.3. Core data entities")
    add_table(doc, ["Entity group", "Purpose"], [
        ("Users, sessions, audit", "Identity, roles, session lifecycle, and append-only activity history."),
        ("Assets and authorizations", "Inventory context and time-limited permission for website or email checks."),
        ("Investigations and attempts", "Parent work item, retries, transactional outbox delivery, and collector execution."),
        ("Evidence and relationships", "Source-backed snapshots, hashes, typed graph edges, observation time, and coverage."),
        ("Findings and risk revisions", "Reviewable candidates, applicability, score inputs, and historical explanations."),
        ("Incidents and remediation", "Cases, timeline events, playbook tasks, plans, actions, and control mappings."),
        ("Reports and catalogs", "Saved report snapshots, versioned ATT&CK data, and feed snapshots."),
    ], widths=[2.1, 4.72], font_size=9)
    add_figure(doc, WORK / "fig_data_model.png", 6.55, "Fig. 3.3. Core data relationships.")
    add_section(doc, "3.5 Risk Assessment Method", [
        "CyberLens uses the documented policy named cyberlens-academic-1.0 to produce a deterministic prioritization score from assessed evidence categories. It records the observations, category coverage, exclusions, applicability decisions, and score revision so an analyst can inspect why a value changed. Unavailable or missing sources reduce coverage and are not silently converted into evidence of safety.",
        "A vulnerability candidate begins as needs_review. Only an analyst decision that it applies contributes to vulnerability risk. The project also treats an applicable KEV item with a severity floor when required by the policy. EPSS is stored separately and does not affect this score. The score is an academic prioritization method and has not been calibrated using a labeled set of incident outcomes."
    ])
    add_section(doc, "3.6 Security and Privacy Design", [
        "The workspace uses role-based authorization for Admin, Analyst, and Viewer roles. Passwords are stored as Argon2 hashes. Session cookies are protected with HTTP-only settings, CSRF tokens are required for state-changing requests, and Redis provides shared login throttling. Administrative password resets revoke the target user’s active sessions and require a password change at next sign-in.",
        "Provider keys stay on the backend. Authenticated provider requests are restricted to the provider’s intended origin. Outbound HTTP requests use fixed or validated destinations, public-address checks, DNS pinning, redirect validation, byte limits, and request deadlines to reduce server-side request forgery exposure [12]. Website inspections require active authorization and are bounded observations; they do not exploit or enumerate a target.",
        "The application records evidence checksums and an append-only audit hash chain. These controls help detect later changes to stored content. They do not prove who collected evidence or establish a complete forensic chain of custody. New passwords in Live mode are screened using the keyless HIBP Pwned Passwords range protocol; explicit email-breach searches are a separate provider capability and may require an HIBP subscription key [11]."
    ])
    add_section(doc, "3.7 Operating Modes", [
        "The default Docker Compose project uses Live mode. It can make real provider requests when each integration is enabled, credentials and permission are available, and the source is reachable. Results can be partial, stale, unavailable, or quota-limited. The user interface retains these states.",
        "The separate Demo Compose project uses synthetic fixtures and makes no provider or website requests. It has separate named PostgreSQL and Redis volumes. Live and Demo both use the local gateway port 8443, so only one gateway should run on that host port at a time. Live mode is a local showcase configuration; it is not a hardened public deployment."
    ])

    doc.add_page_break()
    add_chapter(doc, 4, "Implementation and Evaluation")
    add_section(doc, "4.1 Technology Stack", [
        "CyberLens separates the browser interface, API, durable storage, queue, dispatcher, and worker into services. The frontend uses React and TypeScript for component-based screens [1]. Vite produces the static build, and Nginx serves it. FastAPI provides typed HTTP endpoints and OpenAPI documentation [2]. SQLAlchemy maps application records to PostgreSQL, Alembic applies schema migrations, and psycopg connects the Python service to PostgreSQL [3]. Redis and RQ support background job execution [4, 5]. Docker Compose defines the local service stack [6]."
    ])
    add_caption(doc, "Table 4.1. Technology stack")
    add_table(doc, ["Component", "Technology", "Role in CyberLens"], [
        ("Frontend", "React 18, TypeScript, Vite, Recharts", "Analyst workspace, status views, graphs, and charts."),
        ("Static web server", "Nginx", "Serves the compiled frontend inside its container."),
        ("Gateway", "Caddy", "Local HTTPS, frontend routing, and API reverse proxy."),
        ("API", "Python 3.12, FastAPI, Uvicorn", "Authentication, validation, APIs, health checks, and reports."),
        ("Persistence", "PostgreSQL 16, SQLAlchemy, Alembic", "Durable relational data and versioned schema changes."),
        ("Queue and worker", "Redis 7, RQ, Python worker", "Background jobs, delivery state, and collector execution."),
        ("Local orchestration", "Docker Compose", "Builds and starts the application services and named volumes."),
    ], widths=[1.12, 2.2, 3.5], font_size=8.8)
    add_section(doc, "4.2 Core Modules", [
        "The asset module stores domains, IP addresses, URLs, email addresses, applications, and software components. Authorization records control website inspections and selected email-provider requests. The investigation module coordinates collectors and exposes status and history. The findings module stores provider-backed candidates and analyst applicability decisions. The risk view shows the score, contributors, assessed categories, excluded coverage, sensitivity, and historical revisions.",
        "Incident management links cases to findings and investigations. A case contains status history, timeline events, and playbook tasks. Remediation plans and actions track proposed work and verification instructions. Control mappings retain a rationale and confidence. Reports capture PDF or JSON snapshots, while the integrity view checks evidence checksums and the audit chain.",
        "Other modules include threat modeling, the evidence graph, Change Radar, continuous monitoring, provider status, posture scorecards, MITRE ATT&CK mappings, and shared threat-feed snapshots. These modules reuse the same authenticated API, persisted records, and audit model."
    ])
    add_section(doc, "4.3 Durable Investigation Orchestration", [
        "The API does not perform all provider calls synchronously inside the user request. It commits the investigation, initial attempt, and outbox delivery event together. The separate dispatcher claims pending events and enqueues RQ jobs using stable identifiers. If delivery is repeated, the stable job ID prevents duplicate execution. The worker claims the attempt, refreshes its heartbeat, runs the selected collectors, and saves each collector run and evidence snapshot.",
        "The design separates the authoritative business record from the transient queue. PostgreSQL retains the investigation and delivery intent; Redis carries the job to a worker. A reconciler recovers old queued deliveries, handles stale running attempts, and materializes due monitoring runs. Limited exponential backoff is used for transient provider or network failures. Permanent configuration or authorization failures do not become unbounded retries."
    ])
    add_section(doc, "4.4 Evidence Sources and Interpretation", [
        "The collectors combine externally sourced observations with local matching against stored snapshots. A source result carries a status and provenance so the analyst can distinguish match, no match, partial coverage, stale data, provider outage, and not-applicable conditions."
    ])
    add_caption(doc, "Table 4.2. Selected evidence sources and interpretation")
    add_table(doc, ["Source or collector", "CyberLens use", "Interpretation limit"], [
        ("DNS and RDAP", "Collects domain and registration context.", "Public registration and DNS data may be incomplete or privacy-protected."),
        ("Website and TLS", "Observes a bounded HTTP response, selected headers, redirects, and certificate details.", "One observation is not a complete web or TLS audit."),
        ("VirusTotal", "Reads a provider report for an explicitly submitted asset when configured.", "Provider quota and verdicts do not prove compromise."),
        ("NVD and CPE", "Returns vulnerability candidates based on inventoried product/version context.", "A candidate requires analyst confirmation of applicability."),
        ("CISA KEV and FIRST EPSS", "Adds catalog membership and a separate population-level exploitation estimate.", "Neither signal proves exploitation of the specific asset."),
        ("OSV", "Checks an explicit npm or PyPI package and version.", "No automatic dependency discovery or SBOM upload occurs."),
        ("Threat-feed snapshots", "Matches an explicitly submitted public IP or URL against a validated local snapshot.", "A no-match means only absence from that snapshot."),
        ("HIBP or XposedOrNot", "Performs explicitly selected email-breach lookups under provider-specific access and consent.", "Historical exposure does not mean the account is currently compromised."),
    ], widths=[1.55, 2.75, 2.52], font_size=8.5)
    add_body_paragraph(doc, "NVD, CISA KEV, FIRST EPSS, and MITRE ATT&CK provide distinct data models and should not be merged into a single unqualified verdict [7-10]. The application presents provenance and limitations alongside observations. A source outage leaves prior evidence unknown unless a later successful collection can support a meaningful comparison.", indent=False)
    add_section(doc, "4.5 Evidence Graph, Change Radar, and Reports", [
        "The evidence graph is built from stored assets, domains, IP addresses, certificates, software, CVEs, findings, investigations, incidents, and tasks. Each relationship stores a foreign key to supporting evidence, its source and collector, observation time, and whether it is direct evidence or contextual linkage. The graph is a projection from PostgreSQL data and is not a separate source of truth.",
        "Change Radar compares an investigation with a prior saved run and classifies relationships as new, changed, no longer observed, or unknown. A failed, partial, unavailable, not-applicable, or unrun collector cannot justify a removal classification. Reports store a point-in-time snapshot so later changes to a case or remediation plan do not silently rewrite an earlier report."
    ])
    add_section(doc, "4.6 Verification and Observed Results", [
        "The repository’s engineering record dated 26 October 2026 documents frontend TypeScript checks and a production build, a combined workflow and presentation suite with 78 passing tests in an isolated offline backend plus mocked-provider setup, and a separate real-backend smoke test with one passing test. The same record states that no live-provider test was run. These checks support the reported local workflow and interface behavior; they do not establish current external provider availability or public-production readiness.",
        "The verification record also documents role and workflow coverage, responsive views, keyboard/accessibility checks, reports, monitoring, integrity, integrations, and persistence across a full-service restart in earlier isolated runs. The report does not claim these historical checks were rerun during report creation. A reviewer can reproduce the application workflow locally with the project Compose instructions and inspect the health endpoints."
    ])
    add_caption(doc, "Table 4.3. Documented verification evidence")
    add_table(doc, ["Verification item", "Recorded result", "Scope"], [
        ("Frontend TypeScript and production build", "Passed in the 26 Oct 2026 UI review.", "Application and Playwright TypeScript; frontend bundle."),
        ("Offline workflow and mocked presentation suite", "78 passed in 5.2 minutes.", "Isolated offline backend workflows and mocked UI/provider cases."),
        ("Real-backend smoke test", "1 passed in 7.6 seconds.", "Isolated local backend login and dashboard; not a live provider check."),
        ("Live provider validation", "Not run in the cited review.", "External provider behavior remains environment-dependent."),
    ], widths=[2.05, 1.65, 3.12], font_size=9)
    add_section(doc, "4.7 Limitations", [
        "Live results depend on network access, provider terms, account tier, API quota, freshness, and source quality. Some integrations are optional or disabled by default. A provider response is an observation from that provider and not a complete security assessment.",
        "The risk method is deterministic and explainable but is not calibrated against a labeled dataset of real incidents. The evidence checksum detects later byte changes but is not proof of forensic authenticity. The website collector performs a bounded observation rather than a comprehensive scan. OSV checks only explicitly inventoried package names and versions. Live and Demo each use a local single-workspace profile, and the current Compose deployment is not intended to be exposed publicly.",
        "The optional evidence-grounded AI briefing is disabled in the current project configuration. CyberLens does not send evidence or analyst notes to an external AI service. Automatic remediation, containment, and external notifications are outside the project scope."
    ])

    doc.add_page_break()
    add_chapter(doc, 5, "Conclusion and Future Work")
    add_section(doc, "5.1 Conclusion", [
        "CyberLens implements a local analyst workspace that connects asset inventory, background investigations, provider observations, evidence snapshots, findings, risk revisions, incident records, remediation tracking, and saved reports. Its architecture separates the browser interface from the API and long-running collection work. PostgreSQL preserves durable records, while the transactional outbox, dispatcher, Redis/RQ queue, and worker support reliable asynchronous processing.",
        "The project emphasizes traceability and careful interpretation. Each finding can be reviewed against its evidence. Vulnerability applicability remains an analyst decision. Provider gaps are visible as unknown or partial coverage. Reports preserve the state captured when they were generated. These design choices help reduce overstatement and make the analyst’s reasoning easier to inspect.",
        "The project provides a Live mode that can use real sources when configured, and a separate offline Demo mode for repeatable synthetic workflows. The implementation is suitable for local demonstration and academic evaluation. Further operational hardening and live-provider testing would be required before any internet-facing deployment."
    ])
    add_section(doc, "5.2 Future Work", [
        "Future work can improve both evaluation and deployment. The prioritization method could be calibrated and validated against a clearly defined incident or vulnerability outcome dataset. Additional integration tests could exercise external providers in a controlled account, with explicit quotas and reproducible fixtures.",
        "A hardened deployment profile could add managed secrets, TLS certificate lifecycle, network segmentation, centralized backups, monitoring, disaster recovery, and multi-workspace isolation. The current application is a single-workspace local service, so tenant boundaries and operational controls would need careful design before shared deployment.",
        "Other extensions include broader package ecosystem coverage, standardized import and export formats, richer evidence retention controls, additional role workflows, and improved source freshness diagnostics. Any automated response capability should require explicit policy, authorization, auditability, and human approval rather than being inferred from a finding."
    ])
    add_caption(doc, "Table 4.4. Limitations and proposed extensions")
    add_table(doc, ["Current limitation", "Possible future work"], [
        ("Academic score is not calibrated to outcomes.", "Develop a documented validation dataset and evaluate calibration and usefulness."),
        ("Live providers were not exercised in the cited UI verification.", "Add controlled provider integration checks with quotas and consent."),
        ("Local single-workspace deployment.", "Design and review tenant isolation, managed secrets, backups, and monitoring."),
        ("Package checks require explicit inventory.", "Add authorized inventory import and additional package ecosystems."),
        ("No automated containment or remediation.", "If added, require bounded policies, approval, audit, and rollback."),
    ], widths=[3.0, 3.82], font_size=9)

    doc.add_page_break()
    add_front_title(doc, "References")
    refs = [
        "[1] React Team, “Quick Start,” React Documentation. Available: https://react.dev/learn. Accessed 29 Oct. 2026.",
        "[2] FastAPI, “FastAPI Documentation.” Available: https://fastapi.tiangolo.com/. Accessed 29 Oct. 2026.",
        "[3] PostgreSQL Global Development Group, “PostgreSQL 16 Documentation.” Available: https://www.postgresql.org/docs/16/. Accessed 29 Oct. 2026.",
        "[4] Redis, “Redis Job Queue,” Redis Documentation. Available: https://redis.io/docs/latest/develop/use-cases/job-queue/. Accessed 29 Oct. 2026.",
        "[5] Python RQ, “Documentation Overview.” Available: https://python-rq.org/docs/. Accessed 29 Oct. 2026.",
        "[6] Docker, “Docker Compose.” Available: https://docs.docker.com/compose/. Accessed 29 Oct. 2026.",
        "[7] National Institute of Standards and Technology, “NVD API: Vulnerabilities.” Available: https://nvd.nist.gov/developers/vulnerabilities. Accessed 29 Oct. 2026.",
        "[8] Cybersecurity and Infrastructure Security Agency, “Known Exploited Vulnerabilities Catalog.” Available: https://www.cisa.gov/known-exploited-vulnerabilities-catalog. Accessed 29 Oct. 2026.",
        "[9] FIRST, “Exploit Prediction Scoring System (EPSS).” Available: https://www.first.org/epss/. Accessed 29 Oct. 2026.",
        "[10] MITRE, “ATT&CK STIX Data.” Available: https://github.com/mitre-attack/attack-stix-data. Accessed 29 Oct. 2026.",
        "[11] Have I Been Pwned, “API Documentation: Pwned Passwords and Breach Search.” Available: https://haveibeenpwned.com/API/v3. Accessed 29 Oct. 2026.",
        "[12] OWASP Foundation, “Server Side Request Forgery Prevention Cheat Sheet.” Available: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html. Accessed 29 Oct. 2026.",
    ]
    for item in refs:
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Inches(0.3)
        p.paragraph_format.first_line_indent = Inches(-0.3)
        p.paragraph_format.space_after = Pt(7)
        p.paragraph_format.line_spacing = 1.15
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        set_run_font(p.add_run(item), size=10)

    doc.add_page_break()
    add_front_title(doc, "Appendix A  API Resource Summary")
    add_body_paragraph(doc, "The HTTP API is organized under /api/v1. The following resource groups summarize the workspace interface. The interactive OpenAPI reference is served at /docs when the local application is running.", indent=False)
    add_table(doc, ["Resource group", "Representative operations"], [
        ("Authentication", "CSRF token, sign in, current user, sign out, password change."),
        ("Assets", "Create, read, update, authorize, and manage components for inventoried assets."),
        ("Investigations", "Create, list, inspect, retry, compare, inspect evidence graph and changes."),
        ("Findings", "Inspect candidate findings and record applicability decisions."),
        ("Incidents", "Create and update cases, add timeline events, complete playbook tasks."),
        ("Reports", "Create, retrieve, and download PDF or JSON snapshots."),
        ("Remediation", "Create plans and actions; map findings to controls with rationale."),
        ("Integrity and operations", "Check audit/evidence integrity, liveness, readiness, and metrics."),
    ], widths=[1.55, 5.27], font_size=9.2)
    add_body_paragraph(doc, "Mutating requests require the normal authenticated session and CSRF protection. Admin-only actions include user administration, catalog synchronization, and selected provider-feed refreshes. The API enforces roles on the server; hiding a control in the interface is not treated as an authorization boundary.", indent=False)

    doc.add_page_break()
    add_front_title(doc, "Appendix B  Local Run and Showcase Notes")
    add_body_paragraph(doc, "The default local Compose project runs Live mode. Docker Desktop must be running before starting the stack. The gateway is bound to loopback on port 8443; the API, worker, dispatcher, PostgreSQL, and Redis are not published directly to the host.", indent=False)
    add_caption(doc, "Table B.1. Local service startup")
    add_table(doc, ["Task", "PowerShell command"], [
        ("Start the existing Live stack", "docker compose up -d"),
        ("Rebuild and start after source changes", "docker compose up --build -d"),
        ("Check service status", "docker compose ps"),
        ("Follow API logs", "docker compose logs -f api"),
        ("Open the workspace", "https://localhost:8443"),
    ], widths=[2.55, 4.27], font_size=9.5)
    add_body_paragraph(doc, "For an academic showcase, demonstrate an asset that is owned by the project team or explicitly authorized, then show the investigation status, source provenance, evidence, analyst applicability decision, score explanation, case or remediation record, and report snapshot. Provider status and quota should be checked before the presentation. Synthetic Demo results must be identified as synthetic.", indent=False)
    add_body_paragraph(doc, "Keep credentials and API keys in the local environment configuration. Do not include them in this report, screenshots, source control, or presentation slides. The report contains editable fields for student, supervisor, department, institute, degree program, and date; replace them with accurate institutional details before submission.", indent=False)

    fill_markers(doc, page_map)
    doc.save(OUT)
    print(OUT)


if __name__ == "__main__":
    build()
