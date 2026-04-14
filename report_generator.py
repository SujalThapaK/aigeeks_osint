"""
OSINT Report — PDF Generation Engine
=====================================
Produces professional, styled investigation reports using ReportLab.

Pages:
  1. Cover          — classification banner, target metadata, risk gauge
  2. Executive Summary + Entity Map
  3. Categorised Findings tables (one table per source category)
  4. Full Audit Trail
"""

import re
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether, Image,
)
from reportlab.graphics.shapes import Drawing, Circle, String
from reportlab.lib.colors import HexColor

# ── Palette ──────────────────────────────────────────────────────────────────
DARK_BG   = HexColor("#0D1117")
ACCENT    = HexColor("#00D9A3")
ACCENT2   = HexColor("#1E3A5F")
TEXT_MAIN = HexColor("#1A1A2E")
TEXT_MUTED = HexColor("#4A5568")
TEXT_WHITE = HexColor("#F0F4F8")
RED       = HexColor("#E53E3E")
ORANGE    = HexColor("#DD6B20")
YELLOW    = HexColor("#D69E2E")
GREEN     = HexColor("#38A169")
BORDER    = HexColor("#CBD5E0")
LIGHT_BG  = HexColor("#F7FAFC")
STRIPE    = HexColor("#EDF2F7")
TBL_HDR   = HexColor("#1E3A5F")


# ── Palette ──────────────────────────────────────────────────────────────────

PAGE_W, PAGE_H = A4


# ── Page Template (header / footer on every page) ────────────────────────────

def _header_footer(canvas_obj, doc):
    canvas_obj.saveState()
    w, h = PAGE_W, PAGE_H

    # Dark top bar (smaller)
    canvas_obj.setFillColor(DARK_BG)
    canvas_obj.rect(0, h - 15 * mm, w, 15 * mm, fill=1, stroke=0)

    canvas_obj.setFillColor(ACCENT)
    canvas_obj.setFont("Helvetica-Bold", 10)
    canvas_obj.drawString(18 * mm, h - 10 * mm, "OSINT INTELLIGENCE REPORT")

    canvas_obj.setFillColor(TEXT_WHITE)
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.drawRightString(w - 18 * mm, h - 10 * mm,
                               f"Page {doc.page}")

    # Accent underline stripe
    canvas_obj.setFillColor(ACCENT)
    canvas_obj.rect(0, h - 16 * mm, w, 1.5, fill=1, stroke=0)

    canvas_obj.restoreState()


# ── Paragraph styles ─────────────────────────────────────────────────────────

def _styles() -> dict:
    s: dict = {}
    s["h1"] = ParagraphStyle("h1",
        fontName="Helvetica-Bold", fontSize=13, leading=18,
        textColor=ACCENT2, spaceBefore=14, spaceAfter=6)
    s["h2"] = ParagraphStyle("h2",
        fontName="Helvetica-Bold", fontSize=10, leading=13,
        textColor=ACCENT2, spaceBefore=10, spaceAfter=4)
    s["body"] = ParagraphStyle("body",
        fontName="Helvetica", fontSize=9, leading=14,
        textColor=TEXT_MAIN, spaceAfter=6, alignment=TA_JUSTIFY)
    s["mono"] = ParagraphStyle("mono",
        fontName="Courier", fontSize=8, leading=12,
        textColor=HexColor("#2D3748"), spaceAfter=4)
    s["small"] = ParagraphStyle("small",
        fontName="Helvetica", fontSize=7.5, leading=11,
        textColor=TEXT_MUTED)
    s["label"] = ParagraphStyle("label",
        fontName="Helvetica-Bold", fontSize=8, leading=11,
        textColor=ACCENT2)
    s["center"] = ParagraphStyle("center",
        fontName="Helvetica", fontSize=9, leading=14,
        textColor=TEXT_MAIN, alignment=TA_CENTER)
    return s


# ── Risk gauge drawing ────────────────────────────────────────────────────────

# Risk assessment section removed


# ── Shared helpers ────────────────────────────────────────────────────────────

def _section_divider(title: str, styles: dict) -> list:
    return [
        Spacer(1, 8),
        HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceAfter=4),
        Paragraph(title.upper(), styles["h1"]),
    ]


_TBL_BASE = TableStyle([
    ("BACKGROUND",   (0, 0), (-1, 0), TBL_HDR),
    ("TEXTCOLOR",    (0, 0), (-1, 0), TEXT_WHITE),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, STRIPE]),
    ("FONTSIZE",     (0, 0), (-1, -1), 8),
    ("TOPPADDING",   (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ("LEFTPADDING",  (0, 0), (-1, -1), 6),
    ("GRID",         (0, 0), (-1, -1), 0.4, BORDER),
    ("VALIGN",       (0, 0), (-1, -1), "TOP"),
])


# ── Cover page ────────────────────────────────────────────────────────────────

def _cover(report: dict, styles: dict) -> list:
    elems: list = [Spacer(1, 12 * mm)]

    em = report.get("entity_map", {})
    photo_path = em.get("primary_photo_local") or em.get("primary_photo")
    img = None
    if photo_path:
        try:
            # We use a fixed size for letterhead profile photo
            img = Image(photo_path, width=40 * mm, height=40 * mm)
            img.hAlign = 'LEFT'
        except Exception:
            pass

    started   = report.get("started_at", "")[:10]
    completed = report.get("completed_at", "")[:10]

    right_inner = []
    name_style = ParagraphStyle(
        "LHName", fontName="Helvetica-Bold", fontSize=20, textColor=ACCENT2, leading=24
    )
    target_name = report.get("target", "").upper()
    right_inner.append(Paragraph(target_name, name_style))
    right_inner.append(Spacer(1, 4 * mm))

    meta_style = ParagraphStyle("LHMeta", fontName="Helvetica", fontSize=9, textColor=TEXT_MAIN)
    meta_label = ParagraphStyle("LHMetaL", fontName="Helvetica-Bold", fontSize=9, textColor=TEXT_MUTED)
    
    info_data = [
        [Paragraph("INVESTIGATION STARTED", meta_label), Paragraph(started, meta_style)],
        [Paragraph("INVESTIGATION COMPLETED", meta_label), Paragraph(completed, meta_style)],
        [Paragraph("TOTAL FINDINGS", meta_label), Paragraph(str(report.get("total_sources", 0)), meta_style)],
    ]
    info_inner_tbl = Table(info_data, colWidths=[45 * mm, 80 * mm])
    info_inner_tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    right_inner.append(info_inner_tbl)

    if img:
        lh_data = [[img, right_inner]]
        lh_cols = [45 * mm, 125 * mm]
        lh_style = TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING", (1, 0), (1, 0), 5 * mm),
        ])
    else:
        lh_data = [[right_inner]]
        lh_cols = [170 * mm]
        lh_style = TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ])

    letterhead = Table(lh_data, colWidths=lh_cols)
    letterhead.setStyle(lh_style)
    
    elems.append(letterhead)
    elems.append(Spacer(1, 15 * mm))

    return elems


# ── Executive Summary ─────────────────────────────────────────────────────────

def _executive_summary(report: dict, styles: dict) -> list:
    elems: list = []
    elems += _section_divider("1. Executive Summary", styles)

    summary = report.get("executive_summary", "No summary available.")
    summary = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", summary)
    elems.append(Paragraph(summary, styles["body"]))
    elems.append(Spacer(1, 6))

    adapters_val = ", ".join(report.get("adapters_used", []))
    adapters_rows = [
        ["ADAPTERS DEPLOYED", Paragraph(adapters_val, styles["body"]) if adapters_val else "None"],
    ]
    adapters_tbl = Table(adapters_rows, colWidths=[60 * mm, 110 * mm])
    adapters_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, -1), ACCENT2),
        ("TEXTCOLOR",     (0, 0), (0, -1), TEXT_WHITE),
        ("BACKGROUND",    (1, 0), (1, -1), LIGHT_BG),
        ("TEXTCOLOR",     (1, 0), (1, -1), TEXT_MAIN),
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",      (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("GRID",          (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elems.append(adapters_tbl)

    return elems


# ── Findings section ──────────────────────────────────────────────────────────

def _findings(report: dict, styles: dict) -> list:
    elems: list = []
    import json
    elems += _section_divider("2. Categorised Findings", styles)

    findings = report.get("findings", [])
    cats: dict = {}
    for f in findings:
        cats.setdefault(f.get("category", "Other"), []).append(f)

    finding_title_style = ParagraphStyle("FindingTitle", parent=styles["h2"], textColor=TEXT_MAIN)
    table_style = TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), STRIPE),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",         (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ])

    for cat_name, cat_finds in cats.items():
        elems.append(Paragraph(cat_name, styles["h2"]))
        elems.append(Spacer(1, 4))

        for f in cat_finds:
            source_name = f.get("source", "Unknown Source")
            elems.append(Paragraph(source_name, finding_title_style))

            rows = []
            
            # Confidence
            conf_val = f"{(f.get('confidence', 0) * 100):.0f}%"
            rows.append([Paragraph("<b>Confidence</b>", styles["label"]), Paragraph(conf_val, styles["body"])])
            
            # Data keys
            data = f.get("data", {})
            for k, v in data.items():
                if isinstance(v, list):
                    val_str = "\\n".join(str(x) for x in v)
                elif isinstance(v, dict):
                    try:
                        val_str = json.dumps(v)
                    except Exception:
                        val_str = str(v)
                else:
                    val_str = str(v) if v is not None else ""
                
                # Escape HTML specific characters for ReportLab Paragraph
                val_str = val_str.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                val_str = val_str.replace("\\n", "<br/>")

                rows.append([Paragraph(f"<b>{k}</b>", styles["label"]), Paragraph(val_str, styles["mono"])])
            
            # Source URL
            url = f.get("source_url", "")
            if url:
                safe_url = url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                url_disp = f'<link href="{safe_url}" color="#1E3A5F">{safe_url}</link>'
                rows.append([Paragraph("<b>Source URL</b>", styles["label"]), Paragraph(url_disp, styles["mono"])])
                
            # Timestamp
            ts = f.get("timestamp", "")
            if ts:
                rows.append([Paragraph("<b>Timestamp</b>", styles["label"]), Paragraph(ts, styles["mono"])])
                
            # Notes
            notes = str(f.get("notes", ""))
            fp_marker = " [FP?]" if f.get("is_false_positive") else ""
            if notes or fp_marker:
                safe_notes = notes.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") + fp_marker
                rows.append([Paragraph("<b>Notes</b>", styles["label"]), Paragraph(safe_notes, styles["body"])])
                
            tbl = Table(rows, colWidths=[40 * mm, 134 * mm])
            tbl.setStyle(table_style)
            
            elems.append(tbl)
            elems.append(Spacer(1, 10))

    return elems


# ── Audit Trail ───────────────────────────────────────────────────────────────

def _audit_trail(report: dict, styles: dict) -> list:
    elems: list = []
    elems += _section_divider("3. Audit Trail", styles)
    elems.append(Paragraph(
        "Every data point below includes the originating source URL and retrieval "
        "timestamp for full traceability.",
        styles["body"],
    ))
    elems.append(Spacer(1, 4))

    rows = [[
        Paragraph("<b>#</b>",                  styles["label"]),
        Paragraph("<b>Source</b>",             styles["label"]),
        Paragraph("<b>Source URL</b>",         styles["label"]),
        Paragraph("<b>Retrieved (UTC)</b>",    styles["label"]),
        Paragraph("<b>Category</b>",           styles["label"]),
        Paragraph("<b>FP?</b>",               styles["label"]),
    ]]

    for i, f in enumerate(report.get("findings", []), 1):
        ts  = f.get("timestamp", "")[:19].replace("T", " ")
        url = f.get("source_url", "")
        url_disp = url[:52] + "…" if len(url) > 52 else url
        fp  = "YES" if f.get("is_false_positive") else "no"

        rows.append([
            Paragraph(str(i),                        styles["small"]),
            Paragraph(f.get("source", "")[:32],      styles["small"]),
            Paragraph(
                f'<link href="{url}" color="#1E3A5F">{url_disp}</link>',
                styles["small"],
            ),
            Paragraph(ts,                            styles["mono"]),
            Paragraph(f.get("category", "")[:22],   styles["small"]),
            Paragraph(fp,                            styles["small"]),
        ])

    audit_tbl = Table(rows, colWidths=[9*mm, 38*mm, 62*mm, 30*mm, 22*mm, 9*mm])
    audit_tbl.setStyle(_TBL_BASE)
    elems.append(audit_tbl)
    return elems


# ── Public entry point ────────────────────────────────────────────────────────

def generate_pdf(report_dict: dict, output_path: str) -> str:
    """Build and save the full PDF report.  Returns output_path."""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=10 * mm,
        title=f"OSINT Report — {report_dict.get('target', '')}",
        author="OSINT Intelligence Engine",
    )

    styles = _styles()
    story: list = []
    story += _cover(report_dict, styles)
    story += _executive_summary(report_dict, styles)
    story.append(Spacer(1, 15 * mm))
    story += _findings(report_dict, styles)
    story.append(Spacer(1, 15 * mm))
    story += _audit_trail(report_dict, styles)

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return output_path
