"""
pdf_report.py — генерация PDF-отчёта через ReportLab.
Используется из GUI (кнопка «PDF-отчёт») и из API (/report/pdf/{id}).
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, HRFlowable, PageBreak)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
from pathlib import Path
import os

# ── Шрифты — DejaVu если есть, иначе Helvetica ────────────────

def _register_fonts():
    paths = {
        'DejaVu':      '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        'DejaVu-Bold': '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
        'DejaVu-Mono': '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
    }
    if all(os.path.exists(p) for p in paths.values()):
        for name, path in paths.items():
            pdfmetrics.registerFont(TTFont(name, path))
        return 'DejaVu', 'DejaVu-Bold', 'DejaVu-Mono'
    return 'Helvetica', 'Helvetica-Bold', 'Courier'

FONT, FONT_BOLD, FONT_MONO = _register_fonts()

# ── Константы ──────────────────────────────────────────────────

UNIVERSITY   = "INTERNATIONAL INFORMATION TECHNOLOGY UNIVERSITY (IITU)"
FACULTY      = "Faculty of Computer Technology and Cybersecurity"
SPECIALTY    = "Field of Study: Network Security"
SUPERVISOR   = "Supervisor: Alin G.T."
AUTHORS      = ["Amangeldi Manas", "Kurmanov Iskander", "Kuanyshbek Bekarys"]
YEAR         = "2026"
PROJECT_NAME = "RootkitGuard"

# ── Стили ──────────────────────────────────────────────────────

def _styles():
    def ps(name, font=None, size=11, color='#333333', align=0, before=0, after=6):
        return ParagraphStyle(name,
            fontName=font or FONT,
            fontSize=size,
            textColor=colors.HexColor(color),
            alignment=align,
            spaceBefore=before,
            spaceAfter=after)
    return {
        'uni':         ps('uni',  FONT_BOLD, 13, '#1a1a2e', align=1, after=4),
        'faculty':     ps('fac',  FONT,      11, '#444444', align=1, after=4),
        'project':     ps('prj',  FONT_BOLD, 22, '#1f538d', align=1, after=8),
        'project_sub': ps('psb',  FONT,      13, '#555555', align=1, after=20),
        'author':      ps('aut',  FONT,      12, '#222222', align=1, after=5),
        'supervisor':  ps('sup',  FONT,      11, '#666666', align=1, after=4),
        'year':        ps('yr',   FONT_BOLD, 14, '#1a1a2e', align=1),
        'heading':     ps('hd',   FONT_BOLD, 14, '#1f538d', before=16, after=8),
        'normal':      ps('nm',   FONT,      11, '#333333', after=6),
        'footer':      ps('ft',   FONT,       8, '#888888', align=1),
        'small':       ps('sm',   FONT,       9, '#888888', align=1),
    }

# ── Титульная страница ─────────────────────────────────────────

def _title_page(elements, st):
    # Цветные полосы вверху
    d = Drawing(480, 8)
    d.add(Rect(0,   0, 160, 8, fillColor=colors.HexColor('#1f538d'), strokeColor=None))
    d.add(Rect(162, 0, 160, 8, fillColor=colors.HexColor('#2d6a4f'), strokeColor=None))
    d.add(Rect(324, 0, 160, 8, fillColor=colors.HexColor('#6d3a9c'), strokeColor=None))
    elements.append(d)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph(UNIVERSITY, st['uni']))
    elements.append(Paragraph(FACULTY,    st['faculty']))
    elements.append(Paragraph(SPECIALTY,  st['faculty']))
    elements.append(Spacer(1, 40))

    # Центральный блок
    box = Table(
        [[Paragraph(PROJECT_NAME, st['project'])],
         [Paragraph("System Technical Report", st['project_sub'])]],
        colWidths=[16*cm]
    )
    box.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), colors.HexColor('#f0f4ff')),
        ('BOX',           (0,0), (-1,-1), 2, colors.HexColor('#1f538d')),
        ('TOPPADDING',    (0,0), (-1,-1), 20),
        ('BOTTOMPADDING', (0,0), (-1,-1), 20),
        ('LEFTPADDING',   (0,0), (-1,-1), 20),
        ('RIGHTPADDING',  (0,0), (-1,-1), 20),
    ]))
    elements.append(box)
    elements.append(Spacer(1, 30))

    elements.append(Paragraph(
        "Development of an anomaly detection system based on ensemble methods "
        "Machine learning algorithms: Random Forest, XGBoost, Isolation Forest. "
        "Dataset: CIC-IDS2018. Platform: Python 3.12.",
        st['normal']))
    elements.append(Spacer(1, 40))

    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 16))
    elements.append(Paragraph("Project authors:", st['supervisor']))
    roles = [
        "Main developer (ML pipeline, GUI, Docker)",
        "Backend developer (API, database)",
        "Data engineer (PDF report, visualization)",
    ]
    for author, role in zip(AUTHORS, roles):
        elements.append(Paragraph(f"<b>{author}</b> — {role}", st['author']))
    elements.append(Spacer(1, 16))
    elements.append(Paragraph(SUPERVISOR, st['supervisor']))
    elements.append(Spacer(1, 16))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 20))

    bottom = Table(
        [[Paragraph("IITU", st['year']),
          Paragraph(YEAR,   st['year']),
          Paragraph("Almaty", st['year'])]],
        colWidths=[5*cm, 6*cm, 5*cm]
    )
    bottom.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR',     (0,0), (-1,-1), colors.white),
        ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING',    (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
    ]))
    elements.append(bottom)
    elements.append(PageBreak())

# ── Главная функция ────────────────────────────────────────────

def generate_pdf_report(scan_data: dict,
                         output_path: str = "reports/rootkitguard_report.pdf") -> str:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm,   bottomMargin=2*cm,
    )
    st = _styles()
    elements = []

    # ── Титульная страница ──────────────────────────────────
    _title_page(elements, st)

    # ── Мета-информация ─────────────────────────────────────
    elements.append(Paragraph("Information about report", st['heading']))
    meta = [
        ["Date of formation:", datetime.now().strftime('%d.%m.%Y %H:%M:%S')],
        ["System version:",    "RootkitGuard v2.0.0"],
        ["University:",       "IITU, Almaty"],
        ["Speciality:",     "Network security"],
        ["Models:",            "Random Forest + XGBoost + Isolation Forest"],
        ["Dataset:",           "CIC-IDS2018 (1,044,525 records)"],
        ["Authors:",            ", ".join(AUTHORS)],
        ["Supervisor:",      SUPERVISOR],
    ]
    mt = Table(meta, colWidths=[5*cm, 12*cm])
    mt.setStyle(TableStyle([
        ('FONTNAME',       (0,0), (0,-1), FONT_BOLD),
        ('FONTNAME',       (1,0), (1,-1), FONT),
        ('FONTSIZE',       (0,0), (-1,-1), 10),
        ('TEXTCOLOR',      (0,0), (0,-1), colors.HexColor('#1f538d')),
        ('TEXTCOLOR',      (1,0), (1,-1), colors.HexColor('#333333')),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#f8f9fa'), colors.white]),
        ('BOTTOMPADDING',  (0,0), (-1,-1), 6),
        ('TOPPADDING',     (0,0), (-1,-1), 6),
        ('GRID',           (0,0), (-1,-1), 0.3, colors.HexColor('#eeeeee')),
    ]))
    elements.append(mt)
    elements.append(Spacer(1, 20))

    # ── Результаты сканирования ─────────────────────────────
    elements.append(Paragraph("Scanning result", st['heading']))

    total   = scan_data.get('total_rows', 0)
    anomaly = scan_data.get('anomalies', 0)
    normal  = scan_data.get('normal', 0)
    pct     = scan_data.get('pct', 0.0)
    threat  = scan_data.get('threat', 'LOW')

    threat_color = {
        'HIGH': colors.HexColor('#e74c3c'),
        'MEDIUM': colors.HexColor('#f39c12'),
        'LOW':  colors.HexColor('#2dc97e'),
    }.get(threat, colors.gray)

    res_data = [
        ["Indicator",       "Definition",      "Commentary"],
        ["Total records",    f"{total:,}",     "Analyzed using the model"],
        ["Normals",       f"{normal:,}",    "Standard behavior"],
        ["Anomalies (Bot)",   f"{anomaly:,}",   "Suspicious activity"],
        ["Anomaly percent", f"{pct:.2f}%",    "> 20% = high threat"],
        ["Threat level",   threat,           "Overall evaluation of the system"],
    ]
    rt = Table(res_data, colWidths=[6*cm, 4*cm, 7*cm])
    rt.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0), colors.HexColor('#1f538d')),
        ('TEXTCOLOR',     (0,0), (-1,0), colors.white),
        ('FONTNAME',      (0,0), (-1,0), FONT_BOLD),
        ('FONTNAME',      (0,1), (-1,-1), FONT),
        ('FONTSIZE',      (0,0), (-1,-1), 10),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [colors.HexColor('#f0f4ff'), colors.white]),
        ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING',    (0,0), (-1,-1), 8),
        ('TEXTCOLOR',     (1,-1), (1,-1), threat_color),
        ('FONTNAME',      (1,-1), (1,-1), FONT_BOLD),
    ]))
    elements.append(rt)
    elements.append(Spacer(1, 20))

    # ── Pie chart ───────────────────────────────────────────
    elements.append(Paragraph("Class Schedule", st['heading']))
    drawing = Drawing(400, 180)
    pie = Pie()
    pie.x, pie.y = 30, 15
    pie.width = pie.height = 150
    pie.data   = [max(normal, 1), max(anomaly, 1)]
    pie.labels = ['', '']
    pie.slices[0].fillColor   = colors.HexColor('#2dc97e')
    pie.slices[1].fillColor   = colors.HexColor('#e74c3c')
    pie.slices[0].strokeColor = colors.white
    pie.slices[1].strokeColor = colors.white
    pie.slices[1].popout = 10
    drawing.add(pie)
    drawing.add(Rect(220, 120, 14, 14, fillColor=colors.HexColor('#2dc97e'), strokeColor=None))
    drawing.add(String(240, 123, f'Normals: {normal:,}',
                       fontName=FONT, fontSize=10, fillColor=colors.HexColor('#333333')))
    drawing.add(Rect(220, 95, 14, 14, fillColor=colors.HexColor('#e74c3c'), strokeColor=None))
    drawing.add(String(240, 98, f'Anomalies: {anomaly:,}',
                       fontName=FONT, fontSize=10, fillColor=colors.HexColor('#333333')))
    drawing.add(String(220, 70, f'Overall: {total:,}',
                       fontName=FONT_BOLD, fontSize=10, fillColor=colors.HexColor('#1f538d')))
    drawing.add(String(220, 50, f'Anomalies: {pct:.1f}%',
                       fontName=FONT_BOLD, fontSize=10, fillColor=colors.HexColor('#e74c3c')))
    elements.append(drawing)
    elements.append(Spacer(1, 10))

    # ── Метрики моделей ─────────────────────────────────────
    elements.append(Paragraph("Comparison of machine learning models", st['heading']))
    metrics = [
        ["Model",           "F1-score", "ROC-AUC", "FPR",    "FNR",    "Type"],
        ["Random Forest",    "1.0000",   "0.9999",  "0.0001", "0.0001", "Supervised"],
        ["XGBoost",          "1.0000",   "1.0000",  "0.0000", "0.0001", "Supervised"],
        ["Isolation Forest", "0.0200",   "0.3258",  "0.3666", "0.9818", "Unsupervised"],
        ["Ensemble",         "1.0000",   "0.9999",  "0.0000", "0.0001", "Hybrid"],
    ]
    mtt = Table(metrics, colWidths=[4.5*cm, 2.5*cm, 2.5*cm, 2.5*cm, 2.5*cm, 3*cm])
    mtt.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0), colors.HexColor('#1f538d')),
        ('TEXTCOLOR',     (0,0), (-1,0), colors.white),
        ('FONTNAME',      (0,0), (-1,0), FONT_BOLD),
        ('FONTNAME',      (0,1), (-1,-1), FONT),
        ('FONTSIZE',      (0,0), (-1,-1), 9),
        ('ALIGN',         (1,0), (-1,-1), 'CENTER'),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [colors.HexColor('#f0f4ff'), colors.white]),
        ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('TOPPADDING',    (0,0), (-1,-1), 7),
        ('TEXTCOLOR',     (1,3), (4,3), colors.HexColor('#e74c3c')),
        ('BACKGROUND',    (0,4), (-1,4), colors.HexColor('#e8f5e9')),
    ]))
    elements.append(mtt)
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        "* Isolation Forest — unsupervised method that does not require labeled data. "
        "The low F1 score is offset by the supervised models in the ensemble.",
        st['small']))
    elements.append(Spacer(1, 16))

    # ── Топ признаков ───────────────────────────────────────
    elements.append(Paragraph("Top 5 Signs by Importance (Feature Importance)", st['heading']))
    feat_data = [
        ["#", "Sign",       "Importance", "Interpretation"],
        ["1", "Dst Port",      "0.1374",   "Destination port — bots use specific C&C ports"],
        ["2", "Flow Pkts/s",   "0.1023",   "Packet rate — the characteristic rhythm of beacon traffic"],
        ["3", "Fwd Pkts/s",    "0.0901",   "Outgoing packets per second — abnormal request frequency"],
        ["4", "Bwd Seg Size",  "0.0812",   "Server response size — Fixed-size C&C packets"],
        ["5", "Flow IAT Mean", "0.0501",   "Average inter-packet time — beaconing at a fixed interval"],
    ]
    ft = Table(feat_data, colWidths=[1*cm, 3.5*cm, 2.5*cm, 10*cm])
    ft.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0), colors.HexColor('#2d6a4f')),
        ('TEXTCOLOR',     (0,0), (-1,0), colors.white),
        ('FONTNAME',      (0,0), (-1,0), FONT_BOLD),
        ('FONTNAME',      (0,1), (-1,-1), FONT),
        ('FONTSIZE',      (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [colors.HexColor('#f0fff4'), colors.white]),
        ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('TOPPADDING',    (0,0), (-1,-1), 7),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(ft)
    elements.append(Spacer(1, 20))

    # ── Вклад команды ───────────────────────────────────────
    elements.append(Paragraph("The team's contribution", st['heading']))
    team_data = [
        ["Member",    "Role",                    "Modules Implemented"],
        [AUTHORS[0],    "Main developer",    "ML pipeline, GUI, Docker, monitoring of processes"],
        [AUTHORS[1],    "Backend developer",     "FastAPI, SQLite, REST endpoints, Swagger"],
        [AUTHORS[2],    "Data engineer",            "PDF reports, SHAP visualization, testing"],
    ]
    tt = Table(team_data, colWidths=[5*cm, 4*cm, 8*cm])
    tt.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0), colors.HexColor('#6d3a9c')),
        ('TEXTCOLOR',     (0,0), (-1,0), colors.white),
        ('FONTNAME',      (0,0), (-1,0), FONT_BOLD),
        ('FONTNAME',      (0,1), (-1,-1), FONT),
        ('FONTSIZE',      (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [colors.HexColor('#f5f0ff'), colors.white]),
        ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING',    (0,0), (-1,-1), 8),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(tt)
    elements.append(Spacer(1, 20))

    # ── Заключение ──────────────────────────────────────────
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#1f538d')))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("Conclusion", st['heading']))

    conclusion = (
        f"System <b>RootkitGuard</b>, developed by a team of students from IITU "
        f"speciality «Network security», successfully detected "
        f"<b>{anomaly:,}</b> anomalous network entries from <b>{total:,}</b> "
        f"verified ({pct:.2f}%). Threat level: <b>{threat}</b>. "
        f"An ensemble approach (RF + XGBoost + Isolation Forest) reached "
        f"ROC-AUC = 0.9999 with a False Positive Rate = 0.0000. "
    )
    if threat == 'HIGH':
        conclusion += ("An immediate investigation of the identified anomalies is recommended "
                       "and checking the destination ports.")
    elif threat == 'MEDIUM':
        conclusion += "Enhanced monitoring of the system is recommended."
    else:
        conclusion += "The system is operating normally."

    elements.append(Paragraph(conclusion, st['normal']))
    elements.append(Spacer(1, 24))
    elements.append(Paragraph(
        f"IITU · Almaty · {YEAR} · {SUPERVISOR}",
        st['footer']))

    doc.build(elements)
    print(f"[+] PDF saved: {output_path}")
    return output_path


if __name__ == "__main__":
    scan_data = {
        'total_rows': 1048575,
        'anomalies':  286225,
        'normal':     762350,
        'pct':        27.3,
        'threat':     'HIGH',
        'top_ports':  [8080, 50891, 50895],
    }
    generate_pdf_report(scan_data)
