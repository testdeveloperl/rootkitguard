"""
pdf_report.py v2.1 — минимальный PDF отчёт RootkitGuard
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, HRFlowable)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
YEAR = '2026'
from pathlib import Path
import os

def _register_fonts():
    paths = {
        'DejaVu':      '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        'DejaVu-Bold': '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
    }
    if all(os.path.exists(p) for p in paths.values()):
        for name, path in paths.items():
            pdfmetrics.registerFont(TTFont(name, path))
        return 'DejaVu', 'DejaVu-Bold'
    return 'Helvetica', 'Helvetica-Bold'

FONT, FONT_BOLD = _register_fonts()

C_BLUE  = colors.HexColor('#1f538d')
C_GREEN = colors.HexColor('#2dc97e')
C_RED   = colors.HexColor('#e74c3c')
C_ORANGE= colors.HexColor('#f39c12')
C_LIGHT = colors.HexColor('#f8fafc')
C_DARK  = colors.HexColor('#0d1117')

def _p(name, font=None, size=11, color='#333333', align=0, before=0, after=6):
    return ParagraphStyle(name, fontName=font or FONT, fontSize=size,
        textColor=colors.HexColor(color), alignment=align,
        spaceBefore=before, spaceAfter=after)

def generate_pdf_report(scan_data: dict,
                         output_path: str = "reports/rootkitguard_report.pdf") -> str:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             rightMargin=2*cm, leftMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)

    total    = scan_data.get('total_rows', 0)
    anomaly  = scan_data.get('anomalies', 0)
    normal   = scan_data.get('normal', 0)
    pct      = scan_data.get('pct', 0.0)
    threat   = scan_data.get('threat', 'НИЗКАЯ')
    ports    = scan_data.get('top_ports', [])
    filename = scan_data.get('filename', '—')
    timestamp= scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    model    = scan_data.get('model', 'Random Forest')

    t_hex = {'ВЫСОКАЯ': '#e74c3c', 'СРЕДНЯЯ': '#f39c12', 'НИЗКАЯ': '#2dc97e'}.get(threat, '#64748b')
    t_col = colors.HexColor(t_hex)

    elements = []

    # ── Шапка ──────────────────────────────────────────────
    d = Drawing(480, 6)
    d.add(Rect(0,   0, 240, 6, fillColor=C_BLUE,  strokeColor=None))
    d.add(Rect(242, 0, 238, 6, fillColor=C_GREEN, strokeColor=None))
    elements.append(d)
    elements.append(Spacer(1, 16))
    elements.append(Paragraph("RootkitGuard — Отчёт сканирования",
                               _p('title', FONT_BOLD, 20, '#0d1117', align=1)))
    elements.append(Paragraph(f"Сформирован: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}",
                               _p('sub', FONT, 10, '#64748b', align=1, after=16)))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=C_BLUE))
    elements.append(Spacer(1, 16))

    # ── 1. Что сканировали ─────────────────────────────────
    elements.append(Paragraph("1. Что сканировали",
                               _p('h1', FONT_BOLD, 13, '#1f538d', before=0, after=8)))
    scan_info = [
        ["Файл:",            filename],
        ["Время скана:",     timestamp],
        ["Всего записей:",   f"{total:,}"],
    ]
    t1 = Table(scan_info, colWidths=[5*cm, 11*cm])
    t1.setStyle(TableStyle([
        ('FONTNAME',      (0,0), (0,-1), FONT_BOLD),
        ('FONTSIZE',      (0,0), (-1,-1), 11),
        ('TEXTCOLOR',     (0,0), (0,-1), C_BLUE),
        ('ROWBACKGROUNDS',(0,0), (-1,-1), [C_LIGHT, colors.white]),
        ('GRID',          (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
        ('TOPPADDING',    (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING',   (0,0), (-1,-1), 12),
    ]))
    elements.append(t1)
    elements.append(Spacer(1, 16))

    # ── 2. Модель ──────────────────────────────────────────
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0')))
    elements.append(Paragraph("2. Модель анализа",
                               _p('h2', FONT_BOLD, 13, '#1f538d', before=12, after=8)))
    model_desc = {
        "Random Forest":    "Supervised. 100 деревьев решений. F1: 1.0000, ROC-AUC: 0.9999",
        "XGBoost":          "Supervised. Градиентный бустинг. F1: 1.0000, ROC-AUC: 1.0000",
        "Isolation Forest": "Unsupervised. Поиск выбросов. F1: 0.0200, ROC-AUC: 0.3258",
        "Ensemble (RF + XGB + ISO)": "Hybrid. Голосование 3 моделей. F1: 1.0000, ROC-AUC: 0.9999",
    }
    desc = model_desc.get(model, "ML модель анализа сетевого трафика")
    model_info = [
        ["Модель:",      model],
        ["Описание:",    desc],
        ["Датасет:",     "CIC-IDS2018 — 1,044,525 записей"],
    ]
    t2 = Table(model_info, colWidths=[5*cm, 11*cm])
    t2.setStyle(TableStyle([
        ('FONTNAME',      (0,0), (0,-1), FONT_BOLD),
        ('FONTSIZE',      (0,0), (-1,-1), 11),
        ('TEXTCOLOR',     (0,0), (0,-1), C_BLUE),
        ('ROWBACKGROUNDS',(0,0), (-1,-1), [C_LIGHT, colors.white]),
        ('GRID',          (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
        ('TOPPADDING',    (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING',   (0,0), (-1,-1), 12),
    ]))
    elements.append(t2)
    elements.append(Spacer(1, 16))

    # ── 3. Результаты ──────────────────────────────────────
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0')))
    elements.append(Paragraph("3. Результаты",
                               _p('h3', FONT_BOLD, 13, '#1f538d', before=12, after=8)))

    # Карточки
    cards = [
        [Paragraph(f"<b>{total:,}</b>", _p('cv', FONT_BOLD, 18, '#1f538d', align=1)),
         Paragraph(f"<b>{normal:,}</b>", _p('cv', FONT_BOLD, 18, '#2dc97e', align=1)),
         Paragraph(f"<b>{anomaly:,}</b>", _p('cv', FONT_BOLD, 18, '#e74c3c', align=1)),
         Paragraph(f"<b>{pct:.1f}%</b>", _p('cv', FONT_BOLD, 18, t_hex, align=1))],
        [Paragraph("Всего", _p('cl', FONT, 9, '#64748b', align=1)),
         Paragraph("Нормальных", _p('cl', FONT, 9, '#64748b', align=1)),
         Paragraph("Аномалий", _p('cl', FONT, 9, '#64748b', align=1)),
         Paragraph("Доля аномалий", _p('cl', FONT, 9, '#64748b', align=1))],
    ]
    ct = Table(cards, colWidths=[4*cm, 4*cm, 4*cm, 4*cm])
    ct.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (0,-1), colors.HexColor('#e8f0ff')),
        ('BACKGROUND',    (1,0), (1,-1), colors.HexColor('#e8fff0')),
        ('BACKGROUND',    (2,0), (2,-1), colors.HexColor('#ffe8e8')),
        ('BACKGROUND',    (3,0), (3,-1), colors.HexColor('#fff8e8')),
        ('BOX',           (0,0), (0,-1), 1, C_BLUE),
        ('BOX',           (1,0), (1,-1), 1, C_GREEN),
        ('BOX',           (2,0), (2,-1), 1, C_RED),
        ('BOX',           (3,0), (3,-1), 1, C_ORANGE),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('ALIGN',         (0,0), (-1,-1), 'CENTER'),
    ]))
    elements.append(ct)
    elements.append(Spacer(1, 16))

    # Pie chart
    drawing = Drawing(480, 140)
    pie = Pie()
    pie.x, pie.y = 20, 5
    pie.width = pie.height = 120
    pie.data   = [max(normal, 1), max(anomaly, 1)]
    pie.labels = ['', '']
    pie.slices[0].fillColor   = C_GREEN
    pie.slices[1].fillColor   = C_RED
    pie.slices[0].strokeColor = colors.white
    pie.slices[1].strokeColor = colors.white
    if anomaly > 0:
        pie.slices[1].popout = 8
    drawing.add(pie)
    drawing.add(Rect(195, 100, 12, 12, fillColor=C_GREEN, strokeColor=None))
    drawing.add(String(213, 102, f'Нормальные: {normal:,} ({100-pct:.1f}%)',
                       fontName=FONT, fontSize=10, fillColor=colors.HexColor('#333333')))
    drawing.add(Rect(195, 78, 12, 12, fillColor=C_RED, strokeColor=None))
    drawing.add(String(213, 80, f'Аномалии: {anomaly:,} ({pct:.1f}%)',
                       fontName=FONT, fontSize=10, fillColor=colors.HexColor('#333333')))
    elements.append(drawing)
    elements.append(Spacer(1, 10))

    # Итог угрозы
    threat_bg = {'ВЫСОКАЯ': '#2a0000', 'СРЕДНЯЯ': '#2a1a00', 'НИЗКАЯ': '#002a0d'}.get(threat, '#1a1a2e')
    threat_box = Table(
        [[Paragraph(f"Уровень угрозы: {threat}",
                     _p('tb', FONT_BOLD, 14, t_hex, align=1))]],
        colWidths=[16*cm])
    threat_box.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), colors.HexColor(threat_bg)),
        ('BOX',           (0,0), (-1,-1), 2, t_col),
        ('TOPPADDING',    (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
    ]))
    elements.append(threat_box)

    # Топ порты если есть
    if ports:
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("Атакованные порты:",
                                   _p('hp', FONT_BOLD, 11, '#e74c3c', before=4, after=4)))
        port_rows = [["Порт", "Статус"]]
        for p in ports[:5]:
            port_rows.append([f":{p}", "Подозрительный трафик"])
        pt = Table(port_rows, colWidths=[3*cm, 13*cm])
        pt.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0), colors.HexColor('#7a1e1e')),
            ('TEXTCOLOR',     (0,0), (-1,0), colors.white),
            ('FONTNAME',      (0,0), (-1,0), FONT_BOLD),
            ('FONTNAME',      (0,1), (-1,-1), FONT),
            ('FONTSIZE',      (0,0), (-1,-1), 10),
            ('ROWBACKGROUNDS',(0,1), (-1,-1), [colors.HexColor('#fff0f0'), colors.white]),
            ('GRID',          (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
            ('TOPPADDING',    (0,0), (-1,-1), 7),
            ('BOTTOMPADDING', (0,0), (-1,-1), 7),
            ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ]))
        elements.append(pt)

    # ── Подвал ─────────────────────────────────────────────
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=C_BLUE))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        f"RootkitGuard v2.1  ·  МУИТ  ·  Алматы  ·  {YEAR}  ·  {', '.join(['Амангелды Манас', 'Курманов Искандер', 'Куанышбек Бекарыс'])}  ·  Рук. {SUPERVISOR}",
        _p('ft', FONT, 8, '#64748b', align=1)))

    doc.build(elements)
    return output_path

if __name__ == "__main__":
    generate_pdf_report({
        'total_rows': 2000, 'anomalies': 600, 'normal': 1400,
        'pct': 30.0, 'threat': 'ВЫСОКАЯ',
        'top_ports': [1433, 445, 6666],
        'filename': 'test_with_threats.csv',
        'timestamp': '2026-05-30 19:00:00',
        'model': 'Random Forest',
    })
    print("Done")
