"""Build the Persian (RTL) defense presentation from the evaluated benchmark results.

All numbers are read from the result files under ``results/`` so the deck cannot
drift away from the actual measurements.

Usage:
    python scripts/make_presentation.py [--out thesis/defense-presentation.pptx]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor
from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt

ROOT = Path(__file__).resolve().parent.parent

FONT = "Tahoma"

INK = RGBColor(0x1B, 0x26, 0x3B)
ACCENT = RGBColor(0x0F, 0x62, 0x8B)
ACCENT_LIGHT = RGBColor(0xE3, 0xEF, 0xF6)
GOOD = RGBColor(0x1B, 0x7F, 0x5A)
WARN = RGBColor(0xB4, 0x54, 0x1E)
MUTED = RGBColor(0x6B, 0x74, 0x84)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)
MARGIN = Inches(0.62)
CONTENT_W = SLIDE_W - 2 * MARGIN

EXPERIMENTS = [
    ("A", "exp_A_static_subset600.json", "تحلیل ایستا", False),
    ("B", "exp_B_llm_only_eval600.json", "عامل زبانی", False),
    ("C", "exp_C_static_llm_subset600.json", "ایستا + عامل", False),
    ("D", "exp_D_static_structural_llm_subset600.json", "ایستا + ساختار + عامل", True),
]


def fa(value: float, digits: int = 3) -> str:
    """Format a number with Persian decimal separator and Persian digits."""
    text = f"{value:.{digits}f}".translate(str.maketrans("0123456789.", "۰۱۲۳۴۵۶۷۸۹٫"))
    return text


def pct(value: float, digits: int = 1) -> str:
    return fa(value * 100, digits) + "٪"


def set_rtl(paragraph) -> None:
    """Mark a paragraph right-to-left so Persian renders and aligns correctly."""
    p_pr = paragraph._p.get_or_add_pPr()
    p_pr.set("rtl", "1")
    p_pr.set("algn", "r")


def add_text(
    slide,
    text: str,
    *,
    size: float = 18,
    bold: bool = False,
    color: RGBColor = INK,
    align: PP_ALIGN = PP_ALIGN.RIGHT,
    space_after: float = 6,
    line_spacing: float = 1.35,
    top: float = 0.4,
):
    box = slide.shapes.add_textbox(MARGIN, Inches(top), CONTENT_W, Inches(1))
    frame = box.text_frame
    frame.word_wrap = True
    paragraph = frame.paragraphs[0]
    set_rtl(paragraph)
    paragraph.alignment = align
    paragraph.line_spacing = line_spacing
    paragraph.space_after = Pt(space_after)
    run = paragraph.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color
    run.font.name = FONT
    return box


def add_bullets(
    slide,
    items: list[str],
    *,
    top: float = 1.5,
    size: float = 17,
    height: float = 4.6,
    color: RGBColor = INK,
):
    height = min(height, SLIDE_H - Inches(top) - Inches(0.35))
    box = slide.shapes.add_textbox(MARGIN, Inches(top), CONTENT_W, height)
    frame = box.text_frame
    frame.word_wrap = True
    for index, item in enumerate(items):
        paragraph = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        set_rtl(paragraph)
        paragraph.line_spacing = 1.4
        paragraph.space_after = Pt(12)
        run = paragraph.add_run()
        run.text = "•  " + item
        run.font.size = Pt(size)
        run.font.color.rgb = color
        run.font.name = FONT
    return box


def blank_slide(prs: Presentation):
    return prs.slides.add_slide(prs.slide_layouts[6])


def add_header(slide, title: str, kicker: str | None = None) -> None:
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, Inches(1.02))
    bar.fill.solid()
    bar.fill.fore_color.rgb = ACCENT
    bar.line.fill.background()
    bar.shadow.inherit = False

    box = slide.shapes.add_textbox(MARGIN, Inches(0.16), CONTENT_W, Inches(0.72))
    frame = box.text_frame
    frame.word_wrap = True
    frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    paragraph = frame.paragraphs[0]
    set_rtl(paragraph)
    run = paragraph.add_run()
    run.text = title
    run.font.size = Pt(27)
    run.font.bold = True
    run.font.color.rgb = WHITE
    run.font.name = FONT

    if kicker:
        kick = slide.shapes.add_textbox(MARGIN, Inches(1.06), CONTENT_W, Inches(0.4))
        k_frame = kick.text_frame
        k_frame.word_wrap = True
        k_para = k_frame.paragraphs[0]
        set_rtl(k_para)
        k_run = k_para.add_run()
        k_run.text = kicker
        k_run.font.size = Pt(14)
        k_run.font.color.rgb = MUTED
        k_run.font.name = FONT


def add_footer(slide, number: int) -> None:
    box = slide.shapes.add_textbox(MARGIN, SLIDE_H - Inches(0.52), CONTENT_W, Inches(0.32))
    frame = box.text_frame
    paragraph = frame.paragraphs[0]
    paragraph.alignment = PP_ALIGN.LEFT
    run = paragraph.add_run()
    run.text = str(number)
    run.font.size = Pt(11)
    run.font.color.rgb = MUTED
    run.font.name = FONT


def add_note(slide, text: str) -> None:
    """Speaker note (kept short: these are read aloud, not read from the screen)."""
    slide.notes_slide.notes_text_frame.text = text


def add_table(
    slide,
    headers: list[str],
    rows: list[list[str]],
    *,
    top: float = 1.7,
    left: float = 0.62,
    width: float = 12.09,
    height: float = 3.2,
    font_size: float = 14,
    highlight_row: int | None = None,
):
    shape = slide.shapes.add_table(
        len(rows) + 1, len(headers), Inches(left), Inches(top), Inches(width), Inches(height)
    )
    table = shape.table
    table.first_row = True

    for column, header in enumerate(headers):
        cell = table.cell(0, column)
        cell.fill.solid()
        cell.fill.fore_color.rgb = ACCENT
        cell.text_frame.word_wrap = True
        paragraph = cell.text_frame.paragraphs[0]
        set_rtl(paragraph)
        run = paragraph.add_run()
        run.text = header
        run.font.size = Pt(font_size)
        run.font.bold = True
        run.font.color.rgb = WHITE
        run.font.name = FONT

    for r, row in enumerate(rows, start=1):
        for c, value in enumerate(row):
            cell = table.cell(r, c)
            cell.fill.solid()
            if highlight_row is not None and r - 1 == highlight_row:
                cell.fill.fore_color.rgb = ACCENT_LIGHT
            else:
                cell.fill.fore_color.rgb = WHITE if r % 2 else RGBColor(0xF6, 0xF8, 0xFA)
            cell.text_frame.word_wrap = True
            paragraph = cell.text_frame.paragraphs[0]
            set_rtl(paragraph)
            run = paragraph.add_run()
            run.text = value
            run.font.size = Pt(font_size)
            run.font.bold = highlight_row is not None and r - 1 == highlight_row
            run.font.color.rgb = INK
            run.font.name = FONT

    return table


def add_chart(
    slide,
    categories: list[str],
    series: list[tuple[str, list[float]]],
    *,
    top: float = 1.6,
    height: float = 4.9,
    number_format: str = "0.0",
    max_scale: float | None = None,
):
    data = CategoryChartData()
    data.categories = categories
    for name, values in series:
        data.add_series(name, values)
    frame = slide.shapes.add_chart(
        XL_CHART_TYPE.COLUMN_CLUSTERED,
        MARGIN,
        Inches(top),
        CONTENT_W,
        Inches(height),
        data,
    )
    chart = frame.chart
    chart.has_title = False
    chart.has_legend = True
    chart.legend.position = XL_LEGEND_POSITION.TOP
    chart.legend.include_in_layout = False
    chart.font.size = Pt(13)
    chart.font.name = FONT

    plot = chart.plots[0]
    plot.gap_width = 60
    plot.has_data_labels = True
    labels = plot.data_labels
    labels.number_format = number_format
    labels.number_format_is_linked = False
    labels.font.size = Pt(11)
    labels.font.name = FONT

    value_axis = chart.value_axis
    value_axis.maximum_scale = max_scale
    value_axis.has_major_gridlines = True
    value_axis.tick_labels.font.size = Pt(11)
    value_axis.tick_labels.font.name = FONT
    return chart


def style_chart_text(chart) -> None:
    for axis in (chart.category_axis, chart.value_axis):
        axis.tick_labels.font.name = FONT
        axis.tick_labels.font.size = Pt(12)


def add_box(slide, text: str, left: float, top: float, width: float, height: float, *, fill=ACCENT_LIGHT, size=14, bold=False, color=INK):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height)
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    shape.line.color.rgb = ACCENT
    shape.line.width = Pt(1)
    shape.shadow.inherit = False
    frame = shape.text_frame
    frame.word_wrap = True
    frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    paragraph = frame.paragraphs[0]
    set_rtl(paragraph)
    paragraph.alignment = PP_ALIGN.CENTER
    run = paragraph.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color
    run.font.name = FONT
    return shape


def add_arrow(slide, left: float, top: float, width: float = 0.5, height: float = 0.34):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.LEFT_ARROW, Inches(left), Inches(top), Inches(width), Inches(height)
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = MUTED
    shape.line.fill.background()
    shape.shadow.inherit = False
    return shape


def load_results() -> dict:
    results = {}
    for key, filename, label, _ in EXPERIMENTS:
        path = ROOT / "results" / filename
        if not path.exists():
            raise SystemExit(f"missing result file: {path}")
        data = json.loads(path.read_text())
        sample = data["metadata"]["sample_level"]
        results[key] = {
            "label": label,
            "confusion": data["metrics"]["confusion"],
            "precision": data["metrics"]["precision"],
            "recall": data["metrics"]["recall"],
            "f1": data["metrics"]["f1"],
            "benign_flag_rate": sample["benign_flag_rate"],
            "detection_rate": sample["vulnerable_detection_rate"],
            "per_cwe": {
                cwe: {
                    "precision": values["precision"],
                    "recall": values["recall"],
                    "f1": values["f1"],
                }
                for cwe, values in data["per_cwe"].items()
            },
        }
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(ROOT / "thesis" / "defense-presentation.pptx"))
    args = parser.parse_args()

    res = load_results()
    A, B, C, D = (res[key] for key in "ABCD")

    prs = Presentation()
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H

    n = 0

    # ---------------------------------------------------------------- title
    slide = blank_slide(prs)
    band = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, Inches(2.55))
    band.fill.solid()
    band.fill.fore_color.rgb = ACCENT
    band.line.fill.background()
    band.shadow.inherit = False
    add_text(
        slide,
        "ترکیب تحلیل ساختاری کد با استدلال مدل‌های زبانی بزرگ",
        size=30,
        bold=True,
        color=WHITE,
    )
    add_text(
        slide,
        "و معماری چندعامله برای کاهش هشدارهای کاذب",
        size=24,
        color=ACCENT_LIGHT,
        top=2.75,
    )
    add_text(
        slide,
        "دانشکده مهندسی کامپیوتر، دانشگاه صنعتی امیرکبیر",
        size=15,
        color=MUTED,
        top=4.35,
    )
    add_text(
        slide,
        "نگارنده: علی ناصری‌نیا (۴۰۱۳۱۰۵۳)\nاستاد راهنما: حمیدرضا شهریاری‌کاهکشی        نیمسال اول ۱۴۰۴",
        size=16,
        color=INK,
        top=4.85,
    )
    add_note(slide, "معرفی خود و طرح کلی کار در یک دقیقه.")

    # ------------------------------------------------------------- roadmap
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "سرفصل‌های ارائه")
    add_bullets(
        slide,
        [
            "مسئله: هشدار نادرست در تحلیل ایستا و هزینهٔ آن",
            "پرسش‌های پژوهش",
            "معماری سه‌فاز سامانهٔ پیشنهادی",
            "طراحی ارزیابی و مجموعه‌داده",
            "نتایج و پاسخ به پرسش‌ها",
            "محدودیت‌ها و کارهای آینده",
        ],
        top=1.5,
        size=19,
    )
    add_footer(slide, n)
    add_note(slide, "نقشهٔ راه ارائه؛ حدود ۱۵ دقیقه.")

    # ------------------------------------------------------------- problem
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "مسئله: هشدار نادرست", "چرا ابزارهای تحلیل ایستا را کنار می‌گذاریم؟")
    add_bullets(
        slide,
        [
            "هر ابزار تحلیل ایستا میان سه دسته باید تمایز بگذارد: هشدار درست، هشدار نادرست و از دست رفتن آسیب‌پذیری.",
            "هشدار نادرست یعنی ابزار محلی را معرفی کرده که در واقع ایرادی ندارد یا مسیر آن هرگز اجرا نمی‌شود.",
            "خروجی بسیار زیاد هشدار نادرست، اعتماد توسعه‌دهنده را از بین می‌برد و در نهایت ابزار کنار گذاشته می‌شود.",
            "راه‌حل باید توان کشف را حفظ کند، نه این‌که صرفاً هشدارها را حذف کند.",
        ],
        top=1.65,
        size=18,
    )
    add_box(
        slide,
        f"خط پایهٔ ما: نرخ هشدار روی فایل سالم {pct(A['benign_flag_rate'])} و تنها {pct(A['detection_rate'])} یادآوری",
        0.62,
        5.9,
        12.09,
        0.85,
        fill=ACCENT_LIGHT,
        size=16,
        bold=True,
    )
    add_footer(slide, n)
    add_note(slide, "تعریف هشدار نادرست و هزینهٔ واقعی آن برای تیم توسعه. عدد پایین یادآوری را اینجا معرفی کنید.")

    # ------------------------------------------------------------ why llm
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "چرا عامل زبانی؟ و چرا به‌تنهایی نه؟")
    add_box(
        slide,
        "عامل زبانی\nدرک معنایی از کد و زمینهٔ اجرا",
        0.62,
        1.75,
        5.85,
        1.5,
        size=17,
        bold=True,
    )
    add_box(
        slide,
        "اما به‌تنهایی قابل اتکا نیست\nاحتمال توهم، نشت برچسب و ناپایداری داوری",
        6.86,
        1.75,
        5.85,
        1.5,
        fill=RGBColor(0xFA, 0xEC, 0xE3),
        size=17,
        bold=True,
    )
    add_bullets(
        slide,
        [
            "قواعد صرفاً نحوی، معنای داده را نمی‌بینند؛ تحلیل جریان داده گران است و همچنان ناقص.",
            "مدل زبانی می‌تواند بپرسد آیا مسیر داده واقعاً قابل دسترس است و آیا نام تابع فراخوان با الگوی خطرناک هم‌خوان است.",
            "راه‌حل: نه جایگزینی ابزار، بلکه داوری مبتنی بر شواهدِ همان ابزارها.",
        ],
        top=3.55,
        size=17,
    )
    add_footer(slide, n)
    add_note(slide, "موضع پژوهش: عامل زبانی داور است، نه ابزار کشف.")

    # ----------------------------------------------------------------- RQs
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "پرسش‌های پژوهش")
    questions = [
        ("پرسش ۱", "آیا بازبینی مبتنی بر شواهد، هشدارهای نادرست تحلیل ایستا را کاهش می‌دهد؟"),
        ("پرسش ۲", "بهای این کاهش از نظر یادآوری چقدر است؟"),
        ("پرسش ۳", "افزودن شواهد ساختاری، اثر بازبینی را بهبود می‌دهد؟"),
        ("پرسش ۴", "هر یک از سه مؤلفه به‌تنهایی و در ترکیب با یکدیگر چه تصویری از منحنی مبادلهٔ دقت و یادآوری می‌دهند؟"),
    ]
    for index, (tag, text) in enumerate(questions):
        top = 1.65 + index * 1.22
        add_box(slide, tag, 10.6, top, 2.1, 0.85, fill=ACCENT, size=15, bold=True, color=WHITE)
        add_box(slide, text, 0.62, top, 9.8, 0.85, size=15)
    add_footer(slide, n)
    add_note(slide, "چهار پرسشی که کل فصل چهارم پاسخ می‌دهد.")

    # ----------------------------------------------------------- architecture
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "معماری سامانه", "سه فاز، از فایل خام تا گزارش نهایی")
    phases = [
        (
            "فاز ۱",
            "تحلیل ایستا و ساختاری",
            "cppcheck · Flawfinder · Clang\nTree-sitter: گره، ارجاع، پارامتر",
            0.62,
        ),
        (
            "فاز ۲",
            "بازیابی مسیر داده",
            "اثر انگشت یافته\nمسیر منبع ⟵ مجری (درون‌روشی)",
            4.86,
        ),
        (
            "فاز ۳",
            "داوری چندعامله",
            "Scanner: فرضیه\nVerifier: تأیید / رد",
            9.1,
        ),
    ]
    for tag, title, body, left in phases:
        add_box(slide, tag, left, 1.9, 3.6, 0.6, fill=ACCENT, size=14, bold=True, color=WHITE)
        add_box(slide, title, left, 2.55, 3.6, 0.75, fill=ACCENT_LIGHT, size=16, bold=True)
        add_box(slide, body, left, 3.35, 3.6, 1.35, fill=WHITE, size=13)
    add_arrow(slide, 4.3, 2.75)
    add_arrow(slide, 8.55, 2.75)
    add_bullets(
        slide,
        [
            "بستهٔ شواهد هر فرضیه پیش از داوری ساخته می‌شود: مسیر منبع-مجری، یافتهٔ ابزارهای مجاور، و قطعهٔ کد.",
            "خروجی نهایی: تنها یافته‌های تأییدشده، همراه با شواهد — نه فهرست طولانی هشدارها.",
        ],
        top=5.05,
        size=17,
    )
    add_footer(slide, n)
    add_note(
        slide,
        "برای هر فاز حدود یک دقیقه؛ روی جریان داده و تفکیک نقش Scanner از Verifier تأکید کنید.",
    )

    # ------------------------------------------------------------- phase 1
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "فاز ۱: تحلیل ایستا", "خط پایهٔ سامانه")
    add_bullets(
        slide,
        [
            "سه ابزار مستقل به‌صورت موازی روی هر فایل اجرا می‌شوند؛ انتخاب ابزارها پوشش‌های مکمل دارد: قواعد الگویی، تخصیص حافظه و تحلیل مسیر.",
            "محدودیت ذاتی: این ابزارها با قواعد الگویی کار می‌کنند، پس تنها بخشی از سناریوها را فعال می‌کنند.",
            f"نتیجه روی ۶۰۰ نمونه: تنها ۳۱ یافتهٔ خام از ۲۹ فایل — یادآوری {pct(A['detection_rate'])}.",
            "همین محدودیت، سقف یادآوری سامانهٔ مبتنی بر تحلیل ایستا را تعیین می‌کند؛ سقفی که از توان داوری سامانه مستقل است.",
        ],
        top=1.75,
        size=18,
    )
    add_footer(slide, n)
    add_note(slide, "نکتهٔ کلیدی: یادآوری پایینِ تحلیل ایستا نقص سامانه نیست، ویژگی ابزار است.")

    # ------------------------------------------------------------- phase 2
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "فاز ۲: نرمال‌سازی و همبسته‌سازی یافته‌ها")
    add_bullets(
        slide,
        [
            "ادغام یافته‌های تکراری با اثر انگشت و تطبیق خط: سه ابزار یک ایراد را گاهی با سه زبان متفاوت گزارش می‌کنند.",
            "هر گروه، یک نقطهٔ ضعف واحد را نمایندگی می‌کند و نمایندهٔ گروه می‌شود.",
            "گروه‌هایی که شواهد کافی ندارند، بدون هزینهٔ داوری کنار گذاشته می‌شوند.",
            "نتیجه: به‌جای ده‌ها هشدار پراکنده، چند گروه قابل بازبینی.",
        ],
        top=1.75,
        size=18,
    )
    add_box(
        slide,
        "۳۱ یافتهٔ خام  ⟵  ۳۱ گروه بازبینی  ⟵  داوری یک‌بارهٔ هر گروه توسط عامل زبانی",
        0.62,
        5.75,
        12.09,
        0.85,
        size=16,
        bold=True,
    )
    add_footer(slide, n)
    add_note(slide, "ادغام، هزینهٔ داوری را کم می‌کند و نمایندهٔ گروه را تعیین می‌کند.")

    # ------------------------------------------------------------- phase 3
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "فاز ۳: داوری چندعامله", "Scanner → Verifier")
    add_bullets(
        slide,
        [
            "Scanner: فرضیه‌های منبع-مجری را بر پایهٔ شواهد ساختاری و یافته‌های ابزارهای ایستا تولید می‌کند.",
            "Verifier: هر فرضیه را با بستهٔ شواهد می‌پذیرد و تنها در صورت تأیید زنجیرهٔ منبع-مجری (chain_verified=True) آن را تأیید می‌کند.",
            "بودجهٔ فرضیه و آستانهٔ اعتماد Verifier، کنترل دقت و هزینه را ممکن می‌سازند.",
            "خروجی نهایی: یافته‌های تأییدشده، همراه با دلیل و شواهد؛ فرضیه‌های ردشده ثبت و گزارش می‌شوند.",
        ],
        top=1.7,
        size=17,
    )
    labels = [
        ("تأیید شده", "شاهد کافی برای وجود زنجیرهٔ داده", GOOD),
        ("رد شده", "شاهد کافی برای بی‌خطر بودن مسیر", MUTED),
        ("عدم قطعیت", "شاهد ناکافی؛ نیازمند بررسی انسانی", WARN),
    ]
    for index, (name, desc, color) in enumerate(labels):
        left = 0.62 + index * 4.1
        add_box(slide, name, left, 4.35, 3.85, 0.65, fill=color, size=16, bold=True, color=WHITE)
        add_box(slide, desc, left, 5.05, 3.85, 1.0, fill=WHITE, size=13)
    add_footer(slide, n)
    add_note(slide, "تفکیک نقش‌ها باعث می‌شود Verifier نتواند صرفاً بر اساس عنوان هشدار قضاوت کند.")

    # ------------------------------------------------------- sanitization
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "جلوگیری از نشت برچسب", "چالش اعتبار ارزیابی")
    add_bullets(
        slide,
        [
            "در مجموعه‌دادهٔ جولیت، برچسب در نام فایل و نام توابع وجود دارد؛ متنی مثل badSink یا 73b_bad.",
            "اگر این نشانه‌ها به مدل داده شود، کیفیت بازبینی به‌طور مصنوعی بالا می‌رود و نتیجه بی‌معنا می‌شود.",
            "راه‌حل: ماژول پاک‌سازی کد که پیش از هر بازبینی اجرا می‌شود.",
        ],
        top=1.7,
        size=18,
    )
    add_box(
        slide,
        "پاک‌سازی: حذف حاشیه‌نویسی‌ها · بازنام‌گذاری شناسه‌های افشاگر · حذف برچسب از نام فایل — بدون تغییر شمارهٔ خط گزارش ابزارها",
        0.62,
        4.35,
        12.09,
        0.95,
        size=15,
        bold=True,
    )
    add_box(
        slide,
        "حفظ شمارهٔ خط، شرط لازم تطبیق یافته‌ها با برچسب واقعی است؛ پس این محدودیت از خودِ طراحی سامانه می‌آید، نه از ضعف روش.",
        0.62,
        5.55,
        12.09,
        0.9,
        fill=RGBColor(0xFA, 0xEC, 0xE3),
        size=14,
    )
    add_footer(slide, n)
    add_note(slide, "این اسلاید اعتبار نتایج را توضیح می‌دهد؛ اگر پرسشی دربارهٔ نشت برچسب آمد، به همین اسلاید برگردید.")

    # ------------------------------------------------------------ setup
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "طراحی ارزیابی", "یک جمعیت یکسان برای هر چهار پیکربندی")
    add_bullets(
        slide,
        [
            "زیرمجموعهٔ لایه‌بندی‌شده از جولیت با بذر ثابت: ۶۰۰ فایل = ۳۰۰ آسیب‌پذیر و ۳۰۰ سالم، در دو نوع سرریز بافر و سرریز عدد صحیح.",
            "این ۶۰۰ فایل تقریباً نیمی C و نیمی ++C است؛ گزارش نتایج به تفکیک زبان ارائه می‌شود.",
            "از هر لایه (نوع آسیب‌پذیری × برچسب) دقیقاً ۱۵۰ نمونه.",
            "چهار پیکربندی، یک متغیر در هر بار:",
        ],
        top=1.65,
        size=17,
        height=2.0,
    )
    add_table(
        slide,
        ["پیکربندی", "مؤلفه‌ها", "پرسشی که پاسخ می‌دهد"],
        [
            ["A", "تحلیل ایستا", "خط پایهٔ ابزارها"],
            ["B", "عامل زبانی تنها", "توان عامل بدون کمک ابزار"],
            ["C", "ایستا + عامل", "اثر بازبینی مبتنی بر شواهد"],
            ["D", "ایستا + ساختار + عامل", "اثر افزودن شواهد ساختاری"],
        ],
        top=3.85,
        height=2.4,
        font_size=15,
    )
    add_footer(slide, n)
    add_note(slide, "تأکید کنید که مقایسه روی جمعیت یکسان انجام شده است.")

    # ------------------------------------------------------------- results
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "نتایج اصلی", "۶۰۰ نمونهٔ متعادل · دقت، یادآوری و نرخ هشدار روی فایل سالم")
    chart = add_chart(
        slide,
        ["A · ایستا", "B · عامل", "C · ایستا+عامل", "D · +ساختار"],
        [
            ("دقت", [res[k]["precision"] for k in "ABCD"]),
            ("یادآوری", [res[k]["recall"] for k in "ABCD"]),
            ("نرخ هشدار سالم", [res[k]["benign_flag_rate"] for k in "ABCD"]),
        ],
        number_format="0.000",
        max_scale=0.7,
    )
    style_chart_text(chart)
    add_box(
        slide,
        f"C در برابر A: هشدار نادرست {pct(A['benign_flag_rate'])} ⟵ {pct(C['benign_flag_rate'])} (حدود ۸۷٪ کاهش)، اما یادآوری {pct(A['recall'])} ⟵ {pct(C['recall'])}",
        0.62,
        6.55,
        12.09,
        0.72,
        size=15,
        bold=True,
    )
    add_footer(slide, n)
    add_note(slide, "پیام اصلی: کاهش چشمگیر هشدار نادرست، اما نه بدون هزینه.")

    # ------------------------------------------------------- confusion matrix
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "ماتریس سردرگمی", "دانه‌بندی یافته برای مثبت/منفی، دانه‌بندی فایل برای سالم")
    rows = []
    for key in "ABCD":
        c = res[key]["confusion"]
        rows.append(
            [
                f"{key} · {res[key]['label']}",
                fa(c["tp"]),
                fa(c["fp"]),
                fa(c["fn"]),
                fa(c["tn"]),
            ]
        )
    add_table(
        slide,
        ["پیکربندی", "مثبت درست", "مثبت نادرست", "منفی از دست رفته", "منفی درست"],
        rows,
        top=1.8,
        height=2.6,
        font_size=16,
    )
    add_bullets(
        slide,
        [
            f"B با {fa(B['confusion']['tp'])} مثبت درست، چهار برابر A ({fa(A['confusion']['tp'])}) آسیب‌پذیری یافت؛ چیزهایی که ابزارهای ایستا از آن‌ها غافل‌اند.",
            f"اما {fa(B['confusion']['fp'])} مثبت نادرست، یعنی نرخ هشدار روی فایل سالم {pct(B['benign_flag_rate'])}.",
        ],
        top=4.7,
        size=16,
    )
    add_footer(slide, n)
    add_note(slide, "این جدول مبنای محاسبهٔ معیارهای اسلاید قبل است.")

    # -------------------------------------------------------------- funnel
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "اثر شواهد ساختاری", "چرا تصمیم‌های عامل تغییر کرد؟")
    chart = add_chart(
        slide,
        ["C · بدون ساختار", "D · با ساختار"],
        [
            ("تأیید", [5, 11]),
            ("رد", [13, 14]),
            ("عدم قطعیت", [13, 6]),
        ],
        number_format="0",
        max_scale=16,
        top=1.6,
        height=4.0,
    )
    style_chart_text(chart)
    add_bullets(
        slide,
        [
            "با افزودن شواهد ساختاری، تأییدها بیش از دو برابر و خروجی‌های نامطمئن نصف شدند.",
            f"یادآوری از {pct(C['recall'])} به {pct(D['recall'])} رسید؛ بهای آن، رشد مثبت نادرست از {fa(C['confusion']['fp'])} به {fa(D['confusion']['fp'])} بود.",
            "شواهد بیشتر، عامل را مطمئن‌تر می‌کند و اطمینان بیشتر، هم یافتهٔ درست و هم یافتهٔ نادرست بیشتری تولید می‌کند.",
        ],
        top=5.75,
        size=15,
        height=1.4,
    )
    add_footer(slide, n)
    add_note(slide, "پاسخ پرسش سوم: بله، شواهد ساختاری تصمیم‌گیری را بهبود می‌دهد، اما آستانهٔ اطمینان را جابه‌جا می‌کند.")

    # -------------------------------------------------------------- per-CWE
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "نتایج به تفکیک نوع آسیب‌پذیری", "سرریز بافر (CWE-122) در برابر سرریز عدد صحیح (CWE-190)")
    rows = []
    for key in "ABCD":
        rows.append(
            [
                f"{key} · {res[key]['label']}",
                fa(res[key]["per_cwe"]["CWE-122"]["precision"]),
                fa(res[key]["per_cwe"]["CWE-122"]["recall"]),
                fa(res[key]["per_cwe"]["CWE-190"]["precision"]),
                fa(res[key]["per_cwe"]["CWE-190"]["recall"]),
            ]
        )
    add_table(
        slide,
        ["پیکربندی", "۱۲۲ دقت", "۱۲۲ یادآوری", "۱۹۰ دقت", "۱۹۰ یادآوری"],
        rows,
        top=1.8,
        height=2.5,
        font_size=16,
    )
    add_bullets(
        slide,
        [
            "هیچ پیکربندی مبتنی بر تحلیل ایستا، حتی یک نمونه از ۱۵۰ نمونهٔ سرریز عدد صحیح را کشف نکرد: یادآوری صفر.",
            f"تنها پیکربندی B توانست در این نوع کشف کند: یادآوری {pct(B['per_cwe']['CWE-190']['recall'])} با دقت {pct(B['per_cwe']['CWE-190']['precision'])}.",
            "علت، ماهیت دو نوع آسیب‌پذیری است: سرریز بافر الگوی شناخته‌شده‌ای دارد، اما سرریز عدد صحیح شکست بنیادی در مدل نوع را آشکار می‌کند.",
        ],
        top=4.6,
        size=15,
    )
    add_footer(slide, n)
    add_note(slide, "این مهم‌ترین یافتهٔ تفصیلی کار است.")

    # ------------------------------------------------------------ scale
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "بررسی در مقیاس کامل", "آیا نتیجه وابسته به اندازهٔ نمونه است؟")
    add_bullets(
        slide,
        [
            "پیکربندی A علاوه بر زیرمجموعهٔ ۶۰۰ نمونه‌ای، روی کل ۴۰۹۸ فایل مجموعه‌داده اجرا شد.",
            "نتیجه با مقدار زیرمجموعه هم‌خوان بود: دقت ۰٫۴۱۲، یادآوری ۰٫۰۴۶ و نرخ هشدار سالم ۰٫۰۵۱.",
            "بنابراین محدودیت یادآوری تحلیل ایستا، ویژگی ابزار و مجموعه‌داده است، نه اثر تصادفی نمونه‌گیری.",
        ],
        top=1.9,
        size=18,
    )
    add_box(
        slide,
        "دامنهٔ ارزیابی: A روی ۴۰۹۸ فایل، و A تا D روی ۶۰۰ فایل لایه‌بندی‌شده",
        0.62,
        4.9,
        12.09,
        0.8,
        size=16,
        bold=True,
    )
    add_footer(slide, n)
    add_note(slide, "پاسخ به اعتراض احتمالی دربارهٔ اندازهٔ نمونه.")

    # ------------------------------------------------------------- answers
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "پاسخ به پرسش‌های پژوهش")
    rows = [
        [
            "پرسش ۱",
            "بله",
            f"نرخ هشدار سالم {pct(A['benign_flag_rate'])} ⟵ {pct(C['benign_flag_rate'])}؛ حدود ۸۷٪ کاهش و دقت {fa(A['precision'])} ⟵ {fa(C['precision'])}",
        ],
        [
            "پرسش ۲",
            "قابل توجه",
            f"یادآوری از {pct(A['recall'])} به {pct(C['recall'])}؛ از {fa(A['confusion']['tp'])} مثبت درست، تنها {fa(C['confusion']['tp'])} مورد باقی ماند",
        ],
        [
            "پرسش ۳",
            "بله",
            f"تأییدها ۵ ⟵ ۱۱ و یادآوری {pct(C['recall'])} ⟵ {pct(D['recall'])}، به بهای رشد مثبت نادرست",
        ],
        [
            "پرسش ۴",
            "نقطهٔ کاری",
            "هیچ پیکربندی برتری مطلق ندارد؛ هر یک نقطهٔ متفاوتی از منحنی مبادلهٔ دقت و یادآوری است",
        ],
    ]
    add_table(
        slide,
        ["", "پاسخ", "شاهد عددی"],
        rows,
        top=1.75,
        height=4.0,
        font_size=14,
    )
    add_footer(slide, n)
    add_note(slide, "این اسلاید، خلاصهٔ کل ارائه است؛ روی آن مکث کنید.")

    # ------------------------------------------------- independent evidence
    n += 1
    slide = blank_slide(prs)
    add_header(
        slide,
        "شواهد روی کد واقعی",
        "مجموعه‌دادهٔ دیویگن: ۲۷٬۲۵۸ تابع C از qemu و FFmpeg",
    )
    add_bullets(
        slide,
        [
            "تا اینجا همهٔ ارزیابی روی جولیت بود؛ قالب‌های تولیدشده و نه کد واقعی.",
            "دیویگن کد واقعی پروژه‌هاست: هر تابع با برچسب «در یک وصلهٔ امنیتی دست‌کاری شده».",
            "برای پرهیز از آلودگی ارزیابی، هر ۲۷٬۲۵۸ تابع از پاک‌سازی عبور داده شد؛ هیچ نشانهٔ برچسبی باقی نماند.",
        ],
        top=1.7,
        size=17,
    )
    add_table(
        slide,
        ["پیکربندی", "TP", "FP", "FN", "TN", "دقت", "یادآوری", "نرخ هشدار"],
        [
            ["مسیر بدون کنترل", "861", "783", "11564", "14050", "0.524", "0.069", "0.053"],
            ["فلاوندر (۶۰۰ متعادل)", "6", "11", "294", "289", "0.353", "0.020", "0.037"],
            ["اتحاد دو روش", "20", "29", "280", "271", "0.408", "0.067", "0.097"],
        ],
        top=3.9,
        height=2.1,
        font_size=13,
    )
    add_box(
        slide,
        "شواهد منبع-مجری حدود ۲٫۸ برابر یادآوری فلاوندر را با دقتی بالاتر و بدون هیچ فراخوانی مدل به دست می‌آورد.",
        0.62,
        6.35,
        12.09,
        0.75,
        size=15,
        bold=True,
    )
    add_footer(slide, n)
    add_note(
        slide,
        "یادآوری پایین است و باید صادقانه گفته شود: برچسب دیویگن بسیار گسترده‌تر از "
        "جریان‌های داده‌ای است که این موتور مدل می‌کند. عدد معنادار، دقت و مقایسه با فلاوندر است.",
    )

    # --------------------------------------------------------- limitations
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "محدودیت‌ها")
    add_bullets(
        slide,
        [
            "اندازهٔ نمونه: تعداد یافته‌های درست در پیکربندی‌های ترکیبی کوچک است (۳ تا ۵)، پس نرخ‌ها حساس‌اند.",
            "مجموعه‌داده: کد جولیت قالب‌محور و کوتاه است؛ ارزیابی روی دیویگن همین ضعف را تا حدی جبران می‌کند اما برچسب آن نیز پرلایه است.",
            "موتور مسیر درون‌روشی است؛ پیوند میان توابع هنوز پیاده‌سازی نشده است.",
            "مدل: ارزیابی تنها روی یک مدل زبانی انجام شده و تعمیم نیازمند آزمایش تکمیلی است.",
            "سیاست تطبیق: چون برچسب خط در مجموعه‌داده ثبت نشده، تطبیق بر پایهٔ فایل و خانوادهٔ CWE است و تا حدی سخاوتمندانه.",
        ],
        top=1.75,
        size=16,
    )
    add_box(
        slide,
        "این محدودیت‌ها جهت‌گیری کارهای آینده را مشخص می‌کنند.",
        0.62,
        5.9,
        12.09,
        0.75,
        size=15,
        bold=True,
    )
    add_footer(slide, n)
    add_note(slide, "محدودیت‌ها را صادقانه بیان کنید؛ این نشانهٔ تسلط بر کار است.")

    # ------------------------------------------------------------- future
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "کارهای آینده")
    add_bullets(
        slide,
        [
            "بستهٔ شواهد به‌جای قطعهٔ ثابت کد، مسیر دادهٔ میان منبع و نقطهٔ خطر را بدهد؛ گلوگاه اصلی همین است.",
            "استفاده از خروجی نامطمئن به‌جای دور انداختن آن: ۴۲٪ گروه‌ها در C نامطمئن بودند و این یعنی سیگنال از دست‌رفته.",
            "تنظیم نقطهٔ کاری بر پایهٔ هزینهٔ نسبی خطا، با آستانهٔ متفاوت برای تأیید.",
            "ارزیابی روی مجموعه‌داده‌های دیگر و کد واقعی بلندتر با وابستگی بین‌فایلی.",
            "توسعهٔ بازبینی تک‌مرحله‌ای به عامل چندمرحله‌ای با ابزار پرس‌وجو.",
        ],
        top=1.75,
        size=17,
    )
    add_footer(slide, n)
    add_note(slide, "مسیر روشن و مبتنی بر یافته‌ها.")

    # ---------------------------------------------------------- conclusion
    n += 1
    slide = blank_slide(prs)
    add_header(slide, "جمع‌بندی")
    add_box(
        slide,
        "بازبینی مبتنی بر شواهد، هشدارهای نادرست تحلیل ایستا را به‌طور چشمگیری کاهش می‌دهد، اما این کاهش رایگان نیست؛ افزودن شواهد ساختاری این مبادله را به نقطهٔ کاری متعادل‌تری می‌رساند.",
        0.62,
        1.8,
        12.09,
        1.35,
        size=18,
        bold=True,
    )
    add_bullets(
        slide,
        [
            f"کاهش {pct(1 - C['benign_flag_rate'] / A['benign_flag_rate'], 0)} هشدار نادرست با دقت بالاتر ({fa(C['precision'])} در برابر {fa(A['precision'])}).",
            f"افزودن شواهد ساختاری: یادآوری {pct(C['recall'])} ⟵ {pct(D['recall'])} و تأییدها ۵ ⟵ ۱۱.",
            "پوشش هیچ ابزار ایستایی به‌تنهایی کافی نیست: صفر یافته در سرریز عدد صحیح.",
            "خروجی سامانه، گزارشی است که برای هر یافته دلیل و شاهد می‌آورد؛ نه فهرست طولانی هشدارها.",
        ],
        top=3.5,
        size=17,
    )
    add_footer(slide, n)
    add_note(slide, "جملهٔ پایانی پیش از اسلاید تشکر.")

    # ------------------------------------------------------------- thanks
    n += 1
    slide = blank_slide(prs)
    band = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    band.fill.solid()
    band.fill.fore_color.rgb = ACCENT
    band.line.fill.background()
    band.shadow.inherit = False
    add_text(slide, "با تشکر از توجه شما", size=40, bold=True, color=WHITE, top=2.4)
    add_text(slide, "پرسش و پاسخ", size=24, color=ACCENT_LIGHT, top=3.6)
    add_note(slide, "فضای باقی‌مانده برای پرسش‌های هیئت‌مجازه.")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(out))
    print(f"wrote {out} ({len(prs.slides.__iter__.__self__._sldIdLst)} slides)")


if __name__ == "__main__":
    main()
