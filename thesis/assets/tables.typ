#let table-2-1 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 4,
    inset: 8pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      [*ابزار*],
      [*رویکرد*],
      [*نقطهٔ قوت*],
      [*نقطهٔ ضعف*],
    ),
    text(dir: ltr, [cppcheck]), [قاعده‌محور], [سریع و کم‌هزینه], [عمق تحلیل کم],
    text(dir: ltr, [flawfinder]), [قاعده‌محور], [پوشش سبک‌های خطرناک], [بسیار پرهشدار],
    text(dir: ltr, [clang]), [درخت نحو انتزاعی], [مسیرپیمایی واقعی], [وابسته به کامپایل],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۲.۱: ویژگی ابزارهای تحلیل ایستای به‌کاررفته در فاز یک
    ],
  )
  #v(1%)
])

#let table-2-2 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 5,
    inset: 7pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      [*دسته*],
      [*نمونه*],
      [*نقش*],
      [*محدودیت*],
      [*جایگاه این کار*],
    ),
    [ارزیابی انتقادی], [#link(<ref:6>, "[۶]") #link(<ref:8>, "[۸]")], [سنجش واقع‌بینانه], [وابسته به مجموعه‌داده], [مبانی تعریف معیار],
    [یادگیری ماشین], [#link(<ref:9>, "[۹]")], [دقت بالاتر], [بدون توضیح‌پذیری], [مقایسهٔ عددی],
    [مدل زبانی], [#link(<ref:10>, "[۱۰]") #link(<ref:11>, "[۱۱]")], [فهم زبان طبیعی], [توهم و عدم قطعیت], [تلفیق با ایستا],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۲.۲: جایگاه کار پیشنهادی در میان کارهای پیشین
    ],
  )
  #v(1%)
])

#let table-3-1 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 4,
    inset: 8pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      table.cell(stroke: none, []),
      [*خروجی*],
      [*معنا*],
      [*اثر بر گزارش*],
    ),
    [*تأییدشده*], [#text(dir: ltr)[CONFIRMED]], [شاهد کافی برای پذیرش یافته], [یافته در خروجی نهایی],
    [*ردشده*], [#text(dir: ltr)[REJECTED]], [شاهد ناسازگار با یافته], [حذف از خروجی نهایی],
    [*نامطمئن*], [#text(dir: ltr)[UNCERTAIN]], [شاهد ناکافی], [نیازمند بررسی انسانی],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۳.۱: سه خروجی ممکن عامل زبانی
    ],
  )
  #v(1%)
])

#let table-3-2 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 3,
    inset: 8pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      [*قانون تطبیق*],
      [*شرط*],
      [*دلیل*],
    ),
    [*هم‌بودن فایل*], [نام فایل یکسان], [تطبیق در سطح پروژهٔ واقعی],
    [*خانوادهٔ CWE*], [هم‌پوشانی خانواده], [ابزارها CWE والد گزارش می‌کنند],
    [*فاصلهٔ خط*], [کمتر از ۵ خط], [خطای گزارش ابزار جبران می‌شود],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۳.۲: سیاست تطبیق یافته‌ها با برچسب واقعی
    ],
  )
  #v(1%)
])

#let table-4-1 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 3,
    inset: 8pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      [*ویژگی*],
      [*مقدار*],
      [*توضیح*],
    ),
    [زبان‌ها], [#text(dir: ltr)[C, C++]], [هر دو خانوادهٔ کد مدل می‌شوند],
    [آسیب‌پذیری‌ها], [#text(dir: ltr)[CWE-122, CWE-190]], [سرریز بافر و سرریز عدد صحیح],
    [تعداد نمونهٔ ارزیابی], [۶۰۰], [۳۰۰ آسیب‌پذیر و ۳۰۰ سالم],
    [لایه‌بندی], [۱۵۰ در هر لایه], [چهار لایه، با بذر ۴۲],
    [ابزارهای فاز یک], [#text(dir: ltr)[cppcheck 2.22, flawfinder 2.0.20, clang 22]], [نسخه‌های به‌کاررفته],
    [مدل بازبین], [#text(dir: ltr)[mimo-v2.6-flash-free]], [از راه سرور محلی],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۴.۱: مشخصات مجموعه‌دادهٔ ارزیابی و پیکربندی آزمایش
    ],
  )
  #v(1%)
])

#let table-4-2 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 8,
    inset: 6pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      [*آزمایش*],
      [*پیکربندی*],
      [*مثبت درست*],
      [*مثبت نادرست*],
      [*دقت*],
      [*یادآوری*],
      [F1],
      [*نرخ هشدار روی فایل سالم*],
    ),
    [*A*], [فقط ایستا], [۱۱], [۱۸], [۰٫۳۷۹], [۰٫۰۳۷], [۰٫۰۶۷], [۰٫۰۵۰],
    [*B*], [فقط عامل زبانی], [۴۴], [۷۵], [۰٫۳۷۰], [۰٫۱۴۷], [۰٫۲۱۰], [۰٫۱۹۷],
    [*C*], [ایستا + عامل], [۳], [۲], [۰٫۶۰۰], [۰٫۰۱۰], [۰٫۰۲۰], [۰٫۰۰۷],
    [*D*], [ایستا + ساختار + عامل], [۵], [۶], [۰٫۴۵۵], [۰٫۰۱۷], [۰٫۰۳۲], [۰٫۰۲۰],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۴.۲: نتایج اصلی چهار آزمایش روی ۶۰۰ نمونهٔ متعادل
    ],
  )
  #v(1%)
])

#let table-4-3 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 4,
    inset: 8pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      [*آزمایش*],
      [*تعداد گروه بازبینی*],
      [*تأییدشده*],
      [*ردشده / نامطمئن*],
    ),
    [*B*], [۶۰۰ فایل], [۱۱۹], [۴۷۷ / ۴],
    [*C*], [۳۱], [۵], [۱۳ / ۱۳],
    [*D*], [۳۱], [۱۱], [۱۴ / ۶],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۴.۳: قیف تصمیم عامل زبانی در هر پیکربندی
    ],
  )
  #v(1%)
])
#let table-4-4 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 6,
    inset: 7pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      [*آزمایش*],
      [*نوع*],
      [*مثبت درست*],
      [*دقت*],
      [*یادآوری*],
      [*F1*],
    ),
    [*A*], [#text(dir: ltr)[CWE-122]], [۱۱], [۰٫۵۵۰], [۰٫۰۷۳], [۰٫۱۲۹],
    [*A*], [#text(dir: ltr)[CWE-190]], [۰], [۰٫۰۰۰], [۰٫۰۰۰], [۰٫۰۰۰],
    [*B*], [#text(dir: ltr)[CWE-122]], [۳۵], [۰٫۵۱۵], [۰٫۲۳۳], [۰٫۳۲۱],
    [*B*], [#text(dir: ltr)[CWE-190]], [۹], [۰٫۳۳۳], [۰٫۰۶۰], [۰٫۱۰۲],
    [*C*], [#text(dir: ltr)[CWE-122]], [۳], [۰٫۶۰۰], [۰٫۰۲۰], [۰٫۰۳۹],
    [*C*], [#text(dir: ltr)[CWE-190]], [۰], [۰٫۰۰۰], [۰٫۰۰۰], [۰٫۰۰۰],
    [*D*], [#text(dir: ltr)[CWE-122]], [۵], [۰٫۴۵۵], [۰٫۰۳۳], [۰٫۰۶۲],
    [*D*], [#text(dir: ltr)[CWE-190]], [۰], [۰٫۰۰۰], [۰٫۰۰۰], [۰٫۰۰۰],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۴.۴: نتایج به تفکیک نوع آسیب‌پذیری
    ],
  )
  #v(1%)
])

