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
    text(dir: ltr, [clang]), [تحلیل مسیر], [مسیرپیمایی واقعی], [وابسته به کامپایل],
    text(dir: ltr, [bandit]), [الگوی امنیتی پایتون], [پوشش دامنهٔ پایتون], [هشدار الگویی],
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
      جدول ۳.۱: سه خروجی ممکن عامل ارزیاب
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

#let table-3-3 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 3,
    inset: 8pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      [*فیلد گزارش*],
      [*محتوا*],
      [*الزام پیشنهاده*],
    ),
    [#text(dir: ltr)[cwe]], [شناسهٔ دستهٔ ضعف], [نوع آسیب‌پذیری],
    [#text(dir: ltr)[severity]], [شدت], [تحلیل گزارش],
    [#text(dir: ltr)[file, line, function]], [فایل، خط و تابع], [محل دقیق کد],
    [#text(dir: ltr)[explanation]], [توضیح فنی کوتاه], [توضیح تحلیلی],
    [#text(dir: ltr)[source, sink, chain]], [عبارت‌ها، خط‌ها و مسیر بازیابی‌شده], [شاهد جریان داده],
    [#text(dir: ltr)[chain_verified, taint_origin]], [تأیید زنجیره و منشأ آلودگی], [شاهد جریان داده],
    [#text(dir: ltr)[related_cves, references]], [شناسهٔ واقعی و پیوند مرجع], [مرجع
    #text(dir: ltr)[CVE]],
    [#text(dir: ltr)[confidence, detected_by]], [اعتماد و نقش عامل‌ها], [قابلیت حسابرسی],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۳.۳: شمای گزارش نهایی سامانه
    ],
  )
  #v(1%)
])

#let table-3-4 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 4,
    inset: 7pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      [*دسته*],
      [*زبان*],
      [*نمونهٔ واقعی پیاده‌سازی*],
      [*نسبت با پیشنهاده*],
    ),
    [#text(dir: ltr)[CWE-122]], [#text(dir: ltr)[C]], [#text(dir: ltr)[CVE-2021-3156]], [همان نمونهٔ پیشنهاده؛ مرجع ردهت
    #text(dir: ltr)[CWE-122]
    و علت ریشه‌ای
    #text(dir: ltr)[CWE-193]
    است],
    [#text(dir: ltr)[CWE-190]], [#text(dir: ltr)[C]], [#text(dir: ltr)[CVE-2017-7529]], [همان نمونهٔ پیشنهاده],
    [#text(dir: ltr)[CWE-94]], [#text(dir: ltr)[Python]], [#text(dir: ltr)[CVE-2022-22817]], [همان شناسهٔ پیشنهاده، ولی نمونهٔ واقعی تزریق عبارت در پیلو است، نه بازسازی ناامن در پای‌یامل],
    [#text(dir: ltr)[CWE-1336]], [#text(dir: ltr)[Python]], [#text(dir: ltr)[CVE-2025-27516]], [جایگزین شناسهٔ نادرست پیشنهاده برای تزریق قالب],
    [#text(dir: ltr)[CWE-502]], [#text(dir: ltr)[Python]], [#text(dir: ltr)[CVE-2017-18342]], [نمونهٔ تأییدشدهٔ بازسازی ناامن در پای‌یامل؛ شناسهٔ پیشنهاده متعلق به آن نیست],
    [#text(dir: ltr)[CWE-78]], [#text(dir: ltr)[Python]], [بدون شناسهٔ منتخب], [تنها مرجع کلاس؛ همان دامنهٔ پیشنهاده],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۳.۴: دامنهٔ پیشنهاده و نمونه‌های واقعی به‌کاررفته در گزارش
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
#let table-4-5 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 6,
    inset: 7pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      [*پیکربندی*],
      [*مثبت درست / مثبت نادرست*],
      [*منفی نادرست / منفی درست*],
      [*دقت*],
      [*یادآوری*],
      [*نرخ هشدار سالم*],
    ),
    [هر مسیر منبع تا مصرف], [#text(dir: ltr)[24/9]], [#text(dir: ltr)[0/15]], [#text(dir: ltr)[0.727]], [#text(dir: ltr)[1.000]], [#text(dir: ltr)[0.375]],
    [تنها مسیر بدون کاهش خطر], [#text(dir: ltr)[24/1]], [#text(dir: ltr)[0/23]], [#text(dir: ltr)[0.960]], [#text(dir: ltr)[1.000]], [#text(dir: ltr)[0.042]],
    [بندیت], [#text(dir: ltr)[16/6]], [#text(dir: ltr)[8/18]], [#text(dir: ltr)[0.727]], [#text(dir: ltr)[0.667]], [#text(dir: ltr)[0.250]],
    [اجتماع شواهد و بندیت], [#text(dir: ltr)[24/7]], [#text(dir: ltr)[0/17]], [#text(dir: ltr)[0.774]], [#text(dir: ltr)[1.000]], [#text(dir: ltr)[0.292]],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۴.۵: نتایج موتور قطعی روی محک ۴۸ نمونه‌ای پایتون
    ],
  )
  #v(1%)
])
#let table-4-6 = align(center, [
  #v(2.5%)
  #text(dir: rtl, table(
    columns: 6,
    inset: 6pt,
    stroke: gray + 1pt,
    align: center + horizon,
    table.header(
      [*مجموعه و پیکربندی*],
      [*مثبت درست / مثبت نادرست*],
      [*منفی نادرست / منفی درست*],
      [*دقت*],
      [*یادآوری*],
      [*نرخ هشدار سالم*],
    ),
    [جولیت: هر مسیر], [#text(dir: ltr)[26/33]], [#text(dir: ltr)[274/267]], [#text(dir: ltr)[0.441]], [#text(dir: ltr)[0.087]], [#text(dir: ltr)[0.110]],
    [جولیت: بدون کاهش خطر], [#text(dir: ltr)[7/7]], [#text(dir: ltr)[293/293]], [#text(dir: ltr)[0.500]], [#text(dir: ltr)[0.023]], [#text(dir: ltr)[0.023]],
    [جولیت: فلاویاب], [#text(dir: ltr)[13/10]], [#text(dir: ltr)[287/290]], [#text(dir: ltr)[0.565]], [#text(dir: ltr)[0.043]], [#text(dir: ltr)[0.033]],
    [جولیت: اجتماع], [#text(dir: ltr)[13/11]], [#text(dir: ltr)[287/289]], [#text(dir: ltr)[0.542]], [#text(dir: ltr)[0.043]], [#text(dir: ltr)[0.037]],
    [دیویگن کامل: هر مسیر], [#text(dir: ltr)[971/894]], [#text(dir: ltr)[11454/13939]], [#text(dir: ltr)[0.521]], [#text(dir: ltr)[0.078]], [#text(dir: ltr)[0.060]],
    [دیویگن کامل: بدون کاهش خطر], [#text(dir: ltr)[861/783]], [#text(dir: ltr)[11564/14050]], [#text(dir: ltr)[0.524]], [#text(dir: ltr)[0.069]], [#text(dir: ltr)[0.053]],
    [دیویگن متوازن: شواهد], [#text(dir: ltr)[17/21]], [#text(dir: ltr)[283/279]], [#text(dir: ltr)[0.447]], [#text(dir: ltr)[0.057]], [#text(dir: ltr)[0.070]],
    [دیویگن متوازن: فلاویاب], [#text(dir: ltr)[6/11]], [#text(dir: ltr)[294/289]], [#text(dir: ltr)[0.353]], [#text(dir: ltr)[0.020]], [#text(dir: ltr)[0.037]],
    [دیویگن متوازن: اجتماع], [#text(dir: ltr)[20/29]], [#text(dir: ltr)[280/271]], [#text(dir: ltr)[0.408]], [#text(dir: ltr)[0.067]], [#text(dir: ltr)[0.097]],
  ))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      جدول ۴.۶: نتایج موتور قطعی روی جولیت و دیویگن
    ],
  )
  #v(1%)
])

