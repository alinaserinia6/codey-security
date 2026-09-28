#import "@preview/cetz:0.4.0"
#import "@preview/cetz-plot:0.1.2": chart
#import "@preview/fletcher:0.5.8": diagram, edge, node

#let figure-1-1 = align(center, [
  #v(2.5%)
  #rect(
    stroke: 0.5pt,
    width: 100%,
    align(left, text(dir: ltr, [
      #text(fill: black.lighten(35%), [
        *CWE190\_Integer\_Overflow\_\_int\_rand\_add\_73b\_bad.cpp*
      ])
      ```c

      void badSink(list<int> dataList)
      {
          int data = dataList.back();
          {
              /* POTENTIAL FLAW: Adding 1 to data could
                 cause an overflow */
              int result = data + 1;
              printIntLine(result);
          }
      }

      ```
    ])),
  )
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      شکل ۱.۱: نمونه‌ای از کد آسیب‌پذیر از نوع سرریز عدد صحیح
    ],
  )
  #v(1%)
])

#let figure-1-2 = align(center, [
  #v(2.5%)
  #rect(
    stroke: 0.5pt,
    width: 100%,
    align(left, text(dir: ltr, [
      #text(fill: black.lighten(35%), [
        *CWE190\_Integer\_Overflow\_\_int\_rand\_add\_73b\_good.cpp*
      ])
      ```c

      void goodB2GSink(list<int> dataList)
      {
          int data = dataList.back();
          if (data < INT_MAX) {
              int result = data + 1;
              printIntLine(result);
          } else {
              printLine("data value is too large ...");
          }
      }

      ```
    ])),
  )
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      شکل ۱.۲: نسخهٔ اصلاح‌شدهٔ همان سناریو با بررسی پیش از محاسبه
    ],
  )
  #v(1%)
])

#let figure-1-3 = align(center, [
  #v(1.5%)
  #text(
    dir: rtl,
    diagram(
      spacing: (1.1cm, 1.05cm),

      node((0, 2), rect(width: 120pt, height: 46pt, [
        ابزارهای تحلیل ایستا
        \
        #text(size: 9pt)[cppcheck، flawfinder، clang]
        #v(8%)
      ])),

      node((2, 2), rect(width: 110pt, height: 46pt, [
        همبسته‌سازی و
        \
        ادغام یافته‌های تکراری
        #v(8%)
      ])),

      node((4, 2), rect(width: 110pt, height: 46pt, [
        بازبینی هر گروه
        \
        توسط عامل زبانی
        #v(8%)
      ])),

      node((6, 2), rect(width: 105pt, height: 46pt, [
        گزارش نهایی
        \
        تأییدشده‌ها
        #v(8%)
      ])),

      node((2, 0), rect(width: 220pt, height: 46pt, [
        خروجی: مجموعه‌ای از یافته‌های تأییدشده
        \
        به‌همراه دلیل و شواهد برای هر یک
        #v(8%)
      ])),

      node((0, 0), rect(width: 120pt, height: 46pt, [
        کاربر
        \
        #text(size: 9pt)[نیازمند هشدارهای کمتر و دقیق‌تر]
        #v(8%)
      ])),

      edge((0, 2), (2, 2), "-|>"),
      edge((2, 2), (4, 2), "-|>"),
      edge((4, 2), (6, 2), "-|>"),
      edge((6, 2), (2, 0), "-|>"),
      edge((2, 0), (0, 0), "<|-"),
    ),
  )
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(1.5%)
      شکل ۱.۳: نمای کلی سامانهٔ پیشنهادی و جایگاه بازبینی توسط عامل زبانی
    ],
  )
  #v(1%)
])

#let figure-3-1 = align(center, [
  #v(1%)
  #text(
    dir: rtl,
    diagram(
      spacing: (0.95cm, 0.95cm),

      node((0, 0), rect(width: 105pt, height: 60pt, [
        فایل‌های
        \
        C و ++C
        #v(10%)
      ])),

      node((2, 0), rect(width: 105pt, height: 60pt, [
        فاز یک
        \
        #text(size: 9pt)[اجرای موازی سه ابزار ایستا]
        #v(10%)
      ])),

      node((4, 0), rect(width: 105pt, height: 60pt, [
        فاز دو
        \
        #text(size: 9pt)[ادغام، نرمال‌سازی و همبسته‌سازی]
        #v(10%)
      ])),

      node((6, 0), rect(width: 105pt, height: 60pt, [
        فاز سه
        \
        #text(size: 9pt)[بازبینی مبتنی بر شواهد]
        #v(10%)
      ])),

      node((6, 2), rect(width: 105pt, height: 60pt, [
        گزارش نهایی
        \
        #text(size: 9pt)[یافته‌های تأییدشده]
        #v(10%)
      ])),

      node((2, 2), rect(width: 195pt, height: 60pt, [
        #text(size: 9pt)[شواهد قطعی: ساختار درخت نحوی، فهرست فراخوانی‌ها،]
        \
        #text(size: 9pt)[قطعهٔ کد پاک‌سازی‌شده و پیام ابزار]
        #v(10%)
      ])),

      node((0, 2), rect(width: 105pt, height: 60pt, [
        پایگاه دادهٔ
        \
        #text(size: 9pt)[جولیت]
        #v(10%)
      ])),

      edge((0, 0), (2, 0), "-|>"),
      edge((2, 0), (4, 0), "-|>"),
      edge((4, 0), (6, 0), "-|>"),
      edge((6, 0), (6, 2), "-|>"),
      edge((4, 0), (2, 2), "-<|-"),
      edge((0, 2), (0, 0), "-<|-"),
      edge((6, 2), (6, 0), [dashed, "-|>"]),
    ),
  )
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(1.5%)
      شکل ۳.۱: معماری سه‌فاز سامانه و جریان داده میان فازها
    ],
  )
  #v(1%)
])

#let figure-3-2 = align(center, [
  #v(2.5%)
  #rect(
    stroke: 0.5pt,
    width: 100%,
    align(left, text(dir: ltr, [
      #text(fill: black.lighten(35%), [
        *evidence-packet.json*
      ])
      ```json

      {
        "language": "cpp",
        "group": {
          "id": "G-3",
          "line": 33,
          "severity": "HIGH",
          "cwe": ["CWE-122"],
          "tools": ["cppcheck", "clang"]
        },
        "members": [
          { "tool": "cppcheck", "message": "buffer overflow" },
          { "tool": "clang", "message": "out of bound array access" }
        ],
        "source_context": {
          "start_line": 27,
          "end_line": 39,
          "snippet": "    27:     twoIntsStruct * data;\n ..."
        },
        "structural": {
          "functions": [ { "name": "sym_1902e3", "line": 25 } ],
          "calls": [ { "callee": "action", "line": 33 } ]
        }
      }

      ```
    ])),
  )
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      شکل ۳.۲: ساختار بستهٔ شواهد ارسال‌شده به عامل زبانی
    ],
  )
  #v(1%)
])

#let figure-3-3 = align(center, [
  #v(2.5%)
  #rect(
    stroke: 0.5pt,
    width: 100%,
    align(left, text(dir: ltr, [
      #text(fill: black.lighten(35%), [
        *CWE122\_Heap\_Based\_Buffer\_Overflow\_\_c\_CWE805\_struct\_memcpy\_82a\_bad.cpp*
      ])
      ```c

          24:
          25: void sym_1902e3()
          26: {
          27:     twoIntsStruct * data;
          28:     data = NULL;
          29:
          30:     data = (twoIntsStruct *)malloc(50*sizeof(twoIntsStruct));
          31:     if (data == NULL) {exit(-1);}
          32:     sym_9623a0* baseObject = new sym_5b7d8f;
          33:     baseObject->action(data);
          34:     delete baseObject;
          35: }

      ```
    ])),
  )
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      شکل ۳.۳: قطعهٔ کد پس از پاک‌سازی؛ حاشیه‌نویسی‌ها محو و شناسه‌های افشاگر بازنام‌گذاری شده‌اند
    ],
  )
  #v(1%)
])

#let figure-3-4 = align(center, [
  #v(1%)
  #text(
    dir: rtl,
    diagram(
      spacing: (0.9cm, 0.9cm),

      node((0, 0), rect(width: 100pt, height: 52pt, [
        #text(size: 9pt)[یافته‌های خام ابزارها]
        #v(8%)
      ])),

      node((2, 0), rect(width: 100pt, height: 52pt, [
        #text(size: 9pt)[حذف تکرار با اثر انگشت]
        #v(8%)
      ])),

      node((4, 0), rect(width: 100pt, height: 52pt, [
        #text(size: 9pt)[تطبیق خط با دریچهٔ خط]
        #v(8%)
      ])),

      node((6, 0), rect(width: 100pt, height: 52pt, [
        #text(size: 9pt)[یک گروه به‌ازای هر نقطهٔ ضعف]
        #v(8%)
      ])),

      edge((0, 0), (2, 0), "-|>"),
      edge((2, 0), (4, 0), "-|>"),
      edge((4, 0), (6, 0), "-|>"),
    ),
  )
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(1.5%)
      شکل ۳.۴: زنجیرهٔ ادغام یافته‌های تکراری و تشکیل گروه‌های بازبینی
    ],
  )
  #v(1%)
])

#let figure-4-1 = align(center, [
  #v(2.5%)
  #text(dir: rtl, cetz.canvas({
    let data = (
      ([دقت یافته], 0.379, 0.370, 0.600, 0.455),
      ([یادآوری], 0.037, 0.147, 0.010, 0.017),
      ([نرخ هشدار سالم], 0.050, 0.197, 0.007, 0.020),
    )
    let colors = (red, blue, green, yellow)
    chart.barchart(
      data,
      x-label: [پیکربندی: A ایستا، B عامل، C ایستا+عامل، D ایستا+ساختار+عامل],
      y-label: [نسبت],
      legend-key: 0,
      legend-entry: 0,
      bar-width: 12pt,
      ymin: 0,
      ymax: 0.7,
      xtick-labels: ([A], [B], [C], [D]),
      legend-placement: (top: 1, right: 1),
      size: (10, 5),
    )
  }))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      شکل ۴.۱: مقایسهٔ دقت، یادآوری و نرخ هشدار روی فایل سالم در چهار پیکربندی
    ],
  )
  #v(1%)
])

#let figure-4-2 = align(center, [
  #v(2.5%)
  #text(dir: rtl, cetz.canvas({
    let data = (
      ([A: ایستا], 11, 18, 289, 285),
      ([B: عامل], 44, 75, 256, 241),
      ([C: ایستا+عامل], 3, 2, 297, 298),
      ([D: ایستا+ساختار+عامل], 5, 6, 295, 294),
    )
    let colors = (red, blue, green, yellow)
    chart.barchart(
      data,
      x-label: [پیکربندی],
      y-label: [تعداد نمونه یا یافته],
      legend-key: 0,
      legend-entry: 0,
      bar-width: 10pt,
      ymin: 0,
      ymax: 320,
      xtick-labels: ([A], [B], [C], [D]),
      legend-placement: (top: 1, right: 1),
      size: (10, 5),
    )
  }))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      شکل ۴.۲: ماتریس سردرگمی چهار پیکربندی در دانه‌بندی فایل و یافته
    ],
  )
  #v(1%)
])

#let figure-4-3 = align(center, [
  #v(2.5%)
  #text(dir: rtl, cetz.canvas({
    let data = (
      ([C: بدون ساختار], 5, 13, 13),
      ([D: با ساختار], 11, 14, 6),
    )
    let colors = (green, red, yellow)
    chart.barchart(
      data,
      x-label: [پیکربندی],
      y-label: [تعداد گروه بازبینی‌شده],
      legend-key: 0,
      legend-entry: 0,
      bar-width: 16pt,
      ymin: 0,
      ymax: 20,
      xtick-labels: ([C], [D]),
      legend-placement: (top: 1, right: 1),
      size: (10, 5),
    )
  }))
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      شکل ۴.۳: اثر شواهد ساختاری بر تصمیم‌های عامل زبانی
    ],
  )
  #v(1%)
])


#let figure-2-1 = align(center, [
  #v(2.5%)
  #rect(
    stroke: 0.5pt,
    width: 100%,
    align(left, text(dir: ltr, [
      #text(fill: black.lighten(35%), [
        *CWE190\_Integer\_Overflow\_\_int\_rand\_add\_73b\_bad.cpp*
      ])
      ```c

      void badSink(list<int> dataList)
      {
          int data = dataList.back();
          {
              /* POTENTIAL FLAW: Adding 1 to data could
                 cause an overflow */
              int result = data + 1;
              printIntLine(result);
          }
      }

      ```
    ])),
  )
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      شکل ۲.۱: نسخهٔ آسیب‌پذیر یک سناریوی جولیت
    ],
  )
  #v(1%)
])

#let figure-2-2 = align(center, [
  #v(2.5%)
  #rect(
    stroke: 0.5pt,
    width: 100%,
    align(left, text(dir: ltr, [
      #text(fill: black.lighten(35%), [
        *CWE190\_Integer\_Overflow\_\_int\_rand\_add\_73b\_good.cpp*
      ])
      ```c

      void goodB2GSink(list<int> dataList)
      {
          int data = dataList.back();
          /* FIX: Add a check to prevent an overflow */
          if (data < INT_MAX) {
              int result = data + 1;
              printIntLine(result);
          }
      }

      ```
    ])),
  )
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(0.5%)
      شکل ۲.۲: نسخهٔ سالم همان سناریو؛ تنها تفاوت، یک شرط کنترلی است
    ],
  )
  #v(1%)
])
