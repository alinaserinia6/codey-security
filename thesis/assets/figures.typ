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
      spacing: (0.45cm, 0.9cm),

      node((0, 1), rect(width: 92pt, height: 46pt, [
        #text(size: 9.5pt)[ابزارهای تحلیل ایستا]
        \
        #text(size: 8pt)[cppcheck، flawfinder، bandit]
        #v(4%)
      ])),

      node((1, 1), rect(width: 88pt, height: 46pt, [
        #text(size: 9.5pt)[شواهد قطعی]
        \
        #text(size: 8pt)[ساختار، داده و یافته‌ها]
        #v(4%)
      ])),

      node((2, 1), rect(width: 88pt, height: 46pt, [
        #text(size: 9.5pt)[داوری چندعامله]
        \
        #text(size: 8pt)[جستجوگر و ارزیاب]
        #v(4%)
      ])),

      node((3, 1), rect(width: 82pt, height: 46pt, [
        #text(size: 9.5pt)[گزارش نهایی]
        \
        #text(size: 8pt)[تأییدشده‌ها]
        #v(4%)
      ])),

      node((1.5, 0), rect(width: 165pt, height: 46pt, [
        #text(size: 9.5pt)[خروجی: مجموعه‌ای از یافته‌های تأییدشده]
        \
        #text(size: 8pt)[به‌همراه دلیل و شواهد برای هر یک]
        #v(4%)
      ])),

      node((0, 0), rect(width: 95pt, height: 46pt, [
        #text(size: 9.5pt)[کاربر]
        \
        #text(size: 8pt)[نیازمند هشدارهای کمتر و دقیق‌تر]
        #v(4%)
      ])),

      edge((0, 1), (1, 1), "-|>"),
      edge((1, 1), (2, 1), "-|>"),
      edge((2, 1), (3, 1), "-|>"),
      edge((3, 1), (1.5, 0), "-|>"),
      edge((1.5, 0), (0, 0), "<|-"),
    ),
  )
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(1.5%)
      شکل ۱.۳: نمای کلی سامانهٔ پیشنهادی و جایگاه داوری چندعامله مبتنی بر شواهد
    ],
  )
  #v(1%)
])

#let figure-3-1 = align(center, [
  #v(1%)
  #text(
    dir: rtl,
    diagram(
      spacing: (0.7cm, 0.8cm), // کاهش فاصله ستون‌ها

      node((0, 0), rect(width: 85pt, height: 55pt, [
        فایل‌های
        \
        #text(size: 8.5pt)[پایتون، C و ++C]
        #v(5%)
      ])),

      node((1, 0), rect(width: 95pt, height: 55pt, [
        فاز یک
        \
        #text(size: 8.5pt)[شواهد قطعی و همبسته‌سازی]
        #v(5%)
      ])),

      node((2, 0), rect(width: 85pt, height: 55pt, [
        فاز دو
        \
        #text(size: 8.5pt)[جستجوگر و ارزیاب]
        #v(5%)
      ])),

      node((3, 0), rect(width: 85pt, height: 55pt, [
        فاز سه
        \
        #text(size: 8.5pt)[ارزیابی مستقل]
        #v(5%)
      ])),

      node((3, 1), rect(width: 85pt, height: 55pt, [
        گزارش نهایی
        \
        #text(size: 8.5pt)[یافته‌های تأییدشده]
        #v(5%)
      ])),

      // قرار دادن دقیق این گره در مرکز فاز یک و دو
      node((1.5, 1), rect(width: 175pt, height: 55pt, [
        #text(size: 8.5pt)[شواهد قطعی: ساختار درخت نحوی، فهرست فراخوانی‌ها،]
        \
        #text(size: 8.5pt)[قطعهٔ کد پاک‌سازی‌شده و پیام ابزار]
        #v(5%)
      ])),

      node((0, 1), rect(width: 85pt, height: 55pt, [
        مجموعه‌های ارزیابی
        \
        #text(size: 8.5pt)[جولیت، پایتون و دیویگن]
        #v(5%)
      ])),

      edge((0, 0), (1, 0), "-|>"),
      edge((1, 0), (2, 0), "-|>"),
      edge((2, 0), (3, 0), "-|>"),
      edge((3, 0), (3, 1), "-|>"),
      edge((2, 0), (1.5, 1), "-<|-"), 
      edge((0, 1), (0, 0), "-<|-"),
      edge((3, 1), (3, 0), "-|>", stroke: (dash: "dashed")),
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
        "role": "scanner",
        "language": "python",
        "file": "example.py",
        "source_context": {
          "start_line": 4,
          "end_line": 12,
          "snippet": "    6: name = sys.argv[1]\n ..."
        },
        "static_tool_findings": [
          { "tool": "bandit", "message": "possible shell injection" }
        ],
        "structural": {
          "functions": [ { "name": "run_user_command", "line": 4 } ],
          "calls": [ { "callee": "subprocess.call", "line": 6 } ]
        },
        "dataflow_chains": [
          {
            "source": "sys.argv[1]",
            "sink": "subprocess.call(command, shell=True)",
            "mitigated": false
          }
        ]
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
      شکل ۳.۲: نمونهٔ ساده‌شدهٔ بستهٔ شواهد جستجوگر
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
      spacing: (0.3cm, 0.9cm),

      node((0, 0), rect(width: 90pt, height: 52pt, [
        #text(size: 9pt)[یافته‌های خام ابزارها]
        #v(8%)
      ])),

      node((2, 0), rect(width: 90pt, height: 52pt, [
        #text(size: 9pt)[حذف تکرار با اثر انگشت]
        #v(8%)
      ])),

      node((4, 0), rect(width: 90pt, height: 52pt, [
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

#let _palette = (
  rgb("#2b6cb0"),
  rgb("#c05621"),
  rgb("#2f855a"),
  rgb("#718096"),
)

#let _palette_2 = (
  rgb("#c05621"),
  rgb("#2f855a"),
)

#let _palette_3 = (
  rgb("#2f855a"),
  rgb("#c05621"),
  rgb("#718096"),
)


#let _legend(series, colors: _palette) = align(center, {
  for (i, s) in series.enumerate() {
    box(inset: (x: 5pt), baseline: 35%, [
      #rect(
        width: 18pt,
        height: 9pt,
        fill: colors.at(i),
        stroke: 0.5pt + gray.lighten(45%),
      )
      #h(4pt)
      #text(size: 10pt)[#s]
    ])
  }
})

#let _legend_2(series, colors: _palette_2) = align(center, {
  for (i, s) in series.enumerate() {
    box(inset: (x: 5pt), baseline: 35%, [
      #rect(
        width: 18pt,
        height: 9pt,
        fill: colors.at(i),
        stroke: 0.5pt + gray.lighten(45%),
      )
      #h(4pt)
      #text(size: 10pt)[#s]
    ])
  }
})

#let _legend_3(series, colors: _palette_3) = align(center, {
  for (i, s) in series.enumerate() {
    box(inset: (x: 5pt), baseline: 35%, [
      #rect(
        width: 18pt,
        height: 9pt,
        fill: colors.at(i),
        stroke: 0.5pt + gray.lighten(45%),
      )
      #h(4pt)
      #text(size: 10pt)[#s]
    ])
  }
})


/// Fixed-decimal string formatting for bar value labels.
#let _fixed(v, n) = {
  let scale = calc.pow(10, n)
  let iv = int(calc.round(v * scale))
  let whole = calc.div-euclid(iv, scale)
  let frac = calc.rem-euclid(iv, scale)
  let fs = str(frac)
  let pad = n - fs.len()
  let padded = if pad > 0 { range(pad).map(_ => "0").join() + fs } else { fs }
  str(whole) + "." + padded
}

/// Grouped horizontal bar chart.
/// groups: ((label, (value, ...)), ...)
/// series: (label, ...)
/// digits: auto (print values as-is) or a decimal count
#let grouped-bars(
  groups,
  series,
  colors: _palette,
  max: auto,
  track: 6.9cm,
  digits: auto,
  label-width: auto,
  series-width: auto,
  value-width: auto,
) = {
  let flat = groups.map(g => g.at(1)).flatten()
  let mx = if max == auto { calc.max(..flat) } else { max }
  let cells = ()
  for g in groups {
    for (i, s) in series.enumerate() {
      let v = g.at(1).at(i)
      let label = if digits == auto { [#v] } else { [#_fixed(v, digits)] }
      let st = if i == 0 { (top: 0.7pt + gray.lighten(30%)) } else { none }
      let bar = calc.max(1.5pt, track * v / mx)

      // ستون ۱: برچسب گروه (فقط ردیف اول هر گروه)
      cells.push(grid.cell(
        stroke: st,
        align: horizon + right,
        [#if i == 0 {
          text(dir: rtl, size: 10pt, weight: "bold", g.at(0))
        }],
      ))

      // ستون ۲: نام سری
      cells.push(grid.cell(
        stroke: st,
        align: horizon + right,
        [#text(dir: rtl, size: 10pt, s)],
      ))

      // ستون ۳: میله
      cells.push(grid.cell(
        stroke: st,
        align: horizon,
        box(
          width: 100%,
          height: 12pt,
          inset: 0pt,
          stroke: (left: 0.9pt + black),
          align(horizon + left, rect(
            width: bar,
            height: 12pt,
            fill: colors.at(calc.rem(i, colors.len())),
            stroke: none,
          )),
        ),
      ))

      // ستون ۴: مقدار
      cells.push(grid.cell(
        stroke: st,
        align: horizon + left,
        [#text(dir: ltr, size: 9.5pt, label)],
      ))
    }
  }

  // ستون‌ها: برچسب‌ها auto، میله 1fr، مقدار auto
  grid(
    columns: (
      if label-width == auto { auto } else { label-width },
      if series-width == auto { auto } else { series-width },
      1fr,                             // ← میله فضای باقی‌مانده را می‌گیرد
      if value-width == auto { auto } else { value-width },
    ),
    column-gutter: 7pt,
    row-gutter: 4.5pt,
    ..cells,
  )
}

#let _caption(txt) = text(
  dir: rtl,
  size: 10pt,
  fill: black.lighten(35%),
  [
    #v(0.5%)
    #txt
  ],
)

#let figure-4-1 = align(center, [
  #v(2.5%)
  #_legend(([دقت یافته], [یادآوری], [نرخ هشدار سالم]))
  #v(4pt)
  #grouped-bars(
    (
      ([A: ایستا], (0.355, 0.037, 0.050)),
      ([B: عامل], (0.370, 0.147, 0.197)),
      ([C: ایستا + عامل], (0.600, 0.010, 0.007)),
      ([D: ایستا +  ساختار+عامل], (0.455, 0.017, 0.020)),
    ),
    ([دقت یافته], [یادآوری], [نرخ هشدار سالم]),
  )
  #_caption(
    [شکل ۴.۱: مقایسهٔ دقت، یادآوری و نرخ هشدار روی فایل سالم در چهار پیکربندی],
  )
  #v(1%)
])

#let figure-4-2 = align(center, [
  #v(2.5%)
  #text(
    dir: rtl,
    size: 11pt,
    weight: "bold",
    [مثبت‌ها (دانه‌بندی یافته)],
  )
  #v(3pt)
  #_legend(([مثبت درست], [مثبت نادرست]))
  #v(3pt)
  #grouped-bars(
    (
      ([A: ایستا], (11, 20)),
      ([B: عامل], (44, 75)),
      ([C: ایستا+عامل], (3, 2)),
      ([D: ایستا+ساختار+عامل], (5, 6)),
    ),
    ([مثبت درست], [مثبت نادرست]),
  )
  #v(37pt)
  #text(
    dir: rtl,
    size: 11pt,
    weight: "bold",
    [منفی‌ها (دانه‌بندی یافته و فایل)],
  )
  #v(3pt)
  #_legend_2(([منفی نادرست (یافته)], [منفی درست (فایل)]))
  #v(3pt)
  #grouped-bars(
    (
      ([A: ایستا], (289, 285)),
      ([B: عامل], (256, 241)),
      ([C: ایستا+عامل], (297, 298)),
      ([D: ایستا+ساختار+عامل], (295, 294)),
    ),
    ([منفی نادرست (یافته)], [منفی درست (فایل)]),
    colors: (rgb("#c05621"), rgb("#2f855a")),
  )
  #_caption(
    [
      شکل ۴.۲: ماتریس سردرگمی چهار پیکربندی در دانه‌بندی یافته و دانه‌بندی فایل
    ],
  )
  #v(1%)
])

#let _tradeoff-plot() = {
  let W = 9.0cm
  let H = 5.4cm
  let ox = 2.1cm
  let oy = 0.62cm
  let xmax = 0.16
  let ymax = 0.70
  let pts = (
    ("A", 0.037, 0.355, 0.050),
    ("B", 0.147, 0.370, 0.197),
    ("C", 0.010, 0.600, 0.007),
    ("D", 0.017, 0.455, 0.020),
  )
  let px(v) = W * v / xmax
  let py(v) = H * (1 - v / ymax)
  let grid-paint = gray.lighten(62%)
  block(width: ox + W + 0.7cm, height: oy + H + 1.05cm, {
    for t in (0.0, 0.04, 0.08, 0.12, 0.16) {
      place(top + left, dx: ox + px(t), dy: oy, rect(width: 0.4pt, height: H, fill: grid-paint, stroke: none))
      place(top + left, dx: ox + px(t) - 0.5cm, dy: oy + H + 4pt,
        box(width: 1.0cm, align(center, text(dir: ltr, size: 8.5pt)[#t])))
    }
    for t in (0.0, 0.2, 0.4, 0.6) {
      place(top + left, dx: ox, dy: oy + py(t), rect(width: W, height: 0.4pt, fill: grid-paint, stroke: none))
      place(top + left, dx: ox - 0.62cm, dy: oy + py(t) - 6pt,
        box(width: 0.55cm, align(right, text(dir: ltr, size: 8.5pt)[#t])))
    }
    place(top + left, dx: ox, dy: oy + py(0.355),
      line(length: W, stroke: (paint: rgb("#718096"), thickness: 0.7pt, dash: "dashed")))
    place(top + left, dx: ox + 0.05cm, dy: oy + py(0.355) - 14pt,
      text(dir: rtl, size: 8.5pt, fill: black.lighten(15%))[خطِ دقت])
    place(top + left, dx: ox, dy: oy,
      rect(width: W, height: H, fill: none, stroke: (left: 1pt + black, bottom: 1pt + black)))
    place(top + left, dx: ox - 0.62cm, dy: 0.04cm,
      text(dir: rtl, size: 9pt, weight: "bold")[دقت یافته])
    place(top + left, dx: ox + W / 2 - 1.7cm, dy: oy + H + 0.42cm,
      box(width: 3.4cm, align(center, text(dir: rtl, size: 9pt, weight: "bold")[یادآوری (دانه‌بندی یافته)])))
    for (i, p) in pts.enumerate() {
      let name = p.at(0)
      let rec = p.at(1)
      let prec = p.at(2)
      let fpr = p.at(3)
      let cx = ox + px(rec)
      let cy = oy + py(prec)
      let r = 3pt + 9pt * calc.sqrt(fpr / 0.197)
      let c = _palette.at(i)
      place(top + left, dx: cx - r, dy: cy - r,
        circle(radius: r, fill: c.lighten(45%), stroke: 1.1pt + c))
      if name == "B" {
        place(top + left, dx: cx - r - 3pt - 0.45cm, dy: cy - 7pt,
          box(width: 0.45cm, align(right, text(dir: ltr, size: 10pt, weight: "bold")[#name])))
      } else {
        place(top + left, dx: cx + r + 3pt, dy: cy - 7pt,
          box(width: 0.45cm, align(left, text(dir: ltr, size: 10pt, weight: "bold")[#name])))
      }
    }
  })
}

#let figure-4-3 = block(breakable: false, align(center, [
  #v(2.5%)
  #_legend(([A: ایستا], [B: عامل], [C: ایستا+عامل], [D: ایستا+ساختار+عامل]))
  #v(6pt)
  #_tradeoff-plot()
  #_caption(
    [
      شکل ۴.۳: نمای مبادلهٔ دقت و یادآوری برای چهار پیکربندی؛ اندازهٔ هر حباب متناسب با نرخ هشدار روی فایل سالم است

      (
        A: ۰٫۰۵۰،
        B: ۰٫۱۹۷،
        C: ۰٫۰۰۷،
        D: ۰٫۰۲۰
      ).
      خط‌چین، دقتِ پیکربندی A را نشان می‌دهد؛ هر چه حباب به گوشهٔ بالا-چپ نزدیک‌تر باشد، هم دقت بیشتری دارد و هم هشدار کمتری می‌سازد.
    ],
  )
  #v(1%)
]))

#let figure-4-4 = align(center, [
  #v(2.5%)
  #_legend_3(([تأییدشده], [ردشده], [نامطمئن]))
  #v(4pt)
  #grouped-bars(
    (
      ([C: بدون ساختار], (5, 13, 13)),
      ([D: با ساختار], (11, 14, 6)),
    ),
    ([تأییدشده], [ردشده], [نامطمئن]),
    colors: (rgb("#2f855a"), rgb("#c05621"), rgb("#718096")),
  )
  #_caption([شکل ۴.۴: اثر شواهد ساختاری بر تصمیم‌های عامل زبانی؛ با افزودن شواهد، تأییدها از ۵ به ۱۱ رسید و نامطمئن‌ها از ۱۳ به ۶ کاهش یافت])
  #v(1%)
])

#let figure-4-5 = block(breakable: false, align(center, [
  #v(2.5%)
  #text(
    dir: rtl,
    size: 11pt,
    weight: "bold",
    [یادآوری در هر سه مجموعه],
  )
  #v(5pt)
  #_legend(([موتور شواهد], [ابزار پایه]))
  #v(5pt)
  #grouped-bars(
    (
      ([جولیت: ۶۰۰], (0.023, 0.043)),
      ([دیویگن متوازن: ۶۰۰], (0.057, 0.020)),
      ([پایتون: ۴۸], (1.0, 0.667)),
    ),
    ([موتور شواهد], [ابزار پایه]),
    digits: 3,
  )
  #v(21pt)
  #text(
    dir: rtl,
    size: 11pt,
    weight: "bold",
    [نرخ هشدار روی فایل سالم],
  )
  #v(5pt)
  #_legend(([موتور شواهد], [ابزار پایه]))
  #v(5pt)
  #grouped-bars(
    (
      ([جولیت: ۶۰۰], (0.023, 0.033)),
      ([دیویگن متوازن: ۶۰۰], (0.070, 0.037)),
      ([پایتون: ۴۸], (0.042, 0.250)),
    ),
    ([موتور شواهد], [ابزار پایه]),
    digits: 3,
  )
  #_caption(
    [
      شکل ۴.۵: توان موتور شواهد در برابر ابزار پایه روی هر سه مجموعه؛ موتور شواهد روی دیویگن یادآوری بیشتر و روی پایتون هم دقت بیشتر و هم هشدار کمتری دارد،
      اما در جولیت از فلافایندر عقب می‌ماند. عدد یادآوری پایتون ۱٫۰۰۰ است.
    ],
  )
  #v(1%)
]))


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

#let figure-2-3 = align(center, [
  #v(1.5%)
  #text(
    dir: rtl,
    diagram(
      spacing: (0.27cm, 0.7cm),

      node((0, 0), rect(width: 76pt, height: 56pt, [
        #text(size: 8pt)[چالش ۱]
        \
        #text(size: 9.5pt, weight: "bold")[پایداریِ پاسخ]
        \
        #text(size: 8pt)[خروجیِ ثابت در دو اجرا]
        #v(4%)
      ])),

      node((1, 0), rect(width: 76pt, height: 56pt, [
        #text(size: 8pt)[چالش ۲]
        \
        #text(size: 9.5pt, weight: "bold")[هزینهٔ محاسباتی]
        \
        #text(size: 8pt)[نمونه، بازهٔ اطمینان]
        #v(4%)
      ])),

      node((2, 0), rect(width: 76pt, height: 56pt, [
        #text(size: 8pt)[چالش ۳]
        \
        #text(size: 9.5pt, weight: "bold")[نشتِ برچسب]
        \
        #text(size: 8pt)[خواندنِ پاسخ، نه کد]
        #v(4%)
      ])),

      node((3, 0), rect(width: 76pt, height: 56pt, [
        #text(size: 8pt)[چالش ۴]
        \
        #text(size: 9.5pt, weight: "bold")[شفافیتِ پیکربندی]
        \
        #text(size: 8pt)[بازتولیدِ ناممکنِ نتیجه]
        #v(4%)
      ])),

      node((4, 0), rect(width: 76pt, height: 56pt, [
        #text(size: 8pt)[چالش ۵]
        \
        #text(size: 9.5pt, weight: "bold")[پایداریِ سرویس]
        \
        #text(size: 7pt)[خطای شبکه، یادآوریِ کاذب]
        #v(4%)
      ])),
    ),
  )
  #text(
    dir: rtl,
    size: 10pt,
    fill: black.lighten(35%),
    [
      #v(1.5%)
      شکل ۲.۳: پنج محور چالش‌برانگیزِ ارزیابی سامانه‌های مبتنی بر مدل زبانی
    ],
  )
  #v(1%)
])

#let figure-4-6 = align(center, [
  #v(2.5%)
  #grouped-bars(
    (
      ([A: ایستا], (0.04,)),
      ([B: عامل], (158.3,)),
      ([C: ایستا+عامل], (164.4,)),
      ([D: ایستا+ساختار+عامل], (17.4,)),
    ),
    ([ثانیه به ازای هر واحد کار],),
    max: 165,
  )
  #_caption(
    [
      شکل ۴.۶: میانگین زمان پردازش به ازای هر واحد کار؛ پیکربندی‌های A و B به ازای هر فایل و پیکربندی‌های C و D به ازای هر تصمیم. بر روی همین مقیاس، میلهٔ پیکربندی A غیرقابل‌روئت است.
    ],
  )
  #v(1%)
])
