#import "assets/utils.typ"
#import "assets/resources.typ"

#import "chapters/title.typ"
#import "chapters/in-the-name-of-god.typ"
#import "chapters/originality.typ"
#import "chapters/acknowledgement.typ"
#import "chapters/dedication.typ"
#import "chapters/abstract.typ" as apstract

#import "chapters/list-of-contents.typ"
#import "chapters/list-of-figures.typ"
#import "chapters/list-of-tables.typ"

#import "chapters/chapter-1.typ"
#import "chapters/chapter-2.typ"
#import "chapters/chapter-3.typ"
#import "chapters/chapter-4.typ"
#import "chapters/chapter-5.typ"

#import "chapters/references.typ"

#set page(
  paper: "a4",
  margin: (x: 2.6cm, y: 2.6cm),
)

#set par(
  spacing: 0.1cm,
  leading: 0.4cm,
  first-line-indent: 0.4cm,
  justify: true,
)

#set text(
  font: "IRNazanin",
  size: 12pt,
  spacing: 0.3em,
)

#show footnote.entry: set text(dir: ltr, size: 12pt)

#set footnote(numbering: utils.footnote_numbering)

#set footnote.entry(
  indent: 0pt,
  clearance: 8pt,
  separator: [
    #line(length: 30% + 0pt, stroke: 0.5pt) #v(0.2%)
  ],
)

#set list(indent: 0.8cm)

#show math.equation: set text(size: 11pt)

#title
#pagebreak()

#in-the-name-of-god
#pagebreak()

#originality
#pagebreak()

#acknowledgement
#pagebreak()

#dedication
#pagebreak()

#context counter(page).update(1)
#set page(numbering: utils.alphabet_numbering)

#context counter(footnote).update(0)
#apstract
#pagebreak()

#list-of-contents
#pagebreak()

#list-of-figures
#pagebreak()

#list-of-tables
#pagebreak()

#context counter(page).update(1)
#set page(numbering: "۱")

#context counter(footnote).update(0)
#chapter-1
#pagebreak()

#context counter(footnote).update(0)
#chapter-2
#pagebreak()

#context counter(footnote).update(0)
#chapter-3
#pagebreak()

#context counter(footnote).update(0)
#chapter-4
#pagebreak()

#context counter(footnote).update(0)
#chapter-5
#pagebreak()

#references
