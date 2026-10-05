# Follow-up study: addressing the six limitations of the evidence-packet design

This document turns the limitations reported in `thesis/main.pdf` into a
prioritised, measurable research programme. Every claim about *why* something
fails points at the code that fails; every claim about *how much* a mitigation
buys is either measured from the archived runs (no model calls) or stated as a
hypothesis with an acceptance criterion.

Nothing here re-runs a model unless it has to. The first pass over the archived
600-sample runs already answers the most important open question, so the
expensive experiments are sequenced behind the free ones.

---

## 0. What was measured offline before designing anything

```bash
python scripts/policy_counterfactual.py \
    results/exp_C_static_llm_subset600.json \
    results/exp_D_static_structural_llm_subset600.json \
    --json results/counterfactual_subset600.json \
    --triage-dir results/triage
```

Two questions, answered from `metadata.reports` alone:

1. **Where did the recall go?** Every one of the 300 ground-truth positives is
   attributed to the stage that lost it.
2. **What would a different verdict policy have scored?** The shipped policy
   keeps `CONFIRMED` only (`phase3/extract_predictions.py:80`); the same reports
   are re-scored keeping `CONFIRMED + UNCERTAIN`, and then every verdict.

### 0.1 Miss decomposition — configuration C (300 positives)

| stage | count | share | can it be fixed downstream of Phase 1? |
|---|---:|---:|---|
| matched (true positive) | 3 | 1.0% | — |
| **candidate ceiling** — Phase 1 emitted nothing, the agent never saw the file | **286** | **95.3%** | no |
| **dropped as `UNCERTAIN`** | **8** | **2.7%** | yes |
| dropped as `REJECTED` | 3 | 1.0% | yes, but see below |

Per class: of the 150 CWE-190 positives, 148 never reached the agent and 2 were
rejected — **zero reached a confirmation**. Of the 150 CWE-122 positives, 138
never reached the agent, 8 were dropped as `UNCERTAIN`, 1 was rejected.

Configuration D is the same shape (286 candidate ceiling, 6 uncertain, 3
rejected, 5 matched).

### 0.2 Verdict-policy counterfactual

Precision / recall / FPR with Wilson 95% intervals, same matcher, same corpus.

| config | policy | precision | recall | FPR (benign files) |
|---|---|---|---|---|
| C | shipped (`CONFIRMED`) | 0.600 [0.231, 0.882] | 0.010 [0.003, 0.029] | 0.007 [0.002, 0.024] |
| C | **+ `UNCERTAIN` (triage lane)** | **0.611 [0.386, 0.797]** | **0.037 [0.021, 0.064]** | 0.023 [0.011, 0.047] |
| C | + every verdict (oracle) | 0.355 [0.211, 0.531] | 0.037 [0.021, 0.064] | 0.050 [0.031, 0.081] |
| D | shipped (`CONFIRMED`) | 0.455 [0.213, 0.720] | 0.017 [0.007, 0.038] | 0.020 [0.009, 0.043] |
| D | **+ `UNCERTAIN` (triage lane)** | **0.647 [0.413, 0.827]** | **0.037 [0.021, 0.064]** | **0.020 [0.009, 0.043]** |
| D | + every verdict (oracle) | 0.355 [0.211, 0.531] | 0.037 [0.021, 0.064] | 0.050 [0.031, 0.081] |
| A | static baseline, unfiltered | 0.355 [0.211, 0.531] | 0.037 [0.021, 0.064] | 0.050 [0.031, 0.081] |

Three conclusions, all of which change the shape of the follow-up:

1. **The entire recall loss is the `UNCERTAIN` drop.** For configuration D,
   routing the uncertain verdicts to a separate lane recovers recall to exactly
   the static baseline (0.017 → 0.037) while *raising* precision from 0.455 to
   0.647 and leaving the benign-file FPR unchanged at 0.020. For C the FPR
   rises 0.007 → 0.023, still 54% below the static baseline's 0.050.
2. **Loosening the gate is the wrong fix.** Admitting `REJECTED` verdicts buys
   *zero* additional true positives (11 → 11) while tripling the FPR
   (0.007 → 0.050). The evidence gate is not throwing away true positives; the
   uncertainty is. The intervention must be *routing*, not *relaxing*.
3. **95.3% of misses are upstream of any language reasoning.** No prompt
   change, temperature change or model swap can recover a file that Phase 1
   never proposed. Any follow-up that only touches the agent will plateau at
   ~11/300 recall on this corpus.

Cost of the above: zero model calls.

---

## 1. Limitation — the recall drop

**Where it lives**

* `phase3/extract_predictions.py:80` — only `CONFIRMED` groups become
  predictions; `REJECTED` and `UNCERTAIN` are withheld by design.
* `phase2/multiagent.py:853-854` — anything not `CONFIRMED` produces no
  `ReportFinding` at all.
* `phase2/multiagent.py:1096-1101` — a confirmation carrying non-empty
  `missing_evidence` is flipped to `REJECTED` by `_evidence_gate`.
* `phase2/multiagent.py:982-1022` — `_resolve_hedge` turns an `UNCERTAIN` with
  an unverified chain into `REJECTED`.

**Measured fact:** the loss is concentrated in `UNCERTAIN` (8 of 14 reached
positives for C), not in `REJECTED` (3, and the oracle shows those 3 do not
match even when admitted).

### P0 — a separate triage lane, not a looser gate

Emit the `UNCERTAIN` groups as a second, ranked artifact next to the main
report; leave the shipped report byte-identical.

* Implement `--emit-triage` in the Phase-2 report writer so the queue
  `scripts/policy_counterfactual.py` already produces
  (`triage_queue()`, ranked by confidence) is a first-class output instead of
  an offline reconstruction.
* Report triage **precision separately** from report precision: the claim is
  "recover recall without polluting the main report", so the two populations
  must never be summed into one headline number.
* Confidence ranking is a *hypothesis*, not a fact: in configuration D the mean
  confidence of true findings was 0.81 and of false findings 0.92 (§4.15 of the
  thesis), so the queue must be validated by a precision-vs-rank curve before
  it is called a ranking.

**Acceptance criteria**

* Configuration D: recall ≥ 0.035 with report precision ≥ 0.60 and benign FPR
  ≤ 0.025, measured on ≥ 600 samples with Wilson intervals.
* Triage queue precision-at-k reported for k = 5, 10, 15; if it does not beat
  random ordering, ship the queue unranked and say so.

### P1 — why the verdicts were uncertain in the first place

The evidence packet is function-scoped: `phase2/context.py:58-62` widens the
snippet to the enclosing function (≤ 400 lines, `multiagent.py:68`), and the
taint engine is intra-function. When the destination buffer is allocated in the
*caller*, the agent correctly reports "cannot be determined from the supplied
evidence" — and is then either dropped or, worse, confirmed on absence of
evidence (§4.15).

* Extend the packet with a **caller/callee summary**: for each parameter that
  reaches the sink, add its declaration site, any `sizeof`/capacity expression
  in the caller, and the nearest dominating bounds check — assembled
  deterministically from the Phase-1 structural index, not by another model
  call.
* Hypothesis: this converts a material share of the 13 C-uncertain verdicts
  into decisive answers instead of leaving them for the triage lane.

**Acceptance criteria:** uncertain rate for C falls below 25% (from 42%) while
report precision stays ≥ 0.55; every conversion attributed to a packet field
that was previously absent.

### P2 — do not touch

* Do **not** lower `min_confidence` (`multiagent.py:865-878`).
* Do **not** add a confidence threshold filter — the thesis §5.2 already shows
  confidence does not separate true from false.

---

## 2. Limitation — computational cost and wall-clock time

**Where it lives**

* `agents/openai_compat.py:290-331` — every request is a live POST; there is no
  response cache anywhere in the transport.
* `codey_security.py:416` — legs A/C/D write the result file only at the end;
  `scripts/run_benchmarks.py:137-140` kills a timed-out child and its work is
  discarded. Only leg B resumes (`run_llm_only_benchmark.py:227-243`).
* Measured: 158 s of request time per file for B (94,966.7 s over 600 files ≈
  26 h serial), 164 s per decision for C at concurrency 8. Whole Juliet (4,098
  files) extrapolates to ~180 h serial, ~24 h at concurrency 8.

### P0 — a content-addressed response cache

Key = SHA-256 over the sanitised packet + model id + temperature +
`reasoning_effort` + prompt version; value = the raw completion. Store under
`.cache/llm/` (git-ignored), read through on every call, write on success.

This one change buys four things at once:

1. **Re-evaluation becomes free.** Matcher changes, policy changes, metric
   changes and CI computation stop costing a 26-hour run — the same property
   that makes `scripts/recompute_result.py` possible for metrics already holds
   for verdicts once responses are cached.
2. **The non-determinism study becomes affordable** (limitation 6): replay the
   identical packet at `temperature = 0` and at `0.2` and count verdict flips.
3. **Resume** for A/C/D becomes read-through instead of a second mechanism.
4. **Cost accounting**: store `usage` (already parsed at
   `agents/security_agent.py:458-465`) alongside the response so tokens, not
   wall-clock, become the comparable cost unit — wall-clock is explicitly
   unusable as a comparison metric (§4.13: same workload, 636.9 s vs 67.4 s).

### P0 — complete the provenance block — **done**

`temperature` and `reasoning_effort` were sent on every request and written
into no result file; leg B additionally dropped concurrency. The repair is one
resolver, not four copies:

* `agents/openai_compat.py::sampling_settings()` is now the single place a knob
  is resolved. The transport's `__init__`, `codey_security.py`'s `run_phase3`
  provenance, its `full`-pipeline provenance and `scripts/run_llm_only_benchmark.py`
  all read it, so a file cannot describe a configuration that was never sent.
* `OpenAICompat.effective_settings()` reports the *live* values, including a
  `reasoning_effort` the provider rejected mid-run — recorded as dropped rather
  than as sent.
* `run_full` gains a provenance block with no `elapsed_seconds`, deliberately:
  that path spans Phase 1 + 2 + 3, and a field of that name would not mean what
  it means in a phase3 result. It records what ran, not an invented duration.
* Experiment B writes `temperature`, `reasoning_effort`, `concurrency` (and
  `reasoning_effort_dropped` when it applies) **per record**, and
  `scripts/evaluate_llm_only.py` unions them into
  `temperatures_in_file` / `reasoning_efforts_in_file` /
  `concurrencies_in_file` **from the JSONL**, never from today's `.env` — the
  evaluation often runs hours after the run it scores.
* A static-only run records `temperature: null`, because writing a sampling
  knob next to a run that never called a model claims an experiment that did
  not happen.

Still open: `prompt_version` and per-request attempt counts for legs A/C/D —
those live on the retry path, not on the transport's construction.

### P1 — a two-stage cascade

Cheap pass first (existing static evidence + a single low-effort agent call),
escalate only the `UNCERTAIN` slice to the full scanner/verifier exchange.
Target: ≥ 5× reduction in mean seconds per decision with recall within 0.02 of
the full pipeline. Measure with tokens, not seconds (see above).

### P2 — batch transport and concurrency sweeps

Sweep `phase2_concurrency` ∈ {4, 8, 16, 32} and record throughput *and* error
rate; §4.13 shows the service, not the workload, dominates variance, so a
concurrency sweep with error bars is the only defensible scaling statement.

**Acceptance criteria**

* Second pass over an already-evaluated corpus: ≥ 95% cache hit rate, 0 model
  calls for verdicts that did not change prompt inputs.
* Full Juliet run: ≤ 24 h at concurrency 8 with 0 unrecoverable failures
  (measured failures: 1,068 requests cut at 180 s and 6 unparseable responses
  in the one full-scale attempt).
* `model`, `temperature`, `reasoning_effort`, `concurrency` present in 100% of
  result files — done for new runs; archives written before this pass record
  `null` rather than a guess. `prompt_version` still to do.

---

## 3. Limitation — blind spots in specific vulnerability classes (CWE-190)

**Where it lives**

* `analyzers/structural_analyzer.py:497-554` — emits an index and a
  `dangerous_calls` list; **no arithmetic or width rules at all**.
* `analyzers/static_tools.py:242-270` — `_NOISE_RULES` suppresses Flawfinder's
  numeric/copy rules; cppcheck's integer checks are not enabled.
* `analyzers/taint.py:988-1010` — `TAINT_MODELLED_CWES` deliberately excludes
  CWE-190: an overflow is not a data flow, so no chain is not evidence against
  it. Correct for *gating*, but it also means nothing proposes it.

**Measured:** 148/150 CWE-190 positives never reached the agent; 2 reached it
and were rejected; A/C/D recall = 0.000; the LLM-only leg B found 9 (recall
0.060, precision 0.333) with 18 false positives.

### P0 — a deterministic integer-overflow candidate generator

New `analyzers/intoverflow.py`, wired into `analyzers/phase1_pipeline.py:26-88`
next to the tools. No LLM, tree-sitter only. First patterns, each of which must
be justified by a test case from the corpus:

* value narrowed by a cast to `int`/`short`/`char`/`uint32_t` and then used as
  a size or index;
* `malloc(n * size)` / `calloc` / array declaration where `n` is not provably
  bounded;
* a length reaching an allocation or copy (`strlen`, `recv`, `atoi`, `ntohl`)
  with no dominating range check in the same function;
* arithmetic on a type whose width the operation can exceed, with the
  corresponding guard absent.

### P0 — measure per-tool yield before enabling it

§4.11 found cppcheck precision **0/6** on this subset while Flawfinder carried
all 11 true positives (11/25). Adding a tool is not adding signal. Enable
cppcheck's integer checks behind a flag, run Phase 1 only (22 s for 600 files),
and report per-tool TP/FP before anything reaches an agent.

### P1 — a length→allocation taint analogue

Reuse the taint machinery with a new category: source = attacker-influenced
length, sink = allocation/copy size, mitigation = dominating range check. This
is the structural sibling of what already works for injection (§4.9: precision
0.96, recall 1.0 on the controlled Python benchmark).

### P1 — caller-side bounds, shared with limitation 1's P1

Two of the two CWE-190 verdicts that reached the agent were rejected because
the bound lives in the caller. Same packet extension fixes both.

**Acceptance criteria**

* ≥ 15/150 CWE-190 true positives in configuration C, with benign-file FPR on
  the 150 CWE-190 negatives ≤ 0.05.
* Per-tool yield table published for every candidate source, including the
  ones with zero yield.
* Because language and class are entangled in this subset (limitation 7 of the
  thesis), results are reported **within** CWE-190 only; no cross-language claim.

---

## 4. Limitation — statistical uncertainty

**Where it lived.** The thesis quotes Wilson 95% intervals (§4.12, table 4.8)
but no code computed them: every number in the evaluation layer was a bare
point estimate.

**Fixed in this pass.** `phase3/metrics.py` now implements
`wilson_interval()` and every rate carries `Metrics.ci95`. The implementation
reproduces **all twelve intervals** of table 4.8 exactly — e.g. precision of C
0.600 [0.231, 0.882], recall of D 0.017 [0.007, 0.038], FPR of A 0.050
[0.031, 0.081] — so the written evaluation and the shipped evaluation are now
provably the same evaluation.

### P0 — paired tests instead of overlapping intervals — **done**

All four configurations score the *same* 600 files, so the correct comparison
is paired, not two marginal intervals. `phase3/significance.py` now implements
McNemar's test on per-sample discordant pairs — exact (binomial) for the small
discordant counts this corpus actually produces, chi-square with continuity
correction as the fallback above 1,000 discordances — and reports the
discordance table before the p-value, because with 11 true positives the
*number of disagreeing files* carries the argument.
`scripts/compare_paired.py` rebuilds each run's predictions from that run's own
stored reports, re-scores both with that run's own matching policy, and prints
the table (`--json` keeps it). p-values are stored at six significant digits:
`round(9.1e-13, 10)` is `0.0`, and a printed `p = 0` is a claim of certainty
the test does not make.

| pair | recall p | benign flag p | accuracy p | recall discordance (A-only / B-only) |
|---|---|---|---|---|
| A vs B | 2.1e-09 | 2.4e-09 | 0.300 | 1 / 34 |
| A vs C | 0.0078 | 0.0002 | 0.383 | 8 / 0 |
| A vs D | 0.0312 | 0.0039 | 0.607 | 6 / 0 |
| B vs C | 9.1e-13 | 1.4e-17 | 0.129 | 41 / 0 |
| B vs D | 3.6e-12 | 2.2e-16 | 0.175 | 39 / 0 |
| C vs D | 0.625 | 0.125 | 0.727 | 1 / 3 |

**What this changes.** The thesis's statement that the configurations cannot be
ranked at 95% confidence (§4.15) was an argument from overlapping *marginal*
intervals. Pairing is a more powerful test, and on this corpus it separates
several pairs:

* **C vs D — the pair the shipped conclusion is about — stays indistinguishable
  on every stratum** (p ≥ 0.125, 1 and 3 discordant positives). The
  non-ranking claim survives exactly where it is load-bearing.
* A differs from B, C and D on detection (p ≤ 0.032) and its benign flag rate
  differs from all three (p ≤ 0.0039). Static-only really does flag more clean
  files than any combined configuration — the FPR numbers were right, they were
  never tested.
* B differs from C and D on detection *and* flagging (p ≤ 3.6e-12) while
  **accuracy separates no pair at all** (p ≥ 0.129). An accuracy-only summary
  says "nothing to see here" at this base rate; the paired strata show why
  accuracy is the wrong statistic to rank on.
* No multiplicity correction is applied across the 18 tests. Under Bonferroni
  (α ≈ 0.0028) seven of the eighteen tests survive: A vs B, B vs C and B vs D
  on both detection and flagging, plus A vs C on flagging (0.0002). A vs C on detection
  (0.0078) and A vs D on either stratum (0.0312, 0.0039) do not. The honest
  reading is the one the table already gives: quote the discordance counts with
  the p-value, and do not turn a 6-vs-0 discordance into a ranking.

### P0 — power the next experiment on the paired difference

Sample size must be chosen from the number of *discordant* pairs needed for
80% power at α = 0.05, not from what fits in a budget. On the current corpus
that number is unreachable for the combined configurations; the honest options
are (a) a much larger positive count from a richer corpus, or (b) narrowing the
claim to the one contrast the corpus can support.

### P1 — bootstrap for the rates that are not proportions

`f1`, `balanced_accuracy` and any difference or ratio of rates have no Wilson
interval. Add a stratified (CWE × label) percentile bootstrap over files,
10,000 resamples, seeded and recorded in provenance.

### P1 — repeated runs for non-determinism

k = 5 runs of the same configuration at the recorded temperature; report
mean ± σ per metric **and** the per-verdict flip rate. Requires the cache from
limitation 2 to be affordable.

**Acceptance criteria**

* No ranking claim ("C > D") appears without a paired test result; otherwise it
  is stated as "not distinguishable at this sample size".
* Every rate published with its interval; every non-binomial quantity with its
  bootstrap interval; seeds recorded.

---

## 5. Limitation — context limits and model misinterpretation

**Where it lives**

* `phase2/context.py:49` sanitises, `:58-62` widens to the enclosing function,
  `:69-73` truncates at `context_max_lines = 400` (`multiagent.py:68`).
* `phase2/prompts.py:200, 250-256` — the schema offers `UNCERTAIN` and nudges
  toward it, but nothing *forces* it when a declared must-have field is absent.
* The escape hatch exists and works when used: `_evidence_gate`
  (`multiagent.py:1096-1101`) drops a confirmation carrying
  `missing_evidence`. The §4.15 failure is that the model did not populate
  `missing_evidence` — it read "no check in this function" as positive evidence.

**Measured shape:** 42% of C's groups closed `UNCERTAIN`; structural evidence
(C → D) moved 13 uncertain down to 6 and confirmations from 5 to 11, but also
doubled false positives from 2 to 6. More evidence makes the model more
decisive, not more correct.

### P0 — make evidence sufficiency structural, not rhetorical

* Require the verifier to answer a fixed `missing_context` checklist derived
  from the CWE family (for a buffer/overflow claim: *destination allocation
  site*, *bounds check*, *caller of this function*, *input origin*).
* Force `UNCERTAIN` when any required item is absent — this is a rule in
  `_parse_verification`/`_evidence_gate`, not a sentence in the prompt.
* Add the negative instruction to `phase2/prompts.py`: "absence of a safety
  check inside this function is **not** evidence of vulnerability; if the
  capacity or bounds are defined outside the analysed scope, answer
  `UNCERTAIN`."

### P0 — a labelled regression set for decisions

Hand-label, as a fixture (`tests/fixtures/decisions/`):

* the §4.15 false confirmation (good variant, line 34, `FF1005`, confidence
  0.90) and its true-positive twin (bad variant, line 33, `strcpy`, 0.90);
* all 20 static false positives already enumerated in table 4.7;
* the 13 C and 6 D uncertain verdicts.

Score every prompt/packet change against this set so a "fix" is a number, not
an impression. This is cheap and it is the only guardrail against trading one
error for another (C → D did exactly that).

### P1 — an on-demand query tool

Replace the fixed packet with a small set of read-only queries the agent can
issue (`definition of X`, `callers of Y`, `bounds checks on Z`) — the thesis
§5.3 already identifies this as the way to cut the uncertain rate. Cap the
total budget so the cost story (limitation 2) does not regress.

**Acceptance criteria**

* Zero false confirmations on the regression set that are attributable to
  out-of-scope evidence.
* Uncertain rate does not grow by more than 2× (the checklist will push some
  confirmations into `UNCERTAIN`; that is correct behaviour and must be
  reported, not hidden).

---

## 6. Limitation — evaluation and service stability

| threat | evidence in the repo | mitigation |
|---|---|---|
| response non-determinism | only ad-hoc repeats exist (`results/exp_big_2..5_*`); no n-run statistics anywhere | cache + k=5 runs + flip-rate report (limitations 2 and 4) |
| configuration opacity | was **absent from every result file**: `temperature`, `reasoning_effort`, leg-B concurrency were sent on every request and written nowhere | **fixed**: `sampling_settings()` in `agents/openai_compat.py` is the single resolver the transport, the `run_phase3` / `full` provenance blocks and Experiment B's JSONL all read; leg B additionally records the live `effective_settings()` so an effort the provider rejected mid-run is recorded as dropped. `evaluate_llm_only.py` reads them **back from the records**, never from today's environment. Still open: per-request attempt counts, prompt version |
| label leakage | `phase2/sanitize.py` scrubs comments, leaking identifiers and paths; coverage is good but asserted only case-by-case in `tests/test_sanitize.py` | add a **packet canary**: run the sanitiser over every packet of the 600-sample run and fail if any label token (`bad`/`good`/`CWE-xxx`/variant directory) survives outside a CWE field; add a *label-ablation* control where file paths are dropped entirely and the FPR delta is reported |
| network/API timeouts | 1,068 requests cut at 180 s and 6 unparseable responses in the full-scale run; step timeout kills the whole leg (`run_benchmarks.py:137-140`) | cache-backed resume for A/C/D (limitation 2); classify `timeout` vs `parse` vs `transport` separately in provenance, because only the first two are recoverable and none are method failures |
| errors counted as misses | already correct: faulty samples count as non-discovery, which §4.13 notes makes recall a *lower* bound — keep and state it explicitly in every table |

**Acceptance criteria**

* A single `--audit-run <result.json>` command that prints: model, temperature,
  reasoning effort, concurrency, prompt version, cache hit rate, retry counts,
  timeout/parse/transport failure counts, and whether any label token survived
  sanitisation.
* Re-running the same result file twice at `temperature = 0` yields identical
  verdicts; at `0.2` the flip rate is reported, not assumed.

---

## 7. Sequencing

| priority | item | needs model calls? | expected effect |
|---|---|---|---|
| **P0** | triage lane for `UNCERTAIN` (1) | no | recall 0.017 → 0.037, precision 0.455 → 0.647, FPR unchanged (D) |
| **P0** | Wilson CIs in the metrics layer (4) | no | done — reproduces table 4.8 exactly |
| **P0** | paired significance tests (4) | no | done — C vs D indistinguishable on all three strata; accuracy separates no pair |
| **P0** | provenance completion (6) | no | done — sampling knobs in phase3/full provenance and per record in leg B |
| **P0** | response cache + resume (2) | first pass only | makes everything below affordable |
| **P0** | integer-overflow candidate generator (3) | no (Phase 1 only) | attacks 95.3% of misses; the only path to CWE-190 recall |
| **P0** | forced `missing_context` checklist (5) | yes | removes the §4.15 failure mode |
| **P1** | caller/callee bounds in the packet (1, 3, 5) | yes | converts uncertain verdicts instead of parking them |
| **P1** | length→allocation taint (3) | no | structural coverage of CWE-190 |
| **P1** | two-stage cascade (2) | yes | ≥ 5× cost reduction |
| **P1** | bootstrap intervals + k=5 repeats (4, 6) | yes | non-binomial CIs and a real non-determinism number |
| **P2** | on-demand query tool (5) | yes | fewer uncertain verdicts at fixed cost |
| **P2** | concurrency sweep (2) | yes | a defensible scaling statement |

**Order matters.** The three completed rows cost no model calls and each of
them changes how the remaining ones must be read — Wilson intervals first,
then the paired test that compares them, then the provenance block that says
which configuration produced them. The only no-model-call P0 row left is the
integer-overflow candidate generator (3), which runs in Phase 1; everything
else in the table either touches the model or, like the forced
`missing_context` checklist, changes what the model is asked. Anything *with*
model calls should wait until the response cache exists, because without it a
k=5 repeat is a k=5 bill.

---

## 8. Reproducing everything in this document

```bash
# 1. policy counterfactual + miss decomposition + triage queues (no model calls)
python scripts/policy_counterfactual.py \
    results/exp_C_static_llm_subset600.json \
    results/exp_D_static_structural_llm_subset600.json \
    --json results/counterfactual_subset600.json \
    --triage-dir results/triage

# 2. re-score the archived reports with the interval computation attached
#    (writes elsewhere, so the frozen evidence set is left untouched)
python scripts/recompute_result.py --out results/recomputed \
    results/exp_A_static_subset600.json \
    results/exp_C_static_llm_subset600.json \
    results/exp_D_static_structural_llm_subset600.json

# 3. paired McNemar tests on every shipped pair (reads the archives, writes nothing)
for pair in "A B" "A C" "A D" "B C" "B D" "C D"; do
    set -- $pair
    python scripts/compare_paired.py \
        results/exp_$1_*600.json results/exp_$2_*600.json
done

# 4. test suite
python -m pytest -q
```

The Wilson intervals are asserted against table 4.8 in
`tests/test_policy_counterfactual.py`, so a regression in the interval
computation fails the build rather than silently disagreeing with the thesis.
`tests/test_significance.py` likewise pins the McNemar implementation (exact
and chi-square) and the fact that a one-sided p-value of 9.1e-13 survives
serialisation instead of collapsing to `0.0`, and
`tests/test_provenance.py` pins the sampling-knob provenance — including that
the evaluation reads the settings back from the records rather than from the
environment of the machine that happens to run it.
