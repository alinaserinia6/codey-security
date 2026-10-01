"""Scanner Agent -> Verifier Agent orchestration.

This is the multi-agent core the proposal describes. The two agents are given
deliberately different jobs and different evidence:

* the **Scanner** sees the whole file and emits hypotheses. It is tuned for
  recall and is expected to propose things that turn out to be wrong.
* the **Verifier** sees one hypothesis at a time, is shown the deterministic
  source-to-sink chain from ``analyzers.taint``, and rejects by default. It is
  the only agent whose output can become a reported finding.

Separating them is what makes the false-alarm reduction measurable: the
scanner's over-generation is absorbed by the verifier instead of reaching the
report, and the verifier's rejections are recorded so the report can show why a
candidate was dropped.

The pipeline is written against a callable ``ask_json`` rather than a concrete
LLM client so the orchestration can be tested end to end without a model.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple

from analyzers.catalog import VulnerabilityCatalog, get_catalog
from analyzers.cwe_family import cwes_match
from analyzers.taint import taint_chains_for, taint_modelled

from agents import thinking_log

from .context import load_source_context
from .models import (
    AgentAssessment,
    FinalDecision,
    Hypothesis,
    Phase2Report,
    ReportFinding,
    Verification,
)
from .prompts import SCANNER_PROMPT, VERIFIER_PROMPT
from .sanitize import sanitize_value

JsonClient = Callable[[str, Dict[str, Any]], Awaitable[Dict[str, Any]]]

DECISIONS = ("CONFIRMED", "REJECTED", "UNCERTAIN")


@dataclass
class MultiAgentConfig:
    """Runtime configuration for the Scanner/Verifier pipeline."""

    context_radius: int = 8
    max_hypotheses: int = 12
    max_tokens: int = 40000
    concurrency: int = 4

    # Both default to True: dropping the dataflow evidence would make the
    # verifier's source-to-sink requirement unverifiable, which is the point
    # of the design. They exist so the contribution can be ablated.
    include_taint: bool = True
    include_structural: bool = True
    include_tools: bool = True

    # Verifier rejects below this confidence even when it says CONFIRMED.
    min_confidence: float = 0.5

    # A CONFIRMED verdict for a class the taint engine models must be backed by
    # a chain that is actually in the file. Without this the model can satisfy
    # "confirm the source-to-sink path" by describing one it never saw, which
    # would undo the precision the evidence chain exists to provide. Classes
    # the engine does not model are exempt: there is no chain to check.
    require_chain_evidence: bool = True

    # A chain whose mitigation the engine recognised is evidence the finding is
    # already handled. The verifier is told about it and can still confirm for
    # a reason the engine does not model, but it may not quietly ignore it.
    reject_mitigated: bool = False

    # The scanner restates one issue several times ("CWE-125 at line 176", then
    # again at 178 and at 829). Every restatement otherwise buys its own
    # verifier pass and, when confirmed, its own report entry for something the
    # reader is shown once. With ``merge_claims`` hypotheses that name the same
    # CWE are verified as one claim, walking its sites in scanner order and
    # stopping at the first confirmation; with ``merge_findings`` confirmed
    # findings whose CWE families overlap are folded into a single report entry.
    # Both default to True and are switchable for ablation.
    merge_claims: bool = True
    merge_findings: bool = True

    # Lines within this distance are the same place: a restatement a few lines
    # down does not earn a second verifier pass. It also bounds the line a
    # merged report entry may claim -- a merge spanning more than this reports
    # no line rather than an arbitrary one.
    claim_site_radius: int = 5


class MultiAgentPipeline:
    """Runs the Scanner Agent then the Verifier Agent over one file."""

    def __init__(
        self,
        ask_json: JsonClient,
        *,
        config: Optional[MultiAgentConfig] = None,
        catalog: Optional[VulnerabilityCatalog] = None,
    ) -> None:
        self.ask_json = ask_json
        self.cfg = config or MultiAgentConfig()
        self.catalog = catalog or get_catalog()
        self._sem = asyncio.Semaphore(max(1, self.cfg.concurrency))

    # -- public API ------------------------------------------------------
    async def analyze_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Alias for :meth:`analyze_file`, matching the single-agent pipeline.

        Both Phase 2 pipelines consume one Phase 1 report for one file, so
        callers that switch architectures should not have to change method
        names to compare them on the same input.
        """
        return await self.analyze_file(report)

    async def analyze_file(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Scan then verify one Phase 1 report, returning a Phase 2 report."""
        source = str(report.get("source") or report.get("path") or "<unknown>")
        language = str(report.get("language", "unknown"))

        result = Phase2Report(
            source=source,
            language=language,
            metadata={
                "architecture": "scanner_then_verifier",
                "input_finding_count": len(report.get("findings", [])),
            },
        )

        scan_packet = self._scan_packet(source, language, report)
        scanner_failed = False
        try:
            with thinking_log.scope(id=source, file=source, role="scanner"):
                raw = await self.ask_json(SCANNER_PROMPT, scan_packet)
            hypotheses = self._parse_hypotheses(raw)
        except Exception as exc:  # noqa: BLE001 - one file must not stop a run
            result.errors.append(f"scanner: {type(exc).__name__}: {exc}")
            scanner_failed = True
            hypotheses = []

        if not hypotheses and scanner_failed:
            # A dropped connection must not read as "this file is clean" when
            # the tools already flagged it: the tool findings are exactly what
            # the scanner was going to reason about, so they are handed to the
            # verifier instead of the sample being lost.
            hypotheses = self._fallback_hypotheses(report)
            if hypotheses:
                result.metadata["scanner_fallback"] = True

        result.metadata["hypotheses_proposed"] = len(hypotheses)
        result.metadata["hypotheses_truncated"] = len(hypotheses) > self.cfg.max_hypotheses
        hypotheses = hypotheses[: max(1, self.cfg.max_hypotheses)]
        if not hypotheses:
            return result.to_dict()

        claims = self._claims(hypotheses)
        if self.cfg.merge_claims:
            result.metadata["claims"] = len(claims)
            result.metadata["claims_merged"] = len(hypotheses) - len(claims)

        verifications = await asyncio.gather(
            *[
                self._verify_claim(claim, scan_packet, result, source)
                for claim in claims
            ],
            return_exceptions=True,
        )
        verified: List[Tuple[FinalDecision, Optional[ReportFinding]]] = []
        for outcome in verifications:
            if isinstance(outcome, BaseException):
                result.errors.append(f"verifier: {type(outcome).__name__}: {outcome}")
                continue
            if outcome is None:
                continue
            verified.extend(outcome)

        merges: List[Dict[str, Any]] = []
        if self.cfg.merge_findings:
            verified, merges = self._merge_findings(verified)
        if merges:
            result.metadata["claim_merges"] = merges

        result.decisions = [decision for decision, _ in verified]
        result.findings = [finding for _, finding in verified if finding is not None]
        result.metadata["decision_counts"] = {
            status: sum(1 for d in result.decisions if d.status == status)
            for status in DECISIONS
        }
        result.metadata["reported_findings"] = len(result.findings)
        return result.to_dict()

    # -- claims -----------------------------------------------------------
    def _claims(self, hypotheses: List[Hypothesis]) -> List[List[Hypothesis]]:
        """Group hypotheses that name the same CWE, keeping scanner order.

        One claim is one thing to verify: the scanner restating "CWE-125" at
        nine lines is one vulnerability it pointed at nine times, not nine
        independent questions. A hypothesis without a CWE gets a claim of its
        own -- with nothing to compare there is no evidence the two restatements
        are the same claim, and the verifier is the better judge.
        """
        if not self.cfg.merge_claims:
            return [[hypothesis] for hypothesis in hypotheses]
        order: List[str] = []
        buckets: Dict[str, List[Hypothesis]] = {}
        for hypothesis in hypotheses:
            key = hypothesis.cwe.strip().upper() or f"\x00{hypothesis.id}"
            if key not in buckets:
                buckets[key] = []
                order.append(key)
            buckets[key].append(hypothesis)
        return [buckets[key] for key in order]

    def _sites(self, claim: List[Hypothesis]) -> List[List[Hypothesis]]:
        """Split one claim into the distinct places it points at.

        Lines within ``claim_site_radius`` are the same place, so a restatement
        a few lines down does not buy a second verifier pass. The order is the
        scanner's, because it is the order the model considered the sites in.
        """
        if len(claim) == 1:
            return [claim]
        sites: List[List[Hypothesis]] = []
        for hypothesis in claim:
            line = hypothesis.line
            target: Optional[List[Hypothesis]] = None
            if line is None:
                target = sites[0] if sites else None
            else:
                for site in sites:
                    reference = site[0].line
                    if reference is None or abs(line - reference) <= self.cfg.claim_site_radius:
                        target = site
                        break
            if target is None:
                sites.append([hypothesis])
            else:
                target.append(hypothesis)
        return sites

    async def _verify_claim(
        self,
        claim: List[Hypothesis],
        scan_packet: Dict[str, Any],
        result: Phase2Report,
        source: str,
    ) -> List[Tuple[FinalDecision, Optional[ReportFinding]]]:
        """Verify one claim site by site until the verifier confirms it.

        Stopping at the first confirmation is what keeps a repeated claim from
        producing a report entry per restatement: one confirmed site reports
        the claim, and the sites after it would only restate it. Sites that are
        rejected are still tried, so a claim whose first site is benign keeps
        its chance at the line the scanner also pointed at.
        """
        out: List[Tuple[FinalDecision, Optional[ReportFinding]]] = []
        for site in self._sites(claim):
            outcome = await self._verify_one(site[0], scan_packet, result, source)
            if outcome is None:
                break  # the verifier failed; the error is already recorded
            out.append(outcome)
            if outcome[0].status == "CONFIRMED":
                break
        return out

    @staticmethod
    def _fallback_hypotheses(report: Dict[str, Any]) -> List[Hypothesis]:
        """Tool findings as hypotheses, used when the Scanner call failed."""
        hypotheses: List[Hypothesis] = []
        for index, finding in enumerate(report.get("findings") or []):
            if not isinstance(finding, dict):
                continue
            cwe = finding.get("cwe") or ""
            if isinstance(cwe, (list, tuple)):
                cwe = cwe[0] if cwe else ""
            try:
                line = finding.get("line")
                line = int(line) if line is not None else None
            except (TypeError, ValueError):
                line = None
            hypotheses.append(
                Hypothesis(
                    cwe=str(cwe).strip().upper(),
                    line=line,
                    claim=str(
                        finding.get("message")
                        or finding.get("issue_text")
                        or "reported by a static tool"
                    ),
                    suspected_sink=str(finding.get("rule_id") or ""),
                    id=f"T{index + 1}",
                )
            )
        return hypotheses

    def _merge_findings(
        self,
        verified: List[Tuple[FinalDecision, Optional[ReportFinding]]],
    ) -> Tuple[List[Tuple[FinalDecision, Optional[ReportFinding]]], List[Dict[str, Any]]]:
        """Fold confirmed findings that describe the same claim.

        Confirmed findings whose CWE families overlap say the same thing to a
        reader -- and to the matcher: one report that confirms CWE-125 at six
        lines of a single file states one claim six times. The most confident
        entry survives; it carries every CWE the folded entries claimed, and
        the absorbed entries are recorded in ``metadata["claim_merges"]`` so
        the report still accounts for every verdict it reached.
        """
        slots = [
            index
            for index, (decision, _) in enumerate(verified)
            if decision.status == "CONFIRMED" and decision.cwe
        ]
        if len(slots) < 2:
            return verified, []

        parent = list(range(len(slots)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for i in range(len(slots)):
            for j in range(i + 1, len(slots)):
                if cwes_match(
                    verified[slots[i]][0].cwe, verified[slots[j]][0].cwe
                ):
                    parent[find(i)] = find(j)

        groups: Dict[int, List[int]] = {}
        for i in range(len(slots)):
            groups.setdefault(find(i), []).append(i)

        drops: Dict[int, Dict[str, Any]] = {}
        for members in groups.values():
            if len(members) < 2:
                continue
            group_slots = [slots[m] for m in members]
            primary_slot = max(
                group_slots,
                key=lambda slot: (
                    verified[slot][0].confidence,
                    -(verified[slot][0].line or 0),
                ),
            )
            primary = verified[primary_slot][0]
            lines = [
                verified[slot][0].line
                for slot in group_slots
                if verified[slot][0].line is not None
            ]
            spread = (
                max(abs(line - primary.line) for line in lines)
                if lines and primary.line is not None
                else None
            )

            merged_cwes: List[str] = []
            for slot in [primary_slot] + [
                slot for slot in group_slots if slot != primary_slot
            ]:
                for cwe in verified[slot][0].cwe:
                    if cwe.upper() not in {c.upper() for c in merged_cwes}:
                        merged_cwes.append(cwe)
            confidence = max(verified[slot][0].confidence for slot in group_slots)

            primary.cwe = merged_cwes
            primary.confidence = confidence
            primary.line = (
                primary.line
                if spread is not None and spread <= self.cfg.claim_site_radius
                else None
            )
            for slot in group_slots:
                if slot == primary_slot:
                    continue
                decision = verified[slot][0]
                drops[slot] = {
                    "merged_into": primary.group_id,
                    "group_id": decision.group_id,
                    "line": decision.line,
                    "cwe": list(decision.cwe),
                }
            finding = verified[primary_slot][1]
            if finding is not None:
                finding.line = primary.line

        if not drops:
            return verified, []
        kept = [
            item for index, item in enumerate(verified) if index not in drops
        ]
        return kept, [drops[index] for index in sorted(drops)]


    # -- scanner ---------------------------------------------------------
    def _scan_packet(
        self, source: str, language: str, report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Everything the Scanner is allowed to see.

        Taint chains are attached here as well as in the verifier packet: the
        scanner needs to know where a path already exists so it does not spend
        its whole budget rediscovering it, and the chains carry no labels.
        """
        metadata = report.get("metadata", {}) or {}
        packet: Dict[str, Any] = {
            "role": "scanner",
            "language": language,
            "file": source,
            "source_context": load_source_context(
                source, None, max(self.cfg.context_radius * 3, 24)
            ),
        }
        if self.cfg.include_tools:
            packet["static_tool_findings"] = report.get("findings", [])
        if self.cfg.include_structural:
            packet["structural"] = self._structural_summary(metadata.get("structure", {}))
        if self.cfg.include_taint:
            packet["dataflow_chains"] = self._taint_chains(source, metadata)

        return sanitize_value(packet)

    @staticmethod
    def _parse_hypotheses(raw: Any) -> List[Hypothesis]:
        """Accept the documented list form and a few common variants."""
        if isinstance(raw, dict):
            items = (
                raw.get("hypotheses")
                or raw.get("findings")
                or raw.get("candidates")
                or []
            )
            if isinstance(items, dict):
                items = [items]
        elif isinstance(raw, list):
            items = raw
        else:
            items = []

        hypotheses = [
            Hypothesis.from_dict(item, index)
            for index, item in enumerate(items)
            if isinstance(item, dict)
        ]
        return [h for h in hypotheses if h.claim or h.cwe]

    # -- verifier --------------------------------------------------------
    async def _verify_one(
        self,
        hypothesis: Hypothesis,
        scan_packet: Dict[str, Any],
        result: Phase2Report,
        source: str,
    ) -> Optional[Tuple[FinalDecision, Optional[ReportFinding]]]:
        """Verify one hypothesis; ``None`` when the verifier itself failed.

        The verdict is returned rather than appended to the report so that the
        claim walk decides what reaches it: a claim stops at its first
        confirmation, and the report merge folds the confirmations that
        describe the same thing.
        """
        async with self._sem:
            chains = self._chains_near(scan_packet, hypothesis.line)
            proven = [c for c in chains if c.get("source_expression")]
            packet: Dict[str, Any] = {
                "role": "verifier",
                "language": scan_packet.get("language"),
                "file": scan_packet.get("file"),
                "hypothesis": hypothesis.to_dict(),
                "source_context": self._context_at(
                    scan_packet, hypothesis.line, source
                ),
                "dataflow_chains": chains,
            }
            if self.cfg.include_structural:
                packet["structural"] = scan_packet.get("structural")
            if self.cfg.include_tools:
                # The static tools are the other half of the evidence base, so
                # the verifier is shown the findings near the hypothesis rather
                # than only being told what the scanner made of them.
                nearby = self._tool_findings_near(
                    scan_packet, hypothesis.line
                )
                if nearby:
                    packet["static_tool_findings"] = nearby

            packet = sanitize_value(packet)
            try:
                with thinking_log.scope(
                    id=source, file=source, role="verifier", hypothesis=hypothesis.id
                ):
                    raw = await self.ask_json(VERIFIER_PROMPT, packet)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(
                    f"verifier[{hypothesis.id}]: {type(exc).__name__}: {exc}"
                )
                return None

            verification = self._parse_verification(raw)
            if verification.decision != "CONFIRMED":
                return self._rejection(hypothesis, verification), None

            reason = self._evidence_gate(hypothesis, verification, proven)
            if reason:
                return (
                    self._rejection(hypothesis, verification, reason=reason),
                    None,
                )

            if verification.confidence < self.cfg.min_confidence:
                # A confirmation the verifier itself does not stand behind is
                # downgraded rather than reported.
                return (
                    self._rejection(
                        hypothesis,
                        verification,
                        reason=(
                            f"confidence {verification.confidence:.2f} below "
                            f"threshold {self.cfg.min_confidence:.2f}"
                        ),
                    ),
                    None,
                )
            finding = self._to_finding(hypothesis, verification, chains, source)
            # Confirmed candidates are recorded alongside the rejected ones: the
            # report has to account for every hypothesis the scanner raised, not
            # only the ones that were dropped.
            return self._rejection(hypothesis, verification), finding

    def _evidence_gate(
        self,
        hypothesis: Hypothesis,
        verification: Verification,
        proven: Sequence[Dict[str, Any]],
    ) -> str:
        """Deterministic checks the verifier's own verdict is held to.

        A prompt instruction is only a request, so the two conditions the
        proposal makes load bearing -- that a reported injection really has a
        source-to-sink path, and that a path the engine showed to be mitigated
        is not reported as unmitigated -- are enforced here in code. Each gate
        records the reason it fired so the report shows the candidate was
        dropped for a stated cause rather than silently.
        """
        cwes = verification.cwe or ([hypothesis.cwe] if hypothesis.cwe else [])

        # The verifier's own verdict is a claim about the evidence, so it has to
        # agree with it. A model that confirms a hypothesis while reporting the
        # chain as unverified has contradicted itself, and the contradiction is
        # resolved by dropping the finding rather than by trusting either half.
        if not verification.chain_verified:
            return (
                "verifier did not confirm the source-to-sink chain "
                "(chain_verified is false)"
            )

        if self.cfg.require_chain_evidence and not proven:
            if any(taint_modelled(cwe) for cwe in cwes):
                return (
                    f"confirmed {', '.join(cwes)} but the taint engine found no "
                    "source-to-sink path in this file"
                )
        if self.cfg.reject_mitigated and any(
            c.get("mitigated") for c in proven
        ):
            mitigations = sorted(
                {
                    c.get("mitigation_rule") or "unknown"
                    for c in proven
                    if c.get("mitigated")
                }
            )
            return f"path already mitigated ({', '.join(mitigations)})"
        return ""

    @staticmethod
    def _parse_verification(raw: Any) -> Verification:
        if not isinstance(raw, dict):
            return Verification(
                decision="UNCERTAIN",
                explanation="Verifier returned no usable JSON object.",
            )
        decision = str(raw.get("decision", "UNCERTAIN")).upper()
        if decision not in DECISIONS:
            decision = "UNCERTAIN"
        try:
            confidence = float(raw.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        cwe = raw.get("cwe")
        if isinstance(cwe, str):
            cwe_list = [cwe] if cwe else []
        elif isinstance(cwe, list):
            cwe_list = [str(c) for c in cwe if c]
        else:
            cwe_list = []
        return Verification(
            decision=decision,
            confidence=max(0.0, min(1.0, confidence)),
            cwe=cwe_list,
            severity=str(raw.get("severity", "UNKNOWN")).upper(),
            explanation=str(raw.get("explanation") or raw.get("rationale") or ""),
            evidence=[str(x) for x in (raw.get("evidence") or []) if x],
            missing_evidence=[
                str(x) for x in (raw.get("missing_evidence") or []) if x
            ],
            source_location=raw.get("source_location"),
            chain_verified=bool(raw.get("chain_verified", False)),
        )

    # -- report assembly -------------------------------------------------
    def _to_finding(
        self,
        hypothesis: Hypothesis,
        verification: Verification,
        chains: Sequence[Dict[str, Any]],
        source: str = "",
    ) -> ReportFinding:
        """Turn a confirmed hypothesis into a report entry.

        The CVE and reference fields are filled from the catalogue rather than
        from the model, so a hallucinated CVE id cannot enter the report.
        """
        primary = (verification.cwe or [hypothesis.cwe] or [""])[0].upper()
        catalogue = self.catalog.report_fields(primary)
        best = self._best_chain(chains, verification, hypothesis.line)

        file_part, line_part = self._split_location(verification, chains, source)
        return ReportFinding(
            cwe=primary,
            severity=verification.severity,
            file=file_part,
            line=line_part,
            function=(best or {}).get("function"),
            explanation=verification.explanation,
            source=(best or {}).get("source_expression", ""),
            sink=(best or {}).get("sink_expression", ""),
            source_line=(best or {}).get("source_line"),
            sink_line=(best or {}).get("sink_line"),
            chain=(best or {}).get("chain", ""),
            chain_verified=verification.chain_verified,
            taint_origin=(best or {}).get("taint_origin", ""),
            related_cves=list(catalogue["related_cves"]),
            references=list(catalogue["references"]),
            confidence=verification.confidence,
            detected_by=["scanner", "verifier"],
        )

    @staticmethod
    def _rejection(
        hypothesis: Hypothesis,
        verification: Verification,
        *,
        reason: str = "",
    ) -> Any:
        """Record what became of one candidate, confirmed or not.

        The name predates the confirmed case, which is now also written here so
        the decision log covers every hypothesis the scanner proposed.
        """
        note = reason or verification.explanation
        status = verification.decision
        if reason and status == "CONFIRMED":
            # The model said CONFIRMED and a gate overrode it, so what actually
            # happened to the candidate was a rejection.
            status = "REJECTED"
        return FinalDecision(
            group_id=hypothesis.id,
            line=hypothesis.line,
            status=status,
            confidence=verification.confidence,
            cwe=verification.cwe or ([hypothesis.cwe] if hypothesis.cwe else []),
            severity=verification.severity,
            rationale=note,
            evidence=verification.evidence,
            agents=[
                AgentAssessment(
                    agent="verifier",
                    decision=verification.decision,
                    confidence=verification.confidence,
                    rationale=note,
                    evidence=verification.evidence,
                    missing_evidence=verification.missing_evidence,
                    source_location=verification.source_location,
                )
            ],
        )

    # -- evidence helpers ------------------------------------------------
    @staticmethod
    def _structural_summary(structure: Dict[str, Any]) -> Dict[str, Any]:
        """Trim the structural index to what an agent can actually use.

        The full index carries a reference node per identifier, which is
        thousands of entries on a real file and crowds out the source snippet
        in the context window.
        """
        if not structure:
            return {}
        functions = structure.get("functions", [])
        return {
            "language": structure.get("language"),
            "loc": structure.get("loc"),
            "function_count": len(functions),
            "functions": [
                {
                    "name": f.get("name"),
                    "start_line": f.get("start_line"),
                    "end_line": f.get("end_line"),
                    "parameters": f.get("parameters", []),
                }
                for f in functions[:40]
            ],
            "dangerous_calls": structure.get("dangerous_calls", [])[:40],
            "imports": structure.get("imports", [])[:40],
            "parse_error": bool(structure.get("error_nodes")),
        }

    @staticmethod
    def _taint_chains(source: str, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Chains from the cached index, or computed if the caller has none."""
        cached = metadata.get("taint_chains")
        if isinstance(cached, list):
            return cached
        structure = metadata.get("structure") or {}
        if not structure:
            from analyzers.structural_analyzer import StructuralAnalyzer

            path = Path(source)
            if not path.exists():
                return []
            structure = StructuralAnalyzer().analyze_file(path)
        return taint_chains_for(structure)

    @staticmethod
    def _chains_near(
        packet: Dict[str, Any], line: Optional[int], radius: int = 12
    ) -> List[Dict[str, Any]]:
        """Chains at or near the hypothesis line, falling back to all of them.

        A scanner hypothesis often points at the sink line, so chains whose
        source or sink is within the radius are kept. If nothing is near, the
        full list is returned rather than nothing: the verifier is better
        placed than the scanner to decide the line is wrong.
        """
        chains = packet.get("dataflow_chains") or []
        if not isinstance(chains, list) or not chains or line is None:
            return list(chains) if isinstance(chains, list) else []
        near = [
            chain
            for chain in chains
            if abs((chain.get("sink_line") or 0) - line) <= radius
            or abs((chain.get("source_line") or 0) - line) <= radius
        ]
        return near or list(chains)

    @staticmethod
    def _tool_findings_near(
        packet: Dict[str, Any], line: Optional[int], radius: int = 12
    ) -> List[Dict[str, Any]]:
        """Static-tool findings close to the hypothesis, or all of them.

        Same shape as :meth:`_chains_near` for the same reason: the line the
        scanner chose is a hint, and the verifier is the better judge of whether
        a tool hit is relevant.
        """
        findings = packet.get("static_tool_findings") or []
        if not isinstance(findings, list) or not findings or line is None:
            return list(findings) if isinstance(findings, list) else []
        near = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            found_line = finding.get("line") or finding.get("start_line")
            if not isinstance(found_line, int):
                near.append(finding)
            elif abs(found_line - line) <= radius:
                near.append(finding)
        return near or list(findings)

    def _context_at(
        self, packet: Dict[str, Any], line: Optional[int], source: str
    ) -> Dict[str, Any]:
        """The source around one hypothesis, read from the real path.

        ``packet["file"]`` has already been through ``sanitize_value``, which
        rewrites the leaking ``good``/``bad``/``CWE*`` path segments so the
        agent cannot read the ground-truth label out of the filename. Reading
        the disk with that rewritten path fails with ENOENT and leaves the
        verifier with an empty snippet — so the unsanitised path is passed in
        explicitly instead of being taken back out of the packet.
        """
        context = packet.get("source_context") or {}
        if line is None or not context.get("available"):
            return context
        return load_source_context(source, line, self.cfg.context_radius)

    @staticmethod
    def _best_chain(
        chains: Sequence[Dict[str, Any]],
        verification: Verification,
        line: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Pick the chain to cite in the report.

        A file often has several proven paths, and the hypothesis names the one
        to look at, so the chain whose sink is closest to the hypothesis line
        wins. Chains with no source are never cited: a report that shows a
        source-to-sink path should show an actual path.
        """
        proven = [c for c in chains if c.get("source_expression")]
        if not proven:
            return None
        if line is None:
            return proven[0]
        return min(
            proven,
            key=lambda c: abs((c.get("sink_line") or 0) - line),
        )

    @staticmethod
    def _split_location(
        verification: Verification,
        chains: Sequence[Dict[str, Any]],
        source: str = "",
    ) -> tuple:
        """The exact location required by the proposal's report schema.

        ``source_location`` is model output. The schema shows it as
        ``"file:line"``, and a model asked to be terse sometimes answers with
        that placeholder itself ("file:183") or with a bare basename -- either
        would put a file the report cannot stand behind into the finding. So a
        location that names no path falls back to the file actually being
        analysed, keeping the line when it parsed.
        """
        raw = verification.source_location
        if isinstance(raw, str) and ":" in raw:
            file_part, _, line_text = raw.rpartition(":")
            file_part = file_part.strip()
            try:
                line: Optional[int] = int(line_text)
            except ValueError:
                line = None
            if "/" in file_part or "\\" in file_part:
                return file_part, line
            if source:
                # A bare word is either the file under analysis or the schema's
                # own placeholder; the path we hold is correct in both cases.
                return source, line
        for chain in chains:
            if chain.get("sink_line"):
                return chain.get("file"), int(chain["sink_line"])
        if source:
            return source, None
        return None, None
