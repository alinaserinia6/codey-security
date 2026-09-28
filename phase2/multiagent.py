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
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence

from analyzers.catalog import get_catalog
from analyzers.taint import taint_chains_for, taint_modelled

from .context import load_source_context
from .models import (
    AgentAssessment,
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
    # already handled. The verifier is told about it and can still confirm for a
    # reason the engine does not model, but it may not quietly ignore it.
    reject_mitigated: bool = False


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
        try:
            raw = await self.ask_json(SCANNER_PROMPT, scan_packet)
            hypotheses = self._parse_hypotheses(raw)
        except Exception as exc:  # noqa: BLE001 - one file must not stop a run
            result.errors.append(f"scanner: {type(exc).__name__}: {exc}")
            hypotheses = []

        result.metadata["hypotheses_proposed"] = len(hypotheses)
        result.metadata["hypotheses_truncated"] = len(hypotheses) > self.cfg.max_hypotheses
        hypotheses = hypotheses[: max(1, self.cfg.max_hypotheses)]
        if not hypotheses:
            return result.to_dict()

        verifications = await asyncio.gather(
            *[self._verify_one(h, scan_packet, result) for h in hypotheses],
            return_exceptions=True,
        )
        verdicts: List[str] = []
        for outcome in verifications:
            if isinstance(outcome, BaseException):
                result.errors.append(f"verifier: {type(outcome).__name__}: {outcome}")
                continue
            if outcome is None:
                continue
            finding, verdict = outcome
            verdicts.append(verdict)
            if finding is not None:
                result.findings.append(finding)

        result.metadata["decision_counts"] = {
            status: verdicts.count(status) for status in DECISIONS
        }
        result.metadata["reported_findings"] = len(result.findings)
        return result.to_dict()

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
    ) -> Optional[tuple]:
        async with self._sem:
            chains = self._chains_near(scan_packet, hypothesis.line)
            proven = [c for c in chains if c.get("source_expression")]
            packet: Dict[str, Any] = {
                "role": "verifier",
                "language": scan_packet.get("language"),
                "file": scan_packet.get("file"),
                "hypothesis": hypothesis.to_dict(),
                "source_context": self._context_at(
                    scan_packet, hypothesis.line
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
                raw = await self.ask_json(VERIFIER_PROMPT, packet)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(
                    f"verifier[{hypothesis.id}]: {type(exc).__name__}: {exc}"
                )
                return None

            verification = self._parse_verification(raw)
            if verification.decision != "CONFIRMED":
                result.decisions.append(
                    self._rejection(hypothesis, verification)
                )
                return None, verification.decision

            reason = self._evidence_gate(hypothesis, verification, proven)
            if reason:
                result.decisions.append(
                    self._rejection(
                        hypothesis, verification, reason=reason
                    )
                )
                return None, "REJECTED"

            if verification.confidence < self.cfg.min_confidence:
                # A confirmation the verifier itself does not stand behind is
                # downgraded rather than reported.
                result.decisions.append(
                    self._rejection(
                        hypothesis,
                        verification,
                        reason=(
                            f"confidence {verification.confidence:.2f} below "
                            f"threshold {self.cfg.min_confidence:.2f}"
                        ),
                    )
                )
                return None, "REJECTED"
            finding = self._to_finding(hypothesis, verification, chains)
            # Confirmed candidates are recorded alongside the rejected ones: the
            # report has to account for every hypothesis the scanner raised, not
            # only the ones that were dropped.
            result.decisions.append(
                self._rejection(hypothesis, verification)
            )
            return finding, "CONFIRMED"

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
    ) -> ReportFinding:
        """Turn a confirmed hypothesis into a report entry.

        The CVE and reference fields are filled from the catalogue rather than
        from the model, so a hallucinated CVE id cannot enter the report.
        """
        primary = (verification.cwe or [hypothesis.cwe] or [""])[0].upper()
        catalogue = self.catalog.report_fields(primary)
        best = self._best_chain(chains, verification, hypothesis.line)

        file_part, line_part = self._split_location(verification, chains)
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
        from .models import FinalDecision

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
        self, packet: Dict[str, Any], line: Optional[int]
    ) -> Dict[str, Any]:
        context = packet.get("source_context") or {}
        if line is None or not context.get("available"):
            return context
        return load_source_context(
            packet.get("file", "<unknown>"), line, self.cfg.context_radius
        )

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
        verification: Verification, chains: Sequence[Dict[str, Any]]
    ) -> tuple:
        """The exact location required by the proposal's report schema."""
        raw = verification.source_location
        if isinstance(raw, str) and ":" in raw:
            file_part, _, line_part = raw.rpartition(":")
            try:
                return file_part, int(line_part)
            except ValueError:
                return raw, None
        for chain in chains:
            if chain.get("sink_line"):
                return chain.get("file"), int(chain["sink_line"])
        return None, None
