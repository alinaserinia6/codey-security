"""Verifier Agent: one hypothesis at a time, against a source-to-sink chain.

The verifier is the precision half of the pair and the only agent whose output
can become a reported finding. It is shown a single hypothesis, the source
around it, the chains the deterministic engine found and the nearby static-tool
findings, and it is told to reject by default.

It is deliberately not given the scanner's reasoning: seeing the claim it is
being asked to confirm tends to anchor the verdict on it. It gets the
hypothesis, not the argument for the hypothesis.

The reply is returned unnormalised; ``phase2.multiagent`` parses the verdict and
applies the evidence gates that the prompt alone cannot enforce.
"""
from __future__ import annotations

from typing import Any, Dict

from phase2.prompts import VERIFIER_PROMPT

from .security_agent import SecurityAgent


class VerifierAgent(SecurityAgent):
    """A :class:`SecurityAgent` bound to the Verifier role prompt."""

    system_prompt = VERIFIER_PROMPT

    async def verify(self, evidence_packet: Dict[str, Any]) -> Dict[str, Any]:
        """Return a verdict for one hypothesis."""
        return await self.analyze(
            evidence_packet,
            system_prompt=self.system_prompt,
            normalize=False,
        )
