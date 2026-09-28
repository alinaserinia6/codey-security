"""Scanner Agent: whole-file triage that proposes hypotheses.

The scanner is the recall half of the pair. It is given the file, the
structural index, the static-tool output and the dataflow chains, and asked for
a list of candidate vulnerabilities without being shown any label. It is not
asked to prove anything -- that is the verifier's job, and keeping the two
apart is what lets the scanner be generous and the verifier be strict.

The reply is returned unnormalised: this role's output contract is a
``hypotheses`` list, which ``phase2.multiagent`` parses and validates.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from phase2.prompts import SCANNER_PROMPT

from .security_agent import SecurityAgent


class ScannerAgent(SecurityAgent):
    """A :class:`SecurityAgent` bound to the Scanner role prompt."""

    system_prompt = SCANNER_PROMPT

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        model_id: Optional[str] = None,
        provider_id: Optional[str] = None,
        mode: Optional[str] = None,
        timeout: Optional[float] = None,
        reuse_session: Optional[bool] = None,
        system_prompt: Optional[str] = None,
    ):
        super().__init__(
            base_url=base_url,
            model_id=model_id,
            provider_id=provider_id,
            mode=mode,
            timeout=timeout,
            reuse_session=reuse_session,
        )
        # An explicit prompt still wins, which is what the ablation in
        # ``MultiAgentConfig`` needs.
        self.system_prompt = system_prompt or self.system_prompt

    async def scan(self, evidence_packet: Dict[str, Any]) -> Dict[str, Any]:
        """Propose hypotheses for one file."""
        return await self.analyze(
            evidence_packet,
            system_prompt=self.system_prompt,
            normalize=False,
        )
