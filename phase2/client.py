"""JsonClient bindings that run the Scanner and Verifier agents for real.

``phase2.multiagent`` is written against ``ask_json(system, packet)`` so the
orchestration can be tested without a model. This module is the other
implementation of that same callable: it routes by role to the agent that owns
that prompt, so the pipeline can be pointed at the live endpoint without
touching its own logic.

Both agents share one :class:`~agents.security_agent.SecurityAgent` transport by
default, which keeps the session and connection handling in one place. Set
``separate_sessions`` when the two roles should not share a conversation.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from agents.scanner_agent import ScannerAgent
from agents.security_agent import SecurityAgent
from agents.verifier_agent import VerifierAgent

from .multiagent import MultiAgentConfig, MultiAgentPipeline


class RoleJsonClient:
    """Adapts the two role agents to the pipeline's ``ask_json`` callable."""

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        model_id: Optional[str] = None,
        provider_id: Optional[str] = None,
        mode: Optional[str] = None,
        timeout: Optional[float] = None,
        reuse_session: Optional[bool] = None,
        separate_sessions: bool = False,
    ):
        self.scanner = ScannerAgent(
            base_url=base_url,
            model_id=model_id,
            provider_id=provider_id,
            mode=mode,
            timeout=timeout,
            reuse_session=reuse_session,
        )
        if separate_sessions:
            # Independent session ids, so the verifier cannot see the
            # conversation in which the scanner argued for the hypothesis.
            self.verifier: SecurityAgent = VerifierAgent(
                base_url=base_url,
                model_id=model_id,
                provider_id=provider_id,
                mode=mode,
                timeout=timeout,
                reuse_session=False,
            )
        else:
            self.verifier = VerifierAgent(
                base_url=base_url,
                model_id=model_id,
                provider_id=provider_id,
                mode=mode,
                timeout=timeout,
                reuse_session=reuse_session,
            )

    async def __call__(self, system: str, packet: Dict[str, Any]) -> Dict[str, Any]:
        # The role comes from the packet, not from a match on the prompt text,
        # so a prompt edit cannot silently send verifier work to the scanner.
        if packet.get("role") == "scanner":
            return await self.scanner.scan(packet)
        return await self.verifier.verify(packet)


def build_pipeline(
    *,
    config: Optional[MultiAgentConfig] = None,
    base_url: Optional[str] = None,
    model_id: Optional[str] = None,
    provider_id: Optional[str] = None,
    mode: Optional[str] = None,
    timeout: Optional[float] = None,
    reuse_session: Optional[bool] = None,
    separate_sessions: bool = False,
) -> MultiAgentPipeline:
    """A :class:`MultiAgentPipeline` wired to the live endpoint."""
    client = RoleJsonClient(
        base_url=base_url,
        model_id=model_id,
        provider_id=provider_id,
        mode=mode,
        timeout=timeout,
        reuse_session=reuse_session,
        separate_sessions=separate_sessions,
    )
    return MultiAgentPipeline(client, config=config)
