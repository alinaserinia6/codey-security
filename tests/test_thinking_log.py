"""The reasoning trace must survive the run that produced it.

``SecurityAgent`` streams thinking to stderr, which is unreadable after the
fact; when ``LLM_THINKING_OUT`` is set the same text is appended to a JSON
file keyed by the analysed file. These tests pin the recorder (including the
retry path, which is exactly when a trace is most worth keeping) without a
network by stubbing the OpenCode client.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import pytest

from agents import thinking_log
from agents.security_agent import SecurityAgent, _backoff_delay


class FakeSession:
    """OpenCode-shaped session that never touches the network."""

    def __init__(self, replies: List[Any]) -> None:
        self.replies = list(replies)
        self.chat_calls = 0

    def create(self) -> Dict[str, str]:
        return {"id": "session-1"}

    def chat(self, session_id: str, **kwargs: Any) -> Any:
        self.chat_calls += 1
        if not self.replies:
            raise AssertionError(f"unexpected chat call #{self.chat_calls}")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class FakeClient:
    def __init__(self, replies: List[Any]) -> None:
        self.session = FakeSession(replies)


def reply(text: str, thinking: str = "let me think") -> Dict[str, Any]:
    return {
        "parts": [
            {"type": "reasoning", "text": thinking},
            {"type": "text", "text": text},
        ]
    }


def make_agent(replies: List[Any]) -> SecurityAgent:
    agent = SecurityAgent(base_url="http://stub:1234", model_id="stub-model")
    agent.client = FakeClient(replies)
    return agent


def analyse(agent: SecurityAgent, **scope: Any) -> Dict[str, Any]:
    with thinking_log.scope(**scope):
        return asyncio.run(
            agent.analyze({"file": "sample.c", "language": "c"}, normalize=False)
        )


def read(path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# -- recording --------------------------------------------------------------


def test_no_env_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv(thinking_log.ENV_OUT, raising=False)
    result = analyse(make_agent([reply('{"decision": "REJECTED"}')]), id="s1")
    assert result["decision"] == "REJECTED"
    assert list(tmp_path.iterdir()) == []


def test_thinking_is_written_per_file(tmp_path, monkeypatch):
    out = tmp_path / "trace.thinking.json"
    monkeypatch.setenv(thinking_log.ENV_OUT, str(out))

    analyse(
        make_agent([reply('{"decision": "CONFIRMED"}', thinking="the sink is line 9")]),
        id="sample-1", file="/src/good/a.c", role="llm_only",
    )

    data = read(out)
    node = data["files"]["sample-1"]
    assert node["file"] == "/src/good/a.c"
    assert node["calls"][0]["role"] == "llm_only"
    assert node["calls"][0]["model"] == "stub-model"
    assert "the sink is line 9" in node["calls"][0]["thinking"]
    assert node["calls"][0]["answer"]["decision"] == "CONFIRMED"
    assert "error" not in node["calls"][0]


def test_a_failed_reply_is_still_traced(tmp_path, monkeypatch):
    """The unparsable reply is the one you most want to read afterwards."""
    out = tmp_path / "trace.thinking.json"
    monkeypatch.setenv(thinking_log.ENV_OUT, str(out))
    monkeypatch.setenv("LLM_MAX_ATTEMPTS", "1")

    agent = make_agent([reply('{"decision": "CONFIRMED"', thinking="truncated")])
    with pytest.raises(ValueError):
        analyse(agent, id="sample-2", file="/src/b.c")

    calls = read(out)["files"]["sample-2"]["calls"]
    assert calls[-1]["error"].startswith("ValueError")
    assert "truncated" in calls[-1]["thinking"]
    assert calls[-1]["answer"].startswith('{"decision"')


# -- retry ------------------------------------------------------------------


def test_unparsable_reply_is_retried(tmp_path, monkeypatch):
    out = tmp_path / "trace.thinking.json"
    monkeypatch.setenv(thinking_log.ENV_OUT, str(out))
    monkeypatch.setenv("LLM_MAX_ATTEMPTS", "2")

    agent = make_agent(
        [reply('not json at all'), reply('{"decision": "REJECTED"}')]
    )
    result = analyse(agent, id="sample-3")

    assert result["decision"] == "REJECTED"
    assert agent.client.session.chat_calls == 2
    calls = read(out)["files"]["sample-3"]["calls"]
    assert [c["attempt"] for c in calls] == [1, 2]
    assert "error" in calls[0]


def test_retry_can_be_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv(thinking_log.ENV_OUT, str(tmp_path / "t.json"))
    monkeypatch.setenv("LLM_MAX_ATTEMPTS", "1")

    agent = make_agent([reply("garbage")])
    with pytest.raises(ValueError):
        analyse(agent, id="sample-4")
    assert agent.client.session.chat_calls == 1


# -- retry budgets ---------------------------------------------------------
#
# A transport failure and a garbled reply are not the same event: the endpoint
# that answered with garbage can answer again without waiting, while the one
# that 503'd needs tries it did not get when every kind shared one budget.
# That single budget is what scored a vulnerable sample as an error when an
# upstream 503 survived both attempts.


def test_attempt_budgets_have_documented_defaults(monkeypatch):
    for name in ("LLM_MAX_ATTEMPTS", "LLM_TRANSPORT_ATTEMPTS",
                 "LLM_TIMEOUT_ATTEMPTS"):
        monkeypatch.delenv(name, raising=False)

    assert SecurityAgent._max_attempts() == 2
    assert SecurityAgent._transport_attempts() == 4
    assert SecurityAgent._timeout_attempts() == 2


def test_transport_failures_are_retried_beyond_the_parse_budget(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(thinking_log.ENV_OUT, str(tmp_path / "t.json"))
    monkeypatch.setenv("LLM_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("LLM_TRANSPORT_ATTEMPTS", "4")
    monkeypatch.setattr("agents.security_agent._backoff_delay", lambda n: 0.0)

    agent = make_agent(
        [
            RuntimeError("connection reset"),
            RuntimeError("connection reset"),
            reply('{"decision": "REJECTED"}'),
        ]
    )
    result = analyse(agent, id="sample-5")

    assert result["decision"] == "REJECTED"
    assert agent.client.session.chat_calls == 3


def test_the_parse_budget_still_bounds_a_run_of_garbled_replies(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(thinking_log.ENV_OUT, str(tmp_path / "t.json"))
    monkeypatch.setenv("LLM_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("LLM_TRANSPORT_ATTEMPTS", "4")
    monkeypatch.setattr("agents.security_agent._backoff_delay", lambda n: 0.0)

    # One transport failure then two unparsable replies: the transport budget
    # is spent once, and the two garbage replies exhaust the parse budget of 2
    # rather than being allowed to ride the larger one.
    agent = make_agent(
        [
            RuntimeError("connection reset"),
            reply("garbage"),
            reply("garbage"),
        ]
    )
    with pytest.raises(ValueError):
        analyse(agent, id="sample-6")
    assert agent.client.session.chat_calls == 3


def test_a_timeout_gets_two_tries_even_with_transport_budget_left(
    tmp_path, monkeypatch
):
    """A request that already burned the full timeout is not worth four."""
    monkeypatch.setenv(thinking_log.ENV_OUT, str(tmp_path / "t.json"))
    monkeypatch.setenv("LLM_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("LLM_TRANSPORT_ATTEMPTS", "4")
    monkeypatch.setenv("LLM_TIMEOUT_ATTEMPTS", "2")
    monkeypatch.setattr("agents.security_agent._backoff_delay", lambda n: 0.0)

    agent = make_agent([TimeoutError("hung"), TimeoutError("hung")])
    with pytest.raises(TimeoutError):
        analyse(agent, id="sample-7")
    assert agent.client.session.chat_calls == 2


def test_a_parse_retry_restates_the_output_contract(tmp_path, monkeypatch):
    """Sending the identical prompt again invites the identical bad reply."""
    monkeypatch.setenv(thinking_log.ENV_OUT, str(tmp_path / "t.json"))
    monkeypatch.setenv("LLM_MAX_ATTEMPTS", "2")

    agent = make_agent([reply("here is my analysis:\n```json"), reply("{}")])
    prompts: List[str] = []
    original = agent.client.session.chat

    def recording(session_id, **kwargs):
        prompts.append(kwargs["parts"][0]["text"])
        return original(session_id, **kwargs)

    agent.client.session.chat = recording
    analyse(agent, id="sample-8")

    assert len(prompts) == 2
    assert "could not be parsed as JSON" not in prompts[0]
    assert "could not be parsed as JSON" in prompts[1]
    assert "40 words or fewer" in prompts[1]


def test_backoff_grows_exponentially_and_stops_at_twenty_seconds():
    for attempt, ceiling in ((1, 2.0), (2, 4.0), (3, 8.0), (4, 16.0),
                             (5, 20.0), (9, 20.0)):
        delay = _backoff_delay(attempt)
        assert 0.5 * ceiling <= delay <= ceiling, attempt


# -- recorder plumbing ------------------------------------------------------


def test_records_append_under_one_key(tmp_path, monkeypatch):
    out = tmp_path / "trace.thinking.json"
    monkeypatch.setenv(thinking_log.ENV_OUT, str(out))

    thinking_log.record({"id": "f.c", "role": "scanner", "thinking": "a"})
    thinking_log.record({"id": "f.c", "role": "verifier", "thinking": "b"})

    calls = read(out)["files"]["f.c"]["calls"]
    assert [c["role"] for c in calls] == ["scanner", "verifier"]


def test_unwritable_path_does_not_raise(tmp_path, monkeypatch):
    # The trace path itself is a directory: the write fails, the run must not.
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    monkeypatch.setenv(thinking_log.ENV_OUT, str(blocked))
    thinking_log.record({"id": "x"})
