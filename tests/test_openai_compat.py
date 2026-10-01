"""OpenAI-compatible transport and the thinking-print modes."""

from __future__ import annotations

import asyncio
import json

import pytest

from agents.openai_compat import (
    OPENAI_TRANSPORT,
    OPENCODE_TRANSPORT,
    OpenAICompat,
    TruncatedResponse,
    UpstreamError,
    chat_url,
    envelope,
    resolve_transport,
)
from agents.security_agent import SecurityAgent, _is_retryable


# -- transport selection ---------------------------------------------------


def test_base_url_with_v1_suffix_selects_openai():
    assert resolve_transport("https://api.apmix.ai/v1") == OPENAI_TRANSPORT
    assert resolve_transport("https://api.apmix.ai/v1/") == OPENAI_TRANSPORT


def test_bare_opencode_server_stays_on_the_opencode_transport():
    assert resolve_transport("http://127.0.0.1:4096") == OPENCODE_TRANSPORT


def test_llm_transport_env_overrides_the_heuristic(monkeypatch):
    monkeypatch.setenv("LLM_TRANSPORT", "opencode")
    assert resolve_transport("https://api.apmix.ai/v1") == OPENCODE_TRANSPORT
    monkeypatch.setenv("LLM_TRANSPORT", "openai")
    assert resolve_transport("http://127.0.0.1:4096") == OPENAI_TRANSPORT


@pytest.mark.parametrize(
    "base,expected",
    [
        ("https://api.apmix.ai/v1", "https://api.apmix.ai/v1/chat/completions"),
        ("https://api.apmix.ai/v1/", "https://api.apmix.ai/v1/chat/completions"),
        ("https://api.openai.com", "https://api.openai.com/v1/chat/completions"),
        (
            "https://x.example/v1/chat/completions",
            "https://x.example/v1/chat/completions",
        ),
    ],
)
def test_chat_url(base, expected):
    assert chat_url(base) == expected


# -- reply mapping ---------------------------------------------------------


def test_envelope_maps_content_and_reasoning_content():
    body = {
        "choices": [
            {
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": '{"decision": "CONFIRMED"}',
                    "reasoning_content": "I read the packet first.",
                },
            }
        ]
    }
    parts = envelope(body, max_tokens=4096)
    assert parts["text"] == '{"decision": "CONFIRMED"}'
    assert parts["thinking"] == "I read the packet first."


def test_envelope_accepts_list_content():
    body = {
        "choices": [
            {
                "finish_reason": "stop",
                "message": {
                    "content": [
                        {"type": "text", "text": '{"decision":'},
                        {"type": "text", "text": ' "REJECTED"}'},
                    ]
                },
            }
        ]
    }
    assert envelope(body, max_tokens=4096)["text"] == '{"decision": "REJECTED"}'


def test_envelope_rejects_an_empty_reply():
    body = {"choices": [{"finish_reason": "stop", "message": {"content": ""}}]}
    with pytest.raises(ValueError, match="no content"):
        envelope(body, max_tokens=4096)


def test_envelope_rejects_a_body_without_choices():
    with pytest.raises(ValueError, match="no choices"):
        envelope({"error": {"message": "bad model"}}, max_tokens=4096)


def test_truncated_reply_is_not_retryable():
    body = {"choices": [{"finish_reason": "length", "message": {"content": "{"}}]}
    with pytest.raises(TruncatedResponse) as exc:
        envelope(body, max_tokens=4096)
    assert "LLM_MAX_TOKENS" in str(exc.value)
    # A budget that was too small stays too small: do not burn the retry.
    assert not _is_retryable(exc.value)


# -- the request itself ----------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or (json.dumps(payload) if payload is not None else "")

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class _FakeClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, url, json=None):
        # Snapshot: the transport mutates one payload dict across retries.
        self.calls.append((url, dict(json or {})))
        return self.response

    def close(self):
        pass


def _client(payload=None, response=None):
    return response or _FakeResponse(payload=payload)


def test_chat_posts_system_and_user_with_the_api_key(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "secret-key")
    transport = OpenAICompat(base_url="https://api.apmix.ai/v1", model_id="m")
    transport._client.close()
    fake = _FakeClient(
        _client({"choices": [{"finish_reason": "stop", "message": {"content": "{}"}}]})
    )
    transport._client = fake

    parts = transport.chat("system words", "user words")

    assert parts["text"] == "{}"
    url, payload = fake.calls[0]
    assert url.endswith("/v1/chat/completions")
    assert payload["model"] == "m"
    assert payload["messages"] == [
        {"role": "system", "content": "system words"},
        {"role": "user", "content": "user words"},
    ]
    assert transport._client is fake
    assert fake.calls[0][0].startswith("https://api.apmix.ai")


def test_chat_raises_with_status_and_body_on_http_error():
    transport = OpenAICompat(base_url="https://api.apmix.ai/v1", model_id="m")
    transport._client.close()
    transport._client = _FakeClient(
        _FakeResponse(status_code=401, text='{"error": "bad key"}')
    )
    with pytest.raises(UpstreamError, match="HTTP 401.*bad key"):
        transport.chat("s", "u")


def test_upstream_error_is_wrapped_and_stays_retryable(monkeypatch):
    # A transient 503 must become a retryable error carrying the endpoint
    # identity, not a dead sample: that is what saved both live-run samples.
    monkeypatch.setenv("LLM_BASE_URL", "https://api.apmix.ai/v1")
    agent = SecurityAgent()
    agent._openai._client.close()

    def fail(system, user):
        raise UpstreamError("HTTP 503 from https://api.apmix.ai/v1/chat/completions")

    agent._openai.chat = fail
    with pytest.raises(RuntimeError) as exc:
        asyncio.run(agent._request("SYS", "USR"))
    message = str(exc.value)
    assert "UpstreamError: HTTP 503" in message
    assert "transport=openai" in message
    assert f"model={agent.model_id}" in message
    assert _is_retryable(exc.value)


def test_openai_transport_is_selected_for_an_apmix_base_url(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://api.apmix.ai/v1")
    monkeypatch.delenv("LLM_TRANSPORT", raising=False)
    agent = SecurityAgent()
    assert agent.transport == OPENAI_TRANSPORT
    assert agent._openai is not None
    assert agent.client is None


def test_opencode_transport_keeps_the_sdk_client(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:4096")
    monkeypatch.delenv("LLM_TRANSPORT", raising=False)
    agent = SecurityAgent()
    assert agent.transport == OPENCODE_TRANSPORT
    assert agent._openai is None
    assert agent.client is not None


def test_analyze_routes_through_the_openai_transport(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://api.apmix.ai/v1")
    agent = SecurityAgent()
    agent._openai._client.close()
    seen = {}

    def fake_chat(system, user):
        seen["system"] = system
        seen["user"] = user
        return {
            "text": json.dumps(
                {"decision": "CONFIRMED", "confidence": 0.7, "cwe": ["CWE-78"]}
            ),
            "thinking": "line one\nline two",
        }

    agent._openai.chat = fake_chat
    value = asyncio.run(agent.analyze({"file": "sample.c", "role": "verifier"}))

    assert value["decision"] == "CONFIRMED"
    assert seen["user"].startswith("Evidence packet (JSON):")
    assert "Security Agent" in seen["system"]


def test_opencode_request_still_gets_one_concatenated_prompt(monkeypatch):
    # The OpenCode wire format takes a single text part, so the two pieces
    # must reassemble into exactly what it has always been sent.
    agent = SecurityAgent(base_url="http://127.0.0.1:4096")
    seen = {}

    async def fake_chat(prompt):
        seen["prompt"] = prompt
        return {"text": "{}", "thinking": ""}

    monkeypatch.setattr(agent, "_chat_opencode", fake_chat)
    asyncio.run(agent._request("SYS", "USR"))
    assert seen["prompt"] == "SYS\n\nUSR"


# -- thinking print --------------------------------------------------------


def test_thinking_is_off_silently(monkeypatch, capsys):
    monkeypatch.setenv("LLM_THINKING_PRINT", "off")
    SecurityAgent._emit_thinking("a very long reasoning trace", {"role": "scanner"})
    captured = capsys.readouterr()
    assert captured.err == ""


def test_thinking_short_is_one_line(monkeypatch, capsys):
    monkeypatch.setenv("LLM_THINKING_PRINT", "short")
    SecurityAgent._emit_thinking("word " * 50, {"role": "scanner", "id": "/a/b.c"})
    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert "thinking[scanner|b.c]" in err
    assert "250c" in err


def test_thinking_default_is_short(monkeypatch, capsys):
    monkeypatch.delenv("LLM_THINKING_PRINT", raising=False)
    SecurityAgent._emit_thinking("short trace", {"role": "verifier"})
    assert "thinking[verifier]" in capsys.readouterr().err


def test_thinking_full_keeps_the_box(monkeypatch, capsys):
    monkeypatch.setenv("LLM_THINKING_PRINT", "full")
    SecurityAgent._emit_thinking("a real trace", {})
    err = capsys.readouterr().err
    assert "┌─" in err and "└" in err


# -- budget escalation -----------------------------------------------------


class _SequenceClient(_FakeClient):
    """Returns the next canned response on every call, repeating the last."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, json=None):
        self.calls.append((url, dict(json or {})))
        if len(self.responses) > 1:
            return self.responses.pop(0)
        return self.responses[0]


def _finish(reason, content):
    return _FakeResponse(
        payload={"choices": [{"finish_reason": reason, "message": {"content": content}}]}
    )


def test_truncated_reply_doubles_the_budget_and_asks_again():
    transport = OpenAICompat(
        base_url="https://api.apmix.ai/v1",
        model_id="m",
        max_tokens=4096,
        max_tokens_cap=16384,
    )
    transport._client.close()
    transport._client = _SequenceClient(_finish("length", "{"), _finish("stop", '{"ok":1}'))

    parts = transport.chat("s", "u")

    assert parts["text"] == '{"ok":1}'
    budgets = [payload["max_tokens"] for _, payload in transport._client.calls]
    assert budgets == [4096, 8192]
    # The raised budget sticks: the next sample starts where this one ended.
    assert transport.max_tokens == 8192


def test_budget_stops_at_the_cap():
    transport = OpenAICompat(
        base_url="https://api.apmix.ai/v1",
        model_id="m",
        max_tokens=4096,
        max_tokens_cap=4096,
    )
    transport._client.close()
    transport._client = _SequenceClient(_finish("length", "{"))

    with pytest.raises(TruncatedResponse, match="LLM_MAX_TOKENS_CAP=4096"):
        transport.chat("s", "u")
    assert len(transport._client.calls) == 1


def test_budget_escalation_gives_up_after_three_doublings():
    transport = OpenAICompat(
        base_url="https://api.apmix.ai/v1",
        model_id="m",
        max_tokens=4096,
        max_tokens_cap=1024 * 1024,
    )
    transport._client.close()
    transport._client = _SequenceClient(_finish("length", "{"))

    with pytest.raises(TruncatedResponse):
        transport.chat("s", "u")
    budgets = [payload["max_tokens"] for _, payload in transport._client.calls]
    assert budgets == [4096, 8192, 16384, 32768]


# -- reply parsing ---------------------------------------------------------
#
# The model quotes its own prose ("there is no "hole" in it"), which is
# correct English and invalid JSON: the bare quote closes the value early and
# a verdict the model had answered is discarded as unparsable. Every
# unparsable reply in the recorded llm20 runs was this case.


def test_unescaped_quotes_inside_a_value_are_repaired():
    reply = (
        '{"decision": "REJECTED", "confidence": 0.93, "cwe": [], '
        '"explanation": "There is no "generator function" body here, so the '
        'claim is not demonstrated.", "chain_verified": false}'
    )
    value = SecurityAgent._parse_json(reply)

    assert value["decision"] == "REJECTED"
    assert value["confidence"] == 0.93
    assert (
        value["explanation"]
        == 'There is no "generator function" body here, so the claim is '
        "not demonstrated."
    )


def test_a_literal_newline_inside_a_value_is_escaped():
    reply = '{"decision": "UNCERTAIN", "explanation": "line one\nline two"}'
    assert SecurityAgent._parse_json(reply)["explanation"] == "line one\nline two"


def test_repair_leaves_valid_json_byte_for_byte_unchanged():
    from agents.security_agent import _repair_json

    valid = '{\n  "a": "say \\"hi\\" now",\n  "b": [1, {"c": "d"}]\n}'
    assert _repair_json(valid) == valid


def test_a_prose_preamble_is_stripped_before_repair():
    reply = 'Sure! Here is the JSON:\n{"decision": "CONFIRMED", "confidence": 0.9}'
    assert SecurityAgent._parse_json(reply)["decision"] == "CONFIRMED"


def test_an_irreparable_reply_still_raises():
    with pytest.raises(ValueError, match="invalid JSON"):
        SecurityAgent._parse_json("no json here at all")


# -- token spend -----------------------------------------------------------


def test_envelope_returns_provider_usage():
    body = {
        "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}],
        "usage": {"prompt_tokens": 183, "completion_tokens": 61},
    }
    parts = envelope(body, max_tokens=4096)
    assert parts["usage"]["prompt_tokens"] == 183


def test_envelope_returns_empty_usage_when_the_provider_omits_it():
    body = {"choices": [{"finish_reason": "stop", "message": {"content": "{}"}}]}
    assert envelope(body, max_tokens=4096)["usage"] == {}


def test_chat_sends_the_configured_reasoning_effort(monkeypatch):
    monkeypatch.setenv("LLM_REASONING_EFFORT", "minimal")
    transport = OpenAICompat(base_url="https://api.apmix.ai/v1", model_id="m")
    transport._client.close()
    fake = _FakeClient(_finish("stop", "{}"))
    transport._client = fake

    transport.chat("s", "u")

    assert fake.calls[0][1]["reasoning_effort"] == "minimal"


def test_without_the_key_no_field_is_sent(monkeypatch):
    monkeypatch.delenv("LLM_REASONING_EFFORT", raising=False)
    transport = OpenAICompat(base_url="https://api.apmix.ai/v1", model_id="m")
    transport._client.close()
    fake = _FakeClient(_finish("stop", "{}"))
    transport._client = fake

    transport.chat("s", "u")

    assert "reasoning_effort" not in fake.calls[0][1]


def test_an_unsupported_reasoning_effort_is_dropped_for_the_run(monkeypatch):
    # A provider that does not know the field answers 400 to every request.
    # Losing the field must cost one request, not every sample of the run.
    monkeypatch.setenv("LLM_REASONING_EFFORT", "minimal")
    transport = OpenAICompat(base_url="https://api.apmix.ai/v1", model_id="m")
    transport._client.close()
    fake = _SequenceClient(
        _FakeResponse(
            status_code=400, text='{"error": "unknown field reasoning_effort"}'
        ),
        _finish("stop", "{}"),
    )
    transport._client = fake

    parts = transport.chat("s", "u")

    assert parts["text"] == "{}"
    assert "reasoning_effort" in fake.calls[0][1]
    assert "reasoning_effort" not in fake.calls[1][1]
    assert transport._effort_dropped is True
    # The drop is sticky: the next sample never offers the field again.
    transport.chat("s", "u")
    assert len(fake.calls) == 3
    assert "reasoning_effort" not in fake.calls[2][1]


def test_usage_reaches_the_thinking_log(tmp_path, monkeypatch):
    # What a run cost is exactly what a capped key makes you want to audit
    # afterwards, so the provider's token accounting rides along in the trace.
    out = tmp_path / "trace.thinking.json"
    monkeypatch.setenv("LLM_THINKING_OUT", str(out))
    monkeypatch.setenv("LLM_BASE_URL", "https://api.apmix.ai/v1")
    monkeypatch.setenv("LLM_REASONING_EFFORT", "minimal")
    agent = SecurityAgent()
    agent._openai._client.close()
    agent._openai._client = _FakeClient(
        _FakeResponse(
            payload={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"decision": "REJECTED"}'},
                    }
                ],
                "usage": {
                    "prompt_tokens": 120,
                    "completion_tokens": 40,
                    "total_tokens": 160,
                },
            }
        )
    )

    value = asyncio.run(agent.analyze({"file": "a.c", "role": "verifier"}))

    assert value["decision"] == "REJECTED"
    calls = json.loads(out.read_text())["files"]["a.c"]["calls"]
    assert calls[0]["usage"]["total_tokens"] == 160
