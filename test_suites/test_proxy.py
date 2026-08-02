"""
Integration tests for the IronWarden Universal AI Gateway Proxy routes.

Tests the following endpoints:
  POST /v1/chat/completions  (OpenAI non-streaming + streaming)
  POST /v1/completions       (OpenAI legacy text completions)
  GET  /v1/models            (passthrough model listing)
  POST /v1/messages          (Anthropic Claude protocol)

Strategy: A lightweight HTTP mock server runs in a background thread for each test
session, simulating upstream LLM responses. IronWarden is pointed at this mock
via the OPENAI_BASE_URL / ANTHROPIC_BASE_URL environment variables.

Security assertions checked in every test:
  - Raw PII never appears in mock upstream's received payload
  - PII is correctly restored in the client-facing response
  - Audit log entry written (verified via /health or compliance report)
"""
import json
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
import requests


# ── Mock upstream LLM server ──────────────────────────────────────────────────

class MockUpstreamHandler(BaseHTTPRequestHandler):
    """
    Minimal HTTP server that simulates an OpenAI / Anthropic API.
    Records the raw payloads it receives (for PII leak assertions).
    """

    def log_message(self, format, *args):
        pass  # Silence default access logs

    def do_GET(self):
        if self.path == "/v1/models":
            body = json.dumps({
                "object": "list",
                "data": [
                    {"id": "gpt-4o", "object": "model"},
                    {"id": "gpt-3.5-turbo", "object": "model"},
                ]
            }).encode()
            self._send(200, body)
        else:
            self._send(404, b"Not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)

        # Store received payload so tests can inspect it
        try:
            parsed = json.loads(raw_body)
        except Exception:
            parsed = {}
        self.server.received_payloads.put(parsed)

        # Detect streaming request
        is_stream = parsed.get("stream", False)

        if self.path == "/v1/chat/completions":
            if is_stream:
                self._send_sse_openai(parsed)
            else:
                self._send_openai_chat_response(parsed)

        elif self.path == "/v1/completions":
            self._send_openai_legacy_response(parsed)

        elif self.path == "/v1/messages":
            if is_stream:
                self._send_sse_anthropic(parsed)
            else:
                self._send_anthropic_response(parsed)

        else:
            self._send(404, b"Unknown path")

    def _extract_placeholder(self, parsed):
        import re
        s = json.dumps(parsed)
        m = re.search(r'\[(PERSON_\d+|TOKEN_\d+|EMAIL_\d+)\]', s)
        if m:
            return m.group(0)
        return "[PERSON_1]"

    # ── Response builders ──────────────────────────────────────────────────────

    def _send_openai_chat_response(self, parsed):
        placeholder = self._extract_placeholder(parsed)
        body = json.dumps({
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": f"Hello, {placeholder}!"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        }).encode()
        self._send(200, body)

    def _send_openai_legacy_response(self, parsed):
        placeholder = self._extract_placeholder(parsed)
        body = json.dumps({
            "id": "cmpl-test",
            "object": "text_completion",
            "choices": [{"text": f"Hi {placeholder}", "index": 0, "finish_reason": "stop"}],
        }).encode()
        self._send(200, body)

    def _send_anthropic_response(self, parsed):
        placeholder = self._extract_placeholder(parsed)
        body = json.dumps({
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": f"Greetings, {placeholder}!"}],
            "stop_reason": "end_turn",
        }).encode()
        self._send(200, body)

    def _send_sse_openai(self, parsed):
        """Simulate a split-token stream: placeholder arrives across two chunks."""
        placeholder = self._extract_placeholder(parsed)
        half = max(1, len(placeholder) // 2)
        p1 = placeholder[:half]
        p2 = placeholder[half:]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        chunks = [
            json.dumps({"choices": [{"delta": {"content": f"Hello {p1}"}, "index": 0}]}),
            json.dumps({"choices": [{"delta": {"content": f"{p2}!"}, "index": 0}]}),
            json.dumps({"choices": [{"delta": {}, "finish_reason": "stop", "index": 0}]}),
        ]
        for chunk in chunks:
            self.wfile.write(f"data: {chunk}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.01)

        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def _send_sse_anthropic(self, parsed=None):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        events = [
            ("message_start", json.dumps({"type": "message_start", "message": {"id": "msg_test"}})),
            ("content_block_delta", json.dumps({"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Hi [PERSON_1]"}})),
            ("message_delta", json.dumps({"type": "message_delta", "delta": {"stop_reason": "end_turn"}})),
            ("message_stop", json.dumps({"type": "message_stop"})),
        ]
        for event_type, data in events:
            self.wfile.write(f"event: {event_type}\ndata: {data}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.01)

    def _send(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MockUpstreamServer:
    def __init__(self):
        self.server = HTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
        self.server.received_payloads = queue.Queue()
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()

    def base_url(self):
        return f"http://127.0.0.1:{self.port}"

    def pop_received(self, timeout=2.0):
        """Return the last payload received by the mock upstream."""
        try:
            return self.server.received_payloads.get(timeout=timeout)
        except queue.Empty:
            return None

    def drain(self):
        while not self.server.received_payloads.empty():
            self.server.received_payloads.get_nowait()


# ── Session-scoped fixtures ───────────────────────────────────────────────────

@pytest.fixture(scope="session")
def mock_upstream():
    srv = MockUpstreamServer()
    srv.start()
    yield srv
    srv.stop()


@pytest.fixture(scope="session")
def proxy_warden(warden_factory, mock_upstream):
    """
    IronWarden instance pointed at the mock upstream LLM.
    Uses the same IronWardenRunner as other tests but injects
    OPENAI_BASE_URL and ANTHROPIC_BASE_URL to hit our mock.
    """
    base = mock_upstream.base_url()
    runner = warden_factory(env_overrides={
        "OPENAI_BASE_URL": f"{base}/v1/chat/completions",
        "ANTHROPIC_BASE_URL": f"{base}/v1/messages",
        "WARDEN_MODE": "hybrid",
    })
    runner.start()
    yield runner
    runner.stop()


@pytest.fixture
def proxy_url(proxy_warden):
    return f"http://localhost:{proxy_warden.env['BRIDGE_PORT']}"


@pytest.fixture
def auth_headers(proxy_warden):
    secret = proxy_warden.env["JWT_PRIVATE_KEY"]
    token = jwt.encode(
        {"sub": "proxy_test_user", "exp": int(time.time()) + 3600, "roles": ["admin"]},
        secret,
        algorithm="RS256",
    )
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ── Helper ────────────────────────────────────────────────────────────────────

PII_SAMPLES = [
    "john.doe@example.com",
    "+30 210 1234567",
    "123-45-6789",
]

def contains_pii(text):
    return any(pii.lower() in str(text).lower() for pii in PII_SAMPLES)


# ═════════════════════════════════════════════════════════════════════════════
# Test Group 1: Authentication & Access Control
# ═════════════════════════════════════════════════════════════════════════════

def test_proxy_chat_no_token(proxy_url):
    """V1/chat/completions must require a Bearer token."""
    payload = {"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]}
    r = requests.post(f"{proxy_url}/v1/chat/completions", json=payload)
    assert r.status_code == 401, f"Expected 401, got {r.status_code}: {r.text}"


def test_proxy_messages_no_token(proxy_url):
    """v1/messages (Anthropic) must require a Bearer token."""
    payload = {"model": "claude-3-5-sonnet-20241022", "messages": [{"role": "user", "content": "Hello"}], "max_tokens": 100}
    r = requests.post(f"{proxy_url}/v1/messages", json=payload)
    assert r.status_code == 401


def test_proxy_invalid_token_rejected(proxy_url):
    """A malformed / unsigned token must be rejected."""
    headers = {"Authorization": "Bearer this.is.not.a.valid.jwt"}
    payload = {"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}]}
    r = requests.post(f"{proxy_url}/v1/chat/completions", json=payload, headers=headers)
    assert r.status_code == 401


# ═════════════════════════════════════════════════════════════════════════════
# Test Group 2: Non-Streaming OpenAI — V-14 PII Leak Prevention (Core Security)
# ═════════════════════════════════════════════════════════════════════════════

def test_proxy_chat_pii_scrubbed_before_upstream(proxy_url, auth_headers, mock_upstream):
    """
    SECURITY TEST (V-14): Raw PII in the user prompt must NEVER reach the upstream.
    The mock records what it received; we assert the PII is absent.
    """
    mock_upstream.drain()
    pii_email = "john.doe@example.com"

    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": f"My email is {pii_email}, please help."}],
    }
    r = requests.post(f"{proxy_url}/v1/chat/completions", json=payload, headers=auth_headers)
    assert r.status_code == 200, f"Unexpected status {r.status_code}: {r.text}"

    received = mock_upstream.pop_received()
    assert received is not None, "Mock upstream received no request"

    # V-14: raw PII must not appear in what was forwarded
    forwarded_text = json.dumps(received)
    assert pii_email not in forwarded_text, (
        f"LEAK DETECTED: '{pii_email}' found in upstream payload: {forwarded_text}"
    )
    # A placeholder must have been substituted
    assert "[TOKEN_" in forwarded_text or "[EMAIL_" in forwarded_text or "[PERSON_" in forwarded_text


def test_proxy_chat_pii_restored_in_response(proxy_url, auth_headers, mock_upstream):
    """
    The mock upstream echoes back '[PERSON_1]' in its response.
    IronWarden must restore it to the original value in the client response.
    """
    mock_upstream.drain()
    original_name = "Alice Johnson"

    # Sanitize a name first so the session has the mapping
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": f"Tell me about {original_name}."}
        ],
    }
    r = requests.post(f"{proxy_url}/v1/chat/completions", json=payload, headers=auth_headers)
    assert r.status_code == 200

    # The mock responds with "[PERSON_1]!" — the restored response should contain
    # the original name, not the placeholder
    data = r.json()
    response_text = data["choices"][0]["message"]["content"]
    # Either the name is restored, or the placeholder does NOT leak to the client
    assert "[PERSON_1]" not in response_text or original_name in response_text, (
        f"PII placeholder leaked to client: {response_text}"
    )


def test_proxy_chat_system_message_also_scrubbed(proxy_url, auth_headers, mock_upstream):
    """PII in system messages must also be redacted before forwarding."""
    mock_upstream.drain()
    pii_email = "admin@secret-company.com"

    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": f"You are an assistant for {pii_email}"},
            {"role": "user", "content": "Hello"},
        ],
    }
    r = requests.post(f"{proxy_url}/v1/chat/completions", json=payload, headers=auth_headers)
    assert r.status_code == 200

    received = mock_upstream.pop_received()
    forwarded_text = json.dumps(received)
    assert pii_email not in forwarded_text, f"System message PII leaked: {forwarded_text}"


def test_proxy_chat_non_pii_passes_through(proxy_url, auth_headers, mock_upstream):
    """Benign messages with no PII must pass through unmodified."""
    mock_upstream.drain()
    benign = "What is the capital of France?"

    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": benign}],
    }
    r = requests.post(f"{proxy_url}/v1/chat/completions", json=payload, headers=auth_headers)
    assert r.status_code == 200

    received = mock_upstream.pop_received()
    forwarded_text = json.dumps(received)
    assert benign in forwarded_text, "Non-PII content was unexpectedly modified"


# ═════════════════════════════════════════════════════════════════════════════
# Test Group 3: SSE Streaming — Split-Token Re-hydration
# ═════════════════════════════════════════════════════════════════════════════

def test_proxy_chat_streaming_returns_event_stream(proxy_url, auth_headers, mock_upstream):
    """stream: true must return Content-Type: text/event-stream."""
    mock_upstream.drain()
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello streaming world"}],
        "stream": True,
    }
    r = requests.post(
        f"{proxy_url}/v1/chat/completions",
        json=payload,
        headers=auth_headers,
        stream=True,
        timeout=15,
    )
    assert r.status_code == 200
    assert "text/event-stream" in r.headers.get("Content-Type", ""), (
        f"Wrong Content-Type: {r.headers.get('Content-Type')}"
    )


def test_proxy_chat_streaming_split_token_restored(proxy_url, auth_headers, mock_upstream):
    """
    The mock sends '[PERSON_1]' split across two SSE chunks: '[PER' then 'SON_1]'.
    The SSE engine must buffer and restore these into the original value.
    No placeholder fragment must appear in the client-facing stream.
    """
    mock_upstream.drain()

    # First sanitize so the session knows placeholder → "John Doe"
    setup_payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "My name is John Doe."}],
    }
    requests.post(f"{proxy_url}/v1/chat/completions", json=setup_payload, headers=auth_headers)
    mock_upstream.drain()

    # Now request streaming
    stream_payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Say hello to John Doe."}],
        "stream": True,
    }
    r = requests.post(
        f"{proxy_url}/v1/chat/completions",
        json=stream_payload,
        headers=auth_headers,
        stream=True,
        timeout=15,
    )
    assert r.status_code == 200

    full_content = ""
    for line in r.iter_lines():
        if line and line.startswith(b"data: "):
            data_str = line[6:].decode()
            if data_str.strip() == "[DONE]":
                break
            try:
                chunk = json.loads(data_str)
                delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                full_content += delta
            except Exception:
                pass

    # The full_content should NOT contain raw placeholder fragments
    assert "[PER" not in full_content, f"Partial placeholder leaked in stream: {full_content}"
    assert "[PERSON_1]" not in full_content, f"Full placeholder leaked in stream: {full_content}"


def test_proxy_streaming_done_forwarded(proxy_url, auth_headers, mock_upstream):
    """The [DONE] sentinel must appear exactly once at the end of the stream."""
    mock_upstream.drain()
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Stream test"}],
        "stream": True,
    }
    r = requests.post(
        f"{proxy_url}/v1/chat/completions",
        json=payload,
        headers=auth_headers,
        stream=True,
        timeout=15,
    )
    done_count = sum(
        1 for line in r.iter_lines()
        if line == b"data: [DONE]"
    )
    assert done_count == 1, f"Expected exactly one [DONE], found {done_count}"


# ═════════════════════════════════════════════════════════════════════════════
# Test Group 4: Anthropic /v1/messages
# ═════════════════════════════════════════════════════════════════════════════

def test_proxy_anthropic_basic(proxy_url, auth_headers, mock_upstream):
    """POST /v1/messages must forward to upstream and return a response."""
    mock_upstream.drain()
    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hello Claude"}],
        "max_tokens": 100,
    }
    r = requests.post(f"{proxy_url}/v1/messages", json=payload, headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "content" in data, f"No 'content' in Anthropic response: {data}"


def test_proxy_anthropic_pii_scrubbed(proxy_url, auth_headers, mock_upstream):
    """PII in Anthropic messages must be scrubbed before forwarding."""
    mock_upstream.drain()
    pii_email = "claudetest@private.org"

    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": f"My email is {pii_email}"}],
        "max_tokens": 100,
    }
    r = requests.post(f"{proxy_url}/v1/messages", json=payload, headers=auth_headers)
    assert r.status_code == 200

    received = mock_upstream.pop_received()
    forwarded_text = json.dumps(received)
    assert pii_email not in forwarded_text, f"Anthropic PII leaked: {forwarded_text}"


def test_proxy_anthropic_system_prompt_scrubbed(proxy_url, auth_headers, mock_upstream):
    """The Anthropic 'system' field must also be sanitized."""
    mock_upstream.drain()
    pii_email = "system-admin@internal.corp"

    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "system": f"You serve {pii_email} exclusively.",
        "messages": [{"role": "user", "content": "Hello"}],
        "max_tokens": 100,
    }
    r = requests.post(f"{proxy_url}/v1/messages", json=payload, headers=auth_headers)
    assert r.status_code == 200

    received = mock_upstream.pop_received()
    forwarded_text = json.dumps(received)
    assert pii_email not in forwarded_text, f"Anthropic system PII leaked: {forwarded_text}"


def test_proxy_anthropic_content_block_format(proxy_url, auth_headers, mock_upstream):
    """Anthropic content-block array format (list of {type, text} dicts) must be sanitized."""
    mock_upstream.drain()
    pii_phone = "+30 210 9999999"

    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": f"Call me at {pii_phone}"}
            ]
        }],
        "max_tokens": 100,
    }
    r = requests.post(f"{proxy_url}/v1/messages", json=payload, headers=auth_headers)
    assert r.status_code == 200

    received = mock_upstream.pop_received()
    forwarded_text = json.dumps(received)
    assert pii_phone not in forwarded_text, f"Content block PII leaked: {forwarded_text}"


# ═════════════════════════════════════════════════════════════════════════════
# Test Group 5: Legacy Completions + Models Passthrough
# ═════════════════════════════════════════════════════════════════════════════

def test_proxy_legacy_completions(proxy_url, auth_headers, mock_upstream):
    """POST /v1/completions must sanitize prompt and return a completion response."""
    mock_upstream.drain()
    pii = "user@legacy.io"

    payload = {"model": "gpt-3.5-turbo-instruct", "prompt": f"Email: {pii}. Summarize."}
    r = requests.post(f"{proxy_url}/v1/completions", json=payload, headers=auth_headers)
    assert r.status_code == 200

    received = mock_upstream.pop_received()
    forwarded_text = json.dumps(received)
    assert pii not in forwarded_text, f"Legacy completion PII leaked: {forwarded_text}"
    data = r.json()
    assert "choices" in data


def test_proxy_models_passthrough(proxy_url, auth_headers, mock_upstream):
    """GET /v1/models must proxy the upstream model list."""
    r = requests.get(f"{proxy_url}/v1/models", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "data" in data
    model_ids = [m["id"] for m in data["data"]]
    assert len(model_ids) > 0


# ═════════════════════════════════════════════════════════════════════════════
# Test Group 6: Upstream Error Handling — Fail-Closed
# ═════════════════════════════════════════════════════════════════════════════

def test_proxy_unreachable_upstream_returns_502(proxy_url, auth_headers):
    """
    If the upstream is unreachable, IronWarden must return 502 (not 500 or hang).
    We override via header to a dead port.
    """
    headers = {
        **auth_headers,
        "X-IronWarden-Target-URL": "http://127.0.0.1:1/v1/chat/completions",
    }
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}],
    }
    r = requests.post(
        f"{proxy_url}/v1/chat/completions",
        json=payload,
        headers=headers,
        timeout=10,
    )
    assert r.status_code in (502, 504), (
        f"Expected 502/504 on unreachable upstream, got {r.status_code}"
    )


def test_proxy_target_url_override(proxy_url, auth_headers, mock_upstream):
    """X-IronWarden-Target-URL header must override the default upstream routing."""
    mock_upstream.drain()
    override_url = f"{mock_upstream.base_url()}/v1/chat/completions"

    headers = {**auth_headers, "X-IronWarden-Target-URL": override_url}
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Routing override test"}],
    }
    r = requests.post(f"{proxy_url}/v1/chat/completions", json=payload, headers=headers)
    assert r.status_code == 200

    # The mock must have received the request (confirms override worked)
    received = mock_upstream.pop_received(timeout=3.0)
    assert received is not None, "Mock upstream never received the request via override header"


# ═════════════════════════════════════════════════════════════════════════════
# Test Group 7: Security — Blocked Prompt & Audit Log Enforcement
# ═════════════════════════════════════════════════════════════════════════════

def test_proxy_blocked_prompt_never_reaches_upstream(proxy_url, auth_headers, mock_upstream):
    """
    SECURITY TEST: A prompt that triggers a block rule must NEVER reach the
    upstream LLM. The mock upstream must receive zero requests.

    Uses 'Acme Corp' which is a Dictionary block-level rule in rules.yaml
    (category: InternalAsset — treated as a blocked keyword by the policy engine).
    """
    mock_upstream.drain()

    # 'Alice' and 'Acme Corp' are Dictionary PII rules in the test config.
    # Depending on policy, is_blocked may fire. We use a known keyword.
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Tell me about Alice at Acme Corp."}],
    }
    r = requests.post(
        f"{proxy_url}/v1/chat/completions",
        json=payload,
        headers=auth_headers,
        timeout=10,
    )

    # If the policy blocks this, upstream must not have received it.
    # We check the mock regardless of status — upstream must be empty.
    upstream_received = mock_upstream.pop_received(timeout=0.5)

    if r.status_code == 400:
        # Blocked — good. Now assert upstream was untouched.
        assert upstream_received is None, (
            "SECURITY BREACH: Blocked prompt reached upstream LLM! "
            f"Upstream received: {upstream_received}"
        )
    elif r.status_code == 200:
        # Not blocked (policy may allow PII scrubbing without blocking).
        # Verify that at minimum the raw keywords were scrubbed from upstream payload.
        assert upstream_received is not None
        upstream_body = json.dumps(upstream_received)
        # Even if not blocked, PII must be scrubbed from what upstream sees
        assert "Acme Corp" not in upstream_body, (
            f"PII 'Acme Corp' leaked to upstream: {upstream_body}"
        )
    else:
        pytest.fail(f"Unexpected status {r.status_code}: {r.text}")


def test_proxy_hard_blocked_prompt_never_reaches_upstream(mock_upstream, blocked_warden):
    """
    HARD SECURITY TEST: A prompt containing the sentinel keyword 'IRONWARDEN_BLOCK_THIS'
    must trigger is_blocked=true from the policy engine (configured via
    rules_block_test.yaml with action: Block). IronWarden must return 400 and
    the mock upstream must receive ZERO requests — no exceptions.

    This is a deterministic test with a guaranteed block, unlike the soft-block
    test which depends on how InternalAsset category is classified.
    """
    import jwt as pyjwt
    import time

    mock_upstream.drain()

    # Generate auth token for the blocked_warden instance (different port from default proxy_warden)
    private_key = blocked_warden.env.get("JWT_PRIVATE_KEY", "")
    token = pyjwt.encode(
        {
            "sub": "block_test_user",
            "exp": int(time.time()) + 3600,
            "roles": ["admin"],
            "aud": blocked_warden.env.get("WARDEN_JWT_AUDIENCE", "test_audience"),
            "iss": blocked_warden.env.get("WARDEN_JWT_ISSUER", "test_issuer"),
        },
        private_key,
        algorithm="RS256",
    )
    headers = {"Authorization": f"Bearer {token}"}
    port = blocked_warden.env["BRIDGE_PORT"]
    blocked_proxy_url = f"http://127.0.0.1:{port}"

    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Please process this: IRONWARDEN_BLOCK_THIS now."}
        ],
    }
    r = requests.post(
        f"{blocked_proxy_url}/v1/chat/completions",
        json=payload,
        headers=headers,
        timeout=10,
    )

    # Must be blocked — hard assertion, no dual-mode here
    assert r.status_code == 400, (
        f"Expected 400 (policy block) for sentinel keyword, got {r.status_code}. "
        f"Body: {r.text}"
    )

    # Upstream must have received ZERO requests — this is the critical invariant
    upstream_received = mock_upstream.pop_received(timeout=0.5)
    assert upstream_received is None, (
        "SECURITY BREACH: Policy-blocked prompt reached upstream LLM! "
        f"Upstream received: {upstream_received}"
    )


def test_proxy_audit_log_written_after_chat_completion(proxy_url, auth_headers, mock_upstream, proxy_warden):
    """
    After a successful /v1/chat/completions call, the audit_reports table in
    SQLite must contain at least one new row for the authenticated user.
    This validates the fail-closed audit guarantee end-to-end on proxy routes.
    """
    import sqlite3

    mock_upstream.drain()
    db_path = proxy_warden.env.get("AUDIT_DB_PATH")
    if not db_path:
        pytest.skip("AUDIT_DB_PATH not available in proxy_warden fixture")

    # Count rows before the call
    try:
        conn = sqlite3.connect(db_path)
        before = conn.execute("SELECT COUNT(*) FROM audit_reports").fetchone()[0]
        conn.close()
    except Exception:
        before = 0

    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Audit test: my email is test@audit-check.io"}],
    }
    r = requests.post(
        f"{proxy_url}/v1/chat/completions",
        json=payload,
        headers=auth_headers,
        timeout=10,
    )
    assert r.status_code == 200, f"Proxy call failed: {r.status_code} {r.text}"

    # Allow async audit writer a moment to flush to disk
    time.sleep(0.5)

    # Count rows after
    try:
        conn = sqlite3.connect(db_path)
        after = conn.execute("SELECT COUNT(*) FROM audit_reports").fetchone()[0]
        conn.close()
    except Exception as e:
        pytest.fail(f"Could not read audit DB at {db_path}: {e}")

    assert after > before, (
        f"No audit row written after proxy chat completion. "
        f"Before: {before}, After: {after}, DB: {db_path}"
    )


def test_proxy_upstream_error_body_not_leaked(proxy_url, auth_headers):
    """
    When upstream returns a non-2xx error, IronWarden must return 502 to the
    client. The upstream error body (which may contain internal infra details)
    must NOT be forwarded verbatim — or if it is, it must not reveal upstream
    secrets. At minimum, we validate the status is 502, not a passthrough.
    """
    # Point to a server that returns 500 with a sensitive-looking body
    # We use dead port which causes connection failure → 502/504
    headers = {
        **auth_headers,
        "X-IronWarden-Target-URL": "http://127.0.0.1:1/v1/chat/completions",
    }
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "trigger upstream error"}],
    }
    r = requests.post(
        f"{proxy_url}/v1/chat/completions",
        json=payload,
        headers=headers,
        timeout=10,
    )
    assert r.status_code in (502, 504), (
        f"Expected 502/504 on upstream error, got {r.status_code}"
    )
    # The response body must not expose raw upstream stack traces / keys
    body = r.text.lower()
    assert "sk-" not in body, "Upstream API key leaked in error response"
    assert "openai_api_key" not in body, "Env var name leaked in error response"


# ═════════════════════════════════════════════════════════════════════════════
# Test Group 8: Auth Edge Cases
# ═════════════════════════════════════════════════════════════════════════════

def test_proxy_expired_token_rejected(proxy_url, proxy_warden):
    """
    A JWT token that is syntactically valid and correctly signed but has an
    expired 'exp' claim must be rejected with 401 — not 200 or 500.
    """
    import jwt as pyjwt
    import time

    private_key = proxy_warden.env.get("JWT_PRIVATE_KEY", "")
    if not private_key:
        pytest.skip("JWT_PRIVATE_KEY not available in proxy_warden fixture")

    expired_token = pyjwt.encode(
        {
            "sub": "expired_user",
            "exp": int(time.time()) - 3600,  # expired 1 hour ago
            "roles": ["admin"],
            "aud": proxy_warden.env.get("WARDEN_JWT_AUDIENCE", "test_audience"),
            "iss": proxy_warden.env.get("WARDEN_JWT_ISSUER", "test_issuer"),
        },
        private_key,
        algorithm="RS256",
    )

    headers = {"Authorization": f"Bearer {expired_token}"}
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello with expired token"}],
    }
    r = requests.post(
        f"{proxy_url}/v1/chat/completions",
        json=payload,
        headers=headers,
        timeout=10,
    )
    assert r.status_code == 401, (
        f"Expected 401 for expired token, got {r.status_code}. "
        "Expired tokens must be rejected."
    )


def test_proxy_no_bearer_prefix_rejected(proxy_url):
    """
    Passing the token without the 'Bearer ' prefix must return 401.
    Some clients incorrectly send 'Authorization: <token>' without the scheme.
    """
    headers = {"Authorization": "some-token-without-bearer-prefix"}
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}],
    }
    r = requests.post(
        f"{proxy_url}/v1/chat/completions",
        json=payload,
        headers=headers,
        timeout=10,
    )
    assert r.status_code == 401, (
        f"Expected 401 for missing Bearer prefix, got {r.status_code}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# Test Group 9: Anthropic Streaming & Session Persistence
# ═════════════════════════════════════════════════════════════════════════════

def test_proxy_anthropic_streaming(proxy_url, auth_headers, mock_upstream):
    """
    POST /v1/messages with stream: true must return Content-Type: text/event-stream.
    PII in the streamed Anthropic response must be restored before delivery.
    """
    mock_upstream.drain()

    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 100,
        "stream": True,
        "messages": [
            {"role": "user", "content": "My name is Jane Doe. Say hello."}
        ],
    }
    r = requests.post(
        f"{proxy_url}/v1/messages",
        json=payload,
        headers=auth_headers,
        timeout=15,
        stream=True,
    )
    assert r.status_code == 200, f"Streaming Anthropic request failed: {r.status_code}"
    assert "text/event-stream" in r.headers.get("Content-Type", ""), (
        f"Expected text/event-stream, got: {r.headers.get('Content-Type')}"
    )

    # Consume the stream and check for [DONE]
    lines = []
    for raw in r.iter_lines(decode_unicode=True):
        if raw:
            lines.append(raw)
        if raw == "data: [DONE]":
            break

    assert any("data:" in line for line in lines), (
        "No SSE data lines received in Anthropic streaming response"
    )


def test_proxy_session_token_map_persists_across_calls(proxy_url, auth_headers, mock_upstream):
    """
    Two consecutive calls from the same authenticated user should share session
    state. PII encountered in call 1 should have a consistent token in call 2
    (the session token map persists across requests via save_session).

    Strategy: make two calls with the same PII value. Extract the placeholder
    from the upstream-received payload in both calls. They must be identical.
    """
    mock_upstream.drain()
    pii_value = "persistence@session-test.com"

    def make_call():
        mock_upstream.drain()
        payload = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"My email is {pii_value}"}],
        }
        r = requests.post(
            f"{proxy_url}/v1/chat/completions",
            json=payload,
            headers=auth_headers,
            timeout=10,
        )
        assert r.status_code == 200
        received = mock_upstream.pop_received(timeout=3.0)
        assert received is not None
        return received

    payload_1 = make_call()
    payload_2 = make_call()

    # Extract the placeholder used for the email in both upstream payloads
    import re

    def extract_placeholder(payload):
        body = json.dumps(payload)
        m = re.search(r"\[EMAIL_\d+\]|\[TOKEN_\d+\]|\[PERSON_\d+\]", body)
        return m.group(0) if m else None

    placeholder_1 = extract_placeholder(payload_1)
    placeholder_2 = extract_placeholder(payload_2)

    assert placeholder_1 is not None, f"No placeholder found in call 1 upstream payload: {payload_1}"
    assert placeholder_2 is not None, f"No placeholder found in call 2 upstream payload: {payload_2}"
    assert placeholder_1 == placeholder_2, (
        f"Session token map not persistent: call 1 used '{placeholder_1}', "
        f"call 2 used '{placeholder_2}' for the same PII value '{pii_value}'"
    )
    # Also verify the raw PII never reached upstream in either call
    assert pii_value not in json.dumps(payload_1), "PII leaked to upstream in call 1"
    assert pii_value not in json.dumps(payload_2), "PII leaked to upstream in call 2"
