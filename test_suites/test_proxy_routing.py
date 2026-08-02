"""
Integration tests for IronWarden Universal Proxy upstream routing logic.

Tests the 4-level routing priority implemented in resolve_upstream_url():
  Priority 1: X-IronWarden-Target-URL request header (explicit override)
  Priority 2: Model-name auto-routing
               claude-*             → Anthropic
               llama*/mistral*/phi*/gemma*/qwen* → Ollama
  Priority 3: Env var overrides (OPENAI_BASE_URL / ANTHROPIC_BASE_URL / OLLAMA_BASE_URL)
  Priority 4: Hardcoded API defaults

Strategy: Two mock upstream servers (A and B) are started. IronWarden is pointed
at server A via OPENAI_BASE_URL env var. Tests assert which server receives the
request to verify the routing decision.
"""
import json
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import requests


# ── Shared mock server ────────────────────────────────────────────────────────

class RoutingMockHandler(BaseHTTPRequestHandler):
    """Records which server received the request."""

    def log_message(self, fmt, *args):
        pass

    def _generic_openai_response(self):
        return json.dumps({
            "id": "chatcmpl-routing-test",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        }).encode()

    def _generic_anthropic_response(self):
        return json.dumps({
            "id": "msg-routing-test",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "model": "claude-3-5-sonnet-20241022",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "output_tokens": 2},
        }).encode()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)
        try:
            parsed = json.loads(raw_body)
        except Exception:
            parsed = {}
        self.server.received_payloads.put({"path": self.path, "body": parsed})

        if "/messages" in self.path:
            body = self._generic_anthropic_response()
        else:
            body = self._generic_openai_response()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.received_payloads.put({"path": self.path, "body": {}})
        body = json.dumps({"object": "list", "data": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RoutingMockServer:
    def __init__(self):
        self.server = HTTPServer(("127.0.0.1", 0), RoutingMockHandler)
        self.server.received_payloads = queue.Queue()
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def base_url(self):
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def pop_received(self, timeout=3.0):
        try:
            return self.server.received_payloads.get(timeout=timeout)
        except queue.Empty:
            return None

    def drain(self):
        while not self.server.received_payloads.empty():
            try:
                self.server.received_payloads.get_nowait()
            except queue.Empty:
                break

    def stop(self):
        self.server.shutdown()


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def routing_server_a():
    """Primary mock server — represents 'OpenAI' for routing tests."""
    s = RoutingMockServer()
    yield s
    s.stop()


@pytest.fixture(scope="module")
def routing_server_b():
    """Secondary mock server — represents 'Anthropic/Ollama' for routing tests."""
    s = RoutingMockServer()
    yield s
    s.stop()


@pytest.fixture(scope="module")
def routing_warden(warden_bin, jwt_keys, routing_server_a, routing_server_b):
    """
    IronWarden instance configured with both mock servers as env var targets.
    OPENAI_BASE_URL    → routing_server_a
    ANTHROPIC_BASE_URL → routing_server_b
    OLLAMA_BASE_URL    → routing_server_b
    """
    from conftest import IronWardenRunner

    overrides = {
        "JWT_PRIVATE_KEY": jwt_keys["private"],
        "JWT_PUBLIC_KEY": jwt_keys["public"],
        "OPENAI_BASE_URL": f"{routing_server_a.base_url()}/v1/chat/completions",
        "ANTHROPIC_BASE_URL": f"{routing_server_b.base_url()}/v1/messages",
        "OLLAMA_BASE_URL": f"{routing_server_b.base_url()}/v1/chat/completions",
    }
    runner = IronWardenRunner(warden_bin, env_overrides=overrides)
    runner.start()
    yield runner
    runner.stop(cleanup=True)


@pytest.fixture(scope="module")
def routing_url(routing_warden):
    port = routing_warden.env["BRIDGE_PORT"]
    return f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def routing_auth(routing_warden):
    import jwt as pyjwt
    import time
    private_key = routing_warden.env["JWT_PRIVATE_KEY"]
    token = pyjwt.encode(
        {
            "sub": "routing_test_user",
            "exp": int(time.time()) + 3600,
            "roles": ["admin"],
            "aud": routing_warden.env.get("WARDEN_JWT_AUDIENCE", "test_audience"),
            "iss": routing_warden.env.get("WARDEN_JWT_ISSUER", "test_issuer"),
        },
        private_key,
        algorithm="RS256",
    )
    return {"Authorization": f"Bearer {token}"}


# ── Helper ────────────────────────────────────────────────────────────────────

def post_chat(url, auth, model, extra_headers=None):
    headers = {**auth, **(extra_headers or {})}
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "routing probe"}],
    }
    return requests.post(f"{url}/v1/chat/completions", json=payload, headers=headers, timeout=10)


def post_messages(url, auth, model, extra_headers=None):
    headers = {**auth, **(extra_headers or {})}
    payload = {
        "model": model,
        "max_tokens": 50,
        "messages": [{"role": "user", "content": "routing probe"}],
    }
    return requests.post(f"{url}/v1/messages", json=payload, headers=headers, timeout=10)


# ═════════════════════════════════════════════════════════════════════════════
# Priority 1: X-IronWarden-Target-URL header overrides everything
# ═════════════════════════════════════════════════════════════════════════════

def test_routing_header_override_beats_model_routing(
    routing_url, routing_auth, routing_server_a, routing_server_b
):
    """
    X-IronWarden-Target-URL must be respected even when the model name would
    normally auto-route to a different server.
    Send a claude-* model (would go to server_b) but override to server_a URL.
    Server A must receive it; server B must not.
    """
    routing_server_a.drain()
    routing_server_b.drain()

    override_url = f"{routing_server_a.base_url()}/v1/chat/completions"
    r = post_chat(
        routing_url, routing_auth,
        model="claude-3-5-sonnet-20241022",  # would normally go to server_b
        extra_headers={"X-IronWarden-Target-URL": override_url},
    )
    assert r.status_code == 200, f"Unexpected status: {r.status_code}"

    received_a = routing_server_a.pop_received(timeout=3.0)
    received_b = routing_server_b.pop_received(timeout=0.3)

    assert received_a is not None, (
        "Header override failed: server A (target) did not receive the request"
    )
    assert received_b is None, (
        "Header override failed: server B (model-default) incorrectly received the request"
    )


def test_routing_header_override_beats_env_var(
    routing_url, routing_auth, routing_server_a, routing_server_b
):
    """
    X-IronWarden-Target-URL must beat even the OPENAI_BASE_URL env var.
    gpt-4o would go to server_a (OPENAI_BASE_URL). Override to server_b.
    """
    routing_server_a.drain()
    routing_server_b.drain()

    override_url = f"{routing_server_b.base_url()}/v1/chat/completions"
    r = post_chat(
        routing_url, routing_auth,
        model="gpt-4o",  # normally goes to server_a via OPENAI_BASE_URL
        extra_headers={"X-IronWarden-Target-URL": override_url},
    )
    assert r.status_code == 200

    received_a = routing_server_a.pop_received(timeout=0.3)
    received_b = routing_server_b.pop_received(timeout=3.0)

    assert received_b is not None, "Header override to server_b not applied"
    assert received_a is None, "Server_a received request despite header override to server_b"


# ═════════════════════════════════════════════════════════════════════════════
# Priority 2: Model-name auto-routing
# ═════════════════════════════════════════════════════════════════════════════

def test_routing_claude_model_goes_to_anthropic_server(
    routing_url, routing_auth, routing_server_a, routing_server_b
):
    """claude-3-5-sonnet must route to ANTHROPIC_BASE_URL (server_b), not server_a."""
    routing_server_a.drain()
    routing_server_b.drain()

    r = post_messages(routing_url, routing_auth, model="claude-3-5-sonnet-20241022")
    assert r.status_code == 200, f"Unexpected status: {r.status_code} {r.text}"

    received_b = routing_server_b.pop_received(timeout=3.0)
    received_a = routing_server_a.pop_received(timeout=0.3)

    assert received_b is not None, "claude-* model did not route to Anthropic server (server_b)"
    assert received_a is None, "claude-* model incorrectly hit OpenAI server (server_a)"


@pytest.mark.parametrize("model", [
    "llama3",
    "llama3.3:70b",
    "mistral-7b",
    "mistral-nemo",
    "phi-3",
    "phi-3.5-mini",
    "gemma2",
    "gemma-2-27b",
    "qwen2.5",
    "qwen2.5-coder",
])
def test_routing_local_models_go_to_ollama_server(
    routing_url, routing_auth, routing_server_a, routing_server_b, model
):
    """
    All local LLM model name prefixes (llama, mistral, phi, gemma, qwen) must
    route to OLLAMA_BASE_URL (server_b), not server_a (OpenAI).
    """
    routing_server_a.drain()
    routing_server_b.drain()

    r = post_chat(routing_url, routing_auth, model=model)
    assert r.status_code == 200, f"Model '{model}' routing failed: {r.status_code}"

    received_b = routing_server_b.pop_received(timeout=3.0)
    received_a = routing_server_a.pop_received(timeout=0.3)

    assert received_b is not None, (
        f"Model '{model}' did not route to Ollama server (server_b)"
    )
    assert received_a is None, (
        f"Model '{model}' incorrectly routed to OpenAI server (server_a)"
    )


def test_routing_gpt_model_goes_to_openai_server(
    routing_url, routing_auth, routing_server_a, routing_server_b
):
    """gpt-4o must route to OPENAI_BASE_URL (server_a)."""
    routing_server_a.drain()
    routing_server_b.drain()

    r = post_chat(routing_url, routing_auth, model="gpt-4o")
    assert r.status_code == 200, f"Unexpected status: {r.status_code}"

    received_a = routing_server_a.pop_received(timeout=3.0)
    received_b = routing_server_b.pop_received(timeout=0.3)

    assert received_a is not None, "gpt-4o did not route to OpenAI server (server_a)"
    assert received_b is None, "gpt-4o incorrectly routed to server_b"


def test_routing_unknown_model_falls_through_to_openai(
    routing_url, routing_auth, routing_server_a, routing_server_b
):
    """An unknown model name must fall through to OpenAI default (server_a)."""
    routing_server_a.drain()
    routing_server_b.drain()

    r = post_chat(routing_url, routing_auth, model="some-unknown-model-xyz")
    assert r.status_code == 200, f"Unexpected status: {r.status_code}"

    received_a = routing_server_a.pop_received(timeout=3.0)
    received_b = routing_server_b.pop_received(timeout=0.3)

    assert received_a is not None, (
        "Unknown model did not fall through to OpenAI default (server_a)"
    )
    assert received_b is None, "Unknown model incorrectly went to server_b"


# ═════════════════════════════════════════════════════════════════════════════
# Priority 3+4: Env var routing is already validated implicitly by all the above.
# Add an explicit test that verifies models endpoint proxies to server_a.
# ═════════════════════════════════════════════════════════════════════════════

def test_routing_models_endpoint_uses_openai_base(
    routing_url, routing_auth, routing_server_a, routing_server_b
):
    """GET /v1/models must proxy to OPENAI_BASE_URL (server_a)."""
    routing_server_a.drain()
    routing_server_b.drain()

    r = requests.get(f"{routing_url}/v1/models", headers=routing_auth, timeout=10)
    assert r.status_code == 200

    received_a = routing_server_a.pop_received(timeout=3.0)
    assert received_a is not None, "/v1/models did not reach OpenAI server (server_a)"
