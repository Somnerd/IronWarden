import pytest
import requests
import jwt
import time

@pytest.fixture
def jwt_token(jwt_keys):
    payload = {
        "sub": "test_user",
        "aud": "test_audience",
        "iss": "test_issuer",
        "exp": int(time.time()) + 3600
    }
    return jwt.encode(payload, jwt_keys["private"], algorithm="RS256")

@pytest.fixture
def bridge_url(warden):
    port = warden.env["BRIDGE_PORT"]
    return f"http://localhost:{port}"

def test_bridge_health(warden, bridge_url):
    response = requests.get(f"{bridge_url}/health")
    assert "HEALTHY" in response.text

def test_bridge_enqueue_unauthorized(warden, bridge_url):
    payload = {
        "query": "Hello",
        "thread_id": "thread_123"
    }
    response = requests.post(f"{bridge_url}/enqueue", json=payload)
    assert response.status_code == 401

def test_bridge_enqueue_authorized(bridge_url, jwt_token):
    payload = {
        "query": "My email is test@example.com",
        "thread_id": "thread_123"
    }
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = requests.post(f"{bridge_url}/enqueue", json=payload, headers=headers)
    
    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    assert response.json()["pii_scrubbed"] is True

def test_bridge_rate_limiting(bridge_url, jwt_token):
    # Burst is 100, RPS is 25. Let's try to hit it.
    headers = {"Authorization": f"Bearer {jwt_token}"}
    payload = {"query": "test", "thread_id": "t1"}
    
    # We might not be able to hit 100 in a loop easily without async, 
    # but let's try 110 requests.
    codes = []
    for _ in range(110):
        try:
            r = requests.post(f"{bridge_url}/enqueue", json=payload, headers=headers, timeout=0.1)
            codes.append(r.status_code)
        except requests.exceptions.RequestException:
            break
            
    assert 429 in codes
