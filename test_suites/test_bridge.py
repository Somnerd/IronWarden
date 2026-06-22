"""
HTTP/REST API tests for the IronWarden Bridge endpoint.
Validates authentication, role-based access control (401/403 status codes), rate limiting,
health checks, and job status retrieval via JWT tokens.
"""
import pytest
import requests
import jwt
import time

@pytest.fixture
def jwt_token(warden):
    secret = warden.env["JWT_PRIVATE_KEY"]
    payload = {
        "sub": "test_user",
        "exp": int(time.time()) + 3600,
        "roles": ["admin"]
    }
    return jwt.encode(payload, secret, algorithm="RS256")

@pytest.fixture
def jwt_token_unprivileged(warden):
    secret = warden.env["JWT_PRIVATE_KEY"]
    payload = {
        "sub": "test_user_no_roles",
        "exp": int(time.time()) + 3600,
        "roles": []
    }
    return jwt.encode(payload, secret, algorithm="RS256")

@pytest.fixture
def bridge_url(warden):
    port = warden.env["BRIDGE_PORT"]
    return f"http://localhost:{port}"

def test_bridge_health(bridge_url):
    response = requests.get(f"{bridge_url}/health")
    assert response.status_code == 200
    assert "IronWarden Bridge" in response.text

def test_bridge_enqueue_unauthorized(bridge_url):
    payload = {
        "query": "Hello",
        "thread_id": "thread_123"
    }
    response = requests.post(f"{bridge_url}/enqueue", json=payload)
    assert response.status_code == 401

def test_bridge_enqueue_forbidden(bridge_url, jwt_token_unprivileged):
    payload = {
        "query": "Hello Bob",
        "thread_id": "thread_123"
    }
    headers = {"Authorization": f"Bearer {jwt_token_unprivileged}"}
    response = requests.post(f"{bridge_url}/enqueue", json=payload, headers=headers)
    assert response.status_code == 403

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

def test_bridge_get_result_unauthorized(bridge_url):
    response = requests.get(f"{bridge_url}/results/some_job_id")
    assert response.status_code == 401

def test_bridge_get_result_forbidden(bridge_url, jwt_token_unprivileged):
    headers = {"Authorization": f"Bearer {jwt_token_unprivileged}"}
    response = requests.get(f"{bridge_url}/results/some_job_id", headers=headers)
    assert response.status_code == 403

def test_bridge_get_result_authorized(bridge_url, jwt_token):
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = requests.get(f"{bridge_url}/results/some_job_id", headers=headers)
    # We might get 200 (if we found it), 202 (processing), or some other mapped error if it is not found.
    # What we are testing is that we don't get 401 or 403.
    assert response.status_code in [200, 202, 400, 404, 500]
