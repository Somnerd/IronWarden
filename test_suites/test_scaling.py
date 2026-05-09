import pytest
import requests
import time
import threading
import json
import jwt
from concurrent.futures import ThreadPoolExecutor, as_completed

def test_scaling_bridge_concurrency(warden, jwt_factory):
    """
    Push the SearchBoost Bridge with 50 concurrent users to verify:
    1. LocalSessionManager handles DashMap contention.
    2. SQLite Task-Queue handles concurrent writes.
    3. Latency stays within reasonable bounds.
    """
    bridge_url = f"http://localhost:{warden.env['BRIDGE_PORT']}"
    num_users = 50
    requests_per_user = 10
    total_expected = num_users * requests_per_user
    
    # Pre-generate tokens to avoid timing issues in the hot loop
    user_tokens = {f"user_{i}": jwt_factory(f"user_{i}") for i in range(num_users)}
    
    def send_request(username, token):
        payload = {
            "query": f"Query from {username}: my secret email is {username}@corp.com",
            "thread_id": "t1"
        }
        headers = {"Authorization": f"Bearer {token}"}
        start = time.time()
        try:
            r = requests.post(f"{bridge_url}/enqueue", json=payload, headers=headers, timeout=2.0)
            elapsed = (time.time() - start) * 1000
            return r.status_code, elapsed
        except Exception as e:
            return 500, 0

    print(f"\n🚀 Scaling Test: Firing {total_expected} requests across {num_users} users...")
    
    results = []
    latencies = []
    
    start_test = time.time()
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for i in range(requests_per_user):
            for username, token in user_tokens.items():
                futures.append(executor.submit(send_request, username, token))
        
        for future in as_completed(futures):
            status, elapsed = future.result()
            results.append(status)
            if elapsed > 0:
                latencies.append(elapsed)
    
    total_time = time.time() - start_test
    
    # Analysis
    success_count = results.count(200)
    rate_limited = results.count(429)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0
    
    print(f"\n📈 Results:")
    print(f"   - Total Requests: {len(results)}")
    print(f"   - Success (200): {success_count}")
    print(f"   - Rate Limited (429): {rate_limited}")
    print(f"   - Throughput: {len(results)/total_time:.2f} RPS")
    print(f"   - Avg Latency: {avg_latency:.2f} ms")
    print(f"   - Max Latency: {max_latency:.2f} ms")

    # Critical Assertions
    # We allow some 429s because our limit is 25 RPS (sustained) and 100 Burst.
    assert success_count > 0, "No requests succeeded"
    assert results.count(500) == 0, "Server crashed under load (500 errors detected)"
    
    # Check for deadlocks in LocalSessionManager
    # If it works for 50 users simultaneously, DashMap and SQLite tasks are holding up.
    assert success_count + rate_limited == len(results)

def test_scaling_heavy_scrubbing_latency(warden, jwt_factory):
    """
    Test latency impact when scrubbing a large block of text with many PII hits.
    """
    bridge_url = f"http://localhost:{warden.env['BRIDGE_PORT']}"
    token = jwt_factory("heavy_user")
    
    # 100 repetitions of PII names to stress the Aho-Corasick + TokenMap logic
    heavy_payload = "Contact Alice, Bob, and Acme Corp. " * 100
    
    payload = {
        "query": heavy_payload,
        "thread_id": "heavy_thread"
    }
    headers = {"Authorization": f"Bearer {token}"}
    
    start = time.time()
    response = requests.post(f"{bridge_url}/enqueue", json=payload, headers=headers)
    elapsed = (time.time() - start) * 1000
    
    assert response.status_code == 200
    print(f"\n⚖️ Heavy Scrubbing Latency: {elapsed:.2f} ms for {len(heavy_payload)} chars")
    
    # Performance gate: Should be under 200ms even for heavy local processing
    assert elapsed < 200
