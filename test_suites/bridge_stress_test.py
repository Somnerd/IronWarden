"""
Load and rate-limiting stress test for the IronWarden Bridge /enqueue HTTP endpoint.
Sends burst traffic to verify rate-limiting responses (429) and checks Redis to ensure
enqueued job data only contains redacted placeholders instead of raw sensitive PII.
"""
import asyncio
import httpx
import json
import time
import redis
from typing import List

# Configuration
BRIDGE_URL = "http://localhost:14141"
REDIS_URL = "redis://localhost:6379"
TARGET_RPS = 50  # Above the 25 RPS limit
TEST_QUERY = "Hello, my credit card is 4111-2222-3333-4444 and my email is test@example.com"
USERNAME = "somnerd"
THREAD_ID = "thread_stress_001"

async def send_request(client: httpx.AsyncClient, i: int):
    payload = {
        "query": f"{TEST_QUERY} (Req #{i})",
        "thread_id": THREAD_ID,
        "username": USERNAME,
        "options": {"test": True}
    }
    try:
        start = time.perf_counter()
        response = await client.post(f"{BRIDGE_URL}/enqueue", json=payload, timeout=5.0)
        end = time.perf_counter()
        return i, response.status_code, end - start
    except Exception as e:
        return i, "ERROR", str(e)

async def run_stress_test():
    print(f"🚀 Starting Stress Test against {BRIDGE_URL}...")
    print(f"Target: {TARGET_RPS} requests at burst speed.")
    
    async with httpx.AsyncClient() as client:
        tasks = [send_request(client, i) for i in range(TARGET_RPS)]
        results = await asyncio.gather(*tasks)

    # Analyze Results
    status_counts = {}
    latencies = []
    for i, status, latency in results:
        status_counts[status] = status_counts.get(status, 0) + 1
        if isinstance(latency, float):
            latencies.append(latency)

    print("\n--- Stress Test Results ---")
    for status, count in status_counts.items():
        print(f"Status {status}: {count} requests")
    
    if latencies:
        print(f"Avg Latency: {sum(latencies)/len(latencies):.4f}s")
        print(f"Max Latency: {max(latencies):.4f}s")

    # Verify Rate Limiting
    if status_counts.get(429, 0) > 0:
        print("✅ Rate Limiter Successfully Enforced (429s detected).")
    else:
        print("❌ Rate Limiter FAILED to catch the burst.")

    # Verify PII Scrubbing in Redis
    print("\n🔍 Verifying PII Scrubbing in Redis...")
    r = redis.from_url(REDIS_URL)
    
    # Get the latest jobs from arq:queue
    jobs = r.zrange("arq:queue", -5, -1)
    if not jobs:
        print("❌ No jobs found in Redis queue.")
        return

    for job_id_bytes in jobs:
        job_id = job_id_bytes.decode()
        job_data = r.get(f"arq:job:{job_id}")
        if job_data:
            # Note: This is pickled, but we can search for the raw substrings
            if b"4111-2222-3333-4444" in job_data:
                print(f"❌ CRITICAL FAILURE: Raw PII found in Redis job {job_id}")
            elif b"[CREDIT_CARD" in job_data or b"[EMAIL" in job_data:
                print(f"✅ SUCCESS: PII tokens found in Redis job {job_id}")
            else:
                print(f"❓ WARNING: Could not find query content in job {job_id}")

if __name__ == "__main__":
    asyncio.run(run_stress_test())
