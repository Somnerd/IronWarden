#!/usr/bin/env python3
"""
IronWarden Python OpenAI Client Example
=======================================
Demonstrates how to route OpenAI SDK requests through IronWarden
with zero modifications to message payload structures.

Requirements:
    pip install openai
"""

import os
from openai import OpenAI

# 1. Initialize OpenAI client pointing to IronWarden's local proxy port
# Default port is 8080 (or 14141 for MCP)
client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY", "sk-your-openai-api-key"),
    base_url=os.environ.get("IRONWARDEN_BASE_URL", "http://localhost:8080/v1"),
    default_headers={
        # Bearer token for IronWarden RBAC & user isolation
        "Authorization": f"Bearer {os.environ.get('IRONWARDEN_JWT', 'demo_token')}"
    }
)

def main():
    print("Dispatched prompt with sensitive PII through IronWarden...")
    prompt = "Hello, my name is John Doe, my email is john.doe@example.com and my AFM is 094123456. Summarize my profile."

    # 2. Standard OpenAI chat completion call
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ]
    )

    print("\n--- Upstream LLM Response (De-redacted / Restored by IronWarden) ---")
    print(response.choices[0].message.content)

if __name__ == "__main__":
    main()
