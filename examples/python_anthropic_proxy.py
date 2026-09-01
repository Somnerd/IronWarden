#!/usr/bin/env python3
"""
IronWarden Python Anthropic Client Example
==========================================
Demonstrates how to route Anthropic Claude SDK requests through IronWarden.

Requirements:
    pip install anthropic
"""

import os
import anthropic

# 1. Initialize Anthropic client pointing to IronWarden's local proxy port
client = anthropic.Anthropic(
    api_key=os.environ.get("ANTHROPIC_API_KEY", "sk-ant-your-anthropic-key"),
    base_url=os.environ.get("IRONWARDEN_BASE_URL", "http://localhost:8080"),
    default_headers={
        # Bearer token for IronWarden RBAC & user isolation
        "Authorization": f"Bearer {os.environ.get('IRONWARDEN_JWT', 'demo_token')}",
        # Optional: Pass upstream API key via header if not set in gateway environment
        "X-IronWarden-Upstream-Key": os.environ.get("ANTHROPIC_API_KEY", "sk-ant-your-key")
    }
)

def main():
    print("Dispatching prompt to Anthropic Claude via IronWarden...")
    prompt = "Please verify that the AMKA number 12345678901 and IBAN GR1601101250000000012345678 are valid format formats."

    message = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    print("\n--- Response Received ---")
    for block in message.content:
        if block.type == "text":
            print(block.text)

if __name__ == "__main__":
    main()
