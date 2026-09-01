#!/usr/bin/env python3
"""
IronWarden LangChain Integration Example
========================================
Demonstrates how to use IronWarden as a zero-trust privacy proxy
with LangChain ChatOpenAI LLM models.

Requirements:
    pip install langchain langchain-openai
"""

import os
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

def main():
    # Configure LangChain to route all completions through IronWarden
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        openai_api_key=os.environ.get("OPENAI_API_KEY", "sk-placeholder"),
        openai_api_base=os.environ.get("IRONWARDEN_BASE_URL", "http://localhost:8080/v1"),
        default_headers={
            "Authorization": f"Bearer {os.environ.get('IRONWARDEN_JWT', 'demo_token')}"
        }
    )

    messages = [
        SystemMessage(content="You are a legal research assistant."),
        HumanMessage(content="Draft an NDA for client John Doe with AFM 094123456 and email contact@lawfirm.gr.")
    ]

    print("Invoking LangChain pipeline through IronWarden...")
    response = llm.invoke(messages)
    print("\n--- Response Content ---")
    print(response.content)

if __name__ == "__main__":
    main()
