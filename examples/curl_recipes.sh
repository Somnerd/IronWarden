#!/usr/bin/env bash
# ==============================================================================
# IronWarden cURL API Recipes
# ==============================================================================
# Demonstrates direct HTTP interactions with IronWarden's Universal Gateway.
# ==============================================================================

set -e

IRONWARDEN_URL="${IRONWARDEN_URL:-http://localhost:8080}"
JWT_TOKEN="${JWT_TOKEN:-demo_token}"

echo "=== 1. Health Check ==="
curl -s -X GET "${IRONWARDEN_URL}/health"
echo -e "\n"

echo "=== 2. OpenAI-Compatible Chat Completion (Non-Streaming) ==="
curl -s -X POST "${IRONWARDEN_URL}/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {"role": "user", "content": "Hello! My name is Alice Smith and my email is alice@company.org. Please confirm receipt."}
    ]
  }' | jq . || true
echo -e "\n"

echo "=== 3. OpenAI-Compatible Chat Completion (SSE Streaming) ==="
curl -N -X POST "${IRONWARDEN_URL}/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "model": "gpt-4o-mini",
    "stream": true,
    "messages": [
      {"role": "user", "content": "Write a 2-sentence greeting to patient Bob Jones with AMKA 98765432109."}
    ]
  }'
echo -e "\n"

echo "=== 4. Anthropic Claude Message Endpoint ==="
curl -s -X POST "${IRONWARDEN_URL}/v1/messages" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 512,
    "messages": [
      {"role": "user", "content": "Check validity of IBAN GR1601101250000000012345678."}
    ]
  }' | jq . || true
echo -e "\n"
