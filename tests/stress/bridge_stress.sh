#!/bin/bash

BRIDGE_URL="http://127.0.0.1:14141"
TARGET_RPS=40
USERNAME="somnerd"
THREAD_ID="thread_bash_stress"
TEST_QUERY="My credit card is 4111-2222-3333-4444 and my email is stress@test.com"

echo "🚀 Starting Bash Stress Test against $BRIDGE_URL..."

# Function to send a single request
send_request() {
    local i=$1
    local start=$(date +%s%N)
    local status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BRIDGE_URL/enqueue" \
        -H "Content-Type: application/json" \
        -d "{\"query\": \"$TEST_QUERY (Req #$i)\", \"thread_id\": \"$THREAD_ID\", \"username\": \"$USERNAME\"}")
    local end=$(date +%s%N)
    local duration=$(( (end - start) / 1000000 ))
    echo "Req #$i: Status $status (${duration}ms)"
}

export -f send_request
export BRIDGE_URL TEST_QUERY THREAD_ID USERNAME

# Run parallel requests using xargs
seq 1 $TARGET_RPS | xargs -P $TARGET_RPS -I {} bash -c "send_request {}" | tee stress_results.log

# Analyze results
echo -e "\n--- Results Analysis ---"
echo "Status 200 (Success): $(grep -c "Status 200" stress_results.log)"
echo "Status 429 (Rate Limited): $(grep -c "Status 429" stress_results.log)"
echo "Status 403 (Forbidden): $(grep -c "Status 403" stress_results.log)"
echo "Status ERROR: $(grep -c "ERROR" stress_results.log)"

if [ $(grep -c "Status 429" stress_results.log) -gt 0 ]; then
    echo "✅ Rate Limiter Successfully Enforced."
else
    echo "❌ Rate Limiter FAILED (No 429s)."
fi
