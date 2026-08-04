"""
Session isolation security verification test ("The Credit Card Trap").
Simulates multiple users (Alice and Bob) enqueuing sensitive data to verify
that user Bob cannot restore Alice's sanitized credit card tokens, ensuring session isolation.
"""
import json
import subprocess
import time
import os
import sys
import threading

class IronWardenProcess:
    def __init__(self):
        self.process = subprocess.Popen(
            ['./target/debug/app'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env={
                **os.environ,
                "WARDEN_MODE": "hybrid",
                "WARDEN_PEPPER": "this-is-a-valid-32-byte-test-pepper-string!",
                "OPENAI_API_KEY": "test_key",
                "REDIS_URL": "redis://:searchboost_pass@localhost:6379"
            }
        )
        # Background thread to print stderr
        self.stderr_thread = threading.Thread(target=self._log_stderr, daemon=True)
        self.stderr_thread.start()
        time.sleep(2)

    def _log_stderr(self):
        for line in self.process.stderr:
            print(f" [APP LOG] {line.strip()}", file=sys.stderr)

    def send_mcp(self, method, params):
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": int(time.time() * 1000)
        }
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        
        while True:
            line = self.process.stdout.readline()
            if not line: return None
            line = line.strip()
            if line.startswith('{"jsonrpc"'):
                return json.loads(line)

    def stop(self):
        self.process.terminate()

def test_the_relative_token_trap():
    print("🚀 Starting Isolation Attack Probe: The Credit Card Trap...")
    app = IronWardenProcess()
    
    try:
        # --- PART 1: ALICE ENQUEUES SECRET ---
        alice_cc = "1111-2222-3333-4444"
        print(f"\n[Step 1] User Alice: Sending Credit Card -> '{alice_cc}'")
        alice_res = app.send_mcp("mcp_sanitize_prompt", {
            "username": "Alice", 
            "prompt": f"My card is {alice_cc}"
        })
        
        if not alice_res or "result" not in alice_res:
            print(f"❌ Error (Alice): {alice_res}")
            return

        alice_token = alice_res["result"]["redactions"][0]["placeholder"]
        print(f"User Alice: Received token -> {alice_token}")

        # --- PART 2: BOB ENQUEUES DIFFERENT SECRET ---
        bob_cc = "5555-6666-7777-8888"
        print(f"\n[Step 2] User Bob: Sending Credit Card -> '{bob_cc}'")
        bob_res = app.send_mcp("mcp_sanitize_prompt", {
            "username": "Bob", 
            "prompt": f"Pay with {bob_cc}"
        })
        
        if not bob_res or "result" not in bob_res:
            print(f"❌ Error (Bob): {bob_res}")
            return
            
        bob_token = bob_res["result"]["redactions"][0]["placeholder"]
        print(f"User Bob: Received token -> {bob_token}")

        # --- PART 3: THE PROBE ---
        print(f"\n[Step 3] User Bob: Attempting to restore token {alice_token}...")
        
        restore_res = app.send_mcp("mcp_restore_prompt", {
            "username": "Bob", 
            "response": f"The card is {alice_token}"
        })
        
        if not restore_res or "result" not in restore_res:
            print(f"❌ Error (Restore): {restore_res}")
            return

        restored_value = restore_res["result"]
        print(f"User Bob: Restored value -> '{restored_value}'")

        if alice_cc in restored_value:
            print(f"\n🚨 CRITICAL VULNERABILITY: Session Leak! Bob restored Alice's Credit Card: {alice_cc}")
            exit(1)
        elif bob_cc in restored_value:
            print(f"\n✅ SUCCESS: Session Isolation Verified. Bob restored HIS own credit card for {alice_token}.")
        else:
            print(f"\n❓ UNEXPECTED: Token {alice_token} resolved to: '{restored_value}'")
            
    finally:
        app.stop()

if __name__ == "__main__":
    test_the_relative_token_trap()
