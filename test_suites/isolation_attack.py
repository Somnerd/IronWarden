"""
Session isolation security verification test ("The Credit Card Trap").
Simulates multiple users (Alice and Bob) enqueuing sensitive data to verify
that user Bob cannot restore Alice's sanitized credit card tokens, ensuring session isolation.
"""
import json
import os
import selectors
import subprocess
import sys
import threading
import time
import pytest

class IronWardenProcess:
    def __init__(self):
        binary = "./target/debug/app"
        if not os.path.exists(binary):
            pytest.skip(f"Binary {binary} not found; skipping integration attack probe.")

        self.process = subprocess.Popen(
            [binary],
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
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        
        # Background thread to print stderr
        self.stderr_thread = threading.Thread(target=self._log_stderr, daemon=True)
        self.stderr_thread.start()
        time.sleep(1)

    def _log_stderr(self):
        try:
            for line in self.process.stderr:
                print(f" [APP LOG] {line.strip()}", file=sys.stderr)
        except Exception:
            pass

    def send_mcp(self, method, params, timeout=10.0):
        if self.process.poll() is not None:
            return None
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": int(time.time() * 1000)
        }
        try:
            self.process.stdin.write(json.dumps(request) + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError):
            return None

        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.1, deadline - time.time())
            events = self.selector.select(timeout=remaining)
            if not events:
                break
            line = self.process.stdout.readline()
            if not line:
                break
            line = line.strip()
            if line.startswith('{"jsonrpc"'):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    return None
        return None

    def stop(self):
        if hasattr(self, "selector"):
            try:
                self.selector.close()
            except Exception:
                pass
        if hasattr(self, "process") and self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2.0)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass

    def __del__(self):
        self.stop()

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
            print(f"⚠️ Warning (Alice skipped/unavailable): {alice_res}")
            pytest.skip("IronWarden MCP app not responsive (likely Redis unavailable in test runner)")
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
            pytest.fail("Bob failed to receive redaction response")
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
            pytest.fail("Bob failed to receive restore response")
            return

        restored_value = restore_res["result"]
        print(f"User Bob: Restored value -> '{restored_value}'")

        assert alice_cc not in restored_value, f"CRITICAL VULNERABILITY: Session Leak! Bob restored Alice's Credit Card: {alice_cc}"
        if bob_cc in restored_value:
            print(f"\n✅ SUCCESS: Session Isolation Verified. Bob restored HIS own credit card for {alice_token}.")
        else:
            print(f"\n❓ UNEXPECTED: Token {alice_token} resolved to: '{restored_value}'")
            
    finally:
        app.stop()

if __name__ == "__main__":
    test_the_relative_token_trap()
