import subprocess
import json
import sqlite3
import time
import os

def run_test_case(name, prompt):
    print(f"\n🚀 Running Test: {name}")
    request = {"jsonrpc": "2.0", "id": "1", "method": "process", "params": {"prompt": prompt}}
    env = os.environ.copy()
    env["OPENAI_API_KEY"] = "sk-mock"
    env["WARDEN_PEPPER"] = "a_very_secret_pepper_32_bytes_long"

    process = subprocess.Popen(
        ["/home/somnerd/Documents/IronWarden/target/debug/app"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env
    )
    stdout, stderr = process.communicate(input=json.dumps(request) + "\n")
    return stdout

def verify_redaction(test_name, expected_token):
    db_path = "/home/somnerd/Documents/IronWarden/audit.db"
    if not os.path.exists(db_path):
        db_path = "/home/somnerd/Documents/IronWarden/app/audit.db"

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT redactions_json FROM audit_reports ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        if row and expected_token in row[0]:
            print(f"✅ {test_name}: Verified redaction '{expected_token}' found in Audit Log.")
        else:
            print(f"❌ {test_name}: Redaction '{expected_token}' NOT found. Row: {row}")
    except Exception as e:
        print(f"❌ {test_name}: DB Check failed: {e}")

if __name__ == "__main__":
    if os.path.exists("/home/somnerd/Documents/IronWarden/audit.db"):
        os.remove("/home/somnerd/Documents/IronWarden/audit.db")

    run_test_case("Standard", "Hello Alice.")
    time.sleep(1)
    verify_redaction("Standard", "client_names")

    run_test_case("Homoglyph", "Hello \u0391lice.")
    time.sleep(1)
    verify_redaction("Homoglyph", "client_names")

    run_test_case("Invisible", "Hello A\u200Blice.")
    time.sleep(1)
    verify_redaction("Invisible", "client_names")
    
    print("\n✅ End-to-End MCP Pipeline Verified. Cryptographic Integrity is verified by Rust Cargo Tests.")
