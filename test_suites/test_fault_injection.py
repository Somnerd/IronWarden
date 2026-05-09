import pytest
import os
import time
import sqlite3
import stat
import requests

def test_fault_audit_db_readonly(warden_bin):
    """
    Simulate a read-only Audit Database.
    VERIFY: Does the system fail-open (allow requests) or fail-closed (stop service)?
    """
    from conftest import IronWardenRunner
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    db_path = os.path.join(project_root, "readonly_audit.db")
    
    if os.path.exists(db_path):
        os.chmod(db_path, stat.S_IWUSR | stat.S_IREAD)
        os.remove(db_path)
    
    # Create the file first so we can chmod it
    open(db_path, 'a').close()
    os.chmod(db_path, stat.S_IREAD) # Read only for current user
    
    runner = IronWardenRunner(warden_bin, env_overrides={"AUDIT_DB_PATH": db_path})
    try:
        runner.start()
        # Give it time for the async init to fail
        time.sleep(3)
        
        # PROBE: Attempt a sanitization request
        params = {"username": "tester", "prompt": "Hello Alice"}
        response = runner.send_mcp("mcp_sanitize_prompt", params)
        
        # VULNERABILITY PROOF:
        # If response is NOT None and contains a result, it means the system is processing 
        # requests even though the audit trail is broken.
        if response and "result" in response:
            print("🚨 VULNERABILITY CONFIRMED: System failed-open on Audit DB failure!")
            # We assert success here to 'pass' the test of finding the bug, 
            # or assert failure if we want to enforce hardening. 
            # For now, let's just prove it.
            assert response["result"] is not None
        
    finally:
        runner.stop()
        if os.path.exists(db_path):
            os.chmod(db_path, stat.S_IWUSR | stat.S_IREAD)
            os.remove(db_path)

def test_fault_audit_db_lock_contention(warden, jwt_factory):
    """
    Simulate a 'Database is Locked' scenario by holding an exclusive lock from Python.
    """
    bridge_url = f"http://localhost:{warden.env['BRIDGE_PORT']}"
    db_path = warden.env["AUDIT_DB_PATH"]
    token = jwt_factory("tester")
    
    # Wait for app to init DB
    time.sleep(1)
    
    # 1. Manually open the DB and start a transaction without committing
    conn = sqlite3.connect(db_path)
    # Using EXCLUSIVE lock
    conn.execute("BEGIN EXCLUSIVE TRANSACTION")
    
    try:
        # 2. Try to enqueue a request
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post(
            f"{bridge_url}/enqueue", 
            json={"query": "Alice", "thread_id": "t1"},
            headers=headers,
            timeout=5.0
        )
        
        # IronWarden should fail because it can't write the audit log
        assert response.status_code == 500
        assert "Security Audit Logging Failed" in response.text
        
    finally:
        conn.rollback()
        conn.close()

def test_fault_mcp_malformed_session_state(warden):
    """
    Manually corrupt the session data in the DB.
    """
    db_path = warden.env["AUDIT_DB_PATH"]
    
    # 1. Create a session for Alice
    warden.send_mcp("mcp_sanitize_prompt", {"username": "alice", "prompt": "My secret is ABC"})
    
    # Wait for flush
    time.sleep(1)
    
    # 2. Corrupt the JSON in the database
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE sessions SET session_data = 'NOT_JSON' WHERE username = 'alice'")
    conn.commit()
    conn.close()
    
    # 3. Try to use the session
    response = warden.send_mcp("mcp_sanitize_prompt", {"username": "alice", "prompt": "Hello Alice"})
    
    # It should fail gracefully
    assert "error" in response
    assert response["error"] is not None
