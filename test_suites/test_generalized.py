"""
Generalized integration tests verifying core operational and integrity capabilities of IronWarden.
Tests gateway configuration hot-reloading on rule changes, JSON structure preservation during
PII redaction, and clean process shutdown behavior on SIGINT signals.
"""
import pytest
import time
import os
import json
import shutil

def test_operational_hot_reload(warden_bin):
    """
    Verify that the gateway detects configuration changes and updates its rules at runtime.
    """
    from conftest import IronWardenRunner
    
    # 1. Setup a dedicated temporary config directory
    tmp_config_dir = "test_hotload_config"
    if os.path.exists(tmp_config_dir):
        shutil.rmtree(tmp_config_dir)
    os.makedirs(tmp_config_dir)
    
    # Create an initial rule file
    initial_rule = {
        "rules": [
            {"id": "initial_secret", "pattern": "SECRET_A", "type": "Dictionary"}
        ]
    }
    rule_file_path = os.path.join(tmp_config_dir, "rules.yaml")
    with open(rule_file_path, "w") as f:
        import yaml
        yaml.dump(initial_rule, f)
        
    runner = IronWardenRunner(warden_bin, env_overrides={"WARDEN_CONFIG_PATH": tmp_config_dir})
    try:
        runner.start()
        
        # 2. Verify initial rule works
        params = {"username": "t", "prompt": "My secret is SECRET_A"}
        resp1 = runner.send_mcp("mcp_sanitize_prompt", params)
        assert len(resp1["result"]["redactions"]) > 0 and "SECRET_A" not in resp1["result"]["sanitized_text"]
        
        # 3. Verify a NEW secret is NOT caught yet
        params_new = {"username": "t", "prompt": "My secret is NEW_SECRET_B"}
        resp2 = runner.send_mcp("mcp_sanitize_prompt", params_new)
        assert "NEW_SECRET_B" in resp2["result"]["sanitized_text"]
        
        # 4. Update the config file with the new secret
        updated_rule = {
            "rules": [
                {"id": "initial_secret", "pattern": "SECRET_A", "type": "Dictionary"},
                {"id": "new_secret", "pattern": "NEW_SECRET_B", "type": "Dictionary"}
            ]
        }
        with open(rule_file_path, "w") as f:
            yaml.dump(updated_rule, f)
            
        print("DEBUG: Rule file updated. Waiting for hot-reload polling (5s interval)...")
        # Polling is 5s, so we wait 10s to be sure.
        time.sleep(10)
        
        # 5. Verify the NEW secret is now caught
        resp3 = runner.send_mcp("mcp_sanitize_prompt", params_new)
        assert "NEW_SECRET_B" not in resp3["result"]["sanitized_text"]
        assert len(resp3["result"]["redactions"]) > 0
        
    finally:
        runner.stop()
        if os.path.exists(tmp_config_dir):
            shutil.rmtree(tmp_config_dir)

def test_integrity_json_preservation(warden):
    """
    Verify that scrubbing PII inside a JSON string doesn't corrupt the JSON structure.
    """
    json_payload = {
        "user": "Alice",
        "email": "alice@example.com",
        "metadata": {"project": "Project Alpha"}
    }
    raw_input = json.dumps(json_payload)
    
    params = {"username": "t", "prompt": raw_input}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    sanitized_json_str = response["result"]["sanitized_text"]
    
    # 1. Check if it's still valid JSON
    try:
        parsed = json.loads(sanitized_json_str)
    except json.JSONDecodeError:
        pytest.fail("Scrubbing corrupted the JSON structure")
        
    # 2. Check if keys are preserved but values are tokenized
    assert "user" in parsed
    assert parsed["user"] in ["[NAME_1]", "[TOKEN_1]"]
    assert parsed["email"] in ["[EMAIL_2]", "[TOKEN_2]"]
    assert parsed["metadata"]["project"] in ["[ASSET_3]", "[PROJECT_3]", "[TOKEN_3]"]

def test_operational_graceful_shutdown(warden_bin):
    """
    Verify that the app shuts down cleanly when receiving SIGINT.
    """
    from conftest import IronWardenRunner
    runner = IronWardenRunner(warden_bin)
    runner.start()
    
    # Send a request to ensure it's alive
    runner.send_mcp("initialize", {})
    
    # Trigger stop (which sends SIGINT)
    runner.stop()
    
    # Check logs for graceful shutdown message
    # In main.rs: "IronWarden shutting down..."
    assert any("IronWarden shutting down" in line for line in runner.stderr_output)
    assert any("Bridge: Graceful shutdown signal received" in line for line in runner.stderr_output)
