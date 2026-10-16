"""
Edge case and error handling tests for IronWarden's redaction engine and MCP server.
Checks handling of overlapping rules (avoiding double tokenization), nested PII redaction
(e.g., project names in email addresses), and unknown JSON-RPC method errors.
"""
import pytest
import json

def test_integrity_overlapping_rules(warden):
    """
    Verify behavior when multiple rules match the same text.
    Example: 'Alice' matches both Dictionary rule 'client_names' and a generic Name Regex.
    """
    # 'Alice' is in rules.yaml as 'client_names' (Dictionary)
    # Let's assume there's a heuristic for Capitalized Words too.
    
    params = {"username": "tester", "prompt": "Hello Alice."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    # It should only be redacted ONCE (one token).
    assert len(result["redactions"]) == 1
    assert "Alice" not in result["sanitized_text"]

def test_integrity_nested_pii(warden):
    """
    Test PII inside PII (e.g., an email address containing a secret project name).
    'project_alpha@corp.com' contains 'Project Alpha'.
    """
    # In rules.yaml:
    # 'internal_projects' pattern: "Project Alpha"
    # 'email_address' pattern: regex for email
    
    params = {"username": "tester", "prompt": "Contact project_alpha@corp.com"}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    # Ideally, the longest match (email) should take precedence, 
    # OR they both get redacted if they don't perfectly overlap.
    # Current engine logic sorts by length/start.
    assert len(result["redactions"]) >= 1
    assert "project_alpha" not in result["sanitized_text"]
    assert "corp.com" not in result["sanitized_text"]

def test_mcp_error_invalid_method(warden):
    """
    Ensure the gateway returns a proper JSON-RPC error for unknown methods.
    """
    response = warden.send_mcp("unknown_method", {})
    assert "error" in response
    assert response["error"]["code"] == -32601 # Method not found
