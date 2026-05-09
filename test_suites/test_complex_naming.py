import pytest
import json

@pytest.mark.parametrize("name_type, full_name", [
    ("Western", "Edward Kenway"),
    ("Western_Middle", "Donald John Trump"),
    ("Latin_Spanish", "Ezio Auditore da Firenze"),
    ("Arabic", "Altair Ibn La'Ahad"),
    ("Greek_Long", "Antonis Stefanos Hios"),
    ("Compound", "Mary-Jane Watson-Parker")
])
def test_mcp_complex_name_redaction(warden, name_type, full_name):
    """
    Test how the engine handles multi-word names from different cultures.
    We need to see if it treats them as a single token or multiple tokens, 
    and if any parts are left un-redacted.
    """
    # Note: For these to be caught by the engine, they must either be in the dictionary
    # or caught by heuristics. Since they aren't in rules.yaml, they will trigger
    # the 'Shadow NER' heuristics.
    
    params = {
        "username": "tester",
        "prompt": f"The subject is {full_name}."
    }
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    # 1. Ensure the raw name is gone
    assert full_name not in result["sanitized_text"]
    
    # 2. Check if parts are leaked
    # Split by spaces and common separators
    name_parts = full_name.replace("-", " ").replace("'", " ").split()
    for part in name_parts:
        # Ignore very short common words like 'da' or 'de' or 'Ibn' if they are less than 3 chars
        if len(part) > 2:
            assert part not in result["sanitized_text"], f"Leak detected for {name_type} name part: {part}"

    # 3. Log how it was handled (Token vs Potential Miss)
    redaction_count = len(result["redactions"])
    miss_count = len(result["potential_misses"])
    print(f"DEBUG: {name_type} '{full_name}' -> Redactions: {redaction_count}, Misses: {miss_count}")

def test_mcp_multi_token_restoration(warden):
    """
    Verify that a long name (Ezio Auditore da Firenze) can be fully restored 
    even if it was split into multiple tokens.
    """
    full_name = "Ezio Auditore da Firenze"
    params = {"username": "ezio_fan", "prompt": f"User: {full_name}"}
    
    sanitize_resp = warden.send_mcp("mcp_sanitize_prompt", params)
    sanitized_text = sanitize_resp["result"]["sanitized_text"]
    
    # Send the sanitized text back for restoration
    restore_resp = warden.send_mcp("mcp_restore_prompt", {
        "username": "ezio_fan",
        "response": f"Confirmed identity for {sanitized_text}"
    })
    
    assert full_name in restore_resp["result"]
    # Check that no [TOKEN_X] remains
    assert "[TOKEN_" not in restore_resp["result"]

def test_mcp_name_fragment_collision(warden):
    """
    Test edge case: Two people sharing a common part of a long name.
    'Edward Kenway' and 'Edward Teach'.
    """
    warden.send_mcp("mcp_sanitize_prompt", {"username": "u1", "prompt": "Edward Kenway"})
    warden.send_mcp("mcp_sanitize_prompt", {"username": "u1", "prompt": "Edward Teach"})
    
    # Ensure they have distinct mappings
    resp = warden.send_mcp("mcp_restore_prompt", {
        "username": "u1",
        "response": "Hello [TOKEN_1] and [TOKEN_2]"
    })
    
    assert "Edward Kenway" in resp["result"]
    assert "Edward Teach" in resp["result"]
