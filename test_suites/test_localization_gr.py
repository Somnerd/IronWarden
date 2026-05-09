import pytest
import json

def test_localization_gr_afm_valid(warden):
    """
    Test Greek AFM (Tax Identification Number) - 9 digits.
    """
    afm = "123456789"
    params = {"username": "tester", "prompt": f"My AFM is {afm}"}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    assert afm not in result["sanitized_text"]
    assert "[TOKEN_1]" in result["sanitized_text"]
    assert result["redactions"][0]["rule_id"] == "gr_afm"

def test_localization_gr_amka_valid(warden):
    """
    Test Greek AMKA (Social Security Number) - DDMMYYXXXXX.
    Example: 01018012345 (Born Jan 1, 1980)
    """
    amka = "01018012345"
    params = {"username": "tester", "prompt": f"Patient AMKA: {amka}"}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    assert amka not in result["sanitized_text"]
    assert "[TOKEN_1]" in result["sanitized_text"]
    assert result["redactions"][0]["rule_id"] == "gr_amka"

def test_localization_gr_name_heuristic(warden):
    """
    Test Greek name heuristic. 
    Examples: Παπαδόπουλος, Παπαδοπούλου
    """
    names = ["Παπαδόπουλος", "Παπαδοπούλου", "Γεωργίου"]
    for name in names:
        # Avoid sentence start to trigger heuristic correctly if skip_sentence_start=true
        params = {"username": "tester", "prompt": f"Greetings to {name}"}
        response = warden.send_mcp("mcp_sanitize_prompt", params)
        result = response["result"]
        
        # Heuristics currently return 'potential_misses' if no AI is active, 
        # or redactions if upgraded by AI.
        
        found_in_misses = any(m["text"] == name for m in result["potential_misses"])
        found_in_redactions = any(r["placeholder"].startswith("[TOKEN_") or r["placeholder"].startswith("[AI_REDACTED") for r in result["redactions"])
        
        assert found_in_misses or found_in_redactions, f"Heuristic failed to catch Greek name: {name}"

def test_localization_gr_mixed_greek_latin(warden):
    """
    Test mixed Greek and Latin input.
    """
    prompt = "The user is Γιώργος Παπαδόπουλος with AFM 098765432."
    params = {"username": "tester", "prompt": prompt}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    # AFM should be redacted
    assert "098765432" not in result["sanitized_text"]
    
    # Names should be in potential_misses (Heuristic)
    miss_texts = [m["text"] for m in result["potential_misses"]]
    assert "Γιώργος" in miss_texts or "Παπαδόπουλος" in miss_texts

def test_localization_gr_amka_boundary(warden):
    """
    Ensure AMKA regex doesn't catch invalid dates (e.g. month 13).
    """
    invalid_amka = "32138012345" # Day 32, Month 13
    params = {"username": "tester", "prompt": f"Not an AMKA: {invalid_amka}"}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    # Should NOT be caught by gr_amka
    assert invalid_amka in result["sanitized_text"]
    assert not any(r["rule_id"] == "gr_amka" for r in result["redactions"])
