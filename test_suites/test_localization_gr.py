"""
Localization and PII detection rule tests for the Greek (GR) region.
Verifies detection and sanitization of Greek AFM (Tax ID), Greek AMKA (Social Security Number),
and common Greek names, including boundary checks and mixed Greek-Latin script scenarios.
"""
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
    assert any(t in result["sanitized_text"] for t in ["[AFM_1]", "[TOKEN_1]"])
    assert "gr_afm" in result["redactions"][0]["rule_id"]

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
    assert any(t in result["sanitized_text"] for t in ["[AMKA_1]", "[TOKEN_1]"])
    assert "gr_amka" in result["redactions"][0]["rule_id"]

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
        found_in_redactions = any(r["placeholder"].startswith("[") for r in result["redactions"])
        
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
    
    # Names should be either in potential_misses (Heuristic) or redacted
    miss_texts = [m["text"] for m in result["potential_misses"]]
    found_in_misses = any("Γιώργος" in m or "Παπαδόπουλος" in m for m in miss_texts)
    found_in_redactions = "Γιώργος" not in result["sanitized_text"] and "Παπαδόπουλος" not in result["sanitized_text"]
    assert found_in_misses or found_in_redactions

def test_localization_gr_amka_boundary(warden):
    """
    Ensure AMKA regex doesn't catch invalid dates (e.g. month 13).
    """
    invalid_amka = "32138012345" # Day 32, Month 13
    params = {"username": "tester", "prompt": f"Not an AMKA: {invalid_amka}"}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]
    
    # Should NOT be caught by gr_amka
    assert not any("gr_amka" in r["rule_id"] for r in result["redactions"])
