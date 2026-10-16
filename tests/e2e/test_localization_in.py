"""
Localization and PII detection rule tests for the Indian (IN) region (DPDP Act 2023).
Verifies detection and sanitization of:
- PAN (Permanent Account Number)
- Aadhaar Number
- GSTIN (Goods & Services Tax ID)
- Indian Voter ID (EPIC)
- Indian Mobile Numbers
- Indian Passports
"""
import pytest
import json

def test_localization_in_pan_valid(warden):
    """
    Test Indian PAN Card format: 5 letters, 4 digits, 1 letter.
    """
    pan = "ABCDE1234F"
    params = {"username": "tester", "prompt": f"Employee PAN card is {pan} for tax purposes."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert pan not in result["sanitized_text"]
    assert any("in_pan" in r["rule_id"] for r in result["redactions"])

def test_localization_in_aadhaar_valid(warden):
    """
    Test Indian Aadhaar format: 12 digits (with spaces or continuous).
    """
    aadhaar_spaced = "2345 6789 0123"
    params = {"username": "tester", "prompt": f"UIDAI Aadhaar reference: {aadhaar_spaced}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert aadhaar_spaced not in result["sanitized_text"]
    assert any("in_aadhaar" in r["rule_id"] for r in result["redactions"])

def test_localization_in_gstin_valid(warden):
    """
    Test Indian GSTIN: 15 alphanumeric characters.
    """
    gstin = "27ABCDE1234F1Z5"
    params = {"username": "tester", "prompt": f"Invoice issued under GSTIN: {gstin}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert gstin not in result["sanitized_text"]
    assert any("in_gstin" in r["rule_id"] for r in result["redactions"])

def test_localization_in_voter_id_valid(warden):
    """
    Test Indian Voter ID (EPIC): 3 letters, 7 digits.
    """
    voter_id = "ABC1234567"
    params = {"username": "tester", "prompt": f"Voter identity number: {voter_id}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert voter_id not in result["sanitized_text"]
    assert any("in_voter_id" in r["rule_id"] for r in result["redactions"])

def test_localization_in_phone_valid(warden):
    """
    Test Indian phone numbers (+91 9876543210).
    """
    phone = "+91 9876543210"
    params = {"username": "tester", "prompt": f"Contact mobile: {phone}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert "9876543210" not in result["sanitized_text"]
    assert any("in_phone" in r["rule_id"] or "phone" in r["rule_id"] for r in result["redactions"])

def test_localization_in_passport_valid(warden):
    """
    Test Indian Passport: 1 letter, 7 digits.
    """
    passport = "K1234567"
    params = {"username": "tester", "prompt": f"Travel document passport: {passport}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert passport not in result["sanitized_text"]
    assert any("in_passport" in r["rule_id"] or "passport" in r["rule_id"] for r in result["redactions"])
