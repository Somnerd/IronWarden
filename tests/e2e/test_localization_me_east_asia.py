"""
Localization and PII detection rule tests for:
- Middle East / GCC Region (Saudi Arabia PDPL, UAE Federal Law 45/2021, Qatar PDPPL)
- East Asia Region (China PIPL, Japan APPI, South Korea PIPA, Singapore PDPA)
"""
import pytest
import json

# ==============================================================================
# Middle East / GCC Test Cases
# ==============================================================================

def test_localization_me_emirates_id_valid(warden):
    """
    Test UAE Emirates ID (784-YYYY-XXXXXXX-Z).
    """
    eid = "784-1990-1234567-1"
    params = {"username": "tester", "prompt": f"Resident Emirates ID is {eid}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert eid not in result["sanitized_text"]
    assert any("uae_emirates_id" in r["rule_id"] for r in result["redactions"])

def test_localization_me_saudi_national_id_valid(warden):
    """
    Test Saudi National ID (10 digits starting with 1).
    """
    nid = "1087654321"
    params = {"username": "tester", "prompt": f"Citizen National ID reference: {nid}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert nid not in result["sanitized_text"]
    assert any("saudi_national_id" in r["rule_id"] or "id" in r["rule_id"].lower() for r in result["redactions"])

def test_localization_me_saudi_iban_valid(warden):
    """
    Test Saudi Arabia IBAN (SA + 22 chars).
    """
    iban = "SA0380000000608010167519"
    params = {"username": "tester", "prompt": f"Transfer payment to Saudi IBAN: {iban}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert iban not in result["sanitized_text"]
    assert any("saudi_iban" in r["rule_id"] or "iban" in r["rule_id"] for r in result["redactions"])

def test_localization_me_uae_iban_valid(warden):
    """
    Test UAE IBAN (AE + 21 chars).
    """
    iban = "AE070331234567890123456"
    params = {"username": "tester", "prompt": f"Corporate account UAE IBAN: {iban}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert iban not in result["sanitized_text"]
    assert any("uae_iban" in r["rule_id"] or "iban" in r["rule_id"] for r in result["redactions"])

def test_localization_me_gcc_phone_valid(warden):
    """
    Test Saudi/UAE mobile numbers.
    """
    phone = "+966 512345678"
    params = {"username": "tester", "prompt": f"Client direct hotline: {phone}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert "512345678" not in result["sanitized_text"]
    assert any("gcc_phone" in r["rule_id"] or "phone" in r["rule_id"].lower() for r in result["redactions"])


# ==============================================================================
# East Asia (China, Japan, Korea, Singapore) Test Cases
# ==============================================================================

def test_localization_cn_resident_id_valid(warden):
    """
    Test China Resident Identity Card (18 digits).
    """
    cn_id = "110101199003072345"
    params = {"username": "tester", "prompt": f"National identification number: {cn_id}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert cn_id not in result["sanitized_text"]
    assert any("cn_resident_id" in r["rule_id"] for r in result["redactions"])

def test_localization_cn_uscc_valid(warden):
    """
    Test China Unified Social Credit Code (18 alphanumeric chars).
    """
    uscc = "91350100M000100Y43"
    params = {"username": "tester", "prompt": f"Enterprise USCC registration: {uscc}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert uscc not in result["sanitized_text"]
    assert any("cn_uscc" in r["rule_id"] for r in result["redactions"])

def test_localization_cn_mobile_valid(warden):
    """
    Test China Mobile Phone (+86 13812345678).
    """
    mobile = "+86 13812345678"
    params = {"username": "tester", "prompt": f"Emergency contact: {mobile}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert "13812345678" not in result["sanitized_text"]
    assert any("phone" in r["rule_id"].lower() or "mobile" in r["rule_id"].lower() for r in result["redactions"])

def test_localization_jp_my_number_valid(warden):
    """
    Test Japan My Number (12 digits).
    """
    my_number = "123456789012"
    params = {"username": "tester", "prompt": f"Individual My Number reference: {my_number}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert my_number not in result["sanitized_text"]
    assert any("jp_my_number" in r["rule_id"] or "id" in r["rule_id"].lower() for r in result["redactions"])

def test_localization_kr_rrn_valid(warden):
    """
    Test South Korea Resident Registration Number (13 digits: YYMMDD-GXXXXXX).
    """
    rrn = "900101-1234567"
    params = {"username": "tester", "prompt": f"Citizen RRN record: {rrn}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert rrn not in result["sanitized_text"]
    assert any("kr_rrn" in r["rule_id"] for r in result["redactions"])

def test_localization_sg_nric_valid(warden):
    """
    Test Singapore NRIC / FIN (S/T/F/G/M + 7 digits + checksum letter).
    """
    nric = "S1234567A"
    params = {"username": "tester", "prompt": f"Singapore NRIC document: {nric}."}
    response = warden.send_mcp("mcp_sanitize_prompt", params)
    result = response["result"]

    assert nric not in result["sanitized_text"]
    assert any("sg_nric" in r["rule_id"] for r in result["redactions"])
