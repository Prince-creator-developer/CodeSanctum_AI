"""
CodeSanctum AI - Comprehensive Regression Test Battery
Thorough test coverage across all CWE scenarios, custom code payloads, agent pipelines, API routes, and PDF generators.
"""

import pytest
import os
import sys
import httpx
import asyncio

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from app import app
from core.scenarios import get_scenario_list, get_scenario_by_id, SCENARIOS
from core.ast_parser import ast_analyzer
from core.red_team import red_team_agent
from core.blue_team import blue_team_agent
from core.sandbox_runner import sandbox_harness
from core.auditor import auditor_agent
from core.report_generator import report_generator


# ============================================================================
# 1. SCENARIO REPOSITORY & CATALOG INTEGRITY TESTS
# ============================================================================

def test_scenario_catalog_integrity():
    """Verify that all scenarios meet mandatory security metadata schema."""
    scenarios = get_scenario_list()
    assert len(scenarios) == 5
    expected_cwes = {"CWE-89", "CWE-862", "CWE-502", "CWE-22", "CWE-79"}
    found_cwes = {sc["cwe"] for sc in scenarios}
    assert expected_cwes.issubset(found_cwes)

    for sc_meta in scenarios:
        sc = get_scenario_by_id(sc_meta["id"])
        assert sc is not None
        assert sc["severity"] in ["CRITICAL", "HIGH", "MEDIUM"]
        assert sc["cvss_initial"] >= 7.0
        assert sc["cvss_patched"] == 0.0
        assert len(sc["vulnerable_code"]) > 20
        assert len(sc["patched_code"]) > 20
        assert len(sc["regression_suite"]) >= 2


@pytest.mark.parametrize("scenario_id", list(SCENARIOS.keys()))
def test_all_scenarios_ast_analysis(scenario_id):
    """Verify that AST analyzer correctly parses and flags hotspots in every scenario."""
    sc = get_scenario_by_id(scenario_id)
    res = ast_analyzer.analyze(sc["vulnerable_code"])
    assert res["success"] is True
    assert res["metrics"]["total_lines"] > 0
    assert res["metrics"]["nodes_visited"] > 0
    assert len(res["tree_summary"]) > 0


@pytest.mark.parametrize("scenario_id", list(SCENARIOS.keys()))
def test_all_scenarios_red_team_modeling(scenario_id):
    """Verify Red-Team agent generates threat models for all scenarios."""
    sc = get_scenario_by_id(scenario_id)
    analysis = red_team_agent.analyze_vulnerability(sc["vulnerable_code"], scenario_id)
    assert analysis["status"] == "VULNERABILITY_CONFIRMED"
    assert analysis["cwe"] == sc["cwe"]
    assert analysis["cvss_score"] == sc["cvss_initial"]
    assert len(analysis["telemetry"]) >= 3
    assert "T1" in analysis["mitre_attack"]  # MITRE technique code


@pytest.mark.parametrize("scenario_id", list(SCENARIOS.keys()))
def test_all_scenarios_blue_team_patch_diff(scenario_id):
    """Verify Blue-Team agent synthesizes valid patches and diffs for all scenarios."""
    sc = get_scenario_by_id(scenario_id)
    patch = blue_team_agent.synthesize_patch(sc["vulnerable_code"], scenario_id)
    assert patch["status"] == "PATCH_SYNTHESIZED"
    assert patch["lines_added"] > 0
    assert len(patch["formatted_diff"]) > 0
    assert len(patch["unified_diff"]) > 0
    assert patch["patched_code"] == sc["patched_code"]


@pytest.mark.parametrize("scenario_id", list(SCENARIOS.keys()))
def test_all_scenarios_sandbox_verification(scenario_id):
    """Verify Sandbox execution proves exploit neutralization and zero regressions for all scenarios."""
    res = sandbox_harness.execute_verification(scenario_id)
    assert res["success"] is True
    assert res["verdict"] == "EXPLOIT_NEUTRALIZED_ZERO_REGRESSIONS"
    assert res["exploit_neutralized"] is True
    assert res["regressions_passed"] is True
    assert res["failed_tests"] == 0
    assert res["passed_tests"] >= 3
    assert res["duration_ms"] > 0


@pytest.mark.parametrize("scenario_id", list(SCENARIOS.keys()))
def test_all_scenarios_auditor_compliance_seal(scenario_id):
    """Verify Auditor Veritas signs SHA-256 seal and cross-references compliance."""
    sc = get_scenario_by_id(scenario_id)
    red = red_team_agent.analyze_vulnerability(sc["vulnerable_code"], scenario_id)
    blue = blue_team_agent.synthesize_patch(sc["vulnerable_code"], scenario_id)
    sandbox = sandbox_harness.execute_verification(scenario_id)

    audit = auditor_agent.generate_audit_summary(scenario_id, red, blue, sandbox)
    assert audit["status"] == "AUDIT_CERTIFIED"
    assert audit["initial_cvss"] == sc["cvss_initial"]
    assert audit["remediated_cvss"] == 0.0
    assert audit["risk_reduction_percent"] == 100.0
    assert len(audit["verification_hash"]) == 64
    assert len(audit["compliance_standards"]) == 3


# ============================================================================
# 2. CUSTOM USER CODE & EDGE CASE TESTS
# ============================================================================

def test_custom_code_clean_input():
    """Verify clean benign code produces LOW risk status with zero false alarms."""
    clean_code = '''def calculate_total(prices, tax_rate):
    """Pure mathematical calculation function."""
    subtotal = sum(prices)
    return subtotal * (1 + tax_rate)
'''
    red = red_team_agent.analyze_vulnerability(clean_code, None)
    assert red["status"] == "NO_OBVIOUS_FLAWS_DETECTED"
    assert red["cvss_score"] == 0.0
    assert red["severity"] == "LOW"


def test_custom_code_syntax_error_resilience():
    """Verify AST parser gracefully handles malformed Python syntax without crashing."""
    malformed_code = "def broken_code(a, b\n    return a +"
    res = ast_analyzer.analyze(malformed_code)
    assert res["success"] is False
    assert "Syntax error" in res["error"]


def test_custom_code_dangerous_eval():
    """Verify AST parser catches arbitrary code execution sink (eval)."""
    eval_code = '''def execute_user_script(user_input):
    return eval(user_input)
'''
    res = ast_analyzer.analyze(eval_code)
    assert res["success"] is True
    assert any(h["target"] == "eval" for h in res["hotspots"])


def test_custom_sandbox_execution():
    """Verify sandbox runs fallback execution test suite for custom code snippets."""
    res = sandbox_harness.execute_verification(None)
    assert res["success"] is True
    assert res["verdict"] == "EXPLOIT_NEUTRALIZED_ZERO_REGRESSIONS"
    assert res["exploit_neutralized"] is True
    assert len(res["results"]) == 3


# ============================================================================
# 3. PDF REPORT GENERATOR REGRESSION TESTS
# ============================================================================

def test_pure_pdf_generator_compliance():
    """Verify pure-Python PDF generator builds a 100% compliant PDF 1.4 binary."""
    sc = get_scenario_by_id("cwe-89-sqli")
    red = red_team_agent.analyze_vulnerability(sc["vulnerable_code"], "cwe-89-sqli")
    blue = blue_team_agent.synthesize_patch(sc["vulnerable_code"], "cwe-89-sqli")
    sandbox = sandbox_harness.execute_verification("cwe-89-sqli")
    audit = auditor_agent.generate_audit_summary("cwe-89-sqli", red, blue, sandbox)

    pdf_bytes = report_generator._generate_pure_pdf(sc, red, blue, sandbox, audit)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes
    assert b"CODESANCTUM AI" in pdf_bytes


def test_pdf_report_generator_facade():
    """Verify main generate_dossier facade produces non-empty document."""
    sc = get_scenario_by_id("cwe-862-idor")
    red = red_team_agent.analyze_vulnerability(sc["vulnerable_code"], "cwe-862-idor")
    blue = blue_team_agent.synthesize_patch(sc["vulnerable_code"], "cwe-862-idor")
    sandbox = sandbox_harness.execute_verification("cwe-862-idor")
    audit = auditor_agent.generate_audit_summary("cwe-862-idor", red, blue, sandbox)

    pdf_bytes = report_generator.generate_dossier(sc, red, blue, sandbox, audit)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")


# ============================================================================
# 4. REST API ASYNCHRONOUS ENDPOINT INTEGRATION TESTS
# ============================================================================

def test_api_health_endpoint():
    """Verify /api/health returns operational telemetry."""
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://test")
    res = asyncio.run(client.get("/api/health"))
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"
    assert data["team"] == "Valerion Coders"
    assert data["event"] == "HACKVERSE 2026"
    assert data["active_scenarios"] == 5


def test_api_scenarios_listing_and_detail():
    """Verify /api/scenarios and /api/scenarios/{id} routes."""
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://test")
    
    # List
    res = asyncio.run(client.get("/api/scenarios"))
    assert res.status_code == 200
    assert len(res.json()["scenarios"]) == 5

    # Valid Detail
    res_detail = asyncio.run(client.get("/api/scenarios/cwe-89-sqli"))
    assert res_detail.status_code == 200
    assert res_detail.json()["scenario"]["cwe"] == "CWE-89"

    # Invalid Detail 404
    res_invalid = asyncio.run(client.get("/api/scenarios/invalid-cwe-id"))
    assert res_invalid.status_code == 404


def test_api_full_pipeline_roundtrip():
    """Verify full end-to-end API pipeline: analyze -> patch -> sandbox -> audit -> export."""
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://test")

    sc = get_scenario_by_id("cwe-89-sqli")

    # 1. Analyze
    r1 = asyncio.run(client.post("/api/analyze", json={"code": sc["vulnerable_code"], "scenario_id": "cwe-89-sqli"}))
    assert r1.status_code == 200
    red_data = r1.json()["red_team"]

    # 2. Patch
    r2 = asyncio.run(client.post("/api/synthesize-patch", json={"code": sc["vulnerable_code"], "scenario_id": "cwe-89-sqli"}))
    assert r2.status_code == 200
    blue_data = r2.json()["blue_team"]

    # 3. Sandbox
    r3 = asyncio.run(client.post("/api/verify-sandbox", json={"scenario_id": "cwe-89-sqli"}))
    assert r3.status_code == 200
    sandbox_data = r3.json()["sandbox"]

    # 4. Audit
    r4 = asyncio.run(client.post("/api/audit", json={
        "scenario_id": "cwe-89-sqli",
        "red_team": red_data,
        "blue_team": blue_data,
        "sandbox": sandbox_data
    }))
    assert r4.status_code == 200
    audit_data = r4.json()["audit"]

    # 5. Export Dossier
    r5 = asyncio.run(client.post("/api/export-dossier", json={
        "scenario_id": "cwe-89-sqli",
        "red_team": red_data,
        "blue_team": blue_data,
        "sandbox": sandbox_data,
        "auditor": audit_data
    }))
    assert r5.status_code == 200
    assert r5.headers["content-type"] == "application/pdf"
    assert len(r5.content) > 1000
