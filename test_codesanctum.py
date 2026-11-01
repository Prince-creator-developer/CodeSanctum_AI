"""
CodeSanctum AI - Automated Test Suite
Verifies core agent pipelines, AST security parser, sandbox harness, and PDF generator.
"""

import pytest
import os
import sys

# Ensure local directories are in python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from core.scenarios import get_scenario_list, get_scenario_by_id, SCENARIOS
from core.ast_parser import ast_analyzer
from core.red_team import red_team_agent
from core.blue_team import blue_team_agent
from core.sandbox_runner import sandbox_harness
from core.auditor import auditor_agent
from core.report_generator import report_generator

def test_scenario_catalog():
    """Verify built-in scenarios are registered with valid CWE/CVSS attributes."""
    scenarios = get_scenario_list()
    assert len(scenarios) >= 5
    for sc in scenarios:
        assert "id" in sc
        assert "name" in sc
        assert "cwe" in sc
        assert sc["cvss_initial"] > 0.0

def test_ast_analyzer_vulnerability_detection():
    """Verify AST parser correctly detects SQL injection f-string pattern."""
    sql_scenario = get_scenario_by_id("cwe-89-sqli")
    res = ast_analyzer.analyze(sql_scenario["vulnerable_code"])
    assert res["success"] is True
    assert res["metrics"]["total_lines"] > 0
    assert len(res["hotspots"]) >= 1

    # Check that a hotspot has execute or JoinedStr flagged
    hotspot_names = [h.get("node_type", "") for h in res["hotspots"]]
    assert any("Call" in name or "JoinedStr" in name for name in hotspot_names)

def test_ast_analyzer_syntax_error_handling():
    """Verify AST parser gracefully handles malformed code."""
    bad_code = "def invalid_syntax(:"
    res = ast_analyzer.analyze(bad_code)
    assert res["success"] is False
    assert "Syntax error" in res["error"]

def test_red_team_adversarial_threat_modeling():
    """Verify Red-Team agent synthesizes exploit model and CVSS metrics."""
    scenario = get_scenario_by_id("cwe-89-sqli")
    analysis = red_team_agent.analyze_vulnerability(scenario["vulnerable_code"], "cwe-89-sqli")
    assert analysis["status"] == "VULNERABILITY_CONFIRMED"
    assert analysis["cwe"] == "CWE-89"
    assert analysis["cvss_score"] == 9.8
    assert "attack_vector" in str(analysis) or "exploit_surface" in analysis

def test_blue_team_patch_synthesis_and_diff():
    """Verify Blue-Team agent synthesizes surgical patch with diff."""
    scenario = get_scenario_by_id("cwe-89-sqli")
    patch = blue_team_agent.synthesize_patch(scenario["vulnerable_code"], "cwe-89-sqli")
    assert patch["status"] == "PATCH_SYNTHESIZED"
    assert patch["lines_added"] > 0
    assert len(patch["formatted_diff"]) > 0
    assert "?" in patch["patched_code"] or "parameterized" in patch["rationale"].lower()

def test_sandbox_verification_harness():
    """Verify sandbox runs unpatched exploit confirmation and patched neutralization."""
    res = sandbox_harness.execute_verification("cwe-89-sqli")
    assert res["success"] is True
    assert res["verdict"] == "EXPLOIT_NEUTRALIZED_ZERO_REGRESSIONS"
    assert res["exploit_neutralized"] is True
    assert res["regressions_passed"] is True
    assert res["total_tests"] >= 3

def test_auditor_compliance_and_cryptographic_seal():
    """Verify Auditor agent computes CVSS drop and signs SHA-256 seal."""
    scenario = get_scenario_by_id("cwe-89-sqli")
    red = red_team_agent.analyze_vulnerability(scenario["vulnerable_code"], "cwe-89-sqli")
    blue = blue_team_agent.synthesize_patch(scenario["vulnerable_code"], "cwe-89-sqli")
    sandbox = sandbox_harness.execute_verification("cwe-89-sqli")

    audit = auditor_agent.generate_audit_summary("cwe-89-sqli", red, blue, sandbox)
    assert audit["status"] == "AUDIT_CERTIFIED"
    assert audit["initial_cvss"] == 9.8
    assert audit["remediated_cvss"] == 0.0
    assert len(audit["verification_hash"]) == 64  # SHA-256 standard hex length
    assert len(audit["compliance_standards"]) >= 3

def test_pdf_report_generation():
    """Verify PDF generator produces non-empty binary document."""
    scenario = get_scenario_by_id("cwe-89-sqli")
    red = red_team_agent.analyze_vulnerability(scenario["vulnerable_code"], "cwe-89-sqli")
    blue = blue_team_agent.synthesize_patch(scenario["vulnerable_code"], "cwe-89-sqli")
    sandbox = sandbox_harness.execute_verification("cwe-89-sqli")
    audit = auditor_agent.generate_audit_summary("cwe-89-sqli", red, blue, sandbox)

    pdf_bytes = report_generator.generate_dossier(
        scenario_data=scenario,
        red_team_data=red,
        blue_team_data=blue,
        sandbox_data=sandbox,
        auditor_data=audit
    )

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")
