"""
CodeSanctum AI - Autonomous Multi-Agent Zero-Day Vulnerability Hunter & Self-Healing DevSecOps Engine
Main Web Application & Unified API Server
Author: Valerion Coders (Prince Kumar) | Event: HACKVERSE 2026
"""

import os
import sys
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

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

app = FastAPI(
    title="CodeSanctum AI - Autonomous DevSecOps Engine",
    description="Autonomous Multi-Agent Zero-Day Vulnerability Hunter & Self-Healing DevSecOps Engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static and templates
static_dir = os.path.join(CURRENT_DIR, "static")
templates_dir = os.path.join(CURRENT_DIR, "templates")

os.makedirs(static_dir, exist_ok=True)
os.makedirs(templates_dir, exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)

# Models
class CodeAnalyzeRequest(BaseModel):
    code: str
    scenario_id: Optional[str] = None

class PatchRequest(BaseModel):
    code: str
    scenario_id: Optional[str] = None

class SandboxRequest(BaseModel):
    scenario_id: Optional[str] = None

class AuditRequest(BaseModel):
    scenario_id: Optional[str] = None
    red_team: Dict[str, Any]
    blue_team: Dict[str, Any]
    sandbox: Dict[str, Any]

class ExportDossierRequest(BaseModel):
    scenario_id: Optional[str] = None
    red_team: Dict[str, Any]
    blue_team: Dict[str, Any]
    sandbox: Dict[str, Any]
    auditor: Dict[str, Any]

# Routes
@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    """Serve the main DevSecOps interactive cockpit."""
    scenarios = get_scenario_list()
    default_scenario = get_scenario_by_id("cwe-89-sqli")
    return templates.TemplateResponse("index.html", {
        "request": request,
        "scenarios": scenarios,
        "default_scenario": default_scenario
    })

@app.get("/api/health")
async def health_check():
    """System health check endpoint."""
    return {
        "status": "online",
        "system": "CodeSanctum AI Engine",
        "version": "1.0.0",
        "team": "Valerion Coders",
        "lead": "Prince Kumar",
        "event": "HACKVERSE 2026",
        "active_scenarios": len(SCENARIOS)
    }

@app.get("/api/scenarios")
async def list_scenarios():
    """Retrieve all preloaded vulnerability scenarios."""
    return {"status": "ok", "scenarios": get_scenario_list()}

@app.get("/api/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str):
    """Retrieve full details of a specific scenario."""
    sc = get_scenario_by_id(scenario_id)
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return {"status": "ok", "scenario": sc}

@app.post("/api/analyze")
async def analyze_code(payload: CodeAnalyzeRequest):
    """Run AST parser and Red-Team threat modeling agent."""
    ast_result = ast_analyzer.analyze(payload.code)
    red_team_result = red_team_agent.analyze_vulnerability(payload.code, payload.scenario_id)
    return {
        "status": "ok",
        "ast": ast_result,
        "red_team": red_team_result
    }

@app.post("/api/synthesize-patch")
async def synthesize_patch(payload: PatchRequest):
    """Run Blue-Team surgical patch synthesizer and diff generator."""
    blue_result = blue_team_agent.synthesize_patch(payload.code, payload.scenario_id)
    return {"status": "ok", "blue_team": blue_result}

@app.post("/api/verify-sandbox")
async def verify_sandbox(payload: SandboxRequest):
    """Run the isolated test harness to prove exploit neutralization and zero regressions."""
    sandbox_result = sandbox_harness.execute_verification(payload.scenario_id)
    return {"status": "ok", "sandbox": sandbox_result}

@app.post("/api/audit")
async def audit_remediation(payload: AuditRequest):
    """Run Auditor Veritas agent to compile compliance proof and cryptographic signature."""
    audit_result = auditor_agent.generate_audit_summary(
        payload.scenario_id,
        payload.red_team,
        payload.blue_team,
        payload.sandbox
    )
    return {"status": "ok", "audit": audit_result}

@app.post("/api/export-dossier")
async def export_dossier(payload: ExportDossierRequest):
    """Generate and download executive PDF audit dossier."""
    sc = get_scenario_by_id(payload.scenario_id) if payload.scenario_id else {}
    pdf_bytes = report_generator.generate_dossier(
        scenario_data=sc,
        red_team_data=payload.red_team,
        blue_team_data=payload.blue_team,
        sandbox_data=payload.sandbox,
        auditor_data=payload.auditor
    )
    
    filename = f"CodeSanctum_Dossier_{payload.scenario_id or 'Custom'}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
