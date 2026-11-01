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
    version="1.0.0",
    redirect_slashes=False
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static and Templates Directories
static_dir = os.path.join(CURRENT_DIR, "static")
templates_dir = os.path.join(CURRENT_DIR, "templates")

# Try to mount static files if directory exists
if os.path.exists(static_dir):
    try:
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    except Exception as e:
        print(f"Static mounting notice: {e}")

# Templates setup
try:
    templates = Jinja2Templates(directory=templates_dir)
except Exception as e:
    templates = None
    print(f"Templates initialization notice: {e}")

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

# Static asset endpoints
@app.get("/static/css/style.css")
@app.get("/css/style.css")
async def get_css():
    css_file = os.path.join(static_dir, "css", "style.css")
    if os.path.exists(css_file):
        with open(css_file, "r", encoding="utf-8") as f:
            return Response(content=f.read(), media_type="text/css")
    return Response(content="/* CSS fallback */", media_type="text/css")

@app.get("/static/js/app.js")
@app.get("/js/app.js")
async def get_js():
    js_file = os.path.join(static_dir, "js", "app.js")
    if os.path.exists(js_file):
        with open(js_file, "r", encoding="utf-8") as f:
            return Response(content=f.read(), media_type="application/javascript")
    return Response(content="/* JS fallback */", media_type="application/javascript")

# Web Frontend Routes (handles all Vercel root and proxy variants)
@app.get("/", response_class=HTMLResponse)
@app.get("/api", response_class=HTMLResponse)
@app.get("/api/", response_class=HTMLResponse)
@app.get("/api/index", response_class=HTMLResponse)
@app.get("/api/index.py", response_class=HTMLResponse)
async def serve_index(request: Request):
    """Serve the main DevSecOps interactive cockpit."""
    scenarios = get_scenario_list()
    default_scenario = get_scenario_by_id("cwe-89-sqli")
    
    if templates:
        try:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "scenarios": scenarios,
                "default_scenario": default_scenario
            })
        except Exception:
            pass

    # Direct HTML fallback if template rendering encounters serverless path issues
    html_path = os.path.join(templates_dir, "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
            pills_html = ""
            for sc in scenarios:
                active_class = "bg-cyan-950/70 text-cyan-300 border-cyan-700/80 shadow-sm shadow-cyan-900/50" if sc["id"] == "cwe-89-sqli" else "bg-slate-900/60 text-slate-400 border-slate-800 hover:border-slate-700 hover:text-slate-200"
                pills_html += f'<button onclick="selectScenario(\'{sc["id"]}\')" data-scenario-id="{sc["id"]}" class="scenario-pill px-3 py-1 rounded-md text-xs font-mono transition-all border {active_class}">{sc["cwe"]}</button>\n'
            
            if "{% for sc in scenarios %}" in content:
                loop_start = content.find("{% for sc in scenarios %}")
                loop_end = content.find("{% endfor %}") + len("{% endfor %}")
                content = content[:loop_start] + pills_html + content[loop_end:]
            content = content.replace("{{ default_scenario.vulnerable_code }}", default_scenario["vulnerable_code"])
            return HTMLResponse(content=content)

    return HTMLResponse("<h1>CodeSanctum AI is Online</h1><p>Visit /api/health</p>")

@app.get("/api/health")
@app.get("/health")
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
@app.get("/scenarios")
async def list_scenarios():
    """Retrieve all preloaded vulnerability scenarios."""
    return {"status": "ok", "scenarios": get_scenario_list()}

@app.get("/api/scenarios/{scenario_id}")
@app.get("/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str):
    """Retrieve full details of a specific scenario."""
    sc = get_scenario_by_id(scenario_id)
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return {"status": "ok", "scenario": sc}

@app.post("/api/analyze")
@app.post("/analyze")
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
@app.post("/synthesize-patch")
async def synthesize_patch(payload: PatchRequest):
    """Run Blue-Team surgical patch synthesizer and diff generator."""
    blue_result = blue_team_agent.synthesize_patch(payload.code, payload.scenario_id)
    return {"status": "ok", "blue_team": blue_result}

@app.post("/api/verify-sandbox")
@app.post("/verify-sandbox")
async def verify_sandbox(payload: SandboxRequest):
    """Run the isolated test harness to prove exploit neutralization and zero regressions."""
    sandbox_result = sandbox_harness.execute_verification(payload.scenario_id)
    return {"status": "ok", "sandbox": sandbox_result}

@app.post("/api/audit")
@app.post("/audit")
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
@app.post("/export-dossier")
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
