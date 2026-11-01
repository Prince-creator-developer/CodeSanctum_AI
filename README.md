# CodeSanctum AI — Autonomous Multi-Agent Zero-Day Vulnerability Hunter & Self-Healing DevSecOps Engine

<div align="center">

![CodeSanctum AI Banner](https://img.shields.io/badge/CodeSanctum_AI-Operational_Build_v1.0-06b6d4?style=for-the-badge&logo=shield)
[![Tests Passing](https://img.shields.io/badge/Tests-8%2F8%20Passing%20(100%25)-10b981?style=for-the-badge&logo=pytest)](./test_codesanctum.py)
[![Hackathon](https://img.shields.io/badge/Event-HACKVERSE%202026-6366f1?style=for-the-badge)](https://unstop.com)
[![Team: Valerion Coders](https://img.shields.io/badge/Team-Valerion%20Coders-7c3aed?style=for-the-badge)](#team-valerion-coders)
[![License: MIT](https://img.shields.io/badge/License-MIT-0891b2?style=for-the-badge)](./LICENSE)

**Turn Zero-Day Vulnerability Triage from a Multi-Day Crisis into a 60-Second Autonomous Self-Healing Loop.**  
*Continuous Abstract Syntax Tree (AST) Security Decomposition • Autonomous Red-vs-Blue Multi-Agent Collaboration • Isolated Verification Sandbox • Cryptographic Attestation Seals.*

[🚀 Quickstart Guide](#-quickstart-for-judges-run-in-under-30-seconds) • [🛡️ Multi-Agent Architecture](#%EF%B8%8F-multi-agent-system-architecture) • [🧪 Benchmark Scenarios](#-preloaded-cwe-benchmark-scenarios) • [📄 API Reference](#-rest-api-endpoints)

</div>

---

## 📌 Executive Summary & Hackathon Brief

| Hackathon Parameter | Official Submission Detail |
| :--- | :--- |
| **Event Name** | **HACKVERSE 2026** (Organized by Innovation Hacks via Unstop) |
| **Submission Round** | Project Submission Round (Live Online Evaluation) |
| **Project Title** | **CodeSanctum AI — Autonomous Multi-Agent Zero-Day Vulnerability Hunter & Self-Healing DevSecOps Engine** |
| **Registered Team** | **Valerion Coders** |
| **Solo Participant / Lead** | **Prince Kumar** |
| **Primary Tracks** | **Cybersecurity • AI & Generative AI • Web Development & SaaS** |

---

## 🎯 The Core Problem: The SAST Alert Fatigue & Remediation Bottleneck

Modern software engineering and DevSecOps pipelines face a critical breakdown:
1. **Noisy, Non-Verifiable Alerts:** Legacy Static Application Security Testing (SAST) tools (SonarQube, Snyk, Bandit) flood developers with thousands of noisy warnings without proving whether a vulnerability is practically exploitable in execution context.
2. **Exploitation Uncertainty:** When a zero-day advisory or critical CVE is flagged, security teams must spend hours or days manually constructing Proof-of-Concept (PoC) exploits to reproduce the attack surface.
3. **The Regression Dilemma:** Writing surgical patches without breaking downstream legacy dependencies or introducing subtle syntax/semantic regressions is notoriously error-prone.
4. **Delayed Mean Time to Remediate (MTTR):** The average enterprise takes **over 45 days** to remediate critical vulnerabilities—giving adversaries massive windows of opportunity.

---

## 💡 The Solution: CodeSanctum AI

**CodeSanctum AI** transforms this broken pipeline into a closed-loop, verifiable self-healing engine driven by specialized autonomous agents:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              CODESANCTUM AI AGENTIC WORKFLOW                           │
└────────────────────────────────────────────────────────────────────────────────────────┘

    [ Source Code / Repo ]
              │
              ▼
    ┌───────────────────┐
    │  AST Decomposer   │ ──► Extracts Abstract Syntax Tree, flags insecure execution sinks
    └───────────────────┘
              │
       ┌──────┴──────────────────────────────────┐
       ▼                                         ▼
┌──────────────┐                          ┌──────────────┐
│  RED-TEAM    │                          │  BLUE-TEAM   │
│  Sentinel    │                          │  Patch Aegis │
└──────────────┘                          └──────────────┘
 [ Weaponized PoC ]                         [ Surgical AST ]
 [ Exploit Vector ]                         [ Patch Diff   ]
       │                                         │
       └──────────────────┬──────────────────────┘
                          ▼
              ┌────────────────────────┐
              │   Sandbox Test Bed     │ ◄── Executes dual verification:
              └────────────────────────┘     1. Unpatched target -> EXPLOITED
                          │                  2. Patched target   -> BLOCKED
                          │                  3. Regression suite -> 100% PASSED
                          ▼
              ┌────────────────────────┐
              │    Auditor Veritas     │ ──► Computes CVSS reduction (9.8 -> 0.0)
              └────────────────────────┘     Issues SHA-256 seal & PDF Dossier
```

---

## 🤖 The Multi-Agent Roster

1. **🔴 Red-Team Sentinel (Adversarial Recon & Threat Modeling)**
   - Decomposes the Python code into an Abstract Syntax Tree (AST) using Python's native `ast` compiler.
   - Detects dangerous execution sinks: dynamic string formatting in SQL drivers (`JoinedStr`), insecure deserializers (`pickle.loads`), unvalidated file paths (`open`), and missing access decorators.
   - Synthesizes conceptual Proof-of-Concept (PoC) attack vectors and calculates base CVSS v3.1 severity scores.

2. **🔵 Blue-Team Aegis (Autonomous AST Patch Synthesizer)**
   - Ingests the Red-Team exploit mechanics and AST hotspot coordinates.
   - Synthesizes surgical, minimal code patches adhering to OWASP and NIST SP 800-53 standards (e.g. parameter binding, canonical path normalization, HMAC-SHA256 tokens).
   - Generates line-by-line unified diffs with token metrics (+ additions / - deletions).

3. **⚡ Isolated Sandbox Verification Harness**
   - Runs a two-phase test battery in a memory-isolated execution harness:
     - **Baseline Phase:** Proves that the unpatched target fails boundary containment when hit with the adversarial payload.
     - **Remediation Phase:** Proves that the patched code intercepts and neutralizes the attack vector.
     - **Regression Battery:** Executes 100% of legitimate business logic assertions to guarantee zero broken functionality.

4. **🟢 Auditor Veritas (Compliance & Cryptographic Certification)**
   - Computes the quantitative risk reduction (e.g., CVSS 9.8 Critical $\to$ 0.0 Secure, 100% mitigated).
   - Cross-references compliance matrices: OWASP Top 10 (2021/2025), NIST SP 800-53 Rev. 5, and ISO/IEC 27001.
   - Generates a tamper-evident SHA-256 cryptographic attestation seal binding the target source, patch diff, and timestamp.
   - Compiles a boardroom-ready executive PDF Remediation Dossier via ReportLab.

---

## 🧪 Preloaded CWE Benchmark Scenarios

CodeSanctum AI includes 5 built-in, verifiable vulnerability scenarios ready for 1-click execution:

| Scenario ID | Flaw / CWE Identifier | OWASP Category | Initial CVSS | Post-Patch CVSS |
| :--- | :--- | :--- | :---: | :---: |
| `cwe-89-sqli` | **CWE-89: Direct SQL Injection in Auth Service** | A03:2021-Injection | `9.8` | `0.0` |
| `cwe-862-idor` | **CWE-862: Broken Object-Level Authorization (IDOR)** | A01:2021-Broken Access Control | `8.5` | `0.0` |
| `cwe-502-deserialization` | **CWE-502: Insecure Deserialization in Session RPC** | A08:2021-Software & Data Integrity | `9.8` | `0.0` |
| `cwe-22-path-traversal` | **CWE-22: Arbitrary File Disclosure via Path Traversal** | A01:2021-Broken Access Control | `7.5` | `0.0` |
| `cwe-79-xss` | **CWE-79: Stored Cross-Site Scripting (XSS)** | A03:2021-Injection | `7.2` | `0.0` |
| *Custom Code* | **Interactive User Sandbox (Paste arbitrary Python)** | Custom Evaluated | Dynamic | `0.0` |

---

## 🚀 Quickstart for Judges (Run in Under 30 Seconds)

### 1. Clone & Set Up Environment
```bash
# Clone the official repository
git clone https://github.com/Prince-creator-developer/CodeSanctum_AI.git
cd CodeSanctum_AI

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Automated Pytest Suite
```bash
python -m pytest test_codesanctum.py -v
```
*Expected Output:*
```text
test_codesanctum.py::test_scenario_catalog PASSED                        [ 12%]
test_codesanctum.py::test_ast_analyzer_vulnerability_detection PASSED    [ 25%]
test_codesanctum.py::test_ast_analyzer_syntax_error_handling PASSED      [ 37%]
test_codesanctum.py::test_red_team_adversarial_threat_modeling PASSED    [ 50%]
test_codesanctum.py::test_blue_team_patch_synthesis_and_diff PASSED      [ 62%]
test_codesanctum.py::test_sandbox_verification_harness PASSED            [ 75%]
test_codesanctum.py::test_auditor_compliance_and_cryptographic_seal PASSED [ 87%]
test_codesanctum.py::test_pdf_report_generation PASSED                   [100%]
============================== 8 passed in 0.34s ==============================
```

### 3. Launch the Operational DevSecOps Cockpit
```bash
python app.py
```
Open your browser to: **`http://localhost:8000`**

---

## 📡 REST API Endpoints

| HTTP Method | Route | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves the interactive DevSecOps single-page cockpit dashboard |
| `GET` | `/api/health` | Service health telemetry, active scenarios, and version status |
| `GET` | `/api/scenarios` | Returns catalog of preloaded vulnerability benchmarks |
| `GET` | `/api/scenarios/{id}` | Retrieves detailed scenario specifications, code, and test harness |
| `POST` | `/api/analyze` | Executes AST decomposition and Red-Team threat modeling |
| `POST` | `/api/synthesize-patch` | Triggers Blue-Team agent to generate surgical AST patch and diff |
| `POST` | `/api/verify-sandbox` | Executes isolated dual-phase verification and regression tests |
| `POST` | `/api/audit` | Compiles regulatory compliance scorecard and SHA-256 seal |
| `POST` | `/api/export-dossier` | Generates and streams downloadable ReportLab PDF audit dossier |

---

## 🛠️ Technology Stack

- **Backend Architecture:** Python 3.11, FastAPI (High-performance asynchronous server), Pydantic v2
- **Static Code Analysis:** Python native `ast` (Abstract Syntax Tree) compiler & visitor visitor pattern
- **Test Automation & Verification:** Pytest, Isolated in-memory Sandbox Harness
- **Compliance & Document Engine:** ReportLab 4.0 (Enterprise PDF generation), Hashlib (SHA-256 attestation)
- **Frontend Dashboard:** HTML5, Modern CSS3 with Tailwind CSS CDN, Lucide Icons, Vanilla ES6+ Asynchronous Controller
- **Deployment Ready:** Vercel (`vercel.json`), Docker-compatible standalone ASGI server

---

## 👥 Team: Valerion Coders

- **Prince Kumar** — Lead Architect, Full-Stack DevSecOps & AI Engineer
  - Contact: [GitHub Profile](https://github.com/Prince-creator-developer)
  - Event: **HACKVERSE 2026** by Innovation Hacks (Unstop)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](./LICENSE) file for details.
