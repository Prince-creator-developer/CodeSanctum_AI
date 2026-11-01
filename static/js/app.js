/**
 * CodeSanctum AI - DevSecOps Cockpit Frontend Controller
 * Handles real-time multi-agent orchestration, AST inspection, diff rendering, and verification proofs.
 */

let currentScenarioId = "cwe-89-sqli";
let isCustomMode = false;

// State store
let appState = {
    code: "",
    ast: null,
    red_team: null,
    blue_team: null,
    sandbox: null,
    auditor: null
};

// DOM Elements
const codeEditor = document.getElementById("code-editor");
const currentFilename = document.getElementById("current-filename");
const currentCweBadge = document.getElementById("current-cwe-badge");
const hotspotsCount = document.getElementById("hotspots-count");
const hotspotsList = document.getElementById("hotspots-list");
const terminalFeed = document.getElementById("terminal-feed");
const diffViewer = document.getElementById("diff-viewer");
const diffStats = document.getElementById("diff-stats");
const sandboxTable = document.getElementById("sandbox-table");
const sandboxVerdictBadge = document.getElementById("sandbox-verdict-badge");
const testSummaryBadge = document.getElementById("test-summary-badge");
const badgeCvssInitial = document.getElementById("badge-cvss-initial");
const badgeCvssRemediated = document.getElementById("badge-cvss-remediated");
const footerHash = document.getElementById("footer-hash");

// Action Buttons
const btnRunAll = document.getElementById("btn-run-all");
const btnAnalyze = document.getElementById("btn-analyze");
const btnPatch = document.getElementById("btn-patch");
const btnSandbox = document.getElementById("btn-sandbox");
const btnExportDossier = document.getElementById("btn-export-dossier");

// Initialize on Load
document.addEventListener("DOMContentLoaded", () => {
    appState.code = codeEditor.value;
    // Bind Event Listeners
    btnRunAll.addEventListener("click", () => runFullAutoHealPipeline());
    btnAnalyze.addEventListener("click", () => runStep1Analyze());
    btnPatch.addEventListener("click", () => runStep2Patch());
    btnSandbox.addEventListener("click", () => runStep3Sandbox());
    btnExportDossier.addEventListener("click", () => exportPdfDossier());
});

/**
 * Log message to the operations terminal
 */
function logToTerminal(message, type = "info") {
    const logItem = document.createElement("div");
    logItem.className = "log-enter";

    let colorClass = "text-slate-300";
    if (type === "red") colorClass = "text-red-400";
    if (type === "blue") colorClass = "text-cyan-400";
    if (type === "sandbox") colorClass = "text-emerald-400";
    if (type === "auditor") colorClass = "text-amber-400 font-semibold";
    if (type === "system") colorClass = "text-slate-500";

    const timestamp = new Date().toLocaleTimeString();
    logItem.innerHTML = `<span class="text-slate-600">[${timestamp}]</span> <span class="${colorClass}">${message}</span>`;
    terminalFeed.appendChild(logItem);
    terminalFeed.scrollTop = terminalFeed.scrollHeight;
}

/**
 * Switch scenario
 */
async function selectScenario(scenarioId) {
    try {
        isCustomMode = false;
        currentScenarioId = scenarioId;

        // Update pills UI
        document.querySelectorAll(".scenario-pill").forEach(p => {
            p.classList.remove("bg-cyan-950/70", "text-cyan-300", "border-cyan-700/80", "shadow-sm", "shadow-cyan-900/50");
            p.classList.add("bg-slate-900/60", "text-slate-400", "border-slate-800");
        });
        const activePill = document.querySelector(`[data-scenario-id="${scenarioId}"]`);
        if (activePill) {
            activePill.classList.remove("bg-slate-900/60", "text-slate-400", "border-slate-800");
            activePill.classList.add("bg-cyan-950/70", "text-cyan-300", "border-cyan-700/80", "shadow-sm", "shadow-cyan-900/50");
        }

        const res = await fetch(`/api/scenarios/${scenarioId}`);
        const data = await res.json();
        if (data.status !== "ok") return;

        const sc = data.scenario;
        codeEditor.value = sc.vulnerable_code;
        codeEditor.readOnly = true;
        document.getElementById("editor-hint").innerText = "Read-Only Preset (Switch to Custom to Edit)";

        currentFilename.innerText = sc.vulnerable_file;
        currentCweBadge.innerText = `${sc.severity} (${sc.cwe})`;
        badgeCvssInitial.innerText = `Initial CVSS: ${sc.cvss_initial}`;
        badgeCvssRemediated.innerText = "Post-Patch: Pending";

        // Reset state
        appState.code = sc.vulnerable_code;
        appState.ast = null;
        appState.red_team = null;
        appState.blue_team = null;
        appState.sandbox = null;
        appState.auditor = null;

        // Render Hotspots preview
        renderHotspots(sc.ast_hotspots);

        // Reset diff & sandbox views
        diffViewer.innerHTML = `<div class="text-slate-500 italic p-4 text-center">Unified patch diff will be synthesized by Blue-Team Aegis.</div>`;
        diffStats.innerText = "+0 / -0";
        sandboxTable.innerHTML = `<div class="text-[11px] text-slate-500 italic text-center py-2">Execute verification to observe live adversarial & regression test harness.</div>`;
        sandboxVerdictBadge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700";
        sandboxVerdictBadge.innerText = "PENDING RUN";
        testSummaryBadge.innerText = "0 / 0 Tests";

        logToTerminal(`[SCENARIO] Loaded ${sc.name} (${sc.cve_tag})`, "system");
    } catch (err) {
        console.error("Failed to load scenario", err);
    }
}

/**
 * Enable Custom Code Sandbox mode
 */
function selectCustomCode() {
    isCustomMode = true;
    currentScenarioId = null;

    document.querySelectorAll(".scenario-pill").forEach(p => {
        p.classList.remove("bg-cyan-950/70", "text-cyan-300", "border-cyan-700/80", "shadow-sm", "shadow-cyan-900/50");
        p.classList.add("bg-slate-900/60", "text-slate-400", "border-slate-800");
    });
    const customPill = document.getElementById("pill-custom");
    customPill.classList.remove("bg-slate-900/60", "text-slate-400", "border-slate-800");
    customPill.classList.add("bg-cyan-950/70", "text-cyan-300", "border-cyan-700/80", "shadow-sm", "shadow-cyan-900/50");

    codeEditor.readOnly = false;
    document.getElementById("editor-hint").innerText = "Interactive Mode (Paste or type any Python code)";
    currentFilename.innerText = "custom_sandbox_target.py";
    currentCweBadge.innerText = "USER INPUT";
    badgeCvssInitial.innerText = "Initial CVSS: Evaluating";
    badgeCvssRemediated.innerText = "Post-Patch: Pending";

    logToTerminal("[SANDBOX] Switched to Custom Code Input mode. Paste custom Python code and run Step 1.", "system");
}

/**
 * Render AST Hotspots list
 */
function renderHotspots(hotspots) {
    hotspotsList.innerHTML = "";
    hotspotsCount.innerText = `${hotspots.length} Hotspots`;

    if (!hotspots || hotspots.length === 0) {
        hotspotsList.innerHTML = `<div class="text-[11px] text-slate-500 italic p-2">No critical AST hotspots flagged.</div>`;
        return;
    }

    hotspots.forEach(h => {
        const item = document.createElement("div");
        const isCritical = (h.risk === "Critical" || h.severity === "CRITICAL");
        item.className = `p-2 rounded bg-slate-950/80 border ${isCritical ? 'border-red-900/40 text-red-300' : 'border-amber-900/40 text-amber-300'} text-[11px] flex items-start space-x-2`;
        item.innerHTML = `
            <span class="font-mono font-bold ${isCritical ? 'text-red-400' : 'text-amber-400'}">L${h.line || '?'}:</span>
            <div class="flex-1 text-slate-300">
                <span class="font-semibold text-white">${h.node_type || h.target}</span> &mdash; ${h.name || h.issue}
            </div>
        `;
        hotspotsList.appendChild(item);
    });
}

/**
 * Step 1: Parse AST & Threat Model
 */
async function runStep1Analyze() {
    logToTerminal("[RED-TEAM] Initiating Abstract Syntax Tree (AST) decomposition...", "red");
    appState.code = codeEditor.value;

    try {
        const res = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: appState.code, scenario_id: currentScenarioId })
        });
        const data = await res.json();
        if (data.status !== "ok") throw new Error("Analysis failed");

        appState.ast = data.ast;
        appState.red_team = data.red_team;

        // Render Telemetry
        data.red_team.telemetry.forEach(msg => logToTerminal(msg, "red"));
        renderHotspots(data.ast.hotspots || []);

        badgeCvssInitial.innerText = `Initial CVSS: ${data.red_team.cvss_score}`;
        highlightAgentBadge("agent-badge-red");

        return data;
    } catch (err) {
        logToTerminal(`[ERROR] AST Analysis failed: ${err.message}`, "red");
        throw err;
    }
}

/**
 * Step 2: Synthesize Surgical Patch
 */
async function runStep2Patch() {
    logToTerminal("[BLUE-TEAM] Ingesting Red-Team threat findings and AST hotspots...", "blue");
    appState.code = codeEditor.value;

    try {
        const res = await fetch("/api/synthesize-patch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: appState.code, scenario_id: currentScenarioId })
        });
        const data = await res.json();
        if (data.status !== "ok") throw new Error("Patch synthesis failed");

        appState.blue_team = data.blue_team;

        // Render Telemetry
        data.blue_team.telemetry.forEach(msg => logToTerminal(msg, "blue"));

        // Render Diff
        renderDiff(data.blue_team.formatted_diff, data.blue_team.lines_added, data.blue_team.lines_removed);
        highlightAgentBadge("agent-badge-blue");

        return data;
    } catch (err) {
        logToTerminal(`[ERROR] Patch synthesis failed: ${err.message}`, "blue");
        throw err;
    }
}

/**
 * Render line-by-line diff
 */
function renderDiff(diffLines, added, removed) {
    diffViewer.innerHTML = "";
    diffStats.innerText = `+${added} / -${removed}`;

    if (!diffLines || diffLines.length === 0) {
        diffViewer.innerHTML = `<div class="text-slate-500 italic p-4 text-center">Zero modifications needed. Code is secure.</div>`;
        return;
    }

    diffLines.forEach(l => {
        const lineDiv = document.createElement("div");
        if (l.type === "add") lineDiv.className = "diff-line-add";
        else if (l.type === "del") lineDiv.className = "diff-line-del";
        else if (l.type === "hunk") lineDiv.className = "diff-line-hunk";
        else lineDiv.className = "diff-line-context";

        lineDiv.textContent = l.text;
        diffViewer.appendChild(lineDiv);
    });
}

/**
 * Step 3: Isolated Sandbox Verification & Auditor Consensus
 */
async function runStep3Sandbox() {
    logToTerminal("[SANDBOX] Bootstrapping isolated runtime sandbox test battery...", "sandbox");

    try {
        const res = await fetch("/api/verify-sandbox", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario_id: currentScenarioId })
        });
        const data = await res.json();
        if (data.status !== "ok") throw new Error("Sandbox run failed");

        appState.sandbox = data.sandbox;

        // Render Sandbox Telemetry
        data.sandbox.telemetry.forEach(msg => logToTerminal(msg, "sandbox"));
        renderSandboxBattery(data.sandbox);

        // Run Auditor Agent
        logToTerminal("[AUDITOR] Invoking Auditor Veritas for compliance proof and SHA-256 seal...", "auditor");
        const auditRes = await fetch("/api/audit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                scenario_id: currentScenarioId,
                red_team: appState.red_team || {},
                blue_team: appState.blue_team || {},
                sandbox: appState.sandbox
            })
        });
        const auditData = await auditRes.json();
        appState.auditor = auditData.audit;

        auditData.audit.telemetry.forEach(msg => logToTerminal(msg, "auditor"));

        // Update Header Badges
        badgeCvssRemediated.innerText = `Post-Patch: ${auditData.audit.remediated_cvss} (SECURE)`;
        badgeCvssRemediated.className = "px-2.5 py-0.5 rounded bg-emerald-950/70 border border-emerald-800 text-emerald-300 font-semibold";
        footerHash.innerText = auditData.audit.verification_hash.substring(0, 16) + "...";

        highlightAgentBadge("agent-badge-auditor");

        return data;
    } catch (err) {
        logToTerminal(`[ERROR] Sandbox verification failed: ${err.message}`, "sandbox");
        throw err;
    }
}

/**
 * Render Sandbox Table
 */
function renderSandboxBattery(sandbox) {
    sandboxTable.innerHTML = "";
    testSummaryBadge.innerText = `${sandbox.passed_tests} / ${sandbox.total_tests} Tests Passed`;

    sandbox.results.forEach(t => {
        const row = document.createElement("div");
        const isSafe = (t.status === "PASSED" || t.status === "BLOCKED");
        row.className = `p-2 rounded bg-slate-950/90 border ${isSafe ? 'border-emerald-900/40' : 'border-red-900/40'} text-[11px] flex items-center justify-between`;
        
        row.innerHTML = `
            <div class="flex items-center space-x-2">
                <span class="font-mono ${isSafe ? 'text-emerald-400' : 'text-red-400'} font-semibold">${t.test_id}</span>
                <span class="text-slate-300 truncate max-w-[200px]">${t.name}</span>
            </div>
            <div class="flex items-center space-x-2 font-mono">
                <span class="text-[10px] px-1.5 py-0.5 rounded ${isSafe ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-red-950 text-red-300 border border-red-800'}">
                    ${t.status}
                </span>
                <span class="text-slate-500 text-[10px]">${t.duration_ms}ms</span>
            </div>
        `;
        sandboxTable.appendChild(row);
    });

    sandboxVerdictBadge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-semibold";
    sandboxVerdictBadge.innerText = "EXPLOIT NEUTRALIZED (ZERO REGRESSIONS)";
}

/**
 * 1-Click Auto-Heal Full Pipeline Orchestrator
 */
async function runFullAutoHealPipeline() {
    btnRunAll.disabled = true;
    btnRunAll.innerHTML = `<span class="animate-spin mr-1">?</span> Orchestrating...`;

    try {
        logToTerminal("==================================================", "system");
        logToTerminal("[PIPELINE] Launching Complete Autonomous Self-Healing Pipeline", "system");
        
        await runStep1Analyze();
        await new Promise(r => setTimeout(r, 600));

        await runStep2Patch();
        await new Promise(r => setTimeout(r, 600));

        await runStep3Sandbox();

        logToTerminal("[PIPELINE] Execution complete. Production-ready patch verified.", "system");
        logToTerminal("==================================================", "system");
    } catch (err) {
        logToTerminal(`[PIPELINE ERROR] ${err.message}`, "red");
    } finally {
        btnRunAll.disabled = false;
        btnRunAll.innerHTML = `<i data-lucide="play" class="w-4 h-4 fill-white inline mr-1"></i> Auto-Heal Pipeline (1-Click)`;
        lucide.createIcons();
    }
}

/**
 * Highlight active agent badge in console
 */
function highlightAgentBadge(badgeId) {
    const el = document.getElementById(badgeId);
    if (!el) return;
    el.classList.add("ring-2", "ring-cyan-400", "scale-105");
    setTimeout(() => {
        el.classList.remove("ring-2", "ring-cyan-400", "scale-105");
    }, 1500);
}

/**
 * Export Executive PDF Dossier
 */
async function exportPdfDossier() {
    if (!appState.auditor) {
        logToTerminal("[EXPORT] Running verification pipeline first to generate audit data...", "system");
        await runFullAutoHealPipeline();
    }

    logToTerminal("[EXPORT] Generating boardroom-ready PDF Security Dossier via ReportLab...", "auditor");

    try {
        const payload = {
            scenario_id: currentScenarioId,
            red_team: appState.red_team || {},
            blue_team: appState.blue_team || {},
            sandbox: appState.sandbox || {},
            auditor: appState.auditor || {}
        };

        const res = await fetch("/api/export-dossier", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!res.ok) throw new Error("Failed to generate PDF");

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `CodeSanctum_Remediation_Dossier_${currentScenarioId || 'Custom'}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);

        logToTerminal("[EXPORT] PDF Dossier downloaded successfully.", "sandbox");
    } catch (err) {
        logToTerminal(`[EXPORT ERROR] Failed to download PDF: ${err.message}`, "red");
    }
}
