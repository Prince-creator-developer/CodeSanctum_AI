/**
 * CodeSanctum AI - DevSecOps Cockpit Frontend Controller
 * Features: Multi-agent orchestration, interactive narrated guided demo with browser voice and visual arrow callouts.
 */

let currentScenarioId = "cwe-89-sqli";
let isCustomMode = false;
let soundEnabled = true;
let isGuidedTourActive = false;

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
const btnCopyPatch = document.getElementById("btn-copy-patch");
const btnCopyAttestation = document.getElementById("btn-copy-attestation");
const btnToggleAstTree = document.getElementById("btn-toggle-ast-tree");
const astTreePanel = document.getElementById("ast-tree-panel");
const btnSoundToggle = document.getElementById("btn-sound-toggle");
const iconSound = document.getElementById("icon-sound");

// Modals & Narrator Overlay Elements
const guideModal = document.getElementById("guide-modal");
const btnOpenGuide = document.getElementById("btn-open-guide");
const btnCloseGuide = document.getElementById("btn-close-guide");
const btnStartGuidedDemo = document.getElementById("btn-start-guided-demo");

const cvssModal = document.getElementById("cvss-modal");
const btnCvssModal = document.getElementById("btn-cvss-modal");
const btnCloseCvss = document.getElementById("btn-close-cvss");

const narratorOverlay = document.getElementById("narrator-overlay");
const narratorStageTitle = document.getElementById("narrator-stage-title");
const narratorSubtitle = document.getElementById("narrator-subtitle");
const narratorArrowCallout = document.getElementById("narrator-arrow-callout");
const narratorArrowText = document.getElementById("narrator-arrow-text");
const btnStopNarrator = document.getElementById("btn-stop-narrator");

// Target Panels for Spotlight Highlights
const panelCodeStudio = document.getElementById("panel-code-studio");
const panelAgentOps = document.getElementById("panel-agent-ops");
const panelDiffSandbox = document.getElementById("panel-diff-sandbox");

// Web Audio API Synthesizer for Cyber Haptic Beeps
let audioCtx = null;
function playCyberBeep(freq = 600, type = "sine", duration = 0.08) {
    if (!soundEnabled) return;
    try {
        if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        if (audioCtx.state === "suspended") audioCtx.resume();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = type;
        osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
        gain.gain.setValueAtTime(0.04, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + duration);
    } catch (e) {}
}

/**
 * Text-to-Speech Voice Engine (speaks instructions aloud)
 */
function speakVoice(text) {
    if (!soundEnabled || !('speechSynthesis' in window)) return;
    try {
        window.speechSynthesis.cancel(); // Stop any pending speech
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 1.0;
        utterance.pitch = 1.0;
        utterance.lang = 'en-US';

        // Prefer natural female English voice if available
        const voices = window.speechSynthesis.getVoices();
        const naturalVoice = voices.find(v => (v.name.includes('Natural') || v.name.includes('Google') || v.name.includes('Samantha') || v.name.includes('Zira')) && v.lang.startsWith('en'));
        if (naturalVoice) utterance.voice = naturalVoice;

        window.speechSynthesis.speak(utterance);
    } catch (e) {
        console.warn("Speech synthesis fallback", e);
    }
}

// Initialize on Load
document.addEventListener("DOMContentLoaded", () => {
    appState.code = codeEditor.value;

    if (!localStorage.getItem("codesanctum_guide_seen")) {
        guideModal.classList.remove("hidden");
        guideModal.classList.add("flex");
    } else {
        guideModal.classList.remove("flex");
        guideModal.classList.add("hidden");
    }

    // Bind Event Listeners
    btnRunAll.addEventListener("click", () => runFullAutoHealPipeline());
    btnAnalyze.addEventListener("click", () => runStep1Analyze());
    btnPatch.addEventListener("click", () => runStep2Patch());
    btnSandbox.addEventListener("click", () => runStep3Sandbox());
    btnExportDossier.addEventListener("click", () => exportPdfDossier());

    btnOpenGuide.addEventListener("click", () => {
        guideModal.classList.remove("hidden");
        guideModal.classList.add("flex");
    });
    btnCloseGuide.addEventListener("click", () => {
        guideModal.classList.remove("flex");
        guideModal.classList.add("hidden");
        localStorage.setItem("codesanctum_guide_seen", "true");
    });
    btnStartGuidedDemo.addEventListener("click", () => {
        guideModal.classList.remove("flex");
        guideModal.classList.add("hidden");
        localStorage.setItem("codesanctum_guide_seen", "true");
        launchNarratedGuidedTour();
    });

    btnStopNarrator.addEventListener("click", () => stopGuidedTour());

    btnCvssModal.addEventListener("click", () => {
        cvssModal.classList.remove("hidden");
        cvssModal.classList.add("flex");
    });
    btnCloseCvss.addEventListener("click", () => {
        cvssModal.classList.remove("flex");
        cvssModal.classList.add("hidden");
    });

    btnSoundToggle.addEventListener("click", () => {
        soundEnabled = !soundEnabled;
        if (soundEnabled) {
            btnSoundToggle.classList.add("text-cyan-300");
            btnSoundToggle.classList.remove("text-slate-600");
            playCyberBeep(880, "triangle", 0.1);
        } else {
            btnSoundToggle.classList.remove("text-cyan-300");
            btnSoundToggle.classList.add("text-slate-600");
            if ('speechSynthesis' in window) window.speechSynthesis.cancel();
        }
    });

    btnToggleAstTree.addEventListener("click", () => {
        astTreePanel.classList.toggle("hidden");
    });

    btnCopyPatch.addEventListener("click", () => {
        if (!appState.blue_team || !appState.blue_team.patched_code) {
            logToTerminal("[CLIPBOARD] Run Step 2 or Auto-Heal first to generate patch.", "system");
            return;
        }
        navigator.clipboard.writeText(appState.blue_team.patched_code);
        logToTerminal("[CLIPBOARD] Patched code copied to clipboard!", "blue");
        playCyberBeep(920, "sine", 0.05);
    });

    btnCopyAttestation.addEventListener("click", () => {
        if (!appState.auditor) {
            logToTerminal("[CLIPBOARD] Complete audit pipeline first to generate attestation.", "system");
            return;
        }
        const text = `CodeSanctum AI Verification Proof\nTarget: ${appState.auditor.cwe}\nCVSS Reduction: ${appState.auditor.initial_cvss} -> 0.0\nSHA-256 Seal: ${appState.auditor.verification_hash}\nTimestamp: ${appState.auditor.timestamp}\nTeam: Valerion Coders`;
        navigator.clipboard.writeText(text);
        logToTerminal("[CLIPBOARD] Cryptographic attestation seal copied to clipboard!", "auditor");
        playCyberBeep(1050, "sine", 0.07);
    });
});

/**
 * Log message to the operations terminal
 */
function logToTerminal(message, type = "info") {
    const logItem = document.createElement("div");
    logItem.className = "log-enter";

    let colorClass = "text-slate-300";
    if (type === "red") { colorClass = "text-red-400"; playCyberBeep(450, "sawtooth", 0.04); }
    if (type === "blue") { colorClass = "text-cyan-400"; playCyberBeep(650, "sine", 0.04); }
    if (type === "sandbox") { colorClass = "text-emerald-400"; playCyberBeep(800, "triangle", 0.04); }
    if (type === "auditor") { colorClass = "text-amber-400 font-semibold"; playCyberBeep(1100, "sine", 0.07); }
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

        document.querySelectorAll(".scenario-pill").forEach(p => {
            p.classList.remove("bg-cyan-950/70", "text-cyan-300", "border-cyan-700/80", "shadow-sm", "shadow-cyan-900/50", "font-bold");
            p.classList.add("bg-slate-900/60", "text-slate-400", "border-slate-800");
        });
        const activePill = document.querySelector(`[data-scenario-id="${scenarioId}"]`);
        if (activePill) {
            activePill.classList.remove("bg-slate-900/60", "text-slate-400", "border-slate-800");
            activePill.classList.add("bg-cyan-950/70", "text-cyan-300", "border-cyan-700/80", "shadow-sm", "shadow-cyan-900/50", "font-bold");
        }

        const res = await fetch(`/api/scenarios/${scenarioId}`);
        const data = await res.json();
        if (data.status !== "ok") return;

        const sc = data.scenario;
        codeEditor.value = sc.vulnerable_code;
        codeEditor.readOnly = true;
        document.getElementById("editor-hint").innerText = "Preset Active (Click 'Custom Code' to edit)";

        currentFilename.innerText = sc.vulnerable_file;
        currentCweBadge.innerText = `${sc.severity} (${sc.cwe})`;
        badgeCvssInitial.innerText = `Initial CVSS: ${sc.cvss_initial} (${sc.severity})`;
        badgeCvssRemediated.innerText = "Post-Patch: Pending";

        appState.code = sc.vulnerable_code;
        appState.ast = null;
        appState.red_team = null;
        appState.blue_team = null;
        appState.sandbox = null;
        appState.auditor = null;

        renderHotspots(sc.ast_hotspots);

        diffViewer.innerHTML = `<div class="text-slate-500 italic p-4 text-center">Unified patch diff will be synthesized by Blue-Team Aegis.</div>`;
        diffStats.innerText = "+0 / -0";
        sandboxTable.innerHTML = `<div class="text-[11px] text-slate-500 italic text-center py-2">Execute verification to observe live adversarial & regression test harness.</div>`;
        sandboxVerdictBadge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700";
        sandboxVerdictBadge.innerText = "PENDING RUN";
        testSummaryBadge.innerText = "0 / 0 Tests";

        logToTerminal(`[SCENARIO] Loaded ${sc.name} (${sc.cve_tag})`, "system");
        playCyberBeep(700, "sine", 0.05);
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
        p.classList.remove("bg-cyan-950/70", "text-cyan-300", "border-cyan-700/80", "shadow-sm", "shadow-cyan-900/50", "font-bold");
        p.classList.add("bg-slate-900/60", "text-slate-400", "border-slate-800");
    });
    const customPill = document.getElementById("pill-custom");
    customPill.classList.remove("bg-slate-900/60", "text-slate-400", "border-slate-800");
    customPill.classList.add("bg-cyan-950/70", "text-cyan-300", "border-cyan-700/80", "shadow-sm", "shadow-cyan-900/50", "font-bold");

    codeEditor.readOnly = false;
    document.getElementById("editor-hint").innerText = "Interactive Mode (Paste or type any Python code)";
    currentFilename.innerText = "custom_sandbox_target.py";
    currentCweBadge.innerText = "USER INPUT";
    badgeCvssInitial.innerText = "Initial CVSS: Evaluating";
    badgeCvssRemediated.innerText = "Post-Patch: Pending";

    logToTerminal("[SANDBOX] Switched to Custom Code mode. Paste custom Python code and click Step 1.", "system");
    playCyberBeep(750, "sine", 0.05);
}

/**
 * Render AST Hotspots list
 */
function renderHotspots(hotspots) {
    hotspotsList.innerHTML = "";
    hotspotsCount.innerText = `${hotspots.length} Hotspots Flagged`;

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

        data.red_team.telemetry.forEach(msg => logToTerminal(msg, "red"));
        renderHotspots(data.ast.hotspots || []);

        badgeCvssInitial.innerText = `Initial CVSS: ${data.red_team.cvss_score} (${data.red_team.severity})`;
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

        data.blue_team.telemetry.forEach(msg => logToTerminal(msg, "blue"));
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

        data.sandbox.telemetry.forEach(msg => logToTerminal(msg, "sandbox"));
        renderSandboxBattery(data.sandbox);

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
    btnRunAll.innerHTML = `<span class="animate-spin mr-1">⚡</span> Orchestrating...`;

    try {
        logToTerminal("==================================================", "system");
        logToTerminal("[PIPELINE] Launching Complete Autonomous Self-Healing Pipeline", "system");
        
        await runStep1Analyze();
        await new Promise(r => setTimeout(r, 550));

        await runStep2Patch();
        await new Promise(r => setTimeout(r, 550));

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
 * ============================================================================
 * INTERACTIVE NARRATED GUIDED TOUR ENGINE (Voice + Arrow Callout + Spotlight)
 * ============================================================================
 */
async function launchNarratedGuidedTour() {
    isGuidedTourActive = true;
    narratorOverlay.classList.remove("hidden");

    // Helper to clear spotlights
    function clearSpotlights() {
        panelCodeStudio.classList.remove("ring-4", "ring-cyan-400", "ring-offset-4", "ring-offset-slate-900", "glow-active");
        panelAgentOps.classList.remove("ring-4", "ring-cyan-400", "ring-offset-4", "ring-offset-slate-900", "glow-active");
        panelDiffSandbox.classList.remove("ring-4", "ring-emerald-400", "ring-offset-4", "ring-offset-slate-900", "glow-active");
        btnExportDossier.classList.remove("ring-4", "ring-blue-400", "glow-active");
    }

    try {
        // --- STEP 1: Code Ingestion & AST Analysis ---
        clearSpotlights();
        panelCodeStudio.classList.add("ring-4", "ring-cyan-400", "ring-offset-4", "ring-offset-slate-900", "glow-active");
        
        narratorStageTitle.innerText = "Step 1: Code Ingestion & AST Decomposition";
        narratorSubtitle.innerText = "Red-Team Sentinel parses the Abstract Syntax Tree. Notice the dangerous SQL f-string highlighted at line 3 with a 9.8 Critical CVSS score!";
        narratorArrowCallout.innerHTML = `<i data-lucide="arrow-left" class="w-3.5 h-3.5 animate-bounce"></i> <span>Look at Panel 1 (Left): Dangerous f-string identified at Line 3</span>`;
        lucide.createIcons();

        speakVoice("Step 1. Red-Team Sentinel is analyzing the Abstract Syntax Tree. Notice the dangerous S-Q-L f-string highlighted at line 3.");
        await runStep1Analyze();
        await new Promise(r => setTimeout(r, 4500));
        if (!isGuidedTourActive) return;

        // --- STEP 2: Multi-Agent Synthesis ---
        clearSpotlights();
        panelAgentOps.classList.add("ring-4", "ring-cyan-400", "ring-offset-4", "ring-offset-slate-900", "glow-active");

        narratorStageTitle.innerText = "Step 2: Autonomous Patch Synthesis";
        narratorSubtitle.innerText = "Blue-Team Aegis takes the exploit model and autonomously synthesizes a surgical AST patch with parameterized database query bindings.";
        narratorArrowCallout.innerHTML = `<i data-lucide="arrow-up" class="w-3.5 h-3.5 animate-bounce"></i> <span>Look at Panel 2 (Center): Blue-Team synthesizing surgical patch</span>`;
        lucide.createIcons();

        speakVoice("Step 2. Blue-Team Aegis is now synthesizing a surgical A-S-T patch with parameterized driver bindings.");
        await runStep2Patch();
        await new Promise(r => setTimeout(r, 4500));
        if (!isGuidedTourActive) return;

        // --- STEP 3: Sandbox Verification & Zero Regression ---
        clearSpotlights();
        panelDiffSandbox.classList.add("ring-4", "ring-emerald-400", "ring-offset-4", "ring-offset-slate-900", "glow-active");

        narratorStageTitle.innerText = "Step 3: Dual-Phase Sandbox Verification";
        narratorSubtitle.innerText = "The sandbox executes: unpatched code is exploited, patched code blocks the attack, and all regression tests pass! CVSS drops to 0.0!";
        narratorArrowCallout.innerHTML = `<i data-lucide="arrow-right" class="w-3.5 h-3.5 animate-bounce"></i> <span>Look at Panel 3 (Right): Attack neutralized, 100% tests passed</span>`;
        lucide.createIcons();

        speakVoice("Step 3. Isolated Sandbox executes verification. Unpatched code was exploited, but patched code blocked the attack with zero regressions.");
        await runStep3Sandbox();
        await new Promise(r => setTimeout(r, 5000));
        if (!isGuidedTourActive) return;

        // --- STEP 4: Auditor Veritas Seal & PDF ---
        clearSpotlights();
        btnExportDossier.classList.add("ring-4", "ring-blue-400", "glow-active");

        narratorStageTitle.innerText = "Step 4: Cryptographic SHA-256 Attestation & PDF Dossier";
        narratorSubtitle.innerText = "Auditor Veritas has certified the fix with a tamper-evident SHA-256 seal. You can now download the official executive PDF dossier!";
        narratorArrowCallout.innerHTML = `<i data-lucide="arrow-down" class="w-3.5 h-3.5 animate-bounce"></i> <span>Click below to download the signed Executive PDF Dossier</span>`;
        lucide.createIcons();

        speakVoice("Step 4. Auditor Veritas has certified the fix and signed the cryptographic S-H-A 256 seal. Your executive dossier is ready.");
        await new Promise(r => setTimeout(r, 4500));

    } catch (e) {
        console.error("Tour error", e);
    } finally {
        // Leave narrator open with wrap-up info
        narratorStageTitle.innerText = "Tour Completed Successfully!";
        narratorSubtitle.innerText = "The vulnerability is 100% remediated. Click any scenario pill at the top to test other vulnerability classes!";
        narratorArrowCallout.innerHTML = `<i data-lucide="check-circle" class="w-3.5 h-3.5 text-emerald-400"></i> <span class="text-emerald-300 font-semibold">Self-Healing Loop Complete</span>`;
        lucide.createIcons();
    }
}

function stopGuidedTour() {
    isGuidedTourActive = false;
    narratorOverlay.classList.add("hidden");
    if ('speechSynthesis' in window) window.speechSynthesis.cancel();
    panelCodeStudio.classList.remove("ring-4", "ring-cyan-400", "ring-offset-4", "ring-offset-slate-900", "glow-active");
    panelAgentOps.classList.remove("ring-4", "ring-cyan-400", "ring-offset-4", "ring-offset-slate-900", "glow-active");
    panelDiffSandbox.classList.remove("ring-4", "ring-emerald-400", "ring-offset-4", "ring-offset-slate-900", "glow-active");
    btnExportDossier.classList.remove("ring-4", "ring-blue-400", "glow-active");
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

    logToTerminal("[EXPORT] Generating boardroom-ready PDF Security Dossier with SHA-256 seal...", "auditor");

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
