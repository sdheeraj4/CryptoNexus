"use strict";

// Presentation only: all findings, relationships, and recommendations come from the backend.
const state = { file: null, analysis: null, scannedAt: null, selectedFinding: 0, busy: false };
class RequestError extends Error {}
const pages = {
    scan: ["SCAN WORKSPACE", "Build your cryptographic inventory"],
    inventory: ["INVENTORY", "Cryptographic mechanisms in view"],
    evidence: ["EVIDENCE EXPLORER", "Show me why this was flagged"],
    dependencies: ["DEPENDENCY MAP", "Trace evidence relationships"],
    certificates: ["CERTIFICATES", "Certificate material deserves its own view"],
    migration: ["MIGRATION WORKBENCH", "Turn inventory into an ordered checklist"],
    agility: ["CRYPTO-AGILITY LAB", "Switch providers through the same interface"],
    reports: ["REPORT BUILDER", "Package evidence, risks and validation gates"]
};
const $ = id => document.getElementById(id);
const findings = () => state.analysis?.findings ?? [];
const value = x => x === null || x === undefined || x === "" ? "-" : String(x);
const esc = x => value(x).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
const setText = (id, text) => { $(id).textContent = value(text); };
const nameOf = f => f.algorithm || f.library || f.protocol || f.reference || f.ai_label || f.type;
const empty = text => `<div class="empty-row">${esc(text)}</div>`;
const absent = () => state.analysis ? "No matching findings were returned. This does not establish absence of cryptography." : "Analyze a repository ZIP to populate this view.";
const badge = (status, priority = false) => {
    const allowed = priority ? ["high", "medium", "informational"] : ["confirmed", "likely", "uncertain"];
    return `<span class="${priority ? "status" : "confidence"} ${allowed.includes(status) ? status : "neutral"}">${esc(status)}</span>`;
};
const fact = (label, content) => `<div class="side-fact"><span>${esc(label)}</span><b>${esc(content)}</b></div>`;
const bulletList = items => items.length ? `<ul>${items.map(item => `<li>${esc(item)}</li>`).join("")}</ul>` : '<p class="muted">None returned.</p>';

function openPage(page) {
    if (!pages[page]) return;
    document.querySelectorAll(".page").forEach(el => el.classList.toggle("active", el.id === `page-${page}`));
    document.querySelectorAll(".nav-item").forEach(el => el.classList.toggle("active", el.dataset.page === page));
    setText("topEyebrow", pages[page][0]); setText("pageHeading", pages[page][1]);
}

function message(id, text, error = false) {
    setText(id, text); $(id).classList.toggle("error", error);
}

async function requestJSON(url, options) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 120000);
    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        let data;
        try { data = await response.json(); } catch { throw new RequestError("The backend returned an unreadable response. Please try again."); }
        if (!response.ok) throw new RequestError(`Request failed (${response.status}): ${typeof data?.error === "string" ? data.error : "Check the request fields and try again."}`);
        return data;
    } catch (error) {
        if (error.name === "AbortError") throw new RequestError("The request timed out. Try a smaller repository or retry the test.");
        if (error instanceof TypeError) throw new RequestError("Cannot reach CryptoNexus. Check that the local backend is running.");
        throw error;
    } finally { clearTimeout(timer); }
}

function setBusy(busy) {
    state.busy = busy;
    ["startScan", "chooseFiles", "clearSelection", "fileInput"].forEach(id => { $(id).disabled = busy; });
    $("dropzone").setAttribute("aria-busy", String(busy));
    $("startScan").innerHTML = busy ? "<span>Analyzing repository…</span><span>•••</span>" : "<span>Analyze repository</span><span>↗</span>";
    document.querySelectorAll(".pipeline-step").forEach(step => {
        step.classList.toggle("done", !busy && Boolean(state.analysis));
        step.querySelector("i").textContent = busy ? "·" : state.analysis ? "✓" : "○";
    });
}

function selectFile(files) {
    if (state.busy) return;
    state.file = null; state.analysis = null; state.scannedAt = null;
    renderAll();
    if (files.length !== 1 || !files[0].name.toLowerCase().endsWith(".zip")) message("scanMessage", "Select one repository ZIP file.", true);
    else if (files[0].size > 20 * 1024 * 1024) message("scanMessage", "The ZIP exceeds the 20 MiB upload limit.", true);
    else { state.file = files[0]; message("scanMessage", `${state.file.name} is ready for analysis.`); }
    setText("selectedZip", state.file?.name ?? "None selected");
    setText("selectedSize", state.file ? `${(state.file.size / 1024).toFixed(1)} KiB` : "-");
    setText("selectionStatus", state.file ? "ZIP READY" : "NO INPUT");
    setBusy(false);
}

async function analyzeZip() {
    if (state.busy) return;
    if (!state.file) { message("scanMessage", "Choose a repository ZIP first.", true); return; }
    state.analysis = null; state.scannedAt = null; renderAll(); setBusy(true);
    setText("selectionStatus", "ANALYZING");
    message("scanMessage", "Analyzing with the local backend. This may take a moment.");
    try {
        const data = new FormData(); data.append("file", state.file);
        const analysis = await requestJSON("/api/analyze", { method: "POST", body: data });
        if (!Array.isArray(analysis.findings) || !Array.isArray(analysis.dependencies?.nodes) ||
            !Array.isArray(analysis.dependencies?.edges) || !Array.isArray(analysis.migration_checklist) ||
            !analysis.summary || !analysis.report || !Array.isArray(analysis.report.limitations) ||
            !Array.isArray(analysis.report.compatibility_risks) || !Array.isArray(analysis.report.testing_steps)) {
            throw new RequestError("The backend response is incomplete. Check that the current CryptoNexus backend is running.");
        }
        state.analysis = analysis; state.scannedAt = new Date(); state.selectedFinding = 0;
        renderAll(); setText("selectionStatus", "ANALYSIS READY");
        message("scanMessage", `Analysis complete: ${analysis.summary.total_findings} findings. Results are ready in all workspace sections.`);
        toast("Analysis complete. Open Inventory to review the evidence.");
    } catch (error) {
        state.analysis = null; renderAll(); setText("selectionStatus", "ANALYSIS FAILED");
        message("scanMessage", error instanceof RequestError ? error.message : "Unable to display this analysis. Please retry or check the backend version.", true);
    } finally { setBusy(false); }
}

function renderAll() {
    const summary = state.analysis?.summary;
    for (const [id, key] of Object.entries({ sumTotal: "total_findings", sumHigh: "high_priority", sumConfirmed: "confirmed", sumLikely: "likely", sumUncertain: "uncertain", invFiles: "confirmed", invMechanisms: "total_findings", invHigh: "high_priority", repFiles: "confirmed", repFindings: "total_findings", repHigh: "high_priority" })) setText(id, summary ? summary[key] : 0);
    setText("invDeps", state.analysis?.dependencies.edges.length ?? 0);
    const certCount = findings().filter(f => f.type === "certificate").length;
    setText("invCerts", certCount); setText("repCerts", certCount);
    setText("inventoryTimestamp", state.scannedAt?.toLocaleString() ?? "-");
    renderInventory(); renderEvidence(); renderDependencies(); renderCertificates(); renderMigration(); renderReport();
}

function renderInventory() {
    $("inventoryRows").innerHTML = findings().map((f, i) => `<div class="table-row">
        <div><button class="finding-link" data-evidence="${i}">${esc(nameOf(f))}</button><small>${esc(f.type)}</small>${f.reference ? `<small>${esc(f.reference)}</small>` : ""}</div>
        <div>${esc(f.file)}<small>Line ${esc(f.line)}</small></div><div>${esc(f.usage)}<small>Key size: ${esc(f.key_size)}</small></div>
        <div>${badge(f.priority, true)}<small>${esc(f.migration_concern)}</small></div><div>${badge(f.status)}</div></div>`).join("") || empty(absent());
    $("inventoryRows").querySelectorAll("[data-evidence]").forEach(button => button.addEventListener("click", () => {
        state.selectedFinding = Number(button.dataset.evidence); renderEvidence(); openPage("evidence");
    }));
}

function renderEvidence() {
    $("evidenceList").innerHTML = findings().map((f, i) => `<button class="evidence-item ${i === state.selectedFinding ? "active" : ""}" data-index="${i}">
        <div class="evidence-item-top"><b>${esc(nameOf(f))}</b>${badge(f.status)}</div>
        <p>${esc(f.file)} · line ${esc(f.line)}</p><small>${esc(f.evidence_type)} evidence · ${esc(f.usage)}</small></button>`).join("") || empty(absent());
    $("evidenceList").querySelectorAll("[data-index]").forEach(button => button.addEventListener("click", () => { state.selectedFinding = Number(button.dataset.index); renderEvidence(); }));
    const f = findings()[state.selectedFinding];
    $("evidenceDetail").innerHTML = f ? `<div class="detail-grid"><div>
        <div class="section-kicker">${esc(f.evidence_type)} evidence</div><h3 class="detail-title">${esc(nameOf(f))}</h3>
        <div class="detail-sub">${esc(f.file)} · line ${esc(f.line)}</div>${badge(f.status)}
        <pre class="code-view evidence-code">${esc(f.evidence)}</pre></div><div class="detail-side">
        ${fact("USAGE", f.usage)}${fact("KEY SIZE", f.key_size)}${fact("PRIORITY", f.priority)}${fact("MIGRATION CONCERN", f.migration_concern)}${fact("REASON", f.reason)}
        ${f.ai_label ? fact("AI LABEL", f.ai_label) + fact("AI CONFIDENCE", f.ai_confidence == null ? null : `${(f.ai_confidence * 100).toFixed(1)}%`) : ""}
        </div></div>` : empty(absent());
}

function renderDependencies() {
    const graph = state.analysis?.dependencies;
    if (!graph?.nodes.length) { $("dependencyCanvas").innerHTML = empty(absent()); $("dependencyRows").innerHTML = empty(absent()); return; }
    const nodes = new Map(graph.nodes.map(n => [n.id, n]));
    const nodeCard = id => {
        const n = nodes.get(id);
        return `<div class="dep-node ${n?.type === "file" ? "component-node" : "mechanism-node"}"><span>${esc(n?.type)}</span><b>${esc(n?.label ?? id)}</b></div>`;
    };
    // Lay out existing edges only: never guess paths or construct relationships.
    $("dependencyCanvas").innerHTML = graph.edges.length ? `<p class="muted">${graph.nodes.length} backend nodes · ${graph.edges.length} relationships. Preview shows up to 40; the table lists every edge.</p>` +
        graph.edges.slice(0, 40).map(e => `<div class="dep-edge-layout">${nodeCard(e.from)}<div class="relation-arrow ${e.inferred ? "inferred" : "observed"}">${esc(e.relation)} →<small>${e.inferred ? "INFERRED" : "OBSERVED"}</small></div>${nodeCard(e.to)}</div>`).join("") : graph.nodes.map(n => nodeCard(n.id)).join("");
    $("dependencyRows").innerHTML = graph.edges.map(e => `<div class="dep-row">
        <div>${esc(nodes.get(e.from)?.label ?? e.from)}</div><div>${esc(nodes.get(e.to)?.label ?? e.to)}</div><div>${esc(e.relation)}<small>${esc(e.basis)}</small></div>
        <div><span class="confidence ${e.inferred ? "uncertain" : "confirmed"}">${e.inferred ? "INFERRED" : "OBSERVED"}</span><small>${esc((e.finding_ids ?? []).join(", "))}</small></div></div>`).join("") || empty("No edges were returned.");
}

function renderCertificates() {
    $("certificateRows").innerHTML = findings().filter(f => f.type === "certificate").map(f => `<div class="table-row cert-row">
        <div class="primary">${esc(f.file)}<small>Subject: ${esc(f.subject)}</small></div><div>Issuer: ${esc(f.issuer)}<small>Serial: ${esc(f.serial_number)}</small></div>
        <div>${esc(f.algorithm)}<small>Key size: ${esc(f.key_size)}</small></div><div>${esc(f.signature_algorithm)}<small>From: ${esc(f.valid_from)}</small><small>Until: ${esc(f.valid_until)}</small></div>
        <div>${badge(f.status)} ${badge(f.priority, true)}</div></div>`).join("") || empty(state.analysis ? "No valid parsed certificates were returned." : absent());
    $("certificatePaths").innerHTML = findings().filter(f => ["certificate_path", "key_path"].includes(f.type)).map(f =>
        `<div class="table-row"><div>${esc(f.file)}</div><div>${esc(f.type)}</div><div>${esc(f.reference)}</div><div>${badge(f.status)}</div><div>${badge(f.priority, true)}</div></div>`).join("") || empty("No path references returned.");
}

function migrationItems(items) {
    return items.map(item => `<article class="migration-item"><div class="migration-step">P${esc(item.priority)}</div><div class="migration-main">
        <b>${esc(item.title)}</b><p>${esc(item.affected_components.join(", "))}</p><p>${esc(item.reason)}</p><ol>${item.steps.map(step => `<li>${esc(step)}</li>`).join("")}</ol></div>
        <div class="migration-meta">${badge(item.finding_status)}</div></article>`).join("");
}

function renderMigration() { $("migrationBoard").innerHTML = migrationItems(state.analysis?.migration_checklist ?? []) || empty(absent()); }

function renderReport() {
    $("generateReport").disabled = !state.analysis;
    if (!state.analysis) { $("reportContent").innerHTML = empty(absent()); return; }
    const { report, summary, migration_checklist } = state.analysis;
    setText("reportDisclaimer", report.disclaimer);
    const section = (title, body) => `<section class="panel report-section"><h3>${esc(title)}</h3>${body}</section>`;
    const counts = new Map(); findings().forEach(f => counts.set(f.type, (counts.get(f.type) ?? 0) + 1));
    $("reportContent").innerHTML = section("Scan summary", `<p>${esc(state.file?.name)} · ${esc(state.scannedAt?.toLocaleString())}</p><p>Total: ${esc(summary.total_findings)} · High priority: ${esc(summary.high_priority)} · Confirmed: ${esc(summary.confirmed)} · Likely: ${esc(summary.likely)} · Uncertain: ${esc(summary.uncertain)}</p>`) +
        section("Cryptographic inventory", bulletList([...counts].map(([type, count]) => `${type}: ${count}`))) +
        section("High-priority findings", bulletList(findings().filter(f => f.priority === "high").map(f => `${nameOf(f)} — ${f.file}:${value(f.line)} — ${f.status}`))) +
        section("Migration checklist", migrationItems(migration_checklist) || "<p>No actions returned.</p>") +
        section("Compatibility risks", bulletList(report.compatibility_risks)) + section("Testing steps", bulletList(report.testing_steps)) +
        section("Limitations", bulletList(report.limitations)) + section("Disclaimer", `<p>${esc(report.disclaimer)}</p>`);
}

async function runSandbox() {
    const button = $("applyProfile"); button.disabled = true; $("providerSelect").disabled = true; $("sandboxMessage").disabled = true;
    $("sandboxOutput").innerHTML = empty("Running sign + verify through the selected provider…");
    message("sandboxStatus", "Running a real local sign/verify test…");
    try {
        const result = await requestJSON("/api/sandbox/run", { method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ provider: $("providerSelect").value, message: $("sandboxMessage").value }) });
        $("sandboxOutput").innerHTML = ["provider", "algorithm", "operation", "verified", "key_size", "message_length"].map(key =>
            `<div class="output-card"><span>${esc(key.replaceAll("_", " ").toUpperCase())}${key === "message_length" ? " (UTF-8 BYTES)" : ""}</span><b>${esc(result[key])}</b></div>`).join("") + `<div class="certificate-note">${esc(result.note)}</div>`;
        message("sandboxStatus", result.verified ? "Sign/verify succeeded." : "The provider returned a verification failure.", !result.verified);
    } catch (error) {
        $("sandboxOutput").innerHTML = empty("No test result available."); message("sandboxStatus", error instanceof RequestError ? error.message : "Unable to display the sandbox result. Please retry.", true);
    } finally { button.disabled = false; $("providerSelect").disabled = false; $("sandboxMessage").disabled = false; }
}

function downloadReport() {
    if (!state.analysis) return;
    const report = { product: "CryptoNexus", repository_zip: state.file?.name, scanned_at: state.scannedAt?.toISOString(), ...state.analysis };
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = "cryptonexus-report.json";
    document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Report downloaded from the current backend analysis.");
}

function toast(text) {
    setText("toast", text); $("toast").className = "toast show";
    clearTimeout(toast.timer); toast.timer = setTimeout(() => { $("toast").className = "toast"; }, 4000);
}

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".nav-item").forEach(button => button.addEventListener("click", () => openPage(button.dataset.page)));
    $("openScanButton").addEventListener("click", () => openPage("scan"));
    $("chooseFiles").addEventListener("click", () => $("fileInput").click());
    $("fileInput").addEventListener("change", event => selectFile([...event.target.files]));
    $("clearSelection").addEventListener("click", () => { $("fileInput").value = ""; selectFile([]); message("scanMessage", "Choose a repository ZIP to begin."); });
    $("startScan").addEventListener("click", analyzeZip);
    ["dragenter", "dragover"].forEach(name => $("dropzone").addEventListener(name, event => { event.preventDefault(); if (!state.busy) $("dropzone").classList.add("dragover"); }));
    ["dragleave", "drop"].forEach(name => $("dropzone").addEventListener(name, event => { event.preventDefault(); $("dropzone").classList.remove("dragover"); }));
    $("dropzone").addEventListener("drop", event => selectFile([...event.dataTransfer.files]));
    $("applyProfile").addEventListener("click", runSandbox);
    ["providerSelect", "sandboxMessage"].forEach(id => $(id).addEventListener("input", () => {
        $("sandboxOutput").innerHTML = empty("Inputs changed. Run the test to get a new result."); message("sandboxStatus", "Ready to run sign + verify.");
    }));
    $("generateReport").addEventListener("click", downloadReport);
    renderAll();
});
