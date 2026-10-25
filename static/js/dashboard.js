/**
 * SQL SHIELD AI - Frontend Client Logic
 * Handles interactive detection, simulation runner, incident filters, AI Analyst, and Chart.js integrations.
 */

// Simple markdown-to-HTML formatter for analyst output
function formatMarkdown(text) {
  if (!text) return "";
  let html = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Code blocks: ```lang ... ```
  html = html.replace(/```([a-z0-9_-]*)\n([\s\S]*?)```/gi, (match, lang, code) => {
    return `<div class="code-block"><pre><code>${code.trim()}</code></pre></div>`;
  });

  // Inline code: `...`
  html = html.replace(/`([^`]+)`/g, '<code class="code-inline" style="background:#070c18;padding:2px 6px;border-radius:4px;color:#38bdf8;">$1</code>');

  // Headers: ### [Title]
  html = html.replace(/^###\s+(.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^##\s+(.+)$/gm, '<h2 style="font-size:18px;color:#fff;margin:16px 0 8px;">$1</h2>');

  // Bold: **...**
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

  // Unordered list items: - ...
  html = html.replace(/^\s*-\s+(.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');

  // Paragraph breaks
  html = html.split('\n\n').map(p => {
    if (p.startsWith('<h3>') || p.startsWith('<ul>') || p.startsWith('<div class="code-block">')) return p;
    return `<p>${p.replace(/\n/g, '<br>')}</p>`;
  }).join('');

  return html;
}

// Copy text to clipboard helper
function copyToClipboard(text, btnElement) {
  navigator.clipboard.writeText(text).then(() => {
    const originalText = btnElement.innerText;
    btnElement.innerText = "Copied!";
    setTimeout(() => {
      btnElement.innerText = originalText;
    }, 2000);
  });
}

// Global modal helpers
function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = "flex";
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = "none";
}

// Clear all demonstration logs
async function confirmClearLogs() {
  try {
    const res = await fetch("/api/incidents/clear", { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      window.location.reload();
    } else {
      alert(data.error || "Failed to clear logs.");
    }
  } catch (err) {
    alert("Connection error while clearing logs.");
  }
}

// Interactive Detection Page Handler
function setupDetectPage() {
  const queryInput = document.getElementById("detect-query");
  const analyzeBtn = document.getElementById("btn-analyze");
  const thresholdSlider = document.getElementById("threshold-slider");
  const thresholdVal = document.getElementById("threshold-value");
  const modelSelect = document.getElementById("model-select");
  const resultContainer = document.getElementById("detect-result");

  if (!analyzeBtn) return;

  if (thresholdSlider && thresholdVal) {
    thresholdSlider.addEventListener("input", (e) => {
      thresholdVal.innerText = parseFloat(e.target.value).toFixed(2);
    });
  }

  // Preset chips handler
  document.querySelectorAll(".preset-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const sample = chip.getAttribute("data-sample");
      if (sample && queryInput) {
        queryInput.value = sample;
        queryInput.focus();
      }
    });
  });

  analyzeBtn.addEventListener("click", async () => {
    const query = queryInput.value.trim();
    if (!query) {
      alert("Please enter a SQL query or request payload to analyze.");
      return;
    }

    const threshold = thresholdSlider ? parseFloat(thresholdSlider.value) : 0.5;
    const model = modelSelect ? modelSelect.value : "selected_model";

    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = `<span>Inspecting vector...</span>`;
    resultContainer.style.display = "none";

    try {
      const res = await fetch("/api/detect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, threshold, model }),
      });
      const data = await res.json();

      if (!res.ok) {
        alert(data.error || "Analysis failed.");
        return;
      }

      renderDetectResult(data);
    } catch (err) {
      alert("Could not connect to SQL SHIELD AI Gateway.");
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.innerHTML = `<span>Inspect Request</span>`;
    }
  });

  function renderDetectResult(data) {
    const isBlocked = data.action === "Blocked";
    resultContainer.className = `result-box ${isBlocked ? "blocked" : "allowed"}`;

    const scorePct = Math.round(data.score * 100);
    const scoreClass = scorePct < 40 ? "low" : scorePct < 75 ? "medium" : "high";

    let patternsHtml = "";
    if (data.patterns && data.patterns.length > 0) {
      patternsHtml = `
        <div style="margin: 12px 0;">
          <span style="font-size:12px;color:var(--text-secondary);font-weight:600;">Suspicious Signatures Detected:</span>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px;">
            ${data.patterns.map(p => `<span class="badge badge-warn">${p}</span>`).join("")}
          </div>
        </div>
      `;
    }

    let comparisonHtml = "";
    if (data.comparisons) {
      const rf = data.comparisons.random_forest;
      const xgb = data.comparisons.xgboost;
      if (rf && xgb) {
        comparisonHtml = `
          <div style="display:flex;gap:16px;background:var(--bg-secondary);padding:10px 14px;border-radius:6px;margin:12px 0;font-size:12px;">
            <div><strong>Random Forest:</strong> ${Math.round(rf.score * 100)}% (${rf.label})</div>
            <div style="color:var(--border-color);">|</div>
            <div><strong>XGBoost:</strong> ${Math.round(xgb.score * 100)}% (${xgb.label})</div>
          </div>
        `;
      }
    }

    resultContainer.innerHTML = `
      <div class="result-header">
        <div class="result-title">
          ${isBlocked ? "🛑 POTENTIAL SQL INJECTION (REQUEST BLOCKED)" : "🛡️ LEGITIMATE QUERY (REQUEST PERMITTED)"}
        </div>
        <div style="display:flex;gap:8px;">
          <span class="badge ${isBlocked ? "badge-block" : "badge-allow"}">${data.action}</span>
          <span class="badge badge-neutral">Severity: ${data.severity}</span>
        </div>
      </div>

      <div class="score-meter">
        <div class="score-meter-header">
          <span>ML Malicious Probability: <strong>${(data.score * 100).toFixed(1)}%</strong></span>
          <span>Decision Threshold: ${(data.threshold * 100).toFixed(0)}%</span>
        </div>
        <div class="score-track">
          <div class="score-fill ${scoreClass}" style="width: ${Math.max(scorePct, 3)}%;"></div>
        </div>
      </div>

      ${comparisonHtml}
      ${patternsHtml}

      <div style="margin: 16px 0; font-size:13px; line-height:1.6; color:var(--text-primary);">
        <p><strong>Gateway Explanation:</strong> ${data.explanation}</p>
      </div>

      <div style="background:var(--bg-secondary);padding:14px;border-radius:6px;margin:14px 0;border:1px solid var(--border-color);">
        <div style="font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:4px;">
          SIMULATED APPLICATION EXECUTION PATH:
        </div>
        <div style="font-size:13px;color:${isBlocked ? '#fca5a5' : '#86efac'};">
          ${data.simulation.gateway_action}: ${data.simulation.message}
        </div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">
          ${data.simulation.execution_details}
        </div>
      </div>

      <div style="display:flex;gap:12px;margin-top:18px;">
        <a href="/analyst?incident_id=${data.incident_id}" class="btn btn-primary btn-sm">
          🤖 Consult AI Security Analyst
        </a>
        <a href="/incidents/${data.incident_id}" class="btn btn-secondary btn-sm">
          View Incident Record #${data.incident_id}
        </a>
      </div>
    `;

    resultContainer.style.display = "block";
    resultContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

// Attack Simulation Matrix Handler
function setupSimulationPage() {
  const btnRunAll = document.getElementById("btn-run-all-sim");
  const simCards = document.querySelectorAll(".sim-card");

  if (!simCards.length) return;

  async function runSingleSim(card) {
    const query = card.getAttribute("data-query");
    const statusPill = card.querySelector(".sim-status-pill");
    const scorePill = card.querySelector(".sim-score-pill");
    const btn = card.querySelector(".btn-sim-run");

    if (btn) btn.disabled = true;
    statusPill.innerHTML = `<span style="color:var(--accent-cyan);">Testing...</span>`;

    try {
      const res = await fetch("/api/detect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
      });
      const data = await res.json();

      if (res.ok) {
        const isBlocked = data.action === "Blocked";
        statusPill.innerHTML = `<span class="badge ${isBlocked ? 'badge-block' : 'badge-allow'}">${data.action}</span>`;
        scorePill.innerHTML = `<span style="font-family:var(--font-mono);font-size:12px;color:#fff;">Score: ${(data.score * 100).toFixed(0)}%</span>`;
        card.style.borderColor = isBlocked ? "rgba(239, 68, 68, 0.4)" : "rgba(16, 185, 129, 0.4)";
      } else {
        statusPill.innerHTML = `<span class="badge badge-warn">Error</span>`;
      }
    } catch (e) {
      statusPill.innerHTML = `<span class="badge badge-warn">Failed</span>`;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  simCards.forEach(card => {
    const btn = card.querySelector(".btn-sim-run");
    if (btn) {
      btn.addEventListener("click", () => runSingleSim(card));
    }
  });

  if (btnRunAll) {
    btnRunAll.addEventListener("click", async () => {
      btnRunAll.disabled = true;
      btnRunAll.innerText = "Running Full Test Suite...";
      for (const card of simCards) {
        await runSingleSim(card);
      }
      btnRunAll.disabled = false;
      btnRunAll.innerText = "Run Full Test Suite (Sequential)";
    });
  }
}

// AI Security Analyst Page Handler
function setupAnalystPage() {
  const form = document.getElementById("analyst-form");
  const queryInput = document.getElementById("analyst-query");
  const questionInput = document.getElementById("analyst-question");
  const submitBtn = document.getElementById("btn-analyst-submit");
  const outputContainer = document.getElementById("analyst-output-box");

  if (!form || !submitBtn) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const query = queryInput ? queryInput.value.trim() : "";
    const question = questionInput ? questionInput.value.trim() : "";
    const incidentId = form.getAttribute("data-incident-id") || null;

    if (!query && !incidentId) {
      alert("Please provide a query or select an incident.");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerText = "Generating Technical Briefing...";
    outputContainer.innerHTML = `<div style="color:var(--accent-cyan);padding:20px;text-align:center;">Analyzing incident syntax, security vectors, and remediation strategies...</div>`;

    try {
      const res = await fetch("/api/security-analyst", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          incident_id: incidentId,
          query: query,
          question: question,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        outputContainer.innerHTML = `<div style="color:var(--status-block);padding:20px;">${data.error || "Analysis failed."}</div>`;
        return;
      }

      const formattedHtml = formatMarkdown(data.analysis);
      const modeLabels = {
        gemini_api: "Gemini AI Assistant",
        groq_api: "Groq AI Assistant",
        local_provider_unavailable: "AI provider unavailable",
        rule_based_fallback: "Local Security Engine",
      };
      const modeLabel = modeLabels[data.mode] || "Local Security Engine";
      const providerNote = data.note
        ? `<div style="margin-bottom:12px;color:var(--text-secondary);font-size:12px;">${data.note}</div>`
        : "";
      outputContainer.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border-color);">
          <span class="badge badge-cyan">Mode: ${modeLabel}</span>
          <button class="btn btn-secondary btn-sm" onclick="copyToClipboard(document.getElementById('raw-analyst-content').innerText, this)">Copy Report</button>
        </div>
        ${providerNote}
        <div id="raw-analyst-content" style="display:none;">${data.analysis}</div>
        <div class="analyst-output">${formattedHtml}</div>
      `;
    } catch (err) {
      outputContainer.innerHTML = `<div style="color:var(--status-block);padding:20px;">Could not connect to Security Analyst service.</div>`;
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerText = "Analyze with Security Analyst";
    }
  });
}

// Initialize components when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  setupDetectPage();
  setupSimulationPage();
  setupAnalystPage();
});
