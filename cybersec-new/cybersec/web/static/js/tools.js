const toolsModule = {
  allResults: {},

  renderResult(tool, data) {
    // Store for Executive Summary
    this.allResults[tool] = data;
    
    switch (tool) {
      case 'portscanner':
        this.renderPortScan(data);
        break;
      case 'osfp':
        this.renderOsFp(data);
        break;
      case 'webscan':
        this.renderWebscan(data);
        break;
      case 'dns':
        this.renderDNS(data);
        break;
      case 'whois':
        this.renderWhois(data);
        break;
      case 'ping':
        this.renderPing(data);
        break;
      case 'traceroute':
        this.renderTraceroute(data);
        break;
      case 'ssl':
        this.renderSSL(data);
        break;
      case 'headers':
        this.renderHeaders(data);
        break;
      case 'subdomains':
        this.renderSubdomains(data);
        break;
      case 'geo':
        this.renderGeo(data);
        break;
      case 'executive-summary':
        this.renderExecutiveSummary();
        break;
    }
  },

  renderPortScan(data) {
    const output = document.getElementById('portscanner-output');
    const actions = document.getElementById('portscanner-actions');
    if (!data || data.status === 'failed') {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data?.error || 'Scan failed'}</div>`;
      if (actions) actions.style.display = 'none';
      return;
    }
    const results = data.results || [];
    if (!results.length) {
      output.innerHTML = `<div class="alert alert-success">No open ports found on ${data.target}</div>`;
    } else {
      // Role Detection Logic (Local heuristics)
      let role = "General Host";
      let roleIcon = "fa-server";
      const ports = results.map(r => r.port);
      if (ports.includes(80) || ports.includes(443)) { role = "Web Server"; roleIcon = "fa-globe"; }
      else if (ports.includes(25) || ports.includes(465) || ports.includes(587)) { role = "Mail Server"; roleIcon = "fa-envelope"; }
      else if (ports.includes(3306) || ports.includes(5432) || ports.includes(27017)) { role = "Database Server"; roleIcon = "fa-database"; }
      else if (ports.includes(22)) { role = "Remote Access Hub"; roleIcon = "fa-key"; }

      const rows = results.map(r => `
        <tr onclick="toolsModule.renderPortDetail('${r.port}', '${r.service || 'unknown'}', '${r.version || ''}', '${data.target}')" style="cursor:pointer" class="port-row">
          <td><span class="badge" style="background:rgba(255,255,255,0.05)">${r.port}</span></td>
          <td>${r.protocol || 'tcp'}</td>
          <td style="font-weight:600">${r.service || 'unknown'} <i class="fa-solid fa-chevron-right" style="font-size:0.7rem; opacity:0.4; float:right; margin-top:4px"></i></td>
          <td><code>${r.version || '-'}</code></td>
        </tr>
      `).join('');

      output.innerHTML = `
        <div class="result-section">
          <div class="role-badge"><i class="fa-solid ${roleIcon}"></i> Detected Role: ${role}</div>
          <div class="result-title">Open Port Surface: ${data.target}</div>
          
          ${data.avg_latency_ms || data.peak_concurrency ? `
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:10px; margin-bottom:20px">
            ${data.scan_duration ? `<div class="stat-card"><div class="stat-label"><i class="fa-solid fa-stopwatch"></i> Scan Duration</div><div class="stat-value">${data.scan_duration}s</div></div>` : ''}
            ${data.avg_latency_ms ? `<div class="stat-card"><div class="stat-label"><i class="fa-solid fa-bolt"></i> Avg Latency</div><div class="stat-value" style="color:var(--accent-yellow)">${data.avg_latency_ms}ms</div></div>` : ''}
            ${data.peak_concurrency ? `<div class="stat-card"><div class="stat-label"><i class="fa-solid fa-sliders"></i> Peak Workers</div><div class="stat-value" style="color:var(--accent-purple)">${data.peak_concurrency}</div></div>` : ''}
            <div class="stat-card"><div class="stat-label"><i class="fa-solid fa-door-open"></i> Open Ports</div><div class="stat-value" style="color:var(--accent-green)">${results.length}</div></div>
          </div>` : ''}

          <div id="port-vulnerability-ai-container"></div>

          <div class="table-container" style="margin-top:20px">
            <table class="data-table">
              <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>

        <div class="next-steps-container">
           <div style="font-weight:700; margin-bottom:15px; font-size:0.9rem"><i class="fa-solid fa-wand-magic-sparkles"></i> AI Suggested Next Move</div>
           <div class="next-step-item" onclick="document.querySelector('[data-tool=osfp]').click()">
              <i class="fa-solid fa-microchip" style="color:var(--accent-purple)"></i>
              <div>
                 <div style="font-weight:600">Deep OS Fingerprinting</div>
                 <div style="font-size:0.8rem; color:var(--text-muted)">Use the open port patterns to identify the exact OS and kernel version.</div>
              </div>
           </div>
        </div>
      `;

      setTimeout(async () => {
          const aiContainer = document.getElementById('port-vulnerability-ai-container');
          if (!aiContainer) return;
          aiContainer.innerHTML = `
              <div class="ai-insight-box">
                  <div class="ai-insight-header"><i class="fa-solid fa-shield-virus fa-fade"></i> AI is correlating port vulnerabilities...</div>
                  <div class="ai-insight-content">Checking version strings against known CVE patterns.</div>
              </div>
          `;
          try {
              const analyzeResponse = await fetch('/api/ai/chat', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
                  body: JSON.stringify({ 
                      message: "Analyze these open ports and versions for " + data.target + ": " + JSON.stringify(results) + ". Identify any common vulnerability chains or 'low-hanging fruit' for an attacker (e.g., if port 21 and 80 are both open, check for data leakage). Write a 2-3 sentence tactical security summary.",
                      scan_id: null,
                      conversation_history: []
                  })
              });
              
              if (analyzeResponse.ok) {
                  const reader = analyzeResponse.body.getReader();
                  const decoder = new TextDecoder("utf-8");
                  let aiText = '';
                  aiContainer.innerHTML = `
                      <div class="ai-insight-box">
                          <div class="ai-insight-header"><i class="fa-solid fa-diagram-project"></i> Vulnerability Correlation</div>
                          <div class="ai-insight-content" id="portAiContent"></div>
                      </div>
                  `;
                  const contentBox = document.getElementById('portAiContent');
                  while(true) {
                      const { done, value } = await reader.read();
                      if (done) break;
                      const chunk = decoder.decode(value);
                      const lines = chunk.split('\n');
                      for (const line of lines) {
                          if (line.startsWith('data: ')) {
                              const text = line.slice(6);
                              if (text !== '[DONE]') {
                                  aiText += text;
                                  contentBox.innerHTML = marked.parse(aiText);
                              }
                          }
                      }
                  }
              }
          } catch(e) {}
      }, 300);
    }
    if (actions) actions.style.display = 'flex';
  },

  renderPortDetail(port, service, version, target) {
    const aiContainer = document.getElementById('port-vulnerability-ai-container');
    if (!aiContainer) return;
    
    // Smooth scroll to AI container
    aiContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    
    aiContainer.innerHTML = `
      <div class="ai-insight-box highlight">
        <div class="ai-insight-header">
            <span><i class="fa-solid fa-microchip fa-fade"></i> AI Deep Dive: Port ${port} (${service})</span>
            <button onclick="toolsModule.renderPortScan(toolsModule.allResults['portscanner'])" class="btn-mini">Show General View</button>
        </div>
        <div class="ai-insight-content">
            <div id="portSpecificAiContent">Analyzing specific risks for ${service} ${version}...</div>
            <div class="fix-suggest-box" id="portFixSuggest" style="display:none; margin-top:15px"></div>
        </div>
      </div>
    `;

    setTimeout(async () => {
        try {
            const response = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
                body: JSON.stringify({ 
                    message: `Provide a specific security recommendation for port ${port} (${service} ${version}) on target ${target}. What is the most common attack against this service and how can I fix it? Keep it short and technical.`,
                    scan_id: null,
                    conversation_history: []
                })
            });
            if (response.ok) {
                const reader = response.body.getReader();
                const decoder = new TextDecoder("utf-8");
                let aiText = '';
                const contentBox = document.getElementById('portSpecificAiContent');
                while(true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    const chunk = decoder.decode(value);
                    const lines = chunk.split('\n');
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            const text = line.slice(6);
                            if (text !== '[DONE]') {
                                aiText += text;
                                contentBox.innerHTML = marked.parse(aiText);
                            }
                        }
                    }
                }
            }
        } catch(e) {}
    }, 100);
  },

  renderOsFp(data) {
    const output = document.getElementById('osfp-output');
    if (!data || data.error) {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data?.error || 'OS fingerprint failed'}</div>`;
      document.getElementById('osfp-actions').style.display = 'none';
      return;
    }

    let confidencePct = data.confidence_pct || 0;
    if (confidencePct > 100) {
      confidencePct = Math.min(Math.round(confidencePct / 100), 100);
    }
    
    const getConfidenceColor = (pct) => {
      if (pct >= 80) return '#6acf80';
      if (pct >= 50) return '#f0b860';
      return '#f07070';
    };
    const confColor = getConfidenceColor(confidencePct);
    
    const openPorts = data.open_ports_scanned || [];
    const portsHtml = openPorts.map(p => `<span class="osfp-port-pill">${p}</span>`).join('');

    let icon = 'fa-solid fa-desktop';
    const osLower = (data.os_name || '').toLowerCase();
    if (osLower.includes('linux') || osLower.includes('ubuntu') || osLower.includes('debian') || osLower.includes('unix')) icon = 'fa-brands fa-linux';
    else if (osLower.includes('windows')) icon = 'fa-brands fa-windows';
    else if (osLower.includes('mac') || osLower.includes('apple') || osLower.includes('osx')) icon = 'fa-brands fa-apple';

    output.innerHTML = `
      <style>
        @keyframes osfp-fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes osfp-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .osfp-zone { animation: osfp-fadeIn 0.4s ease-out forwards; opacity: 0; }
        .osfp-zone-1 { animation-delay: 0ms; }
        .osfp-zone-2 { animation-delay: 80ms; }
        .osfp-zone-3 { animation-delay: 160ms; }
        .osfp-zone-4 { animation-delay: 240ms; }
        .osfp-zone-5 { animation-delay: 320ms; }
        .osfp-pulse-dot { width: 6px; height: 6px; border-radius: 50%; background: #a78bfa; animation: osfp-pulse 2s infinite; }
        .osfp-hero-card { background: #111318; border: 0.5px solid #2a2d35; border-radius: 10px; padding: 20px 24px; display: flex; align-items: center; gap: 20px; }
        .osfp-hero-icon { font-size: 32px; color: #a78bfa; }
        .osfp-hero-info { flex: 1; }
        .osfp-hero-name { font-size: 22px; font-weight: 600; color: #e2e3e7; }
        .osfp-hero-sub { font-size: 12px; color: #6b6e78; margin-top: 4px; }
        .osfp-confidence-box { background: #111318; border: 0.5px solid #2a2d35; border-radius: 8px; padding: 10px 16px; text-align: center; min-width: 90px; }
        .osfp-confidence-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6b6e78; }
        .osfp-confidence-value { font-size: 20px; font-weight: 600; display: block; margin-top: 4px; }
        .osfp-confidence-bar { height: 4px; background: #1e2028; border-radius: 2px; margin-top: 8px; overflow: hidden; }
        .osfp-confidence-fill { height: 100%; border-radius: 2px; transition: width 0.8s ease-out; }
        .osfp-details-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 12px; }
        .osfp-detail-card { background: #111318; border: 0.5px solid #2a2d35; border-radius: 8px; padding: 12px 14px; }
        .osfp-detail-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: #6b6e78; margin-bottom: 4px; }
        .osfp-detail-value { font-size: 14px; font-weight: 500; color: #e2e3e7; }
        .osfp-detail-value.mono { font-family: monospace; }
        .osfp-port-pills { display: flex; flex-wrap: wrap; gap: 6px; }
        .osfp-port-pill { background: #1e2130; color: #a78bfa; border: 0.5px solid #4a3a8e; border-radius: 20px; padding: 2px 10px; font-size: 12px; font-family: monospace; display: inline-flex; align-items: center; }
        .osfp-collapse-header { background: #161820; border: 0.5px solid #2a2d35; border-radius: 8px; padding: 10px 14px; display: flex; align-items: center; cursor: pointer; margin-top: 12px; }
        .osfp-collapse-header:hover { background: #1a1d26; }
        .osfp-collapse-icon { font-size: 16px; color: #6b6e78; margin-right: 10px; }
        .osfp-collapse-title { font-size: 13px; color: #b0b2ba; flex: 1; }
        .osfp-collapse-arrow { color: #6b6e78; transition: transform 0.2s; }
        .osfp-collapse-arrow.open { transform: rotate(180deg); }
        .osfp-collapse-content { background: #0d0f14; border: 0.5px solid #2a2d35; border-top: none; border-radius: 0 0 8px 8px; padding: 14px 16px; display: none; }
        .osfp-collapse-content.open { display: block; }
        .osfp-collapse-row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 0.5px solid #1e2028; }
        .osfp-collapse-row:last-child { border-bottom: none; }
        .osfp-collapse-key { font-size: 12px; color: #6b6e78; }
        .osfp-collapse-val { font-size: 12px; font-family: monospace; color: #b0b2ba; }
        .osfp-ai-insight { background: #13101e; border: 0.5px solid #3d2d6e; border-radius: 10px; padding: 16px 20px; margin-top: 12px; }
        .osfp-ai-header { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; font-size: 13px; font-weight: 500; color: #a78bfa; }
        .osfp-ai-content { font-size: 13px; line-height: 1.7; color: #b0b2ba; }
        .osfp-actions-bar { display: flex; align-items: center; gap: 8px; padding-top: 14px; border-top: 0.5px solid #2a2d35; margin-top: 12px; }
        .osfp-rescan-btn { background: transparent; border: 1px solid #2a2d35; color: #b0b2ba; padding: 6px 14px; border-radius: 6px; font-size: 12px; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: all 0.2s; }
        .osfp-rescan-btn:hover { background: #1a1d26; border-color: #3a3d45; }
        .osfp-meta { font-size: 11px; color: #4a4d58; margin-left: auto; }
        .osfp-loading-text { color: #6b6e78; font-style: italic; }
      </style>

      <div class="osfp-zone osfp-zone-1">
        <div class="osfp-hero-card">
          <i class="${icon} osfp-hero-icon"></i>
          <div class="osfp-hero-info">
            <div class="osfp-hero-name">${data.os_name || 'Unknown'}</div>
            <div class="osfp-hero-sub">Detected via ${data.method || 'port_pattern'}</div>
          </div>
          <div class="osfp-confidence-box">
            <div class="osfp-confidence-label">Confidence</div>
            <span class="osfp-confidence-value" style="color: ${confColor}" data-target="${confidencePct}">0%</span>
            <div class="osfp-confidence-bar">
              <div class="osfp-confidence-fill" style="width: 0%; background: ${confColor}" data-target="${confidencePct}"></div>
            </div>
          </div>
        </div>
      </div>

      <div class="osfp-zone osfp-zone-2">
        <div class="osfp-details-grid">
          <div class="osfp-detail-card">
            <div class="osfp-detail-label">TTL Analysis</div>
            <div class="osfp-detail-value">Not performed</div>
          </div>
          <div class="osfp-detail-card">
            <div class="osfp-detail-label">TCP Window Size</div>
            <div class="osfp-detail-value">Not detected</div>
          </div>
          <div class="osfp-detail-card">
            <div class="osfp-detail-label">SYN Packet Logic</div>
            <div class="osfp-detail-value">Standard detection</div>
          </div>
          <div class="osfp-detail-card">
            <div class="osfp-detail-label">Detection Method</div>
            <div class="osfp-detail-value">${data.method || 'port_pattern'}</div>
          </div>
          <div class="osfp-detail-card">
            <div class="osfp-detail-label">Scan Mode</div>
            <div class="osfp-detail-value">Common ports</div>
          </div>
          <div class="osfp-detail-card">
            <div class="osfp-detail-label">Observed Ports</div>
            <div class="osfp-port-pills">${openPorts.length > 0 ? portsHtml : '<span class="osfp-detail-value">None detected</span>'}</div>
          </div>
        </div>
      </div>

      <div class="osfp-zone osfp-zone-3">
        <div class="osfp-collapse-header" onclick="this.querySelector('.osfp-collapse-arrow').classList.toggle('open'); this.nextElementSibling.classList.toggle('open');">
          <i class="fa-solid fa-gear osfp-collapse-icon"></i>
          <span class="osfp-collapse-title">Technical Details</span>
          <i class="fa-solid fa-chevron-down osfp-collapse-arrow"></i>
        </div>
        <div class="osfp-collapse-content">
          <div class="osfp-collapse-row">
            <span class="osfp-collapse-key">TTL Analysis</span>
            <span class="osfp-collapse-val">Not performed in this mode</span>
          </div>
          <div class="osfp-collapse-row">
            <span class="osfp-collapse-key">TCP Window Size</span>
            <span class="osfp-collapse-val">Not detected</span>
          </div>
          <div class="osfp-collapse-row">
            <span class="osfp-collapse-key">SYN Packet Logic</span>
            <span class="osfp-collapse-val">Fingerprinted via standard detection parameters</span>
          </div>
        </div>
      </div>

      <div class="osfp-zone osfp-zone-4">
        <div id="osfp-ai-container">
          <div class="osfp-ai-insight">
            <div class="osfp-ai-header">
              <span class="osfp-pulse-dot"></span>
              <span>AI Insight</span>
            </div>
            <div class="osfp-ai-content osfp-loading-text">Analyzing fingerprint data...</div>
          </div>
        </div>
      </div>

      <div class="osfp-zone osfp-zone-5">
        <div class="osfp-actions-bar">
          <button class="btn-secondary" onclick="copyToolResult('osfp')"><i class="fa-solid fa-copy"></i> Copy</button>
          <button class="osfp-rescan-btn" onclick="runTool('osfp')"><i class="fa-solid fa-rotate-right"></i> Re-scan</button>
          <span class="osfp-meta">Scanned &middot; ${data.target || 'unknown'} &middot; just now</span>
        </div>
      </div>
    `;

    const confidenceEl = output.querySelector('.osfp-confidence-value');
    const confidenceFill = output.querySelector('.osfp-confidence-fill');
    if (confidenceEl && confidenceFill) {
      const target = parseFloat(confidenceEl.dataset.target);
      let current = 0;
      const startTime = performance.now();
      const duration = 800;
      const animate = (now) => {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        current = Math.round(target * progress);
        confidenceEl.textContent = current + '% confident';
        confidenceFill.style.width = progress * 100 + '%';
        if (progress < 1) requestAnimationFrame(animate);
      };
      requestAnimationFrame(animate);
    }

    document.getElementById('osfp-actions').style.display = 'none';

    setTimeout(async () => {
      const aiContainer = document.getElementById('osfp-ai-container');
      if (!aiContainer) return;
      try {
        const analyzeResponse = await fetch('/api/ai/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
          body: JSON.stringify({
            message: "Based on the open ports detected (" + openPorts.join(', ') + "), confirm if the primary OS guess of " + (data.os_name || 'Unknown') + " (" + confidencePct + "% confidence) is accurate. Write a strict 2-3 sentence technical intuition.",
            scan_id: null,
            conversation_history: []
          })
        });
        
        if (analyzeResponse.ok) {
          const reader = analyzeResponse.body.getReader();
          const decoder = new TextDecoder("utf-8");
          let aiText = '';
          aiContainer.innerHTML = `
            <div class="osfp-ai-insight">
              <div class="osfp-ai-header">
                <span class="osfp-pulse-dot"></span>
                <span>AI Insight</span>
              </div>
              <div class="osfp-ai-content" id="osAiContent"></div>
            </div>
          `;
          const contentBox = document.getElementById('osAiContent');
          while(true) {
            const { done, value } = await reader.read();
            if (done) break;
            const chunk = decoder.decode(value);
            const lines = chunk.split('\n');
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                const text = line.slice(6);
                if (text !== '[DONE]') {
                  aiText += text;
                  contentBox.innerHTML = marked.parse(aiText);
                }
              }
            }
          }
        }
      } catch(e) {}
    }, 100);
  },

  renderWebscan(data, isComplete = false) {
    const output = document.getElementById('webscan-output');
    const actions = document.getElementById('webscan-actions');
    
    const resultData = data.result || data;
    
    if (!resultData || resultData.error) {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${resultData?.error || 'Scan failed'}</div>`;
      if (actions) actions.style.display = 'none';
      return;
    }

    const vulnerabilities = resultData.vulnerabilities || [];
    const criticalCount = resultData.critical_count || 0;
    const highCount = resultData.high_count || 0;
    const mediumCount = resultData.medium_count || 0;
    const lowCount = resultData.low_count || 0;
    const pagesCrawled = resultData.pages_crawled || 0;
    
    const totalVulns = criticalCount + highCount + mediumCount + lowCount;
    const scanDuration = window.webscanStartTime ? ((Date.now() - window.webscanStartTime) / 1000).toFixed(1) : '0.0';

    const vulnTypeLabels = {
      'SQLi': 'SQL Injection',
      'XSS': 'Cross-Site Scripting',
      'CSRF': 'Cross-Site Request Forgery',
      'CORS': 'CORS Misconfiguration',
      'MISSING_HEADER': 'Missing Security Header',
      'EXPOSED_FILE': 'Exposed Sensitive File',
      'SCAN_NOTE': 'Scan Note'
    };

    const groupVulns = {};
    vulnerabilities.forEach(v => {
      const type = v.vuln_type;
      if (!groupVulns[type]) groupVulns[type] = [];
      groupVulns[type].push(v);
    });

    const groupLabels = {
      'MISSING_HEADER': 'Security Headers',
      'CORS': 'CORS Configuration',
      'EXPOSED_FILE': 'Exposed Files',
      'SQLi': 'SQL Injection',
      'XSS': 'Cross-Site Scripting',
      'CSRF': 'Cross-Site Request Forgery',
      'SCAN_NOTE': 'Scan Notes'
    };

    const vulnGroups = Object.entries(groupVulns).map(([type, vulns]) => {
      const rows = vulns.map(v => {
        const hasDetail = v.recommendation;
        return `
        <tr>
          <td><span class="ws-badge ws-badge-${v.severity.toLowerCase()}">${v.severity}</span></td>
          <td class="ws-type-cell">${vulnTypeLabels[v.vuln_type] || v.vuln_type}</td>
          <td class="ws-param-cell">${v.parameter ? v.parameter : '-'}</td>
          <td class="ws-loc-cell">${(v.url || resultData.base_url || '').substring(0, 50)}</td>
          <td>${hasDetail ? `<button class="ws-expand-btn" onclick="this.classList.toggle('expanded'); this.closest('tr').nextElementSibling.classList.toggle('show')"><i class="fa-solid fa-chevron-down"></i></button>` : ''}</td>
        </tr>
        ${hasDetail ? `
        <tr class="ws-detail-row">
          <td colspan="5">
            <div class="ws-detail-content">${v.recommendation}</div>
          </td>
        </tr>
        ` : ''}
      `}).join('');
      return `
        <tbody class="ws-group">
          <tr class="ws-group-header">
            <td colspan="5"><span class="ws-group-label">${groupLabels[type] || type}</span> <span class="ws-group-count">${vulns.length}</span></td>
          </tr>
          ${rows}
        </tbody>
      `;
    }).join('');

    const crawlerWarning = pagesCrawled === 0 && isComplete ? `
      <div class="ws-crawler-warning">
        <i class="fa-solid fa-triangle-exclamation"></i>
        <div>Crawler returned 0 pages. The target may be blocking automated requests or requires authentication. Vulnerability checks were run against the root URL only.</div>
      </div>
    ` : '';

    const targetDisplay = resultData.target || resultData.base_url || 'unknown';

    output.innerHTML = `
      <style>
        @keyframes ws-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        @keyframes ws-fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
        #webscan-output { max-height: none !important; height: auto !important; overflow: visible !important; }
        .ws-summary-bar { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 16px; animation: ws-fadeIn 0.3s ease-out; }
        @media (max-width: 600px) { .ws-summary-bar { grid-template-columns: repeat(2, 1fr); } }
        .ws-stat-card { background: #111318; border: 0.5px solid #2a2d35; border-radius: 8px; padding: 12px 16px; text-align: center; }
        .ws-stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: #6b6e78; margin-bottom: 6px; }
        .ws-stat-value { font-size: 22px; font-weight: 500; color: #e2e3e7; }
        .ws-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; text-transform: uppercase; }
        .ws-badge-critical { background: rgba(240,112,112,0.15); color: #f07070; border: 1px solid rgba(240,112,112,0.3); }
        .ws-badge-high { background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }
        .ws-badge-medium { background: rgba(245,158,11,0.15); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); }
        .ws-badge-low { background: rgba(106,207,128,0.15); color: #6acf80; border: 1px solid rgba(106,207,128,0.3); }
        .ws-badge-info { background: rgba(78,205,196,0.15); color: #4ecdc4; border: 1px solid rgba(78,205,196,0.3); }
        .ws-crawler-warning { background: #2a2010; border: 0.5px solid #5a4010; border-radius: 8px; padding: 12px 16px; display: flex; gap: 10px; align-items: flex-start; margin-bottom: 16px; font-size: 13px; color: #f0b860; }
        .ws-crawler-warning i { color: #f0b860; font-size: 14px; margin-top: 2px; }
        .ws-table-wrapper { overflow-x: auto; margin-top: 16px; animation: ws-fadeIn 0.3s ease-out 0.1s both; }
        .ws-vuln-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .ws-vuln-table th { text-align: left; padding: 10px 14px; background: #161820; border-bottom: 1px solid #2a2d35; color: #6b6e78; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
        .ws-vuln-table td { padding: 0 14px; min-height: 48px; border-bottom: 0.5px solid #1e2028; vertical-align: middle; }
        .ws-vuln-table tr:hover { background: #13151c; }
        .ws-type-cell { font-size: 13px; color: #e2e3e7; }
        .ws-param-cell { font-family: monospace; font-size: 12px; color: #b0b2ba; }
        .ws-loc-cell { font-size: 12px; color: #6b6e78; }
        .ws-group-header td { background: #0d0f14; border-left: 3px solid #a78bfa; padding: 8px 14px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #a78bfa; font-weight: 500; }
        .ws-group-count { margin-left: 8px; background: #1e2130; color: #a78bfa; border: 0.5px solid #4a3a8e; border-radius: 20px; padding: 2px 8px; font-size: 11px; }
        .ws-expand-btn { background: none; border: none; color: #6b6e78; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: transform 0.2s; }
        .ws-expand-btn:hover { background: #1e2130; }
        .ws-expand-btn.expanded { transform: rotate(180deg); }
        .ws-detail-row { display: none; }
        .ws-detail-row.show { display: table-row; }
        .ws-detail-content { background: #0d0f14; border-top: 0.5px solid #1e2028; padding: 12px 16px 14px 48px; font-size: 13px; color: #b0b2ba; line-height: 1.6; }
        .ws-no-vulns { background: rgba(106,207,128,0.1); border: 0.5px solid rgba(106,207,128,0.3); border-radius: 8px; padding: 16px 20px; color: #6acf80; text-align: center; margin-top: 16px; }
        .ws-actions-bar { display: flex; align-items: center; gap: 8px; padding: 12px 14px 0; border-top: 0.5px solid #2a2d35; margin-top: 16px; animation: ws-fadeIn 0.3s ease-out 0.2s both; }
        .ws-rescan-btn { background: transparent; border: 1px solid #2a2d35; color: #b0b2ba; padding: 6px 14px; border-radius: 6px; font-size: 12px; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: all 0.2s; }
        .ws-rescan-btn:hover { background: #1a1d26; border-color: #3a3d45; }
        .ws-meta { font-size: 11px; color: #4a4d58; margin-left: auto; }
        .ws-log-section { margin-top: 16px; animation: ws-fadeIn 0.3s ease-out 0.3s both; }
        .ws-log-header { background: #161820; border: 0.5px solid #2a2d35; border-radius: 8px; padding: 10px 14px; display: flex; align-items: center; gap: 10px; cursor: pointer; font-size: 13px; color: #b0b2ba; }
        .ws-log-header:hover { background: #1a1d26; }
        .ws-log-header i:first-child { color: #6b6e78; }
        .ws-log-arrow { margin-left: auto; color: #6b6e78; transition: transform 0.2s; }
        .ws-log-header.open .ws-log-arrow { transform: rotate(180deg); }
        .ws-log-content { background: #0d0f14; border: 0.5px solid #2a2d35; border-top: none; border-radius: 0 0 8px 8px; max-height: 200px; overflow-y: auto; display: none; }
        .ws-log-content.open { display: block; }
        .ws-ai-insight { background: #13101e; border: 0.5px solid #3d2d6e; border-radius: 10px; padding: 16px 20px; margin-top: 16px; animation: ws-fadeIn 0.3s ease-out 0.4s both; }
        .ws-ai-inner { background: transparent; }
        .ws-ai-header { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; font-size: 13px; font-weight: 500; color: #a78bfa; }
        .ws-pulse-dot { width: 6px; height: 6px; border-radius: 50%; background: #a78bfa; animation: ws-pulse 2s infinite; }
        .ws-ai-content { font-size: 13px; line-height: 1.7; color: #b0b2ba; }
        .ws-ai-content a { color: #a78bfa; font-family: monospace; font-size: 12px; text-decoration: none; }
        .ws-progress-item { padding: 4px 0; border-bottom: 1px solid #1e2028; display: flex; gap: 12px; animation: ws-fadeIn 0.2s ease-out; }
        .ws-progress-item:last-child { border-bottom: none; }
        .ws-progress-time { color: #4a4a58; font-size: 11px; min-width: 70px; }
        .ws-progress-stage { color: #a78bfa; font-size: 11px; min-width: 80px; }
        .ws-progress-msg { color: #b0b2ba; font-size: 12px; flex: 1; }
        .ws-progress-dot { width: 6px; height: 6px; border-radius: 50%; margin-right: 6px; }
        .ws-dot-success { background: #6acf80; }
        .ws-dot-running { background: #a78bfa; animation: ws-pulse 1s infinite; }
        .ws-dot-error { background: #f07070; }
      </style>

      <div class="ws-summary-bar">
        <div class="ws-stat-card">
          <div class="ws-stat-label">Total Vulnerabilities</div>
          <div class="ws-stat-value" style="color: ${totalVulns > 0 ? '#f07070' : '#6acf80'}">${totalVulns}</div>
        </div>
        <div class="ws-stat-card">
          <div class="ws-stat-label">Pages Crawled</div>
          <div class="ws-stat-value">${pagesCrawled}</div>
        </div>
        <div class="ws-stat-card">
          <div class="ws-stat-label">Checks Run</div>
          <div class="ws-stat-value">${4 + pagesCrawled}</div>
        </div>
        <div class="ws-stat-card">
          <div class="ws-stat-label">Scan Duration</div>
          <div class="ws-stat-value">${scanDuration}s</div>
        </div>
      </div>

      ${crawlerWarning}

      ${totalVulns > 0 ? `
        <div class="ws-table-wrapper">
          <table class="ws-vuln-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>Parameter</th>
                <th>Location</th>
                <th></th>
              </tr>
            </thead>
            ${vulnGroups}
          </table>
        </div>
      ` : (isComplete ? `<div class="ws-no-vulns">No vulnerabilities detected. The site appears well-configured.</div>` : `
        <div class="ws-no-vulns" style="background: rgba(167,139,250,0.1); border-color: rgba(167,139,250,0.3); color: #a78bfa;">
          <i class="fa-solid fa-spinner fa-spin" style="margin-right: 8px;"></i> Scanning in progress...
        </div>
      `)}

      <div class="ws-actions-bar">
        <button class="btn-secondary" onclick="copyToolResult('webscan')"><i class="fa-solid fa-copy"></i> Copy</button>
        <button class="ws-rescan-btn" onclick="runTool('webscan')"><i class="fa-solid fa-rotate-right"></i> Re-scan</button>
        <span class="ws-meta">Scanned &middot; ${targetDisplay} &middot; ${isComplete ? 'just now' : 'in progress'}</span>
      </div>

      <div class="ws-ai-insight" id="web-ai-executive-insight"></div>
    `;

    if (isComplete) {
      const logEl = document.getElementById('webscan-log');
      if (logEl && logEl.children.length > 1) {
        const logSection = document.createElement('div');
        logSection.className = 'ws-log-section';
        logSection.innerHTML = `
          <div class="ws-log-header" onclick="this.classList.toggle('open'); this.nextElementSibling.classList.toggle('open')">
            <i class="fa-solid fa-terminal"></i>
            <span>Technical Log</span>
            <i class="fa-solid fa-chevron-down ws-log-arrow"></i>
          </div>
          <div class="ws-log-content"></div>
        `;
        logSection.querySelector('.ws-log-content').appendChild(logEl);
        output.appendChild(logSection);
      }

      setTimeout(async () => {
        const aiInsight = document.getElementById('web-ai-executive-insight');
        if (!aiInsight) return;
        aiInsight.innerHTML = `
          <div class="ws-ai-inner">
            <div class="ws-ai-header"><span class="ws-pulse-dot"></span> AI is analyzing vulnerabilities...</div>
          </div>
        `;
        try {
          const analyzeResponse = await fetch('/api/ai/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
            body: JSON.stringify({ 
              message: "Summarize these web vulnerabilities for " + targetDisplay + ": " + JSON.stringify(vulnerabilities) + ". Provide a 2-sentence executive risk summary and the single most critical fix needed first.",
              scan_id: null,
              conversation_history: []
            })
          });
          if (analyzeResponse.ok) {
            const reader = analyzeResponse.body.getReader();
            const decoder = new TextDecoder("utf-8");
            let aiText = '';
            aiInsight.innerHTML = `
              <div class="ws-ai-inner">
                <div class="ws-ai-header"><span class="ws-pulse-dot"></span> Executive Risk Summary</div>
                <div class="ws-ai-content" id="webAiExecContent"></div>
              </div>
            `;
            const contentBox = document.getElementById('webAiExecContent');
            while(true) {
              const { done, value } = await reader.read();
              if (done) break;
              const chunk = decoder.decode(value);
              const lines = chunk.split('\n');
              for (const line of lines) {
                if (line.startsWith('data: ')) {
                  const text = line.slice(6);
                  if (text !== '[DONE]') {
                    aiText += text;
                    let parsed = marked.parse(aiText);
                    parsed = parsed.replace(/href="(https?:\/\/[^"]+)"/g, 'style="color:#a78bfa;font-family:monospace;font-size:12px;"');
                    contentBox.innerHTML = parsed;
                  }
                }
              }
            }
          }
        } catch(e) {}
      }, 300);
    }

    if (actions) actions.style.display = 'none';
  },

  renderDNS(data) {
    const output = document.getElementById('dns-output');
    const actions = document.getElementById('dns-actions');
    if (data.error) {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error}</div>`;
      if (actions) actions.style.display = 'none';
      return;
    }

    const aRecs = data.a_records || [];
    const mxRecs = data.mx_records || [];
    const txtRecs = data.txt_records || [];
    const nsRecs = data.ns_records || [];

    const allRecords = [
      ...aRecs.map(r => ({ type: 'A', value: r })),
      ...(data.aaaa_records || []).map(r => ({ type: 'AAAA', value: r })),
      ...mxRecs.map(r => ({ type: 'MX', value: r })),
      ...nsRecs.map(r => ({ type: 'NS', value: r })),
      ...txtRecs.map(r => ({ type: 'TXT', value: r })),
      ...(data.cname_records || []).map(r => ({ type: 'CNAME', value: r })),
      ...(data.soa_record ? [{ type: 'SOA', value: data.soa_record }] : []),
    ];

    if (allRecords.length === 0) {
      output.innerHTML = `<div class="alert alert-warning">No DNS records found for ${data.target}</div>`;
      return;
    }

    // Health Checks
    const hasSPF = txtRecs.some(t => t.toLowerCase().includes('v=spf1'));
    const hasDMARC = txtRecs.some(t => t.toLowerCase().includes('v=dmarc1'));
    const hasMX = mxRecs.length > 0;

    const rows = allRecords.map(r => `<tr><td><span class="badge" style="background:rgba(255,255,255,0.05)">${r.type}</span></td><td><code>${r.value}</code></td></tr>`).join('');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">DNS Records: ${data.target}</div>
        
        <div class="dns-health-card">
           <div style="font-weight:700; margin-bottom:12px; font-size:0.9rem; color:var(--text-secondary)">🛡️ SECURITY HEALTH CHECK</div>
           <div class="dns-health-item ${hasSPF ? 'pass' : 'issue'}">
              <i class="fa-solid ${hasSPF ? 'fa-check-circle' : 'fa-circle-exclamation'} status"></i>
              <span><strong>SPF Record:</strong> ${hasSPF ? 'Present' : 'Missing (Risk of Email Spoofing)'}</span>
           </div>
           <div class="dns-health-item ${hasDMARC ? 'pass' : 'issue'}">
              <i class="fa-solid ${hasDMARC ? 'fa-check-circle' : 'fa-circle-exclamation'} status"></i>
              <span><strong>DMARC Policy:</strong> ${hasDMARC ? 'Present' : 'Not Detected (Phishing Risk)'}</span>
           </div>
           <div class="dns-health-item ${hasMX ? 'pass' : 'issue'}">
              <i class="fa-solid ${hasMX ? 'fa-check-circle' : 'fa-circle-exclamation'} status"></i>
              <span><strong>Email Servers:</strong> ${hasMX ? `${mxRecs.length} Servers Found` : 'None Configured'}</span>
           </div>
        </div>

        <div class="table-container" style="margin-top:20px">
          <table class="data-table">
            <thead><tr><th>Type</th><th>Value</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>

      <div id="dns-ai-analysis-container" style="margin-top:20px;"></div>

      <div class="next-steps-container">
         <div style="font-weight:700; margin-bottom:15px; font-size:0.9rem"><i class="fa-solid fa-wand-magic-sparkles"></i> AI Suggested Next Move</div>
         <div class="next-step-item" onclick="document.querySelector('[data-tool=whois]').click()">
            <i class="fa-solid fa-address-card" style="color:var(--accent-blue)"></i>
            <div>
               <div style="font-weight:600">Analyze WHOIS Records</div>
               <div style="font-size:0.8rem; color:var(--text-muted)">Cross-reference registrar and nameserver records for full OSINT.</div>
            </div>
         </div>
      </div>
    `;

    setTimeout(async () => {
        const aiContainer = document.getElementById('dns-ai-analysis-container');
        if (!aiContainer) return;
        aiContainer.innerHTML = `
            <div class="ai-insight-box">
                <div class="ai-insight-header"><i class="fa-solid fa-robot fa-fade"></i> AI is analyzing DNS hygiene...</div>
                <div class="ai-insight-content">Groq is checking for spoofing avenues and configuration flaws.</div>
            </div>
        `;
        try {
            const analyzeResponse = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
                body: JSON.stringify({ 
                    message: "Analyze these DNS records for " + data.target + ". Records: " + JSON.stringify(data) + ". Identify any missing email security records (SPF/DMARC/DKIM) or misconfigurations that could lead to spoofing or subdomain hijacking. Write a 2-3 sentence technical overview.",
                    scan_id: null,
                    conversation_history: []
                })
            });
            
            if (analyzeResponse.ok) {
                const reader = analyzeResponse.body.getReader();
                const decoder = new TextDecoder("utf-8");
                let aiText = '';
                aiContainer.innerHTML = `
                    <div class="ai-insight-box">
                        <div class="ai-insight-header"><i class="fa-solid fa-fingerprint"></i> DNS Misconfiguration Insight</div>
                        <div class="ai-insight-content" id="dnsAiContent"></div>
                    </div>
                `;
                const contentBox = document.getElementById('dnsAiContent');
                while(true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    const chunk = decoder.decode(value);
                    const lines = chunk.split('\n');
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            const text = line.slice(6);
                            if (text !== '[DONE]') {
                                aiText += text;
                                contentBox.innerHTML = marked.parse(aiText);
                            }
                        }
                    }
                }
            } else { aiContainer.innerHTML = ''; }
        } catch(e) { aiContainer.innerHTML = ''; }
    }, 200);

    if (actions) actions.style.display = 'flex';
  },

  renderWhois(data) {
    const output = document.getElementById('whois-output');
    const actions = document.getElementById('whois-actions');

    if (data.error) {
      output.innerHTML = `<div class="result-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error}</div>`;
      if (actions) actions.style.display = 'none';
      return;
    }

    const created = data.creation_date ? new Date(data.creation_date) : null;
    const expires = data.expiration_date ? new Date(data.expiration_date) : null;
    const updated = data.updated_date ? new Date(data.updated_date) : null;
    const now = new Date();
    
    const fmtDate = (d) => {
      if (!d) return '<span class="unknown">N/A</span>';
      const date = new Date(d);
      if (isNaN(date.getTime())) return `<span class="unknown">${d}</span>`;
      return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    };

    let ageHtml = '';
    let ageValue = 0;
    if (created && !isNaN(created.getFullYear())) {
      ageValue = (now - created) / (1000 * 60 * 60 * 24 * 365);
      const months = (ageValue * 12).toFixed(1);
      if (ageValue > 5) {
        ageHtml = `<div class="whois-health-item pass"><i class="fa-solid fa-check-circle"></i><span><strong>Domain Age:</strong> ${ageValue.toFixed(1)} years - <span class="pass-text">Trusted</span></span></div>`;
      } else if (ageValue < 1) {
        ageHtml = `<div class="whois-health-item risk"><i class="fa-solid fa-triangle-exclamation"></i><span><strong>Domain Age:</strong> ${months} months - <span class="risk-text">Suspicious/New</span></span></div>`;
      } else {
        ageHtml = `<div class="whois-health-item warn"><i class="fa-solid fa-clock"></i><span><strong>Domain Age:</strong> ${ageValue.toFixed(1)} years</span></div>`;
      }
    } else {
      ageHtml = `<div class="whois-health-item warn"><i class="fa-solid fa-question-circle"></i><span><strong>Domain Age:</strong> <span class="unknown">Unknown</span></span></div>`;
    }

    let expHtml = '';
    if (expires && !isNaN(expires.getFullYear())) {
      const daysLeft = Math.round((expires - now) / (1000 * 60 * 60 * 24));
      if (daysLeft < 0) {
        expHtml = `<div class="whois-health-item risk"><i class="fa-solid fa-calendar-xmark"></i><span><strong>Expiry:</strong> <span class="risk-text">EXPIRED</span></span></div>`;
      } else if (daysLeft < 30) {
        expHtml = `<div class="whois-health-item risk"><i class="fa-solid fa-clock"></i><span><strong>Expiry:</strong> ${daysLeft} days - <span class="risk-text">High Risk</span></span></div>`;
      } else if (daysLeft < 90) {
        expHtml = `<div class="whois-health-item warn"><i class="fa-solid fa-calendar"></i><span><strong>Expiry:</strong> ${daysLeft} days - <span class="warn-text">Soon</span></span></div>`;
      } else {
        expHtml = `<div class="whois-health-item pass"><i class="fa-solid fa-calendar-check"></i><span><strong>Expiry:</strong> ${daysLeft} days - <span class="pass-text">Safe</span></span></div>`;
      }
    } else {
      expHtml = `<div class="whois-health-item warn"><i class="fa-solid fa-question-circle"></i><span><strong>Expiry:</strong> <span class="unknown">Unknown</span></span></div>`;
    }

    let timelineHtml = '';
    if (created && expires && !isNaN(created.getFullYear()) && !isNaN(expires.getFullYear())) {
      const startYear = created.getFullYear();
      const endYear = expires.getFullYear();
      const currentYear = now.getFullYear();
      const totalLength = endYear - startYear;
      const progress = totalLength > 0 ? ((currentYear - startYear) / totalLength) * 100 : 100;
      const cleanProgress = Math.max(0, Math.min(100, progress));
      
      timelineHtml = `
        <div class="whois-timeline">
          <div class="whois-timeline-track">
            <div class="whois-timeline-fill" style="width: ${cleanProgress}%"></div>
            <div class="whois-timeline-marker start">${startYear}</div>
            <div class="whois-timeline-marker end">${endYear}</div>
          </div>
          <div class="whois-timeline-labels">
            <span>Created</span>
            <span>Today</span>
            <span>Expires</span>
          </div>
        </div>
      `;
    }

    let nsListHtml = '<span class="unknown">No name servers found</span>';
    if (Array.isArray(data.name_servers) && data.name_servers.length > 0) {
      nsListHtml = '<div class="whois-ns-grid">' + data.name_servers.map(n => `<span class="whois-ns-item"><i class="fa-solid fa-server"></i> ${n}</span>`).join('') + '</div>';
    } else if (data.name_servers && typeof data.name_servers === 'string') {
      nsListHtml = `<span class="whois-ns-item"><i class="fa-solid fa-server"></i> ${data.name_servers}</span>`;
    }

    let statusHtml = '';
    if (Array.isArray(data.status) && data.status.length > 0) {
      const statusBadges = data.status.slice(0, 5).map(s => {
        const isActive = s.toLowerCase().includes('active');
        return `<span class="whois-status-badge ${isActive ? 'active' : 'inactive'}">${s}</span>`;
      }).join('');
      statusHtml = `<div class="whois-detail-row"><span class="whois-detail-label">Status</span><span class="whois-detail-value">${statusBadges}</span></div>`;
    }

    let contactHtml = '';
    if (data.org || data.country || (Array.isArray(data.emails) && data.emails.length > 0)) {
      const emails = Array.isArray(data.emails) ? data.emails.slice(0, 3).join(', ') : '';
      contactHtml = `
        <div class="whois-card whois-contact-card">
          <div class="whois-card-title"><i class="fa-solid fa-address-card"></i> Registrant Info</div>
          ${data.org ? `<div class="whois-detail-row"><span class="whois-detail-label">Organization</span><span class="whois-detail-value">${data.org}</span></div>` : ''}
          ${data.country ? `<div class="whois-detail-row"><span class="whois-detail-label">Country</span><span class="whois-detail-value">${data.country}</span></div>` : ''}
          ${emails ? `<div class="whois-detail-row"><span class="whois-detail-label">Emails</span><span class="whois-detail-value emails">${emails}</span></div>` : ''}
        </div>
      `;
    }

    const domainName = data.domain_name || data.target;
    const registrar = data.registrar || 'Unknown';
    const isTrusted = ageValue >= 5;
    const createdDate = fmtDate(data.creation_date);
    const expiresDate = fmtDate(data.expiration_date);
    const updatedDate = fmtDate(data.updated_date);
    const statusBadge = Array.isArray(data.status) && data.status.length > 0 
      ? `<span class="whois-status-pill ok">${data.status[0]}</span>` 
      : '';
    const icannLink = `<a href="https://icann.org/epp" target="_blank" class="whois-icann-link">https://icann.org/epp</a>`;
    const nameServers = Array.isArray(data.name_servers) ? data.name_servers : (data.name_servers ? [data.name_servers] : []);
    const abuseEmail = Array.isArray(data.emails) && data.emails.length > 0 ? data.emails[0] : (data.abuse_contact || data.registrar_abuse_contact_email || '');
    const ageDisplay = ageValue > 0 ? `${ageValue.toFixed(1)} years` : 'Unknown';
    const ageSubtext = ageValue > 5 ? 'Since ' + (created ? created.getFullYear() : 'N/A') + ' · Trusted' : 'Since ' + (created ? created.getFullYear() : 'N/A');
    const daysLeft = (expires && !isNaN(expires.getFullYear())) ? Math.round((expires - now) / (1000 * 60 * 60 * 24)) : null;
    const expiresDisplay = daysLeft !== null ? `${daysLeft} days` : 'Unknown';
    const expiresSubtext = expiresDate !== '<span class="unknown">N/A</span>' ? expiresDate.replace(/<[^>]*>/g, '') + ' · Safe' : '';
    const timelinePct = (created && expires && !isNaN(created.getFullYear()) && !isNaN(expires.getFullYear())) 
      ? ((ageValue / (ageValue + (daysLeft / 365))) * 100).toFixed(1) 
      : 97.6;

    output.innerHTML = `
      <div class="whois-result">
        <style>
          @keyframes whois-zone-fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
          .whois-zone { animation: whois-zone-fade 0.3s ease-out forwards; opacity: 0; }
          .whois-zone-1 { animation-delay: 0ms; }
          .whois-zone-2 { animation-delay: 60ms; }
          .whois-zone-3 { animation-delay: 120ms; }
          .whois-zone-4 { animation-delay: 180ms; }
          .whois-zone-5 { animation-delay: 220ms; }
          .whois-zone-6 { animation-delay: 280ms; }
          .whois-zone-7 { animation-delay: 320ms; }
          .whois-hero { background: #111318; border: 0.5px solid #2a2d35; border-radius: 10px; padding: 20px 24px; display: flex; align-items: center; justify-content: space-between; }
          .whois-hero-left { display: flex; align-items: center; }
          .whois-hero-icon { font-size: 20px; color: #a78bfa; }
          .whois-hero-domain { font-size: 22px; font-weight: 600; color: #e2e3e7; margin-left: 10px; }
          .whois-hero-registrar { font-size: 12px; color: #6b6e78; margin-left: 40px; margin-top: 2px; }
          .whois-trust-badge { background: #102a18; border: 0.5px solid #1a5a28; border-radius: 8px; padding: 8px 16px; text-align: center; }
          .whois-trust-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6b6e78; }
          .whois-trust-value { font-size: 15px; font-weight: 500; color: #6acf80; }
          .whois-reg-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 12px; }
          .whois-reg-card { background: #111318; border: 0.5px solid #2a2d35; border-radius: 8px; padding: 12px 14px; }
          .whois-reg-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: #6b6e78; margin-bottom: 4px; }
          .whois-reg-value { font-size: 13px; font-weight: 500; color: #e2e3e7; }
          .whois-status-pill { background: #102a18; color: #6acf80; border: 0.5px solid #1a5a28; border-radius: 20px; padding: 3px 10px; font-size: 12px; display: inline-block; }
          .whois-icann-link { color: #a78bfa; font-size: 12px; font-family: monospace; text-decoration: none; }
          .whois-icann-link:hover { text-decoration: underline; }
          .whois-health-row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px; }
          .whois-health-card { background: #111318; border: 0.5px solid #2a2d35; border-radius: 8px; padding: 14px 18px; }
          .whois-health-label { font-size: 11px; text-transform: uppercase; color: #6b6e78; margin-bottom: 4px; }
          .whois-health-value { font-size: 18px; font-weight: 500; color: #6acf80; }
          .whois-health-sub { font-size: 11px; color: #6b6e78; margin-top: 2px; }
          .whois-age-card { border-left: 3px solid #6acf80; }
          .whois-age-card .whois-health-value { color: #6acf80; }
          .whois-exp-card { border-left: 3px solid #f0b860; }
          .whois-exp-card .whois-health-value { color: #f0b860; }
          .whois-timeline-bar { height: 4px; background: #1e2028; border-radius: 2px; margin-top: 10px; overflow: hidden; }
          .whois-timeline-fill { height: 100%; background: #a78bfa; border-radius: 2px; }
          .whois-timeline-note { font-size: 10px; color: #6b6e78; margin-top: 4px; text-align: right; }
          .whois-ns-label { font-size: 11px; text-transform: uppercase; color: #6b6e78; letter-spacing: 0.08em; margin-bottom: 8px; }
          .whois-ns-list { display: flex; flex-wrap: wrap; gap: 8px; }
          .whois-ns-pill { background: #161820; border: 0.5px solid #2e3140; border-radius: 6px; padding: 6px 12px; font-size: 12px; font-family: monospace; color: #b0b2ba; display: inline-flex; align-items: center; gap: 8px; }
          .whois-ns-pill i { font-size: 12px; color: #6b6e78; }
          .whois-abuse-card { background: #111318; border: 0.5px solid #2a2d35; border-radius: 8px; padding: 12px 14px; margin-top: 12px; }
          .whois-abuse-label { font-size: 11px; text-transform: uppercase; color: #6b6e78; margin-bottom: 4px; }
          .whois-abuse-value { font-size: 12px; font-family: monospace; color: #a78bfa; display: flex; align-items: center; gap: 8px; }
          .whois-osint-box { background: #13101e; border: 0.5px solid #3d2d6e; border-radius: 10px; padding: 16px 20px; margin-top: 14px; }
          .whois-osint-header { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 500; color: #a78bfa; margin-bottom: 10px; }
          .whois-osint-dot { width: 6px; height: 6px; border-radius: 50%; background: #a78bfa; }
          .whois-osint-content { font-size: 13px; line-height: 1.7; color: #b0b2ba; }
          .whois-osint-highlight { color: #a78bfa; font-family: monospace; font-size: 12px; }
          .whois-raw-header { background: #161820; border: 0.5px solid #2a2d35; border-radius: 8px; padding: 10px 14px; display: flex; align-items: center; cursor: pointer; margin-top: 14px; gap: 10px; font-size: 13px; color: #b0b2ba; }
          .whois-raw-header:hover { background: #1a1d26; }
          .whois-raw-arrow { color: #6b6e78; transition: transform 0.2s; margin-left: auto; }
          .whois-raw-arrow.open { transform: rotate(180deg); }
          .whois-raw-content { background: #0d0f14; padding: 14px 16px; border-radius: 0 0 8px 8px; display: none; font-family: monospace; font-size: 12px; color: #6b6e78; }
          .whois-raw-content.open { display: block; }
          .whois-actions-bar { display: flex; align-items: center; gap: 8px; padding-top: 14px; border-top: 0.5px solid #2a2d35; margin-top: 14px; }
          .whois-copy-btn { background: #161820; border: 0.5px solid #2e3140; border-radius: 6px; padding: 7px 14px; font-size: 12px; color: #b0b2ba; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .whois-copy-btn:hover { background: #1e2130; }
          .whois-ai-btn { background: #1e2130; border: 0.5px solid #4a3a8e; border-radius: 6px; padding: 7px 14px; font-size: 12px; color: #a78bfa; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .whois-ai-btn:hover { background: #252640; }
          .whois-meta-right { font-size: 11px; color: #4a4d58; margin-left: auto; }
          .whois-loading { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #6b6e78; }
          .whois-loading i { color: #a78bfa; }
        </style>

        <div class="whois-zone whois-zone-1">
          <div class="whois-hero">
            <div class="whois-hero-left">
              <i class="fa-solid fa-globe whois-hero-icon"></i>
              <span class="whois-hero-domain">${domainName}</span>
              <div style="display:flex;flex-direction:column">
                <span class="whois-hero-registrar">Registrar: ${registrar}</span>
              </div>
            </div>
            <div class="whois-trust-badge">
              <div class="whois-trust-label">Trust Status</div>
              <div class="whois-trust-value"><i class="fa-solid fa-check" style="margin-right:4px"></i>${isTrusted ? 'Trusted' : 'New'}</div>
            </div>
          </div>
        </div>

        <div class="whois-zone whois-zone-2">
          <div class="whois-reg-grid">
            <div class="whois-reg-card">
              <div class="whois-reg-label">Created</div>
              <div class="whois-reg-value">${createdDate}</div>
            </div>
            <div class="whois-reg-card">
              <div class="whois-reg-label">Expires</div>
              <div class="whois-reg-value">${expiresDate}</div>
            </div>
            <div class="whois-reg-card">
              <div class="whois-reg-label">Last Updated</div>
              <div class="whois-reg-value">${updatedDate}</div>
            </div>
            <div class="whois-reg-card">
              <div class="whois-reg-label">Status</div>
              <div class="whois-reg-value">${statusBadge || '<span class="whois-reg-value">ok</span>'}</div>
            </div>
            <div class="whois-reg-card">
              <div class="whois-reg-label">Registrar</div>
              <div class="whois-reg-value" style="font-size:12px;word-break:break-word">${registrar}</div>
            </div>
            <div class="whois-reg-card">
              <div class="whois-reg-label">ICANN Link</div>
              <div class="whois-reg-value">${icannLink}</div>
            </div>
          </div>
        </div>

        <div class="whois-zone whois-zone-3">
          <div class="whois-health-row">
            <div class="whois-health-card whois-age-card">
              <div class="whois-health-label">Domain Age</div>
              <div class="whois-health-value">${ageDisplay}</div>
              <div class="whois-health-sub">${ageSubtext}</div>
            </div>
            <div class="whois-health-card whois-exp-card">
              <div class="whois-health-label">Expires In</div>
              <div class="whois-health-value">${expiresDisplay}</div>
              <div class="whois-health-sub">${expiresSubtext}</div>
            </div>
          </div>
          <div class="whois-timeline-bar">
            <div class="whois-timeline-fill" style="width:${timelinePct}%"></div>
          </div>
          <div class="whois-timeline-note">Expires ${expiresDate.replace(/<[^>]*>/g, '')}</div>
        </div>

        <div class="whois-zone whois-zone-4">
          <div class="whois-ns-label">Name Servers</div>
          <div class="whois-ns-list">
            ${nameServers.length > 0 
              ? nameServers.map(ns => `<span class="whois-ns-pill"><i class="fa-solid fa-gear"></i>${ns}</span>`).join('')
              : '<span class="whois-reg-value">No name servers found</span>'}
          </div>
        </div>

        <div class="whois-zone whois-zone-5">
          <div class="whois-abuse-card">
            <div class="whois-abuse-label">Registrant Abuse Contact</div>
            <div class="whois-abuse-value">
              <i class="fa-solid fa-envelope"></i>
              ${abuseEmail || '<span style="color:#6b6e78">N/A</span>'}
            </div>
          </div>
        </div>

        <div class="whois-zone whois-zone-6">
          <div id="whois-ai-analysis-container"></div>
        </div>

        <div class="whois-zone whois-zone-7">
          <div class="whois-raw-header" onclick="this.querySelector('.whois-raw-arrow').classList.toggle('open'); this.nextElementSibling.classList.toggle('open');">
            <i class="fa-solid fa-code"></i> Raw WHOIS Data
            <i class="fa-solid fa-chevron-down whois-raw-arrow"></i>
          </div>
          <div class="whois-raw-content">
            <pre>${JSON.stringify(data, null, 2)}</pre>
          </div>
        </div>

        <div class="whois-actions-bar">
          <button class="whois-copy-btn" onclick="copyToolResult('whois')"><i class="fa-solid fa-copy"></i> Copy</button>
          <button class="whois-ai-btn" onclick="sendToAI('whois')"><i class="fa-solid fa-robot"></i> Send to AI</button>
          <span class="whois-meta-right">${domainName} · just now</span>
        </div>
      </div>
    `;

    setTimeout(async () => {
      const aiContainer = document.getElementById('whois-ai-analysis-container');
      if (!aiContainer) return;
      aiContainer.innerHTML = `
        <div class="whois-loading" style="margin-top:14px">
          <i class="fa-solid fa-robot fa-flip"></i> AI analyzing WHOIS data...
        </div>
      `;
      try {
        const analyzeResponse = await fetch('/api/ai/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || localStorage.getItem('cybersec_token') || '') },
          body: JSON.stringify({ 
            message: `Analyze this WHOIS record for OSINT purposes. Domain: ${data.domain_name || data.target}. Registrar: ${data.registrar || 'Unknown'}. Created: ${data.creation_date || 'Unknown'}. Expires: ${data.expiration_date || 'Unknown'}. Age: ${ageValue.toFixed(1)} years. Nameservers: ${Array.isArray(data.name_servers) ? data.name_servers.join(', ') : 'Unknown'}. Organization: ${data.org || 'Unknown'}. Country: ${data.country || 'Unknown'}. Write 2-3 sentences explaining if this domain indicates legitimacy or risk based on age, registrar reputation, and any red flags. Highlight any domain names or technical terms with appropriate formatting.`,
            scan_id: null,
            conversation_history: []
          })
        });
        
        if (analyzeResponse.ok) {
          const reader = analyzeResponse.body.getReader();
          const decoder = new TextDecoder("utf-8");
          let aiText = '';
          aiContainer.innerHTML = `
            <div class="whois-osint-box">
              <div class="whois-osint-header"><div class="whois-osint-dot"></div> OSINT Analysis</div>
              <div class="whois-osint-content" id="whoisAiContent"></div>
            </div>
          `;
          const contentBox = document.getElementById('whoisAiContent');
          while(true) {
            const { done, value } = await reader.read();
            if (done) break;
            const chunk = decoder.decode(value);
            const lines = chunk.split('\n');
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                const text = line.slice(6);
                if (text !== '[DONE]' && text.trim()) {
                  aiText += text;
                  if (contentBox) contentBox.innerHTML = marked.parse(aiText);
                }
              }
            }
          }
        } else {
          aiContainer.innerHTML = '';
        }
      } catch(e) {
        aiContainer.innerHTML = '';
      }
    }, 300);

    if (actions) actions.style.display = 'flex';
  },

  renderPing(data) {
    const output = document.getElementById('ping-output');
    const actions = document.getElementById('ping-actions');
    if (data.status === 'failed') {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error}</div>`;
      if (actions) actions.style.display = 'none';
      return;
    }

    // Safety fix for backend bugs
    const minVal = Math.min(data.min_ms || 0, data.max_ms || 0);
    const maxVal = Math.max(data.min_ms || 0, data.max_ms || 0);
    const avgVal = data.avg_ms || ((minVal + maxVal) / 2);
    const lossPct = parseFloat(data.packet_loss_pct || (data.packet_loss ? data.packet_loss.replace('%','') : 0));
    
    // Parse individual responses for graph
    const raw = data.raw_output || '';
    const timeMatches = [...raw.matchAll(/time=([\d.]+)\s*ms/gi)];
    const responseTimes = timeMatches.map(m => parseFloat(m[1]));
    
    let quality = 'excellent';
    let qualityText = 'Excellent';
    let qualityIcon = 'fa-gauge-high';
    
    if (lossPct > 0 || avgVal > 200) { quality = 'poor'; qualityText = 'Poor'; qualityIcon = 'fa-triangle-exclamation'; }
    else if (avgVal > 100) { quality = 'moderate'; qualityText = 'Moderate'; qualityIcon = 'fa-gauge-simple-high'; }

    const barWidth = Math.min(100, (avgVal / 300) * 100);
    const chartHtml = responseTimes.length > 0 ? responseTimes.map(t => {
        const height = Math.min(100, (t / 300) * 100);
        return `<div class="ping-bar-item" style="height: ${height}%" data-ms="${t.toFixed(1)}"></div>`;
    }).join('') : '<div style="color:var(--text-muted);width:100%;text-align:center;padding-top:40px">No response data points</div>';

    output.innerHTML = `
      <div class="ping-quality-section">
          <div class="ping-quality-indicator ${quality}">
              <i class="fa-solid ${qualityIcon}"></i>
              <span style="font-size:0.7rem; font-weight:700; text-transform:uppercase">${qualityText}</span>
          </div>
          <div style="flex:1">
              <h3 style="margin-bottom:8px">Connection Quality: ${qualityText}</h3>
              <p style="color:var(--text-secondary); font-size:0.9rem">
                 Target: <span style="font-family:monospace; color:var(--text-primary)">${data.target}</span> (${data.ip || 'Unknown IP'})
              </p>
              <div class="latency-bar-container">
                  <div class="latency-bar-fill" style="width: ${barWidth}%"></div>
              </div>
              <div style="display:flex; justify-content:space-between; font-size:0.8rem; color:var(--text-muted)">
                   <span>0ms</span>
                   <span>Average: ${avgVal.toFixed(1)}ms</span>
                   <span>300ms+</span>
              </div>
          </div>
      </div>

      <div class="ping-summary-grid">
          <div class="ping-summary-card"><div class="lbl">Min Latency</div><div class="val">${minVal.toFixed(2)} ms</div></div>
          <div class="ping-summary-card"><div class="lbl">Avg Latency</div><div class="val" style="color:var(--accent-blue)">${avgVal.toFixed(2)} ms</div></div>
          <div class="ping-summary-card"><div class="lbl">Max Latency</div><div class="val">${maxVal.toFixed(2)} ms</div></div>
          <div class="ping-summary-card ${lossPct > 0 ? 'loss' : ''}"><div class="lbl">Packet Loss</div><div class="val" style="color:${lossPct > 0 ? 'var(--accent-red)' : 'var(--accent-green)'}">${lossPct}%</div></div>
      </div>

      ${lossPct > 0 ? `<div class="ping-warning-box"><i class="fa-solid fa-circle-exclamation"></i> Packet loss detected (${lossPct}%). This indicates possible network instability.</div>` : ''}

      <div class="ping-chart-container">
          <div class="ping-chart-header">
              <span style="font-weight:700; font-size:0.95rem"><i class="fa-solid fa-chart-line" style="margin-right:8px; color:var(--purple-gradient-start)"></i> Response Times</span>
              <span style="color:var(--text-muted); font-size:0.8rem">Sample Count: ${responseTimes.length}</span>
          </div>
          <div class="ping-chart-bars">
              ${chartHtml}
          </div>
      </div>

      <div id="ping-ai-analysis-container" style="margin-bottom:20px;"></div>

      <details class="os-accordion">
          <summary><i class="fa-solid fa-microchip"></i> Show Advanced Details & Raw Output <i class="fa-solid fa-chevron-down" style="margin-left:auto;font-size:0.8rem"></i></summary>
          <div class="os-accordion-content">
              <p><strong>Jitter:</strong> ${(maxVal - minVal).toFixed(2)} ms</p>
              <p><strong>Packets Sent:</strong> ${data.packets_sent || responseTimes.length}</p>
              <p><strong>Packets Received:</strong> ${data.packets_received || responseTimes.length}</p>
              <pre class="raw-output" style="margin-top:15px; background:rgba(0,0,0,0.2)">${raw}</pre>
          </div>
      </details>
    `;

    setTimeout(async () => {
        const aiContainer = document.getElementById('ping-ai-analysis-container');
        if (!aiContainer) return;
        aiContainer.innerHTML = `
            <div class="ai-insight-box">
                <div class="ai-insight-header"><i class="fa-solid fa-robot fa-fade"></i> AI is analyzing network performance...</div>
                <div class="ai-insight-content">Groq is evaluating latency stability and loss vectors.</div>
            </div>
        `;
        try {
            const analyzeResponse = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
                body: JSON.stringify({ 
                    message: "Analyze these PING results: Target " + data.target + ", Avg Latency " + avgVal.toFixed(1) + "ms, Packet Loss " + lossPct + "%, Jitter " + (maxVal-minVal).toFixed(1) + "ms. Individual responses: [" + responseTimes.join(', ') + "]. Write a 2-sentence technical synopsis of this connection's health and reliability for real-time traffic.",
                    scan_id: null,
                    conversation_history: []
                })
            });
            
            if (analyzeResponse.ok) {
                const reader = analyzeResponse.body.getReader();
                const decoder = new TextDecoder("utf-8");
                let aiText = '';
                aiContainer.innerHTML = `
                    <div class="ai-insight-box">
                        <div class="ai-insight-header"><i class="fa-solid fa-brain"></i> Network Analysis Insight</div>
                        <div class="ai-insight-content" id="pingAiContent"></div>
                    </div>
                `;
                const contentBox = document.getElementById('pingAiContent');
                while(true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    const chunk = decoder.decode(value);
                    const lines = chunk.split('\n');
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            const text = line.slice(6);
                            if (text !== '[DONE]') {
                                aiText += text;
                                contentBox.innerHTML = marked.parse(aiText);
                            }
                        }
                    }
                }
            } else { aiContainer.innerHTML = ''; }
        } catch(e) { aiContainer.innerHTML = ''; }
    }, 200);

    if (actions) actions.style.display = 'flex';
  },

  renderTraceroute(data) {
    const output = document.getElementById('traceroute-output');
    const actions = document.getElementById('traceroute-actions');
    if (data.status === 'failed') {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error}</div>`;
      if (actions) actions.style.display = 'none';
      return;
    }

    const hops = data.hops || [];
    const hopRows = hops.map(h => `
      <div class="hop-row">
        <div class="hop-number">${h.hop}</div>
        <div class="hop-ip">${h.ip || '*'}</div>
        <div class="hop-host">${h.host || (h.ip ? 'Resolving...' : '*')}</div>
        <div class="hop-rtt">${h.rtt_ms != null ? h.rtt_ms + ' ms' : '-'}</div>
      </div>
    `).join('');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">Network Path: ${data.target}</div>
        
        <div id="traceroute-ai-intuition-container"></div>

        <div class="hop-container" style="margin-top:20px">
            <div class="hop-header">
                <div class="hop-number">#</div>
                <div class="hop-ip">IP Address</div>
                <div class="hop-host">Hostname</div>
                <div class="hop-rtt">RTT</div>
            </div>
            ${hopRows || '<div class="alert alert-warning">No hops recorded</div>'}
        </div>
      </div>

      <div class="next-steps-container">
         <div style="font-weight:700; margin-bottom:15px; font-size:0.9rem"><i class="fa-solid fa-wand-magic-sparkles"></i> AI Suggested Next Move</div>
         <div class="next-step-item" onclick="document.querySelector('[data-tool=ping]').click()">
            <i class="fa-solid fa-bolt" style="color:var(--accent-yellow)"></i>
            <div>
               <div style="font-weight:600">Performance Benchmark (Ping)</div>
               <div style="font-size:0.8rem; color:var(--text-muted)">Measure stability and packet loss after identifying the network path.</div>
            </div>
         </div>
      </div>
    `;

    if (hops.length > 0) {
        setTimeout(async () => {
            const aiContainer = document.getElementById('traceroute-ai-intuition-container');
            if (!aiContainer) return;
            aiContainer.innerHTML = `
                <div class="ai-insight-box">
                    <div class="ai-insight-header"><i class="fa-solid fa-route fa-fade"></i> AI is analyzing route path...</div>
                    <div class="ai-insight-content">Evaluating hop infrastructure for VPN/WAF fingerprints.</div>
                </div>
            `;
            try {
                const analyzeResponse = await fetch('/api/ai/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
                    body: JSON.stringify({ 
                        message: "Analyze this traceroute to " + data.target + ". Hops: " + JSON.stringify(hops) + ". Determine if the path suggests a CDN (like Cloudflare), a VPN/Proxy tunnel, or standard ISP routing. Write a 2-sentence intuition summary.",
                        scan_id: null,
                        conversation_history: []
                    })
                });
                
                if (analyzeResponse.ok) {
                    const reader = analyzeResponse.body.getReader();
                    const decoder = new TextDecoder("utf-8");
                    let aiText = '';
                    aiContainer.innerHTML = `
                        <div class="ai-insight-box">
                            <div class="ai-insight-header"><i class="fa-solid fa-map"></i> Route Path Intuition</div>
                            <div class="ai-insight-content" id="traceAiContent"></div>
                        </div>
                    `;
                    const contentBox = document.getElementById('traceAiContent');
                    while(true) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        const chunk = decoder.decode(value);
                        const lines = chunk.split('\n');
                        for (const line of lines) {
                            if (line.startsWith('data: ')) {
                                const text = line.slice(6);
                                if (text !== '[DONE]') {
                                    aiText += text;
                                    contentBox.innerHTML = marked.parse(aiText);
                                }
                            }
                        }
                    }
                }
            } catch(e) {}
        }, 300);
    }

    if (actions) actions.style.display = 'flex';
  },

  renderSSL(data) {
    const output = document.getElementById('ssl-output');
    const actions = document.getElementById('ssl-actions');
    if (data.status === 'failed' || data.status === 'ssl_error') {
      const iconClass = data.status === 'ssl_error' ? 'warning' : 'expired';
      output.innerHTML = `
        <div class="cert-card">
          <div class="cert-card-header">
            <div class="cert-icon ${iconClass}"><i class="fa-solid fa-exclamation-triangle"></i></div>
            <div>
              <div class="cert-subject">SSL Error</div>
              <div class="cert-issuer">${data.error}</div>
            </div>
          </div>
        </div>
      `;
      if (actions) actions.style.display = 'none';
      return;
    }

    const now = new Date();
    const validTo = data.valid_to ? new Date(data.valid_to) : null;
    const daysLeft = validTo ? Math.ceil((validTo - now) / (1000 * 60 * 60 * 24)) : null;

    let certStatus = 'valid';
    if (daysLeft !== null && daysLeft < 0) certStatus = 'expired';
    else if (daysLeft !== null && daysLeft < 30) certStatus = 'warning';

    const tlsVersions = data.tls_versions || [];
    const protocolVersion = tlsVersions[0] || 'Unknown';
    const isOldProtocol = protocolVersion.includes('1.0') || protocolVersion.includes('1.1');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">SSL Certificate: ${data.target}</div>
        <div class="cert-card">
          <div class="cert-card-header">
            <div class="cert-icon ${certStatus}">
              <i class="fa-solid fa-${certStatus === 'valid' ? 'check' : certStatus === 'expired' ? 'times' : 'exclamation'}"></i>
            </div>
            <div>
              <div class="cert-subject">${data.cn || 'Unknown'}</div>
              <div class="cert-issuer">Issued by: ${data.issuer || 'Unknown'}</div>
            </div>
          </div>
          <div class="cert-details">
            <div class="cert-detail-label">Protocol</div>
            <div class="cert-detail-value ${isOldProtocol ? 'badge badge-medium' : ''}">${protocolVersion}</div>
            <div class="cert-detail-label">Cipher</div>
            <div class="cert-detail-value">${data.cipher_suite || 'Unknown'}</div>
            <div class="cert-detail-label">Valid From</div>
            <div class="cert-detail-value">${data.valid_from || 'Unknown'}</div>
            <div class="cert-detail-label">Expires</div>
            <div class="cert-detail-value badge badge-${daysLeft !== null && daysLeft < 30 ? 'medium' : 'low'}">${data.valid_to || 'Unknown'} ${daysLeft !== null ? `(${daysLeft} days)` : ''}</div>
          </div>
        </div>
        ${isOldProtocol ? `
           <div class="alert alert-warning"><i class="fa-solid fa-exclamation-triangle"></i> Older TLS version detected.</div>
           <div id="ssl-remediation-container"></div>
        ` : (certStatus !== 'valid' ? `<div id="ssl-remediation-container"></div>` : '')}
      </div>

      <div class="next-steps-container">
         <div style="font-weight:700; margin-bottom:15px; font-size:0.9rem"><i class="fa-solid fa-wand-magic-sparkles"></i> AI Suggested Next Move</div>
         <div class="next-step-item" onclick="document.querySelector('[data-tool=headers]').click()">
            <i class="fa-solid fa-shield-halved" style="color:var(--accent-green)"></i>
            <div>
               <div style="font-weight:600">Scan Security Headers</div>
               <div style="font-size:0.8rem; color:var(--text-muted)">Verify HSTS and other headers required for a complete secure transport setup.</div>
            </div>
         </div>
      </div>
    `;

    if (isOldProtocol || certStatus !== 'valid') {
        setTimeout(async () => {
            const remContainer = document.getElementById('ssl-remediation-container');
            if (!remContainer) return;
            remContainer.innerHTML = `
               <div class="ai-insight-box" style="border-left-color:var(--accent-blue)">
                   <div class="ai-insight-header"><i class="fa-solid fa-wand-magic-sparkles fa-fade"></i> AI Remediation Wizard is writing a fix...</div>
                   <p style="font-size:0.85rem; opacity:0.8">Generating the optimal Nginx/Apache configuration to harden this endpoint.</p>
               </div>
            `;
            try {
                const analyzeResponse = await fetch('/api/ai/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
                    body: JSON.stringify({ 
                        message: "The SSL check for " + data.target + " found " + (isOldProtocol ? "Expired/Weak TLS Protocols (" + protocolVersion + ")" : "an Expiring Certificate") + ". Act as a security engineer and provide the exact Nginx and Apache configuration snippets to disable weak protocols and enforce secure ciphers. Format the response with clear headers and markdown code blocks.",
                        scan_id: null,
                        conversation_history: []
                    })
                });
                
                if (analyzeResponse.ok) {
                    const reader = analyzeResponse.body.getReader();
                    const decoder = new TextDecoder("utf-8");
                    let aiText = '';
                    remContainer.innerHTML = `
                       <div class="ai-insight-box" style="border-left-color:var(--accent-blue)">
                           <div class="ai-insight-header"><i class="fa-solid fa-book-medical"></i> SSL Remediation Wizard</div>
                           <div id="sslRemContent"></div>
                       </div>
                    `;
                    const contentBox = document.getElementById('sslRemContent');
                    while(true) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        const chunk = decoder.decode(value);
                        const lines = chunk.split('\n');
                        for (const line of lines) {
                            if (line.startsWith('data: ')) {
                                const text = line.slice(6);
                                if (text !== '[DONE]') {
                                    aiText += text;
                                    contentBox.innerHTML = marked.parse(aiText);
                                }
                            }
                        }
                    }
                }
            } catch(e) {}
        }, 300);
    }

    if (actions) actions.style.display = 'flex';
  },

  renderHeaders(data) {
    const output = document.getElementById('headers-output');
    const actions = document.getElementById('headers-actions');
    if (data.status === 'failed' || data.status === 'timeout') {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error || 'Connection failed'}</div>`;
      if (actions) actions.style.display = 'none';
      return;
    }

    const headers = data.headers || {};
    const securityHeaders = {
      'strict-transport-security': 'HSTS',
      'content-security-policy': 'CSP',
      'x-content-type-options': 'X-Content-Type',
      'x-frame-options': 'X-Frame-Options',
      'x-xss-protection': 'X-XSS-Protection',
      'referrer-policy': 'Referrer-Policy',
      'permissions-policy': 'Permissions-Policy',
      'x-permitted-cross-domain-policies': 'Cross-Domain',
    };

    const missingHeaders = [];
    const headerItems = Object.entries(securityHeaders).map(([header, name]) => {
      const found = Object.keys(headers).find(h => h.toLowerCase() === header);
      if (found) {
        return `<li class="present"><span class="check-icon"><i class="fa-solid fa-check"></i></span><span class="header-name">${name}</span><span class="header-value">${headers[found]}</span></li>`;
      }
      missingHeaders.push(name);
      return `<li class="missing"><span class="check-icon"><i class="fa-solid fa-times"></i></span><span class="header-name">${name}</span></li>`;
    }).join('');

    const otherHeaders = Object.entries(headers)
      .filter(([k]) => !Object.keys(securityHeaders).includes(k.toLowerCase()))
      .map(([k, v]) => `<tr><td><code>${k}</code></td><td><code>${v}</code></td></tr>`)
      .join('');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">HTTP Headers: ${data.url}</div>
        <div class="result-item" style="margin-bottom: 16px; display:flex; align-items:center; gap:10px">
          <span class="result-key">Status Code:</span>
          <span class="badge badge-${data.status_code === 200 ? 'low' : 'medium'}">${data.status_code || 'Unknown'}</span>
          <span class="result-key" style="margin-left:15px">Server:</span>
          <span style="font-family:monospace; font-size:0.85rem">${headers['server'] || 'Undisclosed'}</span>
        </div>

        <div id="header-attack-scenario-container"></div>

        <div class="result-title" style="font-size: 1rem; margin-top: 25px;">Security Hygiene Checklist</div>
        <ul class="headers-checklist">${headerItems}</ul>
        
        ${otherHeaders ? `
          <div class="result-title" style="font-size: 1rem; margin-top: 25px;">Full Header Dump</div>
          <div class="table-container">
            <table class="data-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>${otherHeaders}</tbody></table>
          </div>
        ` : ''}
      </div>

      <div class="next-steps-container">
         <div style="font-weight:700; margin-bottom:15px; font-size:0.9rem"><i class="fa-solid fa-wand-magic-sparkles"></i> AI Suggested Next Move</div>
         <div class="next-step-item" onclick="document.querySelector('[data-tool=webscan]').click()">
            <i class="fa-solid fa-spider" style="color:var(--accent-red)"></i>
            <div>
               <div style="font-weight:600">Deep Vulnerability Scan</div>
               <div style="font-size:0.8rem; color:var(--text-muted)">Missing security headers often correlate with injection flaws. Start a full web scan.</div>
            </div>
         </div>
      </div>
    `;

    if (missingHeaders.length > 0) {
        setTimeout(async () => {
            const scenarioContainer = document.getElementById('header-attack-scenario-container');
            if (!scenarioContainer) return;
            scenarioContainer.innerHTML = `
                <div class="attack-scenario-alert">
                    <div class="attack-scenario-header">
                        <i class="fa-solid fa-skull-crossbones fa-beat-fade"></i> AI Attack Scenario Modeling...
                    </div>
                    <div style="font-size:0.85rem; color:var(--text-secondary)">Synthesizing risks for ${missingHeaders.slice(0,3).join(', ')}...</div>
                </div>
            `;
            try {
                const analyzeResponse = await fetch('/api/ai/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
                    body: JSON.stringify({ 
                        message: "The URL " + data.url + " is missing these security headers: " + missingHeaders.join(', ') + ". Act as a red teamer and write a 2-sentence 'Attack Scenario' explaining how a real-world attacker would exploit these specific omissions (e.g., Session hijacking via Clickjacking or XSS).",
                        scan_id: null,
                        conversation_history: []
                    })
                });
                
                if (analyzeResponse.ok) {
                    const reader = analyzeResponse.body.getReader();
                    const decoder = new TextDecoder("utf-8");
                    let aiText = '';
                    scenarioContainer.innerHTML = `
                        <div class="attack-scenario-alert">
                            <div class="attack-scenario-header"><i class="fa-solid fa-radiation"></i> Likely Attack Scenario</div>
                            <div id="headerScenarioContent" style="font-size:0.9rem; line-height:1.5"></div>
                        </div>
                    `;
                    const contentBox = document.getElementById('headerScenarioContent');
                    while(true) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        const chunk = decoder.decode(value);
                        const lines = chunk.split('\n');
                        for (const line of lines) {
                            if (line.startsWith('data: ')) {
                                const text = line.slice(6);
                                if (text !== '[DONE]') {
                                    aiText += text;
                                    contentBox.innerHTML = marked.parse(aiText);
                                }
                            }
                        }
                    }
                }
            } catch(e) {}
        }, 300);
    }

    if (actions) actions.style.display = 'flex';
  },

  renderSubdomains(data) {
    const output = document.getElementById('subdomains-output');
    const actions = document.getElementById('subdomains-actions');
    const subdomains = data.subdomains_found || [];
    
    // High Interest Logic
    const highInterestRegex = /dev|admin|vpn|jira|api|v1|test|staging|internal|ssh|mail/i;
    const rows = subdomains.map(s => {
        const isInteresting = highInterestRegex.test(s);
        return `
            <tr>
                <td>
                    <code>${s}</code>
                    ${isInteresting ? '<span class="badge-high-interest">High Interest</span>' : ''}
                </td>
            </tr>`;
    }).join('');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">Subdomain Recon: ${data.domain}</div>
        
        <div style="display:flex; gap:15px; margin-bottom:20px">
            <div class="stat-card" style="flex:1">
              <div class="stat-label">Total Subdomains</div>
              <div class="stat-value">${data.total_found || 0}</div>
            </div>
            <div class="stat-card" style="flex:1">
              <div class="stat-label">High Interest Targets</div>
              <div class="stat-value" style="color:var(--accent-red)">${subdomains.filter(s => highInterestRegex.test(s)).length}</div>
            </div>
        </div>

        ${subdomains.length > 0 ? `
          <div class="table-container">
            <table class="data-table">
              <thead><tr><th>Subdomain Address</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        ` : '<div class="alert alert-warning">No subdomains found during discovery</div>'}
      </div>

      <div id="subdomain-ai-analysis-container" style="margin-top:20px;"></div>

      <div class="next-steps-container">
         <div style="font-weight:700; margin-bottom:15px; font-size:0.9rem"><i class="fa-solid fa-wand-magic-sparkles"></i> AI Suggested Next Move</div>
         <div class="next-step-item" onclick="document.querySelector('[data-tool=portscanner]').click()">
            <i class="fa-solid fa-network-wired" style="color:var(--accent-blue)"></i>
            <div>
               <div style="font-weight:600">Port Scan High-Interest Targets</div>
               <div style="font-size:0.8rem; color:var(--text-muted)">Perform deep service enumeration on the flagged subdomains to find entry points.</div>
            </div>
         </div>
      </div>
    `;

    if (subdomains.length > 0) {
        setTimeout(async () => {
            const aiContainer = document.getElementById('subdomain-ai-analysis-container');
            if (!aiContainer) return;
            aiContainer.innerHTML = `
                <div class="ai-insight-box">
                    <div class="ai-insight-header"><i class="fa-solid fa-map-location-dot fa-fade"></i> AI is prioritizing targets...</div>
                    <div class="ai-insight-content">Evaluating subdomains for staging environment leak potential.</div>
                </div>
            `;
            try {
                const analyzeResponse = await fetch('/api/ai/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
                    body: JSON.stringify({ 
                        message: "Analyze this list of subdomains for " + data.domain + ": " + subdomains.slice(0, 20).join(', ') + ". Identify which 3 subdomains are the most valuable for further security testing (e.g., API docs, VPNs, or dev environments) and briefly explain why.",
                        scan_id: null,
                        conversation_history: []
                    })
                });
                
                if (analyzeResponse.ok) {
                    const reader = analyzeResponse.body.getReader();
                    const decoder = new TextDecoder("utf-8");
                    let aiText = '';
                    aiContainer.innerHTML = `
                        <div class="ai-insight-box">
                            <div class="ai-insight-header"><i class="fa-solid fa-crosshairs"></i> Reconstruction Prioritization</div>
                            <div class="ai-insight-content" id="subdomainAiContent"></div>
                        </div>
                    `;
                    const contentBox = document.getElementById('subdomainAiContent');
                    while(true) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        const chunk = decoder.decode(value);
                        const lines = chunk.split('\n');
                        for (const line of lines) {
                            if (line.startsWith('data: ')) {
                                const text = line.slice(6);
                                if (text !== '[DONE]') {
                                    aiText += text;
                                    contentBox.innerHTML = marked.parse(aiText);
                                }
                            }
                        }
                    }
                }
            } catch(e) {}
        }, 300);
    }

    if (actions) actions.style.display = 'flex';
  },

  renderGeo(data) {
    const output = document.getElementById('geo-output');
    const actions = document.getElementById('geo-actions');
    if (data.status === 'failed') {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error}</div>`;
      if (actions) actions.style.display = 'none';
      return;
    }

    const info = [
      { label: 'IP Address', value: data.ip || 'Unknown', icon: 'fa-network-wired' },
      { label: 'Country', value: `${data.country || 'Unknown'} ${data.country_code ? `(${data.country_code})` : ''}`, icon: 'fa-flag' },
      { label: 'Region/State', value: data.region || 'Unknown', icon: 'fa-map' },
      { label: 'City', value: data.city || 'Unknown', icon: 'fa-city' },
      { label: 'Organization (ISP)', value: data.org || 'Unknown', icon: 'fa-building' },
      { label: 'ASN', value: data.asn || 'Unknown', icon: 'fa-microchip' },
    ];

    const cards = info.map(i => `
      <div class="stat-card">
        <div class="stat-icon"><i class="fa-solid ${i.icon}"></i></div>
        <div class="stat-label">${i.label}</div>
        <div class="stat-value">${i.value}</div>
      </div>
    `).join('');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">GeoIP Intelligence: ${data.ip}</div>
        <div class="grid grid-3 mb-20" style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:15px">
          ${cards}
        </div>
        <div id="geo-ai-context-container"></div>
      </div>

      <div class="next-steps-container" style="margin-top:20px">
         <div style="font-weight:700; margin-bottom:15px; font-size:0.9rem"><i class="fa-solid fa-wand-magic-sparkles"></i> AI Suggested Next Move</div>
         <div class="next-step-item" onclick="document.querySelector('[data-tool=traceroute]').click()">
            <i class="fa-solid fa-route" style="color:var(--accent-blue)"></i>
            <div>
               <div style="font-weight:600">Trace Physical Route</div>
               <div style="font-size:0.8rem; color:var(--text-muted)">See the network hops across countries to reach this geographical destination.</div>
            </div>
         </div>
      </div>
    `;

    setTimeout(async () => {
        const aiContainer = document.getElementById('geo-ai-context-container');
        if (!aiContainer) return;
        aiContainer.innerHTML = `
            <div class="ai-insight-box">
                <div class="ai-insight-header"><i class="fa-solid fa-earth-americas fa-fade"></i> AI is analyzing geographical risk...</div>
                <div class="ai-insight-content">Evaluating ASN reputation and jurisdictional risk factors.</div>
            </div>
        `;
        try {
            const analyzeResponse = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
                body: JSON.stringify({ 
                    message: "Analyze the GeoIP and ISP data for IP " + data.ip + " in " + data.country + " (ISP: " + data.org + "). Determine if this IP belongs to a residential consumer node, a cloud provider (like AWS/DigitalOcean), or a high-risk jurisdiction. Write a 2-sentence tactical summary.",
                    scan_id: null,
                    conversation_history: []
                })
            });
            
            if (analyzeResponse.ok) {
                const reader = analyzeResponse.body.getReader();
                const decoder = new TextDecoder("utf-8");
                let aiText = '';
                aiContainer.innerHTML = `
                    <div class="ai-insight-box">
                        <div class="ai-insight-header"><i class="fa-solid fa-shield-halved"></i> Geo-Jurisdictional Insight</div>
                        <div class="ai-insight-content" id="geoAiContent"></div>
                    </div>
                `;
                const contentBox = document.getElementById('geoAiContent');
                while(true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    const chunk = decoder.decode(value);
                    const lines = chunk.split('\n');
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            const text = line.slice(6);
                            if (text !== '[DONE]') {
                                aiText += text;
                                contentBox.innerHTML = marked.parse(aiText);
                            }
                        }
                    }
                }
            }
        } catch(e) {}
    }, 200);

    if (actions) actions.style.display = 'flex';
  },

  async renderExecutiveSummary() {
    const output = document.getElementById('executive-summary-output');
    const toolsRun = Object.keys(this.allResults);
    
    if (toolsRun.length === 0) {
        output.innerHTML = `<div class="alert alert-info"><i class="fa-solid fa-circle-info"></i> No scan data found in this session. Run some tools to generate a report.</div>`;
        return;
    }

    output.innerHTML = `
      <div class="executive-summary-view" style="padding:10px">
          <div class="ai-insight-box" style="margin-bottom:30px; border-left-width:8px; border-left-color:var(--purple-gradient-start)">
              <div class="ai-insight-header" style="font-size:1.1rem">
                  <i class="fa-solid fa-brain fa-fade"></i> AI Executive Security Report
              </div>
              <p style="opacity:0.8">Synthesizing data from ${toolsRun.length} tools: ${toolsRun.join(', ')}...</p>
              <div id="execSummaryContent" style="margin-top:20px; font-size:1rem; line-height:1.6; color:var(--text-primary)">
                  <div class="loading-bar"><div class="loading-progress"></div></div>
              </div>
          </div>

          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:20px">
              <div class="dns-health-card" style="margin-top:0">
                  <div style="font-weight:700; margin-bottom:15px; color:var(--text-secondary)">DATA SOURCES ANALYZED</div>
                  <ul style="list-style:none; padding:0">
                      ${toolsRun.map(t => `<li style="padding:8px 0; border-bottom:1px solid rgba(255,255,255,0.05); display:flex; justify-content:space-between">
                          <span><i class="fa-solid fa-check" style="color:var(--accent-green); margin-right:10px"></i> ${t.toUpperCase()}</span>
                          <span style="font-size:0.8rem; opacity:0.5">Contextualized</span>
                      </li>`).join('')}
                  </ul>
              </div>
          </div>
      </div>
    `;

    try {
        const analyzeResponse = await fetch('/api/ai/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
            body: JSON.stringify({ 
                message: "Act as a Senior Cyber Security Auditor. Generate a professional 'Executive Security Report' based on the tool results recorded: " + JSON.stringify(this.allResults).slice(0, 15000) + ". The report must have 3 sections: 1. Attack Surface Overview, 2. Critical Findings, and 3. Strategic Recommendations. Use professional language.",
                scan_id: null,
                conversation_history: []
            })
        });
        
        if (analyzeResponse.ok) {
            const reader = analyzeResponse.body.getReader();
            const decoder = new TextDecoder("utf-8");
            let aiText = '';
            const contentBox = document.getElementById('execSummaryContent');
            while(true) {
                const { done, value } = await reader.read();
                if (done) break;
                const chunk = decoder.decode(value);
                const lines = chunk.split('\n');
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const text = line.slice(6);
                        if (text !== '[DONE]') {
                            aiText += text;
                            contentBox.innerHTML = marked.parse(aiText);
                        }
                    }
                }
            }
        }
    } catch(e) {
        document.getElementById('execSummaryContent').innerHTML = `<div class="alert alert-error">AI Analysis failed.</div>`;
    }
  }
};

window.toolsModule = toolsModule;
