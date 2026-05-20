const toolsModule = {
  allResults: {},

  renderResult(tool, data) {
    // Store for Executive Summary
    this.allResults[tool] = data;
    
    switch (tool) {
      case 'portscanner':
        this.renderPortScan(data);
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
    if (!data || data.status === 'failed' || data.status === 'cancelled' || data.status === 'timed_out') {
      const icon = data?.status === 'cancelled' ? 'fa-ban' : data?.status === 'timed_out' ? 'fa-clock' : 'fa-circle-exclamation';
      const label = data?.status === 'cancelled' ? 'Scan cancelled' : data?.status === 'timed_out' ? 'Scan timed out' : 'Scan failed';
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid ${icon}"></i> ${data?.error || label}</div>`;
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
        .ws-stat-card { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 20px; text-align: center; }
        .ws-stat-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: #6B7280; margin-bottom: 6px; }
        .ws-stat-value { font-size: 28px; font-weight: 600; font-family: monospace; color: white; }
        .ws-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; }
        .ws-badge-critical { background: #EAB308; color: #0E1016; }
        .ws-badge-high { background: #EAB308; color: #0E1016; }
        .ws-badge-medium { background: #8B5CF6; color: white; }
        .ws-badge-low { background: #1A1F2E; color: #6B7280; border: 1px solid #232736; }
        .ws-badge-info { background: #1A1F2E; color: #6B7280; border: 1px solid #232736; }
        .ws-crawler-warning { background: #2a2010; border: 0.5px solid #5a4010; border-radius: 8px; padding: 12px 16px; display: flex; gap: 10px; align-items: flex-start; margin-bottom: 16px; font-size: 13px; color: #f0b860; }
        .ws-crawler-warning i { color: #f0b860; font-size: 14px; margin-top: 2px; }
        .ws-table-wrapper { overflow-x: auto; margin-top: 16px; animation: ws-fadeIn 0.3s ease-out 0.1s both; }
        .ws-vuln-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .ws-vuln-table th { text-align: left; padding: 10px 16px; background: #0E1016; border-bottom: 1px solid #232736; color: #6B7280; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; }
        .ws-vuln-table td { padding: 0 16px; min-height: 48px; border-bottom: 0.5px solid #1e2028; vertical-align: middle; }
        .ws-vuln-table tbody tr:nth-child(even) { background: #0E1016; }
        .ws-vuln-table tbody tr:nth-child(odd) { background: #111318; }
        .ws-vuln-table tr:hover { background: #1A1F2E; }
        .ws-type-cell { font-size: 13px; color: white; font-family: monospace; }
        .ws-param-cell { font-family: monospace; font-size: 12px; color: #C4B5FD; }
        .ws-loc-cell { font-size: 12px; color: #6B7280; }
        .ws-group-header td { background: #0d0f14; border-left: 3px solid #8B5CF6; padding: 8px 16px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #8B5CF6; font-weight: 600; }
        .ws-group-count { margin-left: 8px; background: #4C1D95; color: #C4B5FD; border-radius: 999px; padding: 1px 8px; font-size: 12px; }
        .ws-expand-btn { background: none; border: none; color: #6B7280; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: transform 0.2s; }
        .ws-expand-btn:hover { background: #1A1F2E; }
        .ws-expand-btn.expanded { transform: rotate(180deg); }
        .ws-detail-row { display: none; }
        .ws-detail-row.show { display: table-row; }
        .ws-detail-content { background: #0A0D12; border-left: 3px solid #232736; padding: 10px 20px; font-size: 13px; color: #9CA3AF; font-family: monospace; line-height: 1.6; }
        .ws-no-vulns { background: rgba(106,207,128,0.1); border: 0.5px solid rgba(106,207,128,0.3); border-radius: 8px; padding: 16px 20px; color: #6acf80; text-align: center; margin-top: 16px; }
        .ws-actions-bar { display: flex; align-items: center; gap: 12px; padding: 12px 0 0; border-top: 1px solid #232736; margin-top: 16px; animation: ws-fadeIn 0.3s ease-out 0.2s both; }
        .ws-rescan-btn { background: transparent; border: 1px solid #232736; color: #9CA3AF; padding: 6px 16px; border-radius: 999px; font-size: 13px; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: all 0.2s; }
        .ws-rescan-btn:hover { background: #1A1F2E; }
        .ws-rescan-btn i { color: #8B5CF6; }
        .ws-meta { font-size: 12px; color: #4B5563; margin-left: auto; }
        .ws-log-section { margin-top: 16px; animation: ws-fadeIn 0.3s ease-out 0.3s both; }
        .ws-log-header { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 14px 16px; display: flex; align-items: center; gap: 10px; cursor: pointer; font-size: 13px; color: white; }
        .ws-log-header:hover { background: #1A1F2E; }
        .ws-log-header i:first-child { color: #EAB308; }
        .ws-log-arrow { margin-left: auto; color: #6B7280; transition: transform 0.2s; }
        .ws-log-header.open .ws-log-arrow { transform: rotate(180deg); }
        .ws-log-content { background: #0d0f14; border: 0.5px solid #2a2d35; border-top: none; border-radius: 0 0 8px 8px; max-height: 200px; overflow-y: auto; display: none; }
        .ws-log-content.open { display: block; }
        .ws-ai-insight { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px 20px; margin-top: 16px; animation: ws-fadeIn 0.3s ease-out 0.4s both; }
        .ws-ai-inner { background: transparent; }
        .ws-ai-header { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; font-size: 13px; font-weight: 600; color: #EAB308; }
        .ws-pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: #EAB308; animation: ws-pulse 2s infinite; }
        .ws-ai-content { font-size: 13px; line-height: 1.7; color: #9CA3AF; font-family: monospace; }
        .ws-ai-content a { color: #8B5CF6; font-family: monospace; font-size: 12px; text-decoration: none; }
        .ws-progress-item { padding: 4px 0; border-bottom: 1px solid #1e2028; display: flex; gap: 12px; animation: ws-fadeIn 0.2s ease-out; }
        .ws-progress-item:last-child { border-bottom: none; }
        .ws-progress-time { color: #4a4a58; font-size: 11px; min-width: 70px; }
        .ws-progress-stage { color: #8B5CF6; font-size: 11px; min-width: 80px; }
        .ws-progress-msg { color: #b0b2ba; font-size: 12px; flex: 1; }
        .ws-progress-dot { width: 6px; height: 6px; border-radius: 50%; margin-right: 6px; }
        .ws-dot-success { background: #6acf80; }
        .ws-dot-running { background: #8B5CF6; animation: ws-pulse 1s infinite; }
        .ws-dot-error { background: #f07070; }
      </style>

      <div class="ws-summary-bar">
        <div class="ws-stat-card">
          <div class="ws-stat-label">Total Vulnerabilities</div>
          <div class="ws-stat-value" style="color: ${totalVulns > 0 ? '#EAB308' : '#6acf80'}">${totalVulns}</div>
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
        <button class="ws-rescan-btn" onclick="copyToolResult('webscan')"><i class="fa-solid fa-copy"></i> Copy</button>
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
            <span style="color: #EAB308; font-family: monospace;">&gt;_</span>
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
          @keyframes whois-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
          .whois-zone { animation: whois-zone-fade 0.3s ease-out forwards; opacity: 0; }
          .whois-zone-1 { animation-delay: 0ms; }
          .whois-zone-2 { animation-delay: 60ms; }
          .whois-zone-3 { animation-delay: 120ms; }
          .whois-zone-4 { animation-delay: 180ms; }
          .whois-zone-5 { animation-delay: 220ms; }
          .whois-zone-6 { animation-delay: 280ms; }
          .whois-zone-7 { animation-delay: 320ms; }
          .whois-hero { background: #151823; border: 1px solid #232736; border-radius: 10px; padding: 20px; display: flex; align-items: center; justify-content: space-between; }
          .whois-hero-left { display: flex; align-items: center; }
          .whois-hero-icon { font-size: 20px; color: #8B5CF6; }
          .whois-hero-domain { font-size: 22px; font-weight: 700; color: white; margin-left: 10px; }
          .whois-hero-registrar { font-size: 13px; color: #6B7280; margin-left: 40px; margin-top: 2px; }
          .whois-trust-badge { background: #151823; border: 1px solid #EAB308; border-radius: 8px; padding: 8px 14px; text-align: center; }
          .whois-trust-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; }
          .whois-trust-value { font-size: 15px; font-weight: 600; color: #EAB308; }
          .whois-reg-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 12px; }
          .whois-reg-card { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 14px 16px; }
          .whois-reg-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-bottom: 4px; }
          .whois-reg-value { font-size: 15px; color: white; font-family: monospace; }
          .whois-status-pill { background: #0A0D12; border: 1px solid #232736; border-radius: 6px; padding: 10px; color: #EAB308; font-family: monospace; font-size: 13px; display: inline-block; }
          .whois-icann-link { color: #8B5CF6; font-size: 15px; font-family: monospace; text-decoration: none; }
          .whois-icann-link:hover { text-decoration: underline; }
          .whois-health-row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px; }
          .whois-health-card { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px; }
          .whois-health-label { font-size: 10px; text-transform: uppercase; color: #6B7280; margin-bottom: 4px; }
          .whois-health-value { font-size: 20px; font-weight: 500; font-family: monospace; }
          .whois-health-sub { font-size: 10px; color: #6B7280; margin-top: 2px; }
          .whois-age-card { border-left: 3px solid #8B5CF6; }
          .whois-age-card .whois-health-value { color: #8B5CF6; }
          .whois-exp-card { border-left: 3px solid #EAB308; }
          .whois-exp-card .whois-health-value { color: #EAB308; }
          .whois-timeline-bar { height: 4px; background: #1e2028; border-radius: 2px; margin-top: 10px; overflow: hidden; }
          .whois-timeline-fill { height: 100%; background: #8B5CF6; border-radius: 2px; }
          .whois-timeline-note { font-size: 10px; color: #6b6e78; margin-top: 4px; text-align: right; }
          .whois-ns-label { font-size: 11px; text-transform: uppercase; color: #6b6e78; letter-spacing: 0.08em; margin-bottom: 8px; }
          .whois-ns-list { display: flex; flex-wrap: wrap; gap: 8px; }
          .whois-ns-pill { background: #151823; border: 1px solid #232736; border-radius: 999px; padding: 6px 14px; font-size: 12px; font-family: monospace; color: #C4B5FD; display: inline-flex; align-items: center; gap: 8px; }
          .whois-ns-pill i { font-size: 12px; color: #8B5CF6; }
          .whois-ns-expiry { color: #4B5563; font-size: 11px; margin-left: 8px; }
          .whois-abuse-card { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 14px 16px; margin-top: 12px; }
          .whois-abuse-label { font-size: 10px; text-transform: uppercase; color: #6B7280; margin-bottom: 4px; }
          .whois-abuse-value { font-size: 12px; font-family: monospace; color: #8B5CF6; display: flex; align-items: center; gap: 8px; }
          .whois-abuse-value i { color: #8B5CF6; }
          .whois-osint-box { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 14px 20px; margin-top: 14px; }
          .whois-osint-header { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; color: #EAB308; margin-bottom: 10px; }
          .whois-osint-dot { width: 8px; height: 8px; border-radius: 50%; background: #EAB308; animation: whois-pulse 2s infinite; }
          .whois-osint-content { font-size: 12px; line-height: 1.7; color: #9CA3AF; font-family: monospace; }
          .whois-osint-highlight { color: #8B5CF6; font-family: monospace; font-size: 12px; }
          .whois-raw-header { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 14px 16px; display: flex; align-items: center; cursor: pointer; margin-top: 14px; gap: 10px; font-size: 13px; color: white; }
          .whois-raw-header:hover { background: #1A1F2E; }
          .whois-raw-header i:first-child { color: #8B5CF6; }
          .whois-raw-arrow { color: #6B7280; transition: transform 0.2s; margin-left: auto; }
          .whois-raw-arrow.open { transform: rotate(180deg); }
          .whois-raw-content { background: #0d0f14; padding: 14px 16px; border-radius: 0 0 8px 8px; display: none; font-family: monospace; font-size: 12px; color: #6b6e78; }
          .whois-raw-content.open { display: block; }
          .whois-actions-bar { display: flex; align-items: center; gap: 12px; padding-top: 14px; border-top: 1px solid #232736; margin-top: 14px; }
          .whois-copy-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .whois-copy-btn:hover { background: #1A1F2E; }
          .whois-copy-btn i { color: #8B5CF6; }
          .whois-ai-btn { background: #8B5CF6; border: none; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: white; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .whois-ai-btn:hover { background: #7C3AED; }
          .whois-ai-btn i { color: white; }
          .whois-meta-right { font-size: 12px; color: #4B5563; margin-left: auto; }
          .whois-loading { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #6b6e78; }
          .whois-loading i { color: #8B5CF6; }
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
              <div class="whois-trust-value"> ${isTrusted ? 'Trusted' : 'New'}</div>
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
              ? nameServers.map(ns => `<span class="whois-ns-pill"><i class="fa-solid fa-gear"></i>${ns}</span>`).join('') + `<span class="whois-ns-expiry">Expires ${expiresDate.replace(/<[^>]*>/g, '')}</span>`
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
            <span style="color: #8B5CF6; font-family: monospace;">&lt;/&gt;</span> Raw WHOIS Data
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

    const minVal = Math.min(data.min_ms || 0, data.max_ms || 0);
    const maxVal = Math.max(data.min_ms || 0, data.max_ms || 0);
    const avgVal = data.avg_ms || ((minVal + maxVal) / 2);
    const lossPct = parseFloat(data.packet_loss_pct || (data.packet_loss ? data.packet_loss.replace('%','') : 0));
    const raw = data.raw_output || '';
    const timeMatches = [...raw.matchAll(/time=([\d.]+)\s*ms/gi)];
    const responseTimes = timeMatches.length > 0 ? timeMatches.map(m => parseFloat(m[1])) : [];
    const jitter = maxVal - minVal;
    const packetsSent = data.packets_sent || responseTimes.length || 4;
    const packetsReceived = data.packets_received || responseTimes.length || 4;
    const packetsLost = packetsSent - packetsReceived;

    const getQuality = (ms) => {
      if (ms < 50) return { label: 'EXCELLENT', color: '#6acf80' };
      if (ms < 100) return { label: 'GOOD', color: '#f0b860' };
      if (ms < 200) return { label: 'FAIR', color: '#f07040' };
      return { label: 'POOR', color: '#f07070' };
    };

    const quality = getQuality(avgVal);
    const minQuality = getQuality(minVal);
    const maxQuality = getQuality(maxVal);
    const lossColor = lossPct > 0 ? '#f07070' : '#6acf80';
    const jitterColor = jitter < 5 ? '#6acf80' : jitter < 20 ? '#f0b860' : '#f07070';

    const chartData = responseTimes.length > 0 ? responseTimes : [minVal, minVal + jitter * 0.3, minVal + jitter * 0.6, maxVal];
    const chartMax = Math.max(...chartData, 100) * 1.1;
    const avgLineY = 100 - (avgVal / chartMax) * 100;
    const barsHtml = chartData.map((t, i) => {
      const height = (t / chartMax) * 100;
      return `<div style="display:flex;flex-direction:column;align-items:center;flex:1">
        <div class="ping-bar-wrapper" style="height:100px;display:flex;align-items:flex-end;width:100%;padding:0 4px">
          <div class="ping-chart-bar" style="height:0%;width:100%;background:#a78bfa;opacity:0.7;border-radius:3px 3px 0 0;transition:height 0.4s ease-out ${i * 80}ms" data-target="${height}"></div>
        </div>
        <div style="font-size:10px;color:#6b6e78;margin-top:4px">Ping ${i + 1}</div>
        <div style="font-size:10px;color:#a78bfa;font-family:monospace">${t.toFixed(1)}ms</div>
      </div>`;
    }).join('');

    const generateFallbackInsight = (d) => {
      const q = d.avgVal < 50 ? 'excellent' : d.avgVal < 100 ? 'good' : d.avgVal < 200 ? 'fair' : 'poor';
      const stability = d.jitter < 5 ? 'very stable' : d.jitter < 20 ? 'moderately stable' : 'unstable';
      return `Connection to ${d.target} shows ${q} performance with an average latency of ${d.avgVal.toFixed(1)}ms and ${d.lossPct}% packet loss. Jitter of ${d.jitter.toFixed(1)}ms indicates ${stability} network conditions.`;
    };

    output.innerHTML = `
      <div class="ping-result">
        <style>
          @keyframes ping-zone-fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
          @keyframes ping-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
          .ping-zone { animation: ping-zone-fade 0.3s ease-out forwards; opacity: 0; }
          .ping-zone-1 { animation-delay: 0ms; }
          .ping-zone-2 { animation-delay: 60ms; }
          .ping-zone-3 { animation-delay: 120ms; }
          .ping-zone-4 { animation-delay: 180ms; }
          .ping-zone-5 { animation-delay: 240ms; }
          .ping-zone-6 { animation-delay: 300ms; }
          .ping-hero { background: #151823; border-left: 3px solid #EAB308; border: 1px solid #232736; border-radius: 8px; padding: 20px; display: flex; align-items: center; justify-content: space-between; }
          .ping-hero-left {}
          .ping-quality-badge { background: #EAB308; color: #0E1016; font-size: 10px; font-weight: 700; letter-spacing: 0.08em; border-radius: 999px; padding: 2px 10px; display: inline-block; }
          .ping-hero-title { font-size: 20px; font-weight: 700; color: white; font-family: monospace; margin-top: 6px; }
          .ping-hero-target { font-size: 13px; color: #6B7280; margin-top: 4px; }
          .ping-latency-box { background: #0E1016; border: 1px solid #EAB308; border-radius: 8px; padding: 10px 16px; text-align: center; }
          .ping-latency-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; }
          .ping-latency-value { font-size: 24px; font-weight: 700; color: #EAB308; font-family: monospace; margin-top: 2px; }
          .ping-stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 12px; }
          .ping-stat-card { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px; }
          .ping-stat-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-bottom: 4px; }
          .ping-stat-value { font-size: 20px; font-weight: 600; font-family: monospace; color: #EAB308; }
          .ping-stat-sub { font-size: 12px; color: #6B7280; margin-top: 2px; }
          .ping-health-row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px; }
          .ping-health-card { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px; }
          .ping-health-label { font-size: 10px; text-transform: uppercase; color: #6B7280; margin-bottom: 4px; }
          .ping-health-value { font-size: 20px; font-weight: 600; font-family: monospace; }
          .ping-health-sub { font-size: 12px; color: #6B7280; margin-top: 2px; }
          .ping-jitter-card { border-left: 3px solid #EAB308; }
          .ping-jitter-card .ping-health-value { color: #EAB308; }
          .ping-packets-card { border-left: 3px solid #8B5CF6; }
          .ping-packets-row { display: flex; gap: 16px; }
          .ping-packets-sent { font-size: 14px; color: white; font-family: monospace; }
          .ping-packets-recv { font-size: 14px; color: #8B5CF6; font-family: monospace; }
          .ping-chart-section { margin-top: 12px; }
          .ping-chart-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: #6B7280; }
          .ping-chart-container { background: #0A0D12; border: 1px solid #232736; border-radius: 8px; padding: 16px; height: 160px; position: relative; }
          .ping-chart-bars { display: flex; align-items: flex-end; height: 100px; gap: 8px; }
          .ping-chart-bar { cursor: pointer; background: linear-gradient(to top, #EAB308 60%, transparent); stroke: #EAB308; stroke-width: 2px; }
          .ping-chart-bar:hover { opacity: 1 !important; }
          .ping-avg-line { position: absolute; left: 16px; right: 16px; height: 1px; border-top: 1px dashed #EAB308; opacity: 0.4; }
          .ping-avg-label { position: absolute; right: 20px; font-size: 10px; color: #EAB308; transform: translateY(-150%); }
          .ping-chart-yaxis { position: absolute; left: 0; top: 0; bottom: 0; width: 30px; display: flex; flex-direction: column; justify-content: space-between; padding: 4px 0; font-size: 11px; color: #6B7280; font-family: monospace; }
          .ping-chart-grid { position: absolute; left: 40px; right: 16px; top: 16px; bottom: 30px; }
          .ping-grid-line { position: absolute; left: 0; right: 0; height: 1px; background: #1A1F2E; border-style: dashed; border-width: 1px 0 0 0; }
          .ping-osint-box { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px 20px; margin-top: 14px; }
          .ping-osint-header { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; color: #EAB308; margin-bottom: 10px; }
          .ping-osint-dot { width: 8px; height: 8px; border-radius: 50%; background: #EAB308; animation: ping-pulse 2s infinite; }
          .ping-osint-content { font-size: 12px; line-height: 1.7; color: #9CA3AF; font-family: monospace; }
          .ping-fallback-box { background: #111318; border: 0.5px solid #2a2d35; border-radius: 10px; padding: 16px 20px; margin-top: 14px; }
          .ping-fallback-header { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 500; color: #6b6e78; margin-bottom: 10px; }
          .ping-fallback-content { font-size: 13px; line-height: 1.7; color: #b0b2ba; }
          .ping-raw-header { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 14px 16px; display: flex; align-items: center; cursor: pointer; margin-top: 14px; gap: 10px; font-size: 13px; color: white; }
          .ping-raw-header:hover { background: #1A1F2E; }
          .ping-raw-header i:first-child { color: #8B5CF6; }
          .ping-raw-arrow { color: #6B7280; transition: transform 0.2s; }
          .ping-raw-arrow.open { transform: rotate(180deg); }
          .ping-raw-content { background: #0d0f14; padding: 14px 16px; border-radius: 0 0 8px 8px; display: none; }
          .ping-raw-content.open { display: block; }
          .ping-raw-row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 0.5px solid #1e2028; }
          .ping-raw-key { font-size: 12px; color: #6b6e78; }
          .ping-raw-val { font-size: 12px; font-family: monospace; color: #b0b2ba; }
          .ping-actions-bar { display: flex; align-items: center; gap: 12px; padding-top: 14px; border-top: 1px solid #232736; margin-top: 14px; }
          .ping-copy-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .ping-copy-btn:hover { background: #1A1F2E; }
          .ping-copy-btn i { color: #8B5CF6; }
          .ping-reping-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .ping-reping-btn:hover { background: #1A1F2E; }
          .ping-reping-btn i { color: #8B5CF6; }
          .ping-meta-right { font-size: 12px; color: #4B5563; margin-left: auto; }
          .ping-loading { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #6b6e78; }
          .ping-loading i { color: #8B5CF6; }
        </style>

        <div class="ping-zone ping-zone-1">
          <div class="ping-hero">
            <div class="ping-hero-left">
              <span class="ping-quality-badge">${quality.label}</span>
              <div class="ping-hero-title">Connection Quality</div>
              <div class="ping-hero-target">Target: ${data.target}</div>
            </div>
            <div class="ping-latency-box">
              <div class="ping-latency-label">Avg Latency</div>
              <div class="ping-latency-value">${avgVal.toFixed(1)}ms</div>
            </div>
          </div>
        </div>

        <div class="ping-zone ping-zone-2">
          <div class="ping-stats-grid">
            <div class="ping-stat-card">
              <div class="ping-stat-label">Min Latency</div>
              <div class="ping-stat-value" style="color:${minQuality.color}">${minVal.toFixed(2)} ms</div>
            </div>
            <div class="ping-stat-card">
              <div class="ping-stat-label">Avg Latency</div>
              <div class="ping-stat-value" style="color:${quality.color}">${avgVal.toFixed(2)} ms</div>
            </div>
            <div class="ping-stat-card">
              <div class="ping-stat-label">Max Latency</div>
              <div class="ping-stat-value" style="color:${maxQuality.color}">${maxVal.toFixed(2)} ms</div>
            </div>
            <div class="ping-stat-card">
              <div class="ping-stat-label">Packet Loss</div>
              <div class="ping-stat-value" style="color:${lossPct === 0 ? '#8B5CF6' : '#EAB308'}">${lossPct}%</div>
              <div class="ping-stat-sub">${packetsReceived}/${packetsSent} packets received</div>
            </div>
          </div>
        </div>

        <div class="ping-zone ping-zone-3">
          <div class="ping-health-row">
            <div class="ping-health-card ping-jitter-card">
              <div class="ping-health-label">Jitter</div>
              <div class="ping-health-value">${jitter.toFixed(2)} ms</div>
              <div class="ping-health-sub">Network stability indicator</div>
            </div>
            <div class="ping-health-card ping-packets-card">
              <div class="ping-health-label">Packets</div>
              <div class="ping-packets-row">
                <span class="ping-packets-sent">Sent: ${packetsSent}</span>
                <span class="ping-packets-recv">Received: ${packetsReceived}</span>
              </div>
              <div class="ping-health-sub" style="color:${packetsLost === 0 ? '#6acf80' : '#f07070'}">${packetsLost} lost</div>
            </div>
          </div>
        </div>

        <div class="ping-zone ping-zone-4">
          <div class="ping-chart-section">
            <div class="ping-chart-label">Response Times</div>
            <div class="ping-chart-container">
              <div class="ping-chart-yaxis"><span style="font-family: monospace;">0ms</span><span style="font-family: monospace;">${Math.round(chartMax)}ms</span></div>
              <div class="ping-chart-grid">
                <div class="ping-grid-line" style="top: 0%"></div>
                <div class="ping-grid-line" style="top: 25%"></div>
                <div class="ping-grid-line" style="top: 50%"></div>
                <div class="ping-grid-line" style="top: 75%"></div>
                <div class="ping-grid-line" style="top: 100%"></div>
              </div>
              <div style="position:absolute;left:40px;right:16px;top:16px;bottom:30px;display:flex;align-items:flex-end">
                ${chartData.map((t, i) => `<div style="flex:1;display:flex;flex-direction:column;align-items:center;height:100%;justify-content:flex-end"><div class="ping-chart-bar" style="width:100%;background:linear-gradient(to top, #EAB308 60%, transparent);border:2px solid #EAB308;border-radius:3px 3px 0 0;height:0%;transition:height 0.5s ease-out ${i * 100}ms" data-target="${(t / chartMax) * 100}"></div></div>`).join('')}
              </div>
              <div class="ping-avg-line" style="bottom:${16 + (avgVal / chartMax) * (160 - 46)}px">
                <span class="ping-avg-label" style="font-family: monospace;">avg ${avgVal.toFixed(1)}ms</span>
              </div>
              <div style="position:absolute;bottom:8px;left:40px;right:0;display:flex;justify-content:space-around">
                ${chartData.map((_, i) => `<span style="font-size:10px;color:#6B7280;font-family: monospace;">Ping ${i + 1}</span>`).join('')}
              </div>
            </div>
          </div>
        </div>

        <div class="ping-zone ping-zone-5">
          <div id="ping-ai-analysis-container"></div>
        </div>

        <div class="ping-zone ping-zone-6">
          <div class="ping-raw-header" onclick="this.querySelector('.ping-raw-arrow').classList.toggle('open'); this.nextElementSibling.classList.toggle('open');">
            <i class="fa-solid fa-gear"></i> Advanced Details
            <i class="fa-solid fa-chevron-down ping-raw-arrow"></i>
          </div>
          <div class="ping-raw-content">
            <div class="ping-raw-row"><span class="ping-raw-key">Jitter</span><span class="ping-raw-val">${jitter.toFixed(2)} ms</span></div>
            <div class="ping-raw-row"><span class="ping-raw-key">Packets Sent</span><span class="ping-raw-val">${packetsSent}</span></div>
            <div class="ping-raw-row"><span class="ping-raw-key">Packets Received</span><span class="ping-raw-val">${packetsReceived}</span></div>
            <div class="ping-raw-row"><span class="ping-raw-key">Packets Lost</span><span class="ping-raw-val">${packetsLost}</span></div>
            <div class="ping-raw-row"><span class="ping-raw-key">Protocol</span><span class="ping-raw-val">ICMP</span></div>
          </div>
        </div>

        <div class="ping-actions-bar">
          <button class="ping-copy-btn" onclick="copyToolResult('ping')"><i class="fa-solid fa-copy"></i> Copy</button>
          <button class="ping-reping-btn" onclick="runTool('ping')"><i class="fa-solid fa-rotate-right"></i> Re-ping</button>
          <span class="ping-meta-right">${data.target} · ${packetsSent} pings · just now</span>
        </div>
      </div>
    `;

    setTimeout(() => {
      document.querySelectorAll('.ping-chart-bar').forEach(bar => {
        bar.style.height = bar.dataset.target + '%';
      });
    }, 50);

    setTimeout(async () => {
        const aiContainer = document.getElementById('ping-ai-analysis-container');
        if (!aiContainer) return;
        aiContainer.innerHTML = `<div class="ping-loading"><i class="fa-solid fa-robot fa-flip"></i> AI analyzing network performance...</div>`;
        
        try {
            const analyzeResponse = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || localStorage.getItem('cybersec_token') || '') },
                body: JSON.stringify({ 
                    message: "Analyze these PING results: Target " + data.target + ", Avg Latency " + avgVal.toFixed(1) + "ms, Packet Loss " + lossPct + "%, Jitter " + jitter.toFixed(1) + "ms. Individual responses: [" + chartData.join(', ') + "]. Write a 2-sentence technical synopsis of this connection's health and reliability for real-time traffic.",
                    scan_id: null,
                    conversation_history: []
                })
            });
            
            if (analyzeResponse.ok) {
                const reader = analyzeResponse.body.getReader();
                const decoder = new TextDecoder("utf-8");
                let aiText = '';
                aiContainer.innerHTML = `
                    <div class="ping-osint-box">
                        <div class="ping-osint-header"><div class="ping-osint-dot"></div> Network Analysis</div>
                        <div class="ping-osint-content" id="pingAiContent"></div>
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
                                if (contentBox) contentBox.innerHTML = marked.parse(aiText);
                            }
                        }
                    }
                }
            } else {
                throw new Error('API error');
            }
        } catch(e) {
            aiContainer.innerHTML = `
                <div class="ping-fallback-box">
                    <div class="ping-fallback-header"><i class="fa-solid fa-brain"></i> Network Analysis</div>
                    <div class="ping-fallback-content">${generateFallbackInsight({ target: data.target, avgVal, lossPct, jitter })}</div>
                </div>
            `;
        }
    }, 300);

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
    const targetReached = hops.length > 0 && hops[hops.length - 1].ip && hops[hops.length - 1].ip !== '*';
    const totalHops = hops.length;
    const reachedLabel = targetReached ? 'Yes' : 'No (timed out)';
    const reachedColor = targetReached ? '#6acf80' : '#f07070';
    
    const responsiveHops = hops.filter(h => h.rtt_ms != null && h.rtt_ms !== '*');
    const maxRTT = responsiveHops.length > 0 ? Math.max(...responsiveHops.map(h => parseFloat(h.rtt_ms))) : 0;
    const totalRTT = responsiveHops.length > 0 ? responsiveHops.reduce((a, b) => a + parseFloat(b.rtt_ms), 0).toFixed(1) : '0';
    const rttColor = maxRTT < 10 ? '#6acf80' : maxRTT < 50 ? '#f0b860' : maxRTT < 100 ? '#f07040' : '#f07070';

    const getHopColor = (hop, ip) => {
      if (!ip || ip === '*') return '#2a2d35';
      if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')) return '#8B5CF6';
      if (hop <= 7) return '#EAB308';
      return '#4ADE80';
    };

    const getRttColor = (rtt) => {
      if (rtt === '*' || rtt == null) return '#4a4d58';
      const r = parseFloat(rtt);
      if (r < 30) return '#8B5CF6';
      if (r < 60) return '#EAB308';
      return '#F59E0B';
    };

    const timeoutHops = hops.filter(h => !h.ip || h.ip === '*');
    const activeHops = hops.filter(h => h.ip && h.ip !== '*');
    
    let hopRowsHtml = '';
    activeHops.forEach((h, i) => {
      const hopColor = getHopColor(h.hop, h.ip);
      const rttColor = getRttColor(h.rtt_ms);
      const rttDisplay = h.rtt_ms != null && h.rtt_ms !== '*' ? parseFloat(h.rtt_ms).toFixed(3) + ' ms' : '*';
      const hostname = h.host || (h.ip ? '<span class="resolving">Resolving<span class="dots">...</span></span>' : '*');
      hopRowsHtml += `
        <div class="trace-hop-row" style="border-left: 3px solid ${hopColor}" data-hop="${h.hop}">
          <div class="trace-hop-num">${h.hop}</div>
          <div class="trace-hop-ip">${h.ip}</div>
          <div class="trace-hop-host">${hostname}</div>
          <div class="trace-hop-rtt" style="color:${rttColor}">${rttDisplay}</div>
        </div>
      `;
    });

    if (timeoutHops.length > 0) {
      hopRowsHtml += `
        <div class="trace-timeout-row">
          <i class="fa-solid fa-shield"></i> Hops ${activeHops.length + 1}–${totalHops} · No response (ICMP filtered or firewall blocking)
        </div>
      `;
    }

    const chartPoints = responsiveHops.slice(0, 10).map((h, i) => ({
      x: i + 1,
      y: parseFloat(h.rtt_ms),
      ip: h.ip
    }));
    
    let svgPath = '';
    let svgArea = '';
    if (chartPoints.length > 0) {
      const maxY = Math.max(...chartPoints.map(p => p.y), 100) * 1.2;
      const width = 100;
      const height = 80;
      const padding = 10;
      
      const points = chartPoints.map((p, i) => {
        const x = padding + (i / (chartPoints.length - 1 || 1)) * (width - padding * 2);
        const y = height - padding - (p.y / maxY) * (height - padding * 2);
        return `${x},${y}`;
      });
      
      svgPath = `<polyline points="${points.join(' ')}" fill="none" stroke="#EAB308" stroke-width="2" class="trace-line"/>`;
      svgArea = `<polygon points="${padding},${height - padding} ${points.join(' ')} ${width - padding},${height - padding}" fill="url(#goldGradient)"/>`;
      
      chartPoints.forEach((p, i) => {
        const x = padding + (i / (chartPoints.length - 1 || 1)) * (width - padding * 2);
        const y = height - padding - (p.y / maxY) * (height - padding * 2);
        svgPath += `<circle cx="${x}" cy="${y}" r="3" fill="#EAB308" class="trace-point" data-info="Hop ${p.x} · ${p.ip} · ${p.y.toFixed(2)}ms"/>`;
      });
    }

    const generateFallback = (hopsData, target) => {
      const reachable = hopsData.filter(h => h.rtt_ms != null && h.rtt_ms !== '*').length;
      const maxR = Math.max(...hopsData.filter(h => h.rtt_ms != null && h.rtt_ms !== '*').map(h => parseFloat(h.rtt_ms)), 0);
      const timeouts = hopsData.filter(h => !h.ip || h.ip === '*').length;
      const jumpHop = hopsData.find((h, i) => i > 0 && h.rtt_ms != null && parseFloat(h.rtt_ms) > 50);
      
      return `Route to ${target} traversed ${reachable} responsive hops with a maximum RTT of ${maxR.toFixed(1)}ms. ${timeouts} hops did not respond, likely due to ICMP filtering or firewall rules.${jumpHop ? ` The significant latency jump at hop ${jumpHop.hop} (${jumpHop.ip}) suggests a transition from ISP infrastructure to the internet backbone.` : ''}`;
    };

    output.innerHTML = `
      <div class="trace-result">
        <style>
          @keyframes trace-fade { from { opacity: 0; transform: translateX(-8px); } to { opacity: 1; transform: translateX(0); } }
          @keyframes trace-dot-pulse { 0%, 80%, 100% { opacity: 0; } 40% { opacity: 1; } }
          @keyframes trace-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
          .trace-zone { animation: trace-fade 0.3s ease-out forwards; opacity: 0; }
          .trace-zone-1 { animation-delay: 0ms; }
          .trace-zone-2 { animation-delay: 60ms; }
          .trace-zone-3 { animation-delay: 120ms; }
          .trace-zone-4 { animation-delay: 180ms; }
          .trace-zone-5 { animation-delay: 240ms; }
          .trace-hero { background: #151823; border: 1px solid #232736; border-radius: 10px; padding: 20px; display: flex; align-items: center; justify-content: space-between; }
          .trace-hero-left { display: flex; align-items: center; gap: 12px; }
          .trace-hero-icon { font-size: 20px; color: #8B5CF6; }
          .trace-hero-title { font-size: 20px; font-weight: 700; color: white; font-family: monospace; }
          .trace-hero-target { font-size: 13px; color: #6B7280; margin-top: 4px; }
          .trace-stats-row { display: flex; gap: 10px; }
          .trace-stat-pill { background: #0E1016; border: 1px solid #232736; border-radius: 8px; padding: 8px 14px; text-align: center; }
          .trace-stat-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; }
          .trace-stat-value { font-size: 14px; font-weight: 500; margin-top: 2px; }
          .trace-hop-table { background: #151823; border: 1px solid #232736; border-radius: 8px; margin-top: 12px; overflow: hidden; }
          .trace-hop-header { display: grid; grid-template-columns: 50px 160px 1fr 100px; padding: 10px 16px; background: #0E1016; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; border-bottom: 1px solid #232736; }
          .trace-hop-row { display: grid; grid-template-columns: 50px 160px 1fr 100px; padding: 0 16px; min-height: 44px; align-items: center; border-bottom: 0.5px solid #1e2028; animation: trace-fade 0.3s ease-out forwards; opacity: 0; }
          .trace-hop-row:nth-child(even) { background: #0E1016; }
          .trace-hop-row:nth-child(odd) { background: #111318; }
          .trace-hop-row:hover { background: #1A1F2E; }
          .trace-hop-num { font-size: 13px; color: #4B5563; font-family: monospace; }
          .trace-hop-ip { font-size: 13px; color: white; font-family: monospace; font-weight: 600; }
          .trace-hop-host { font-size: 13px; color: #6B7280; font-family: monospace; }
          .trace-hop-host .resolving { color: #4a4d58; }
          .trace-hop-host .dots { animation: trace-dot-pulse 1.4s infinite; }
          .trace-hop-rtt { font-size: 13px; font-family: monospace; text-align: right; }
          .trace-timeout-row { background: #0A0D12; border: 1px solid #232736; border-radius: 6px; margin: 8px 16px; padding: 10px 16px; font-size: 12px; color: #6B7280; font-family: monospace; display: flex; align-items: center; gap: 8px; }
          .trace-timeout-row i { font-size: 14px; color: #6B7280; }
          .trace-legend { display: flex; gap: 16px; padding: 8px 16px; font-size: 12px; color: #9CA3AF; }
          .trace-legend-item { display: flex; align-items: center; gap: 6px; }
          .trace-legend-dot { width: 8px; height: 8px; border-radius: 50%; }
          .trace-chart-section { margin-top: 12px; }
          .trace-chart-label { font-size: 10px; text-transform: uppercase; color: #6B7280; letter-spacing: 0.1em; margin-bottom: 8px; }
          .trace-chart-container { background: #0A0D12; border: 1px solid #232736; border-radius: 8px; padding: 16px; height: 120px; position: relative; }
          .trace-chart-svg { width: 100%; height: 100%; }
          .trace-line { stroke-dasharray: 500; stroke-dashoffset: 500; animation: trace-draw 0.8s ease-out forwards; }
          @keyframes trace-draw { to { stroke-dashoffset: 0; } }
          .trace-chart-yaxis { position: absolute; left: 4px; top: 16px; bottom: 30px; display: flex; flex-direction: column; justify-content: space-between; font-size: 11px; color: #6B7280; font-family: monospace; }
          .trace-chart-xaxis { position: absolute; bottom: 8px; left: 40px; right: 8px; display: flex; justify-content: space-between; font-size: 11px; color: #6B7280; font-family: monospace; }
          .trace-chart-grid { position: absolute; left: 40px; right: 8px; top: 16px; bottom: 30px; }
          .trace-grid-line { position: absolute; left: 0; right: 0; height: 1px; background: #1A1F2E; border-style: dashed; border-width: 1px 0 0 0; }
          .trace-osint-box { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px 20px; margin-top: 14px; }
          .trace-osint-header { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; color: #EAB308; margin-bottom: 10px; }
          .trace-osint-dot { width: 8px; height: 8px; border-radius: 50%; background: #EAB308; animation: trace-pulse 2s infinite; }
          .trace-osint-content { font-size: 12px; line-height: 1.7; color: #9CA3AF; font-family: monospace; }
          .trace-fallback-box { background: #111318; border: 0.5px solid #2a2d35; border-radius: 10px; padding: 16px 20px; margin-top: 14px; }
          .trace-fallback-header { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 500; color: #6b6e78; margin-bottom: 10px; }
          .trace-fallback-content { font-size: 13px; line-height: 1.7; color: #b0b2ba; }
          .trace-suggest-box { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px 20px; margin-top: 14px; }
          .trace-suggest-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-bottom: 8px; }
          .trace-suggest-content { display: flex; align-items: center; justify-content: space-between; }
          .trace-suggest-info { display: flex; align-items: center; gap: 12px; }
          .trace-suggest-icon { width: 32px; height: 32px; border-radius: 50%; background: #8B5CF6; display: flex; align-items: center; justify-content: center; color: white; font-size: 14px; }
          .trace-suggest-title { font-size: 14px; font-weight: 600; color: white; font-family: monospace; }
          .trace-suggest-sub { font-size: 12px; color: #6B7280; margin-top: 2px; }
          .trace-run-btn { background: #8B5CF6; border: none; border-radius: 6px; padding: 6px 16px; font-size: 13px; font-weight: 600; color: white; cursor: pointer; }
          .trace-run-btn:hover { background: #7C3AED; }
          .trace-actions-bar { display: flex; align-items: center; gap: 12px; padding-top: 14px; border-top: 1px solid #232736; margin-top: 14px; }
          .trace-copy-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .trace-copy-btn:hover { background: #1A1F2E; }
          .trace-copy-btn i { color: #8B5CF6; }
          .trace-retrace-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .trace-retrace-btn:hover { background: #1A1F2E; }
          .trace-retrace-btn i { color: #8B5CF6; }
          .trace-meta-right { font-size: 12px; color: #4B5563; margin-left: auto; }
          .trace-loading { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #6b6e78; }
          .trace-loading i { color: #8B5CF6; }
        </style>

        <div class="trace-zone trace-zone-1">
          <div class="trace-hero">
            <div class="trace-hero-left">
              <i class="fa-solid fa-route trace-hero-icon"></i>
              <div>
                <div class="trace-hero-title">Network Path</div>
                <div class="trace-hero-target">Target: ${data.target}</div>
              </div>
            </div>
            <div class="trace-stats-row">
              <div class="trace-stat-pill">
                <div class="trace-stat-label">Total Hops</div>
                <div class="trace-stat-value">${totalHops}</div>
              </div>
              <div class="trace-stat-pill">
                <div class="trace-stat-label">Reached Target</div>
                <div class="trace-stat-value" style="color:${targetReached ? '#8B5CF6' : '#EAB308'}">${reachedLabel}</div>
              </div>
              <div class="trace-stat-pill">
                <div class="trace-stat-label">Total RTT</div>
                <div class="trace-stat-value" style="color:#8B5CF6;font-family:monospace">${totalRTT}ms</div>
              </div>
            </div>
          </div>
        </div>

        <div class="trace-zone trace-zone-2">
          <div class="trace-hop-table">
            <div class="trace-hop-header">
              <div>#</div>
              <div>IP Address</div>
              <div>Hostname</div>
              <div style="text-align:right">RTT</div>
            </div>
            ${hopRowsHtml || '<div style="padding:20px;color:#6b6e78">No hops recorded</div>'}
          </div>
          <div class="trace-legend">
            <div class="trace-legend-item"><div class="trace-legend-dot" style="background:#8B5CF6"></div>Local Network</div>
            <div class="trace-legend-item"><div class="trace-legend-dot" style="background:#EAB308"></div>ISP Routing</div>
            <div class="trace-legend-item"><div class="trace-legend-dot" style="background:#4ADE80"></div>Internet</div>
          </div>
        </div>

        <div class="trace-zone trace-zone-3">
          <div class="trace-chart-section">
            <div class="trace-chart-label">Latency Progression</div>
            <div class="trace-chart-container">
              <div class="trace-chart-yaxis"><span style="font-family: monospace;">0ms</span><span style="font-family: monospace;">50ms</span><span style="font-family: monospace;">100ms</span></div>
              <div class="trace-chart-grid">
                <div class="trace-grid-line" style="top: 0%"></div>
                <div class="trace-grid-line" style="top: 25%"></div>
                <div class="trace-grid-line" style="top: 50%"></div>
                <div class="trace-grid-line" style="top: 75%"></div>
                <div class="trace-grid-line" style="top: 100%"></div>
              </div>
              <svg class="trace-chart-svg" viewBox="0 0 100 80" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="goldGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" style="stop-color:#EAB308;stop-opacity:0.5" />
                    <stop offset="100%" style="stop-color:#EAB308;stop-opacity:0" />
                  </linearGradient>
                </defs>
                ${svgArea}
                ${svgPath}
              </svg>
              <div class="trace-chart-xaxis">
                ${chartPoints.map((_, i) => `<span style="font-family: monospace;">${i + 1}</span>`).join('')}
              </div>
            </div>
          </div>
        </div>

        <div class="trace-zone trace-zone-4">
          <div id="traceroute-ai-intuition-container"></div>
        </div>

        <div class="trace-zone trace-zone-5">
          <div class="trace-suggest-box">
            <div class="trace-suggest-label">Suggested Next Step</div>
            <div class="trace-suggest-content">
              <div class="trace-suggest-info">
                <div class="trace-suggest-icon"><i class="fa-solid fa-arrow-right"></i></div>
                <div>
                  <div class="trace-suggest-title">Performance Benchmark (Ping)</div>
                  <div class="trace-suggest-sub">Measure stability and packet loss after identifying the network path</div>
                </div>
              </div>
              <button class="trace-run-btn" onclick="switchTool('ping')">Run Ping <i class="fa-solid fa-arrow-right" style="margin-left:4px"></i></button>
            </div>
          </div>
        </div>

        <div class="trace-actions-bar">
          <button class="trace-copy-btn" onclick="copyToolResult('traceroute')"><i class="fa-solid fa-copy"></i> Copy</button>
          <button class="trace-retrace-btn" onclick="runTool('traceroute')"><i class="fa-solid fa-rotate-right"></i> Re-trace</button>
          <span class="trace-meta-right">${data.target} · ${totalHops} hops · just now</span>
        </div>
      </div>
    `;

    setTimeout(() => {
      document.querySelectorAll('.trace-hop-row').forEach((row, i) => {
        row.style.animationDelay = `${i * 30}ms`;
      });
    }, 50);

    setTimeout(() => {
      document.querySelectorAll('.trace-hop-host .resolving').forEach(el => {
        const row = el.closest('.trace-hop-row');
        const ip = row ? row.querySelector('.trace-hop-ip')?.textContent : '';
        if (el.textContent.includes('Resolving')) {
          setTimeout(() => {
            if (el.textContent.includes('Resolving')) {
              el.outerHTML = ip;
            }
          }, 3000);
        }
      });
    }, 100);

    if (hops.length > 0) {
      setTimeout(async () => {
        const aiContainer = document.getElementById('traceroute-ai-intuition-container');
        if (!aiContainer) return;
        aiContainer.innerHTML = `<div class="trace-loading"><i class="fa-solid fa-robot fa-flip"></i> AI analyzing route path...</div>`;
        
        try {
          const analyzeResponse = await fetch('/api/ai/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || localStorage.getItem('cybersec_token') || '') },
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
              <div class="trace-osint-box">
                <div class="trace-osint-header"><div class="trace-osint-dot"></div> Route Path Intuition</div>
                <div class="trace-osint-content" id="traceAiContent"></div>
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
                    if (contentBox) contentBox.innerHTML = marked.parse(aiText);
                  }
                }
              }
            }
          } else {
            throw new Error('API error');
          }
        } catch(e) {
          aiContainer.innerHTML = `
            <div class="trace-fallback-box">
              <div class="trace-fallback-header"><i class="fa-solid fa-map"></i> Route Path Intuition</div>
              <div class="trace-fallback-content">${generateFallback(hops, data.target)}</div>
            </div>
          `;
        }
      }, 300);
    }

    if (actions) actions.style.display = 'flex';
  },

  renderSSL(data) {
    const output = document.getElementById('ssl-output');
    const actions = document.getElementById('ssl-actions');

    const displayValue = (val) => {
      if (val === null || val === undefined || val === '') return '—';
      if (val === false) return 'No';
      if (val === true) return 'Yes';
      return String(val);
    };

    const extractSSLData = (raw) => {
      const cert = raw?.certificate || raw?.cert || raw?.data || raw;
      
      let issuerOrg = '—';
      const issuerData = cert?.issuer || raw?.issuer || {};
      if (typeof issuerData === 'string') {
        issuerOrg = issuerData;
      } else if (issuerData?.O) {
        issuerOrg = issuerData.O;
      } else if (issuerData?.CN) {
        issuerOrg = issuerData.CN;
      } else if (issuerData?.organizationName) {
        issuerOrg = issuerData.organizationName;
      }

      let validFrom = null;
      if (cert?.valid_from) {
        const d = new Date(cert.valid_from);
        if (!isNaN(d.getTime())) validFrom = d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
      }
      if (cert?.validTo) {
        const d = new Date(cert.validTo);
        if (!isNaN(d.getTime())) validFrom = d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
      }

      let validTo = null;
      let daysRemaining = null;
      if (cert?.valid_to) {
        const d = new Date(cert.valid_to);
        if (!isNaN(d.getTime())) {
          validTo = d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
          daysRemaining = Math.ceil((d - new Date()) / (1000 * 60 * 60 * 24));
        }
      }
      
      const protocol = raw?.tls_version || raw?.tlsVersion || '—';
      const cipher = raw?.cipher_suite || raw?.cipher || '—';
      
      return {
        domain: raw?.host || raw?.domain || raw?.target || 'Unknown',
        issuer: issuerOrg,
        protocol: displayValue(protocol),
        cipher: displayValue(cipher),
        validFrom: validFrom,
        validTo: validTo,
        daysRemaining: daysRemaining,
        isValid: raw?.is_valid !== false && daysRemaining !== null && daysRemaining >= 0,
        subjectAltNames: cert?.san || [],
        fingerprint: cert?.fingerprint256 || cert?.fingerprint || null,
        keyBits: cert?.bits || cert?.keySize || raw?.bits || null,
        rawValidFrom: cert?.valid_from || cert?.validTo || null,
        rawValidTo: cert?.valid_to || null,
        hasData: !!(protocol !== '—' || validTo || issuerOrg !== '—')
      };
    };

    const calculateDaysRemaining = (dateStr) => {
      if (!dateStr) return null;
      const expiry = new Date(dateStr);
      const now = new Date();
      return Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
    };

    const calculateSSLGrade = (sslData) => {
      let score = 100;
      if (!sslData.isValid) score -= 50;
      const proto = sslData.protocol || '';
      if (proto.includes('1.0') || proto.includes('1.1')) score -= 30;
      else if (proto.includes('1.2')) score -= 10;
      if (sslData.keyBits && sslData.keyBits < 2048) score -= 20;
      const days = sslData.daysRemaining;
      if (days !== null) {
        if (days < 30) score -= 20;
        if (days < 7) score -= 30;
      }
      
      if (score >= 90) return { grade: 'A+', color: '#6acf80' };
      if (score >= 80) return { grade: 'A', color: '#6acf80' };
      if (score >= 70) return { grade: 'B', color: '#f0b860' };
      if (score >= 60) return { grade: 'C', color: '#f07040' };
      return { grade: 'F', color: '#f07070' };
    };

    const ssl = extractSSLData(data);
    ssl.daysRemaining = ssl.daysRemaining ?? calculateDaysRemaining(ssl.validTo);

    if (data.status === 'failed' || data.status === 'ssl_error') {
      output.innerHTML = `
        <div class="ssl-result">
          <style>
            @keyframes ssl-fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
            .ssl-zone { animation: ssl-fade 0.3s ease-out forwards; opacity: 0; }
            .ssl-zone-1 { animation-delay: 0ms; }
            .ssl-error-card { background: #111318; border: 0.5px solid #2a2d35; border-radius: 10px; padding: 20px 24px; text-align: center; }
            .ssl-error-icon { font-size: 48px; color: #f07070; margin-bottom: 12px; }
            .ssl-error-title { font-size: 18px; font-weight: 600; color: #e2e3e7; }
            .ssl-error-msg { font-size: 13px; color: #6b6e78; margin-top: 8px; }
          </style>
          <div class="ssl-zone ssl-zone-1">
            <div class="ssl-error-card">
              <div class="ssl-error-icon"><i class="fa-solid fa-circle-exclamation"></i></div>
              <div class="ssl-error-title">SSL Check Failed</div>
              <div class="ssl-error-msg">${data.error || 'Unable to retrieve certificate information'}</div>
            </div>
          </div>
        </div>
      `;
      if (actions) actions.style.display = 'none';
      return;
    }

    const now = new Date();
    let daysLeft = ssl.daysRemaining;
    if (daysLeft === null && ssl.validTo) {
      daysLeft = Math.ceil((new Date(ssl.validTo) - now) / (1000 * 60 * 60 * 24));
    }

    let statusType = 'valid';
    let statusColor = '#6acf80';
    let statusBg = '#102a18';
    let statusBorder = '#1a5a28';
    let statusLabel = 'VALID';
    
    if (daysLeft !== null && daysLeft < 0) {
      statusType = 'expired';
      statusColor = '#f07070';
      statusBg = '#2a1414';
      statusBorder = '#5a2020';
      statusLabel = 'EXPIRED';
    } else if (daysLeft !== null && daysLeft < 30) {
      statusType = 'expiring';
      statusColor = '#f0b860';
      statusBg = '#2a2010';
      statusBorder = '#5a4010';
      statusLabel = 'EXPIRING SOON';
    }

    const grade = ssl.hasData ? calculateSSLGrade(ssl) : null;

    const protoColor = ssl.protocol === '—' ? '#6b6e78' : ssl.protocol.includes('1.3') ? '#6acf80' : ssl.protocol.includes('1.2') ? '#f0b860' : '#f07070';
    const keyColor = !ssl.keyBits || ssl.keyBits === '—' ? '#6b6e78' : ssl.keyBits >= 2048 ? '#6acf80' : '#f07070';

    const fmtDate = (d) => {
      if (!d) return '—';
      const date = new Date(d);
      if (isNaN(date.getTime())) return '—';
      return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    };

    let timelinePct = 0;
    let timelineColor = '#2a2d35';
    let timelineHasData = false;
    if (ssl.rawValidFrom && ssl.rawValidTo) {
      const start = new Date(ssl.rawValidFrom);
      const end = new Date(ssl.rawValidTo);
      if (!isNaN(start.getTime()) && !isNaN(end.getTime()) && end > start) {
        const total = end - start;
        const elapsed = now - start;
        timelinePct = Math.min(100, Math.max(0, (elapsed / total) * 100));
        timelineHasData = true;
        
        if (daysLeft !== null) {
          if (daysLeft > 60) timelineColor = '#6acf80';
          else if (daysLeft > 30) timelineColor = '#f0b860';
          else timelineColor = '#f07070';
        }
      }
    }

    const sanDisplay = ssl.subjectAltNames.length > 0 ? ssl.subjectAltNames.slice(0, 8) : [];
    const extraSans = ssl.subjectAltNames.length - 8;

    const fingerprintDisplay = ssl.fingerprint ? ssl.fingerprint.substring(0, 20) + '...' : '—';

    output.innerHTML = `
      <div class="ssl-result">
        <style>
          @keyframes ssl-fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
          @keyframes ssl-grade-pop { 0% { transform: scale(0.5); opacity: 0; } 50% { transform: scale(1.1); } 100% { transform: scale(1); opacity: 1; } }
          @keyframes ssl-bar-fill { from { width: 0; } }
          .ssl-zone { animation: ssl-fade 0.3s ease-out forwards; opacity: 0; }
          .ssl-zone-1 { animation-delay: 0ms; }
          .ssl-zone-2 { animation-delay: 60ms; }
          .ssl-zone-3 { animation-delay: 120ms; }
          .ssl-zone-4 { animation-delay: 180ms; }
          .ssl-zone-5 { animation-delay: 240ms; }
          .ssl-zone-6 { animation-delay: 300ms; }
          .ssl-hero { background: #151823; border: 1px solid #232736; border-radius: 10px; padding: 20px; display: flex; align-items: center; justify-content: space-between; }
          .ssl-hero-left { display: flex; align-items: center; }
          .ssl-hero-icon { font-size: 24px; color: #8B5CF6; }
          .ssl-hero-domain { font-size: 22px; font-weight: 700; color: white; font-family: monospace; margin-left: 12px; }
          .ssl-hero-issuer { font-size: 13px; color: #6B7280; margin-left: 12px; margin-top: 4px; }
          .ssl-status-badge { background: #0E1016; border: 1px solid #EAB308; border-radius: 8px; padding: 10px 16px; text-align: center; }
          .ssl-status-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; }
          .ssl-status-value { font-size: 16px; font-weight: 600; color: #EAB308; margin-top: 2px; }
          .ssl-details-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 12px; }
          .ssl-detail-card { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 14px 16px; }
          .ssl-detail-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-bottom: 4px; }
          .ssl-detail-value { font-size: 15px; font-weight: 500; color: #4B5563; font-family: monospace; }
          .ssl-detail-value.mono { font-family: monospace; }
          .ssl-timeline-section { margin-top: 12px; }
          .ssl-timeline-label { font-size: 10px; text-transform: uppercase; color: #6B7280; letter-spacing: 0.1em; margin-bottom: 8px; }
          .ssl-timeline-container { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 14px 16px; }
          .ssl-timeline-bar { height: 6px; background: #1A1F2E; border-radius: 999px; overflow: hidden; }
          .ssl-timeline-fill { height: 100%; background: linear-gradient(90deg, #EAB308, #EAB308); border-radius: 999px; width: 0; animation: ssl-bar-fill 0.5s ease-out forwards; }
          .ssl-timeline-labels { display: flex; justify-content: space-between; margin-top: 8px; font-size: 11px; color: #4B5563; font-family: monospace; }
          .ssl-timeline-labels .center { color: #4B5563; }
          .ssl-grade-card { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 20px; margin-top: 12px; display: flex; align-items: center; gap: 24px; }
          .ssl-grade-letter { font-size: 48px; font-weight: 700; animation: ssl-grade-pop 0.6s ease-out forwards; }
          .ssl-grade-info { flex: 1; }
          .ssl-grade-title { font-size: 14px; font-weight: 600; color: white; font-family: monospace; }
          .ssl-grade-desc { font-size: 13px; color: #6B7280; margin-top: 4px; }
          .ssl-sans-section { margin-top: 12px; }
          .ssl-sans-label { font-size: 11px; text-transform: uppercase; color: #6b6e78; letter-spacing: 0.08em; margin-bottom: 8px; }
          .ssl-sans-list { display: flex; flex-wrap: wrap; gap: 6px; }
          .ssl-san-pill { background: #161820; border: 0.5px solid #2e3140; border-radius: 6px; padding: 4px 10px; font-size: 11px; font-family: monospace; color: #b0b2ba; }
          .ssl-san-more { background: #1e2130; border: 0.5px solid #4a3a8e; color: #a78bfa; }
          .ssl-suggest-box { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px 20px; margin-top: 14px; }
          .ssl-suggest-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-bottom: 8px; }
          .ssl-suggest-content { display: flex; align-items: center; justify-content: space-between; }
          .ssl-suggest-info { display: flex; align-items: center; gap: 12px; }
          .ssl-suggest-icon { width: 32px; height: 32px; border-radius: 8px; background: #8B5CF6; display: flex; align-items: center; justify-content: center; color: white; font-size: 14px; }
          .ssl-suggest-title { font-size: 14px; font-weight: 600; color: white; font-family: monospace; }
          .ssl-suggest-sub { font-size: 12px; color: #6B7280; margin-top: 2px; }
          .ssl-run-btn { background: #8B5CF6; border: none; border-radius: 6px; padding: 6px 16px; font-size: 13px; font-weight: 600; color: white; cursor: pointer; }
          .ssl-run-btn:hover { background: #7C3AED; }
          .ssl-actions-bar { display: flex; align-items: center; gap: 12px; padding-top: 14px; border-top: 1px solid #232736; margin-top: 14px; }
          .ssl-copy-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .ssl-copy-btn:hover { background: #1A1F2E; }
          .ssl-copy-btn i { color: #8B5CF6; }
          .ssl-recheck-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .ssl-recheck-btn:hover { background: #1A1F2E; }
          .ssl-recheck-btn i { color: #8B5CF6; }
          .ssl-meta-right { font-size: 12px; color: #4B5563; margin-left: auto; }
        </style>

        <div class="ssl-zone ssl-zone-1">
          <div class="ssl-hero">
            <div class="ssl-hero-left">
              <i class="fa-solid fa-lock ssl-hero-icon"></i>
              <div>
                <div class="ssl-hero-domain">${ssl.domain}</div>
                <div class="ssl-hero-issuer">Issued by: ${ssl.issuer}</div>
              </div>
            </div>
            <div class="ssl-status-badge">
              <div class="ssl-status-label">STATUS</div>
              <div class="ssl-status-value">Unknown</div>
            </div>
          </div>
        </div>

        <div class="ssl-zone ssl-zone-2">
          <div class="ssl-details-grid">
            <div class="ssl-detail-card">
              <div class="ssl-detail-label">Protocol</div>
              <div class="ssl-detail-value mono">${ssl.protocol}</div>
            </div>
            <div class="ssl-detail-card">
              <div class="ssl-detail-label">Cipher</div>
              <div class="ssl-detail-value mono">${ssl.cipher}</div>
            </div>
            <div class="ssl-detail-card">
              <div class="ssl-detail-label">Valid From</div>
              <div class="ssl-detail-value">${ssl.validFrom || '&#8212;'}</div>
            </div>
            <div class="ssl-detail-card">
              <div class="ssl-detail-label">Expires</div>
              <div class="ssl-detail-value">${ssl.validTo || '&#8212;'}</div>
            </div>
            <div class="ssl-detail-card">
              <div class="ssl-detail-label">Key Size</div>
              <div class="ssl-detail-value">${ssl.keyBits ? ssl.keyBits + ' bit' : '&#8212;'}</div>
            </div>
            <div class="ssl-detail-card">
              <div class="ssl-detail-label">Fingerprint</div>
              <div class="ssl-detail-value mono" style="font-size:11px;word-break:break-all">${fingerprintDisplay}</div>
            </div>
          </div>
        </div>

        <div class="ssl-zone ssl-zone-3">
          <div class="ssl-timeline-section">
            <div class="ssl-timeline-label">Validity Period</div>
            <div class="ssl-timeline-container">
              <div class="ssl-timeline-bar">
                <div class="ssl-timeline-fill" style="width:0%;background:linear-gradient(90deg, #EAB308, #EAB308);animation-delay:0.3s"></div>
              </div>
              <div class="ssl-timeline-labels">
                <span>Issued: &#8212;</span>
                <span class="center">Certificate dates unavailable</span>
                <span>Expires: &#8212;</span>
              </div>
            </div>
          </div>
        </div>

        <div class="ssl-zone ssl-zone-4">
          ${grade ? `
          <div class="ssl-grade-card">
            <div class="ssl-grade-letter" style="color:${grade.color}">${grade.grade}</div>
            <div class="ssl-grade-info">
              <div class="ssl-grade-title">SSL Security Grade</div>
              <div class="ssl-grade-desc">Based on protocol, key strength, and expiry</div>
            </div>
          </div>
          ` : `
          <div class="ssl-grade-card">
            <div class="ssl-grade-letter" style="background: #1A1F2E; color: #6B7280; width: 36px; height: 36px; border-radius: 8px; font-size: 20px; font-weight: 700; display: flex; align-items: center; justify-content: center;">?</div>
            <div class="ssl-grade-info">
              <div class="ssl-grade-title">SSL Security Grade</div>
              <div class="ssl-grade-desc">Certificate details unavailable — grade cannot be calculated</div>
            </div>
          </div>
          `}
        </div>

        ${sanDisplay.length > 0 ? `
        <div class="ssl-zone ssl-zone-5">
          <div class="ssl-sans-section">
            <div class="ssl-sans-label">Subject Alternative Names</div>
            <div class="ssl-sans-list">
              ${sanDisplay.map(san => `<span class="ssl-san-pill">${san}</span>`).join('')}
              ${extraSans > 0 ? `<span class="ssl-san-pill ssl-san-more">+${extraSans} more</span>` : ''}
            </div>
          </div>
        </div>
        ` : ''}

        <div class="ssl-zone ssl-zone-6">
          <div class="ssl-suggest-box">
            <div class="ssl-suggest-label">Suggested Next Step</div>
            <div class="ssl-suggest-content">
              <div class="ssl-suggest-info">
                <div class="ssl-suggest-icon"><i class="fa-solid fa-shield-halved"></i></div>
                <div>
                  <div class="ssl-suggest-title">Scan Security Headers</div>
                  <div class="ssl-suggest-sub">Verify HSTS and other headers for complete secure transport</div>
                </div>
              </div>
              <button class="ssl-run-btn" onclick="switchTool('headers')">Open Scanner <i class="fa-solid fa-arrow-right" style="margin-left:4px"></i></button>
            </div>
          </div>
        </div>

        <div class="ssl-actions-bar">
          <button class="ssl-copy-btn" onclick="copyToolResult('ssl')"><i class="fa-solid fa-copy"></i> Copy</button>
          <button class="ssl-recheck-btn" onclick="runTool('ssl')"><i class="fa-solid fa-rotate-right"></i> Re-check</button>
          <span class="ssl-meta-right">${ssl.domain} · port 443 · just now</span>
        </div>
      </div>
    `;

    if (actions) actions.style.display = 'flex';
  },

  renderHeaders(data) {
    const output = document.getElementById('headers-output');
    const actions = document.getElementById('headers-actions');
    if (data.status === 'failed' || data.status === 'timeout') {
      output.innerHTML = `
        <div class="hdr-result">
          <style>
            @keyframes hdr-fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
            .hdr-zone { animation: hdr-fade 0.3s ease-out forwards; opacity: 0; }
            .hdr-zone-1 { animation-delay: 0ms; }
            .hdr-error-card { background: #111318; border: 0.5px solid #2a2d35; border-radius: 10px; padding: 20px 24px; text-align: center; }
            .hdr-error-icon { font-size: 48px; color: #f07070; margin-bottom: 12px; }
            .hdr-error-title { font-size: 18px; font-weight: 600; color: #e2e3e7; }
            .hdr-error-msg { font-size: 13px; color: #6b6e78; margin-top: 8px; }
          </style>
          <div class="hdr-zone hdr-zone-1">
            <div class="hdr-error-card">
              <div class="hdr-error-icon"><i class="fa-solid fa-circle-exclamation"></i></div>
              <div class="hdr-error-title">Headers Check Failed</div>
              <div class="hdr-error-msg">${data.error || 'Unable to fetch headers'}</div>
            </div>
          </div>
        </div>
      `;
      if (actions) actions.style.display = 'none';
      return;
    }

    const headers = data.headers || {};
    const statusCode = data.status_code || 0;
    const url = data.url || 'Unknown';

    const getStatusColor = (code) => {
      if (code >= 200 && code < 300) return { bg: '#102a18', border: '#1a5a28', color: '#6acf80', text: 'OK' };
      if (code >= 300 && code < 400) return { bg: '#2a2010', border: '#5a4010', color: '#f0b860', text: 'Redirect' };
      if (code >= 400 && code < 500) return { bg: '#2a1414', border: '#5a2020', color: '#f07070', text: 'Client Error' };
      if (code >= 500) return { bg: '#2a1414', border: '#5a2020', color: '#f07070', text: 'Server Error' };
      return { bg: '#111318', border: '#2a2d35', color: '#6b6e78', text: 'Unknown' };
    };

    const statusInfo = getStatusColor(statusCode);

    const securityHeadersMap = {
      'strict-transport-security': { name: 'HSTS', risk: 'HIGH' },
      'content-security-policy': { name: 'CSP', risk: 'HIGH' },
      'x-content-type-options': { name: 'X-Content-Type', risk: 'MEDIUM' },
      'x-frame-options': { name: 'X-Frame-Options', risk: 'MEDIUM' },
      'x-xss-protection': { name: 'X-XSS-Protection', risk: 'LOW' },
      'referrer-policy': { name: 'Referrer-Policy', risk: 'LOW' },
      'permissions-policy': { name: 'Permissions-Policy', risk: 'LOW' },
      'x-permitted-cross-domain-policies': { name: 'Cross-Domain', risk: 'INFO' },
    };

    const riskColors = {
      'HIGH': '#EAB308',
      'MEDIUM': '#8B5CF6',
      'LOW': '#1A1F2E',
      'INFO': '#0E1016'
    };

    const presentHeaders = [];
    const missingHeaders = [];
    
    Object.entries(securityHeadersMap).forEach(([header, info]) => {
      const found = Object.keys(headers).find(h => h.toLowerCase() === header);
      if (found) {
        presentHeaders.push({ header: info.name, value: headers[found], risk: info.risk });
      } else {
        missingHeaders.push(info.name);
      }
    });

    const generateAttackFallback = (missing) => {
      const risks = [];
      if (missing.includes('HSTS')) risks.push('Man-in-the-middle attacks via HTTP downgrade');
      if (missing.includes('CSP')) risks.push('Cross-site scripting (XSS) injection attacks');
      if (missing.includes('X-Frame-Options')) risks.push('Clickjacking via iframe embedding');
      if (missing.includes('X-Content-Type-Options')) risks.push('MIME type sniffing attacks');
      if (missing.includes('Referrer-Policy')) risks.push('Referrer leakage exposing internal pages');
      
      return `Missing security headers expose this server to: ${risks.join(', ')}. Priority fix: add HSTS and CSP headers immediately as they address the highest severity risks.`;
    };

    const serverHeader = headers['server'] || headers['Server'] || '';
    const poweredByHeader = headers['x-powered-by'] || headers['X-Powered-By'] || '';
    const interestingHeaders = ['server', 'Server', 'x-powered-by', 'X-Powered-By', 'cache-control', 'Cache-Control', 'etag', 'ETag'];

    const otherHeadersList = Object.entries(headers)
      .filter(([k]) => !Object.keys(securityHeadersMap).includes(k.toLowerCase()))
      .map(([k, v]) => {
        const isInteresting = interestingHeaders.includes(k);
        const borderColor = k.toLowerCase() === 'server' || k.toLowerCase() === 'x-powered-by' ? '#f0b860' 
          : k.toLowerCase() === 'cache-control' ? '#a78bfa' 
          : k.toLowerCase() === 'etag' ? '#4a4d58' : 'transparent';
        return { key: k, value: v, borderColor, isInteresting };
      });

    const serverTech = serverHeader ? serverHeader.split('/')[0] : '';
    const poweredByTechs = poweredByHeader ? poweredByHeader.split(',').map(t => t.trim()) : [];

    output.innerHTML = `
      <div class="hdr-result">
        <style>
          @keyframes hdr-fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
          @keyframes hdr-code-pop { 0% { transform: scale(0.8); opacity: 0; } 100% { transform: scale(1); opacity: 1; } }
          @keyframes hdr-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
          .hdr-zone { animation: hdr-fade 0.3s ease-out forwards; opacity: 0; }
          .hdr-zone-1 { animation-delay: 0ms; }
          .hdr-zone-2 { animation-delay: 60ms; }
          .hdr-zone-3 { animation-delay: 120ms; }
          .hdr-zone-4 { animation-delay: 180ms; }
          .hdr-zone-5 { animation-delay: 240ms; }
          .hdr-hero { background: #151823; border: 1px solid #232736; border-radius: 10px; padding: 20px; display: flex; align-items: center; justify-content: space-between; }
          .hdr-hero-left { display: flex; flex-direction: column; gap: 8px; }
          .hdr-hero-url { font-size: 16px; font-weight: 600; font-family: monospace; color: white; }
          .hdr-hero-tags { display: flex; gap: 6px; flex-wrap: wrap; }
          .hdr-tech-pill { background: #1A1F2E; border: 1px solid #232736; color: #C4B5FD; border-radius: 999px; padding: 2px 10px; font-size: 12px; font-family: monospace; }
          .hdr-tech-pill.purple { color: #C4B5FD; border-color: #232736; }
          .hdr-status-badge { background: #0E1016; border: 1px solid #EAB308; border-radius: 8px; padding: 10px 16px; text-align: center; }
          .hdr-status-code { font-size: 24px; font-weight: 700; color: #EAB308; font-family: monospace; animation: hdr-code-pop 0.4s ease-out forwards; }
          .hdr-status-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-top: 2px; }
          .hdr-checklist-section { margin-top: 12px; }
          .hdr-checklist-summary { font-size: 13px; color: #EAB308; font-family: monospace; font-weight: 600; margin-bottom: 8px; }
          .hdr-checklist-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
          .hdr-check-item { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 12px 16px; display: flex; align-items: center; justify-content: space-between; animation: hdr-fade 0.3s ease-out forwards; opacity: 0; }
          .hdr-check-left { display: flex; align-items: center; gap: 8px; }
          .hdr-check-name { font-size: 13px; font-family: monospace; color: white; font-weight: 600; }
          .hdr-risk-pill { font-size: 10px; padding: 1px 7px; border-radius: 4px; font-weight: 700; }
          .hdr-status-pill { font-size: 12px; padding: 3px 10px; border-radius: 999px; font-weight: 500; }
          .hdr-status-pill.present { background: #1A1F2E; color: #9CA3AF; border: 1px solid #232736; }
          .hdr-status-pill.missing { background: #1A1F2E; color: #9CA3AF; border: 1px solid #232736; }
          .hdr-osint-box { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 14px 20px; margin-top: 14px; }
          .hdr-osint-header { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; color: #EAB308; margin-bottom: 10px; }
          .hdr-osint-dot { width: 8px; height: 8px; border-radius: 50%; background: #EAB308; animation: hdr-pulse 2s infinite; }
          .hdr-osint-content { font-size: 12px; line-height: 1.7; color: #9CA3AF; font-family: monospace; }
          .hdr-fallback-box { background: #111318; border: 0.5px solid #2a2d35; border-radius: 10px; padding: 16px 20px; margin-top: 14px; }
          .hdr-fallback-header { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 500; color: #6b6e78; margin-bottom: 10px; }
          .hdr-fallback-content { font-size: 13px; line-height: 1.7; color: #b0b2ba; }
          .hdr-table-section { margin-top: 12px; }
          .hdr-table-label { font-size: 10px; text-transform: uppercase; color: #6B7280; letter-spacing: 0.1em; margin-bottom: 8px; }
          .hdr-table { background: #0A0D12; border: 1px solid #232736; border-radius: 8px; overflow: hidden; }
          .hdr-table-header { display: grid; grid-template-columns: 1fr 2fr; padding: 10px 16px; background: #111318; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; border-bottom: 1px solid #232736; }
          .hdr-table-row { display: grid; grid-template-columns: 1fr 2fr; padding: 0 16px; min-height: 40px; align-items: center; border-bottom: 1px solid #1e2028; border-left: 3px solid transparent; }
          .hdr-table-row:nth-child(even) { background: #0A0D12; }
          .hdr-table-row:nth-child(odd) { background: #0E1016; }
          .hdr-table-row:hover { background: #1A1F2E; }
          .hdr-table-row:last-child { border-bottom: none; }
          .hdr-table-row.interesting { border-left-color: #EAB308; background: #111318; }
          .hdr-table-key { font-size: 13px; font-family: monospace; color: #C4B5FD; }
          .hdr-table-val { font-size: 13px; font-family: monospace; color: #E5E7EB; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
          .hdr-warning { font-size: 13px; color: #EAB308; padding: 12px 16px; background: #1A1200; border: 1px solid #EAB308; border-left: 3px solid #EAB308; border-radius: 8px; margin-top: 8px; display: flex; align-items: center; gap: 8px; font-family: monospace; }
          .hdr-suggest-box { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px 20px; margin-top: 14px; }
          .hdr-suggest-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-bottom: 8px; }
          .hdr-suggest-content { display: flex; align-items: center; justify-content: space-between; }
          .hdr-suggest-info { display: flex; align-items: center; gap: 12px; }
          .hdr-suggest-icon { width: 36px; height: 36px; border-radius: 8px; background: #1A1F2E; display: flex; align-items: center; justify-content: center; color: #8B5CF6; font-size: 14px; }
          .hdr-suggest-title { font-size: 14px; font-weight: 600; color: white; font-family: monospace; }
          .hdr-suggest-sub { font-size: 12px; color: #6B7280; margin-top: 2px; }
          .hdr-run-btn { background: #8B5CF6; border: none; border-radius: 6px; padding: 6px 16px; font-size: 13px; color: white; cursor: pointer; }
          .hdr-run-btn:hover { background: #7C3AED; }
          .hdr-actions-bar { display: flex; align-items: center; gap: 12px; padding-top: 14px; border-top: 1px solid #232736; margin-top: 14px; }
          .hdr-copy-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .hdr-copy-btn:hover { background: #1A1F2E; }
          .hdr-copy-btn i { color: #8B5CF6; }
          .hdr-rescan-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .hdr-rescan-btn:hover { background: #1A1F2E; }
          .hdr-rescan-btn i { color: #8B5CF6; }
          .hdr-meta-right { font-size: 12px; color: #4B5563; margin-left: auto; }
          .hdr-loading { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #6b6e78; }
          .hdr-loading i { color: #8B5CF6; }
        </style>

        <div class="hdr-zone hdr-zone-1">
          <div class="hdr-hero">
            <div class="hdr-hero-left">
              <div class="hdr-hero-url">${url}</div>
              <div class="hdr-hero-tags">
                ${serverTech ? `<span class="hdr-tech-pill">${serverTech}</span>` : ''}
                ${poweredByTechs.map(t => `<span class="hdr-tech-pill purple">${t}</span>`).join('')}
              </div>
            </div>
            <div class="hdr-status-badge">
              <div class="hdr-status-code">${statusCode}</div>
              <div class="hdr-status-label">${statusInfo.text}</div>
            </div>
          </div>
        </div>

        <div class="hdr-zone hdr-zone-2">
          <div class="hdr-checklist-section">
            <div class="hdr-checklist-summary">${presentHeaders.length} of ${Object.keys(securityHeadersMap).length} security headers present</div>
            <div class="hdr-checklist-grid">
              ${Object.entries(securityHeadersMap).map(([header, info], i) => {
                const found = Object.keys(headers).find(h => h.toLowerCase() === header);
                const isPresent = !!found;
                return `
                  <div class="hdr-check-item" style="animation-delay:${i * 30}ms">
                    <div class="hdr-check-left">
                      <span class="hdr-check-name">${info.name}</span>
                      <span class="hdr-risk-pill" style="background:${info.risk === 'HIGH' ? '#EAB308' : info.risk === 'MEDIUM' ? '#8B5CF6' : info.risk === 'LOW' ? '#1A1F2E' : '#0E1016'};color:${info.risk === 'HIGH' ? '#0E1016' : info.risk === 'MEDIUM' ? 'white' : info.risk === 'LOW' ? '#9CA3AF' : '#6B7280'};${info.risk === 'LOW' || info.risk === 'INFO' ? 'border:1px solid #232736' : ''}">${info.risk}</span>
                    </div>
                    <span class="hdr-status-pill ${isPresent ? 'present' : 'missing'}">
                      ${isPresent ? '✓ Present' : '✗ Missing'}
                    </span>
                  </div>
                `;
              }).join('')}
            </div>
          </div>
        </div>

        <div class="hdr-zone hdr-zone-3">
          <div id="header-attack-scenario-container"></div>
        </div>

        <div class="hdr-zone hdr-zone-4">
          <div class="hdr-table-section">
            <div class="hdr-table-label">FULL HEADER DUMP</div>
            <div class="hdr-table">
              <div class="hdr-table-header">
                <div>HEADER</div>
                <div>VALUE</div>
              </div>
              ${otherHeadersList.map(h => `
                <div class="hdr-table-row ${h.isInteresting ? 'interesting' : ''}" style="color:${h.borderColor}">
                  <div class="hdr-table-key">${h.key}</div>
                  <div class="hdr-table-val" title="${h.value}">${h.value}</div>
                </div>
              `).join('')}
            </div>
            ${(serverHeader || poweredByHeader) ? `
              <div class="hdr-warning">
                <i class="fa-solid fa-triangle-exclamation" style="color: #EAB308;"></i>
                server and x-powered-by headers are exposing your tech stack. Consider removing or masking these.
              </div>
            ` : ''}
          </div>
        </div>

        <div class="hdr-zone hdr-zone-5">
          <div class="hdr-suggest-box">
            <div class="hdr-suggest-label">Suggested Next Step</div>
            <div class="hdr-suggest-content">
              <div class="hdr-suggest-info">
                <div class="hdr-suggest-icon"><i class="fa-solid fa-spider"></i></div>
                <div>
                  <div class="hdr-suggest-title">Scan Security Headers</div>
                  <div class="hdr-suggest-sub">Run a full web application scan to identify exploitable vulnerabilities</div>
                </div>
              </div>
              <button class="hdr-run-btn" onclick="switchTool('webscan')">Run Full Scan <i class="fa-solid fa-arrow-right" style="margin-left:4px"></i></button>
            </div>
          </div>
        </div>

        <div class="hdr-actions-bar">
          <button class="hdr-copy-btn" onclick="copyToolResult('headers')"><i class="fa-solid fa-copy"></i> Copy</button>
          <button class="hdr-rescan-btn" onclick="runTool('headers')"><i class="fa-solid fa-rotate-right"></i> Re-scan</button>
          <span class="hdr-meta-right">${url} · just now</span>
        </div>
      </div>
    `;

    if (missingHeaders.length > 0) {
      setTimeout(async () => {
        const scenarioContainer = document.getElementById('header-attack-scenario-container');
        if (!scenarioContainer) return;
        scenarioContainer.innerHTML = `<div class="hdr-loading"><i class="fa-solid fa-robot fa-flip"></i> AI analyzing attack surface...</div>`;
        
        try {
          const analyzeResponse = await fetch('/api/ai/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || localStorage.getItem('cybersec_token') || '') },
            body: JSON.stringify({ 
              message: "The URL " + url + " is missing these security headers: " + missingHeaders.join(', ') + ". Act as a red teamer and write a 2-sentence 'Attack Scenario' explaining how a real-world attacker would exploit these specific omissions.",
              scan_id: null,
              conversation_history: []
            })
          });
          
          if (analyzeResponse.ok) {
            const reader = analyzeResponse.body.getReader();
            const decoder = new TextDecoder("utf-8");
            let aiText = '';
            scenarioContainer.innerHTML = `
              <div class="hdr-osint-box">
                <div class="hdr-osint-header"><div class="hdr-osint-dot"></div> Attack Surface Analysis</div>
                <div class="hdr-osint-content" id="headerScenarioContent"></div>
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
                    if (contentBox) contentBox.innerHTML = marked.parse(aiText);
                  }
                }
              }
            }
          } else {
            throw new Error('API error');
          }
        } catch(e) {
          scenarioContainer.innerHTML = `
            <div class="hdr-fallback-box">
              <div class="hdr-fallback-header"><i class="fa-solid fa-skull-crossbones"></i> Attack Surface Analysis</div>
              <div class="hdr-fallback-content">${generateAttackFallback(missingHeaders)}</div>
            </div>
          `;
        }
      }, 300);
    }

    if (actions) actions.style.display = 'flex';
  },

  renderSubdomains(data) {
    const output = document.getElementById('subdomains-output');
    const actions = document.getElementById('subdomains-actions');
    
    let subdomains = data.subdomains_found || data.results || data.discovered || data.hosts || data.data || [];
    if (data.total_found > 0 && subdomains.length === 0) {
      subdomains = Object.values(data).find(v => Array.isArray(v) && v.length > 0) || [];
    }

    const totalFound = data.total_found || data.total || subdomains.length || 0;
    const domain = data.domain || data.target || 'Unknown';
    const wordlistSize = data.wordlist_size || data.size || 'Large';

    const getInterestLevel = (sub) => {
      const highPatterns = /dev|admin|vpn|jira|api|v1|test|staging|internal|ssh|db|database/i;
      const medPatterns = /mail|ftp|smtp|pop|imap|relay/i;
      if (highPatterns.test(sub)) return 'HIGH';
      if (medPatterns.test(sub)) return 'MEDIUM';
      return 'LOW';
    };

    const getInterestColor = (level) => {
      if (level === 'HIGH') return '#EAB308';
      if (level === 'MEDIUM') return '#8B5CF6';
      return '#1A1F2E';
    };

    const getStatusBadge = (status) => {
      if (status >= 200 && status < 300) return { text: '200 OK', color: '#4ADE80', bg: '#14532D', border: '#14532D' };
      if (status >= 300 && status < 400) return { text: `${status} Redirect`, color: '#f0b860', bg: '#2a2010', border: '#5a4010' };
      if (status === 403) return { text: '403 Forbidden', color: '#f0b860', bg: '#2a2010', border: '#5a4010' };
      if (status === 404) return { text: '404 Not Found', color: '#6b6e78', bg: '#111318', border: '#2a2d35' };
      if (status >= 500) return { text: `${status} Error`, color: '#f07070', bg: '#2a1414', border: '#5a2020' };
      return { text: '—', color: '#4a4d58', bg: '#111318', border: '#2a2d35' };
    };

    const highInterestSubs = subdomains.filter(s => getInterestLevel(s) === 'HIGH');
    const highInterestCount = highInterestSubs.length;

    const subdomainRows = subdomains.map((sub, i) => {
      const interestLevel = getInterestLevel(sub);
      const interestColor = getInterestColor(interestLevel);
      const status = sub.status || sub.http_status || 200;
      const statusBadge = getStatusBadge(status);
      const ip = sub.ip || sub.address || '—';
      const borderColor = interestLevel === 'HIGH' ? '#f07070' : interestLevel === 'MEDIUM' ? '#f0b860' : '#6acf80';
      
      return `
        <div class="sub-row" style="border-left: 3px solid ${borderColor}; animation-delay:${i * 30}ms">
          <div class="sub-name">${sub.name || sub.subdomain || sub}</div>
          <div class="sub-ip">${ip}</div>
          <div class="sub-status"><span class="sub-status-pill" style="background:${statusBadge.bg};border:0.5px solid ${statusBadge.border};color:${statusBadge.color}">${statusBadge.text}</span></div>
          <div class="sub-interest"><span class="sub-interest-pill" style="background:${interestLevel === 'HIGH' ? '#EAB308' : interestLevel === 'MEDIUM' ? '#8B5CF6' : '#1A1F2E'};color:${interestLevel === 'HIGH' ? '#0E1016' : interestLevel === 'MEDIUM' ? 'white' : '#6B7280'};${interestLevel === 'LOW' ? 'border:1px solid #232736' : ''}">${interestLevel}</span></div>
        </div>
      `;
    }).join('');

    const highInterestCards = highInterestSubs.map(sub => {
      const reason = sub.name?.includes('admin') ? 'Admin panel detected' 
        : sub.name?.includes('api') ? 'API endpoint exposed'
        : sub.name?.includes('dev') || sub.name?.includes('test') ? 'Development environment'
        : sub.name?.includes('vpn') ? 'VPN access point'
        : 'High value target';
      return `
        <div class="sub-high-card">
          <div class="sub-high-header">
            <span class="sub-high-name">${sub.name || sub}</span>
            <span class="sub-high-reason">${reason}</span>
          </div>
          <button class="sub-high-btn" onclick="switchTool('portscanner')">Port Scan this target <i class="fa-solid fa-arrow-right"></i></button>
        </div>
      `;
    }).join('');

    output.innerHTML = `
      <div class="sub-result">
        <style>
          @keyframes sub-fade { from { opacity: 0; transform: translateX(-8px); } to { opacity: 1; transform: translateX(0); } }
          @keyframes sub-scale { from { opacity: 0; transform: scale(0.98); } to { opacity: 1; transform: scale(1); } }
          .sub-zone { animation: sub-fade 0.3s ease-out forwards; opacity: 0; }
          .sub-zone-1 { animation-delay: 0ms; }
          .sub-zone-2 { animation-delay: 60ms; }
          .sub-zone-3 { animation-delay: 120ms; }
          .sub-zone-4 { animation-delay: 180ms; }
          .sub-zone-5 { animation-delay: 240ms; }
          .sub-hero { background: #151823; border: 1px solid #232736; border-radius: 10px; padding: 20px; display: flex; align-items: center; justify-content: space-between; }
          .sub-hero-left { display: flex; align-items: center; gap: 12px; }
          .sub-hero-icon { font-size: 20px; color: #8B5CF6; }
          .sub-hero-title { font-size: 20px; font-weight: 700; color: white; font-family: monospace; }
          .sub-hero-domain { font-size: 12px; color: #6B7280; font-family: monospace; margin-top: 4px; }
          .sub-hero-wordlist { background: #4C1D95; color: #C4B5FD; border-radius: 999px; padding: 2px 10px; font-size: 12px; margin-top: 6px; display: inline-block; }
          .sub-stats-row { display: flex; gap: 10px; }
          .sub-stat-pill { background: #0E1016; border: 1px solid #232736; border-radius: 8px; padding: 8px 14px; text-align: center; }
          .sub-stat-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; }
          .sub-stat-value { font-size: 14px; font-weight: 500; margin-top: 2px; }
          .sub-table { background: #151823; border: 1px solid #232736; border-radius: 8px; overflow: hidden; margin-top: 12px; }
          .sub-table-header { display: grid; grid-template-columns: 1fr 140px 120px 100px; padding: 10px 16px; background: #0E1016; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; border-bottom: 1px solid #232736; }
          .sub-row { display: grid; grid-template-columns: 1fr 140px 120px 100px; padding: 0 16px; min-height: 44px; align-items: center; border-bottom: 1px solid #1e2028; animation: sub-fade 0.3s ease-out forwards; opacity: 0; border-left: 3px solid #8B5CF6; }
          .sub-row:nth-child(even) { background: #0E1016; }
          .sub-row:nth-child(odd) { background: #111318; }
          .sub-row:hover { background: #1A1F2E; }
          .sub-row:last-child { border-bottom: none; }
          .sub-name { font-size: 13px; font-family: monospace; color: white; font-weight: 600; }
          .sub-ip { font-size: 12px; font-family: monospace; color: #C4B5FD; }
          .sub-status { display: flex; }
          .sub-status-pill { font-size: 11px; padding: 2px 10px; border-radius: 999px; font-weight: 500; font-family: monospace; }
          .sub-interest { display: flex; }
          .sub-interest-pill { font-size: 10px; padding: 1px 8px; border-radius: 4px; font-weight: 600; letter-spacing: 0.06em; }
          .sub-empty-card { background: #111318; border: 0.5px solid #2a2d35; border-radius: 8px; padding: 24px; text-align: center; animation: sub-scale 0.2s ease-out forwards; }
          .sub-empty-icon { font-size: 32px; color: #4a4d58; margin-bottom: 12px; }
          .sub-empty-title { font-size: 15px; color: #6b6e78; font-weight: 500; }
          .sub-empty-sub { font-size: 12px; color: #4a4d58; line-height: 1.6; max-width: 400px; margin: 8px auto 16px; }
          .sub-empty-actions { display: flex; gap: 8px; justify-content: center; }
          .sub-empty-btn { background: transparent; border: 0.5px solid #4a3a8e; border-radius: 6px; padding: 6px 14px; font-size: 12px; color: #a78bfa; cursor: pointer; }
          .sub-empty-btn.muted { border-color: #2e3140; color: #6b6e78; }
          .sub-high-section { margin-top: 12px; }
          .sub-high-label { font-size: 11px; text-transform: uppercase; color: #f07070; letter-spacing: 0.08em; margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
          .sub-high-label::before { content: ''; width: 3px; height: 16px; background: #f07070; border-radius: 2px; }
          .sub-high-card { background: #111318; border: 0.5px solid #2a2d35; border-left: 3px solid #f07070; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }
          .sub-high-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
          .sub-high-name { font-size: 14px; font-family: monospace; font-weight: 600; color: #e2e3e7; }
          .sub-high-reason { font-size: 11px; color: #f07070; background: rgba(240,112,112,0.1); padding: 2px 8px; border-radius: 10px; }
          .sub-high-btn { background: #1e2130; border: 0.5px solid #4a3a8e; border-radius: 6px; padding: 6px 14px; font-size: 12px; color: #a78bfa; cursor: pointer; }
          .sub-high-btn:hover { background: #252640; }
          .sub-wildcard-warning { background: #1a1408; border: 0.5px solid #5a4010; border-radius: 8px; padding: 12px 16px; margin-top: 12px; display: flex; align-items: flex-start; gap: 10px; font-size: 12px; color: #f0b860; }
          .sub-wildcard-warning i { margin-top: 2px; }
          .sub-suggest-box { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px 20px; margin-top: 14px; }
          .sub-suggest-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-bottom: 8px; }
          .sub-suggest-content { display: flex; align-items: center; justify-content: space-between; }
          .sub-suggest-info { display: flex; align-items: center; gap: 12px; }
          .sub-suggest-icon { width: 36px; height: 36px; border-radius: 8px; background: #1A1F2E; display: flex; align-items: center; justify-content: center; color: #8B5CF6; font-size: 14px; }
          .sub-suggest-title { font-size: 14px; font-weight: 600; color: white; font-family: monospace; }
          .sub-suggest-sub { font-size: 12px; color: #6B7280; margin-top: 2px; }
          .sub-run-btn { background: #8B5CF6; border: none; border-radius: 6px; padding: 6px 16px; font-size: 13px; font-weight: 600; color: white; cursor: pointer; }
          .sub-run-btn:hover { background: #7C3AED; }
          .sub-actions-bar { display: flex; align-items: center; gap: 12px; padding-top: 14px; border-top: 1px solid #232736; margin-top: 14px; }
          .sub-copy-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .sub-copy-btn:hover { background: #1A1F2E; }
          .sub-copy-btn i { color: #8B5CF6; }
          .sub-rescan-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .sub-rescan-btn:hover { background: #1A1F2E; }
          .sub-rescan-btn i { color: #8B5CF6; }
          .sub-meta-right { font-size: 12px; color: #4B5563; margin-left: auto; }
        </style>

        <div class="sub-zone sub-zone-1">
          <div class="sub-hero">
            <div class="sub-hero-left">
              <i class="fa-solid fa-magnifying-glass sub-hero-icon"></i>
              <div>
                <div class="sub-hero-title">Subdomain Recon</div>
                <div class="sub-hero-domain">${domain}</div>
                <div class="sub-hero-wordlist">${wordlistSize} wordlist</div>
              </div>
            </div>
            <div class="sub-stats-row">
              <div class="sub-stat-pill">
                <div class="sub-stat-label">Total Found</div>
                <div class="sub-stat-value">${totalFound}</div>
              </div>
              <div class="sub-stat-pill">
                <div class="sub-stat-label">High Interest</div>
                <div class="sub-stat-value" style="color:${highInterestCount > 0 ? '#f07070' : '#6b6e78'}">${highInterestCount}</div>
              </div>
              <div class="sub-stat-pill">
                <div class="sub-stat-label">Scan Size</div>
                <div class="sub-stat-value" style="color:#a78bfa">${wordlistSize}</div>
              </div>
            </div>
          </div>
        </div>

        <div class="sub-zone sub-zone-2">
          ${subdomains.length > 0 ? `
            <div class="sub-table">
              <div class="sub-table-header">
                <div>SUBDOMAIN</div>
                <div>IP ADDRESS</div>
                <div>STATUS</div>
                <div>INTEREST</div>
              </div>
              ${subdomainRows}
            </div>
          ` : `
            <div class="sub-empty-card">
              <div class="sub-empty-icon"><i class="fa-solid fa-magnifying-glass"></i></div>
              <div class="sub-empty-title">No subdomains discovered</div>
              <div class="sub-empty-sub">The ${wordlistSize} wordlist scan returned no results. Try scanning with a custom wordlist or check if the domain uses wildcard DNS.</div>
              <div class="sub-empty-actions">
                <button class="sub-empty-btn">Try Custom Wordlist <i class="fa-solid fa-arrow-right" style="margin-left:4px"></i></button>
                <button class="sub-empty-btn muted" onclick="switchTool('dns')">Check DNS Lookup <i class="fa-solid fa-arrow-right" style="margin-left:4px"></i></button>
              </div>
            </div>
          `}
        </div>

        ${highInterestCount > 0 ? `
        <div class="sub-zone sub-zone-3">
          <div class="sub-high-section">
            <div class="sub-high-label">High Interest Targets</div>
            ${highInterestCards}
          </div>
        </div>
        ` : ''}

        ${subdomains.length === 0 && totalFound === 0 ? `
        <div class="sub-zone sub-zone-4">
          <div class="sub-wildcard-warning">
            <i class="fa-solid fa-triangle-exclamation"></i>
            <div>
              <strong>Wildcard DNS Check Recommended</strong><br/>
              Zero subdomains found on a Large wordlist may indicate wildcard DNS is configured, which can mask real subdomains. Run a DNS Lookup to verify.
              <button class="sub-empty-btn muted" style="margin-top:8px;display:inline-block" onclick="switchTool('dns')">Run DNS Lookup <i class="fa-solid fa-arrow-right" style="margin-left:4px"></i></button>
            </div>
          </div>
        </div>
        ` : ''}

        <div class="sub-zone sub-zone-5">
          <div class="sub-suggest-box">
            <div class="sub-suggest-label">Suggested Next Step</div>
            <div class="sub-suggest-content">
              <div class="sub-suggest-info">
                <div class="sub-suggest-icon"><i class="fa-solid fa-network-wired"></i></div>
                <div>
                  <div class="sub-suggest-title">Port Scan High-Interest Targets</div>
                  <div class="sub-suggest-sub">Perform deep service enumeration on flagged subdomains to find entry points</div>
                </div>
              </div>
              <button class="sub-run-btn" onclick="switchTool('portscanner')">Open Port Scanner <i class="fa-solid fa-arrow-right" style="margin-left:4px"></i></button>
            </div>
          </div>
        </div>

        <div class="sub-actions-bar">
          <button class="sub-copy-btn" onclick="copyToolResult('subdomains')"><i class="fa-solid fa-copy"></i> Copy</button>
          <button class="sub-rescan-btn" onclick="runTool('subdomains')"><i class="fa-solid fa-rotate-right"></i> Re-scan</button>
          <span class="sub-meta-right">${domain} · ${wordlistSize} wordlist · just now</span>
        </div>
      </div>
    `;

    if (actions) actions.style.display = 'flex';
  },

  renderGeo(data) {
    const output = document.getElementById('geo-output');
    const actions = document.getElementById('geo-actions');
    if (data.status === 'failed') {
      output.innerHTML = `
        <div class="geo-result">
          <style>
            @keyframes geo-fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
            .geo-zone { animation: geo-fade 0.3s ease-out forwards; opacity: 0; }
            .geo-zone-1 { animation-delay: 0ms; }
            .geo-error-card { background: #111318; border: 0.5px solid #2a2d35; border-radius: 10px; padding: 20px 24px; text-align: center; }
            .geo-error-icon { font-size: 48px; color: #f07070; margin-bottom: 12px; }
            .geo-error-title { font-size: 18px; font-weight: 600; color: #e2e3e7; }
            .geo-error-msg { font-size: 13px; color: #6b6e78; margin-top: 8px; }
          </style>
          <div class="geo-zone geo-zone-1">
            <div class="geo-error-card">
              <div class="geo-error-icon"><i class="fa-solid fa-circle-exclamation"></i></div>
              <div class="geo-error-title">Geolocation Lookup Failed</div>
              <div class="geo-error-msg">${data.error || 'Unable to determine location'}</div>
            </div>
          </div>
        </div>
      `;
      if (actions) actions.style.display = 'none';
      return;
    }

    const ip = data.ip || 'Unknown';
    const country = data.country || 'Unknown';
    const countryCode = data.country_code || data.countryCode || 'XX';
    const region = data.region || data.state || 'Unknown';
    const city = data.city || 'Unknown';
    const org = data.org || data.isp || 'Unknown';
    const asn = data.asn || data.ASN || '—';
    const flag = getFlagEmoji(countryCode);

    const classifyASN = (orgStr) => {
      const hosting = ['godaddy', 'amazon', 'google', 'microsoft', 'digitalocean', 'linode', 'vultr', 'cloudflare', 'hetzner', 'ovh', 'leaseweb'];
      const isHosting = hosting.some(h => orgStr.toLowerCase().includes(h));
      return isHosting ? 'Hosting / Cloud' : 'Residential / Business';
    };

    const ipType = classifyASN(org);
    const isHosting = ipType === 'Hosting / Cloud';

    const generateGeoFallback = (d) => {
      const hosting = ['godaddy', 'amazon', 'google', 'microsoft', 'digitalocean', 'linode', 'vultr', 'cloudflare', 'hetzner', 'ovh', 'leaseweb'];
      const isHost = hosting.some(h => (d.org || '').toLowerCase().includes(h));
      return `IP ${d.ip} is registered to ${d.org || 'Unknown'} (ASN ${d.asn || 'N/A'}) and geolocates to ${d.city || 'Unknown'}, ${d.country || 'Unknown'}. ${isHost ? `This is a hosting provider IP, suggesting the true operator may be a customer of ${d.org}. The server is subject to ${d.country || 'Unknown'} data jurisdiction laws.` : `This appears to be a business or residential IP directly associated with ${d.org}.`}`;
    };

    function getFlagEmoji(countryCode) {
      if (!countryCode || countryCode.length !== 2) return '🌍';
      const codePoints = countryCode.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0));
      return String.fromCodePoint(...codePoints);
    }

    output.innerHTML = `
      <div class="geo-result">
        <style>
          @keyframes geo-fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
          @keyframes geo-slide { from { opacity: 0; transform: translateX(16px); } to { opacity: 1; transform: translateX(0); } }
          @keyframes geo-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
          .geo-zone { animation: geo-fade 0.3s ease-out forwards; opacity: 0; }
          .geo-zone-1 { animation-delay: 0ms; }
          .geo-zone-2 { animation-delay: 40ms; }
          .geo-zone-3 { animation-delay: 80ms; }
          .geo-zone-4 { animation-delay: 120ms; }
          .geo-zone-5 { animation-delay: 160ms; }
          .geo-zone-6 { animation-delay: 200ms; }
          .geo-zone-7 { animation-delay: 240ms; }
          .geo-zone-8 { animation-delay: 280ms; }
          .geo-hero { background: #151823; border: 1px solid #232736; border-radius: 10px; padding: 20px; display: flex; align-items: center; justify-content: space-between; }
          .geo-hero-left { display: flex; flex-direction: column; gap: 4px; }
          .geo-hero-ip { font-size: 20px; font-weight: 700; color: white; font-family: monospace; }
          .geo-hero-org { font-size: 13px; color: #6B7280; }
          .geo-hero-asn { background: #4C1D95; color: #C4B5FD; border-radius: 999px; padding: 3px 12px; font-size: 12px; font-family: monospace; margin-top: 6px; display: inline-block; }
          .geo-location-badge { background: #0E1016; border: 1px solid #232736; border-radius: 8px; padding: 10px 16px; text-align: center; animation: geo-slide 0.3s ease-out forwards; animation-delay: 100ms; opacity: 0; }
          .geo-location-flag { font-size: 24px; margin-bottom: 4px; }
          .geo-location-country { font-size: 14px; font-weight: 600; color: white; }
          .geo-location-code { background: #1A1F2E; color: #6B7280; border-radius: 4px; padding: 1px 8px; font-size: 11px; margin-top: 4px; display: inline-block; }
          .geo-details-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 12px; }
          .geo-detail-card { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 14px 16px; }
          .geo-detail-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-bottom: 4px; }
          .geo-detail-value { font-size: 14px; font-weight: 600; color: white; font-family: monospace; }
          .geo-detail-card.hosting { border-left: 3px solid #f0b860; }
          .geo-hosting-note { font-size: 11px; color: #f0b860; margin-top: 4px; }
          .geo-region-sub { font-size: 12px; color: #4B5563; margin-top: 2px; }
          .geo-asn-card { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px; margin-top: 12px; display: flex; justify-content: space-between; align-items: center; }
          .geo-asn-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-bottom: 6px; }
          .geo-asn-number { font-size: 14px; font-weight: 600; color: #8B5CF6; font-family: monospace; }
          .geo-asn-org { font-size: 13px; color: #9CA3AF; margin-top: 2px; }
          .geo-asn-badges { display: flex; gap: 8px; }
          .geo-type-badge { font-size: 12px; padding: 3px 12px; border-radius: 999px; font-weight: 500; }
          .geo-type-badge.hosting { background: #1A1F2E; color: #9CA3AF; border: 1px solid #232736; }
          .geo-type-badge.residential { background: #1A1F2E; color: #9CA3AF; border: 1px solid #232736; }
          .geo-map-container { background: #0A0D12; border: 1px solid #232736; border-radius: 8px; height: 160px; overflow: hidden; position: relative; margin-top: 12px; }
          .geo-map-label { position: absolute; top: 8px; left: 12px; font-size: 10px; text-transform: uppercase; color: #6B7280; letter-spacing: 0.08em; }
          .geo-map-grid { position: absolute; inset: 0; background-image: linear-gradient(#1A1F2E 1px, transparent 1px), linear-gradient(90deg, #1A1F2E 1px, transparent 1px); background-size: 20px 20px; }
          .geo-map-dot { position: absolute; top: 45%; left: 65%; }
          .geo-map-dot-outer { width: 32px; height: 32px; border-radius: 50%; background: rgba(234,179,8,0.3); animation: geo-pulse 2s infinite; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); }
          .geo-map-dot-inner { width: 10px; height: 10px; border-radius: 50%; background: #EAB308; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); box-shadow: 0 0 8px #EAB308; }
          .geo-map-ip { font-size: 11px; color: #EAB308; font-family: monospace; position: absolute; top: calc(45% + 24px); left: calc(65% - 20px); white-space: nowrap; }
          .geo-map-location { position: absolute; bottom: 8px; right: 12px; font-size: 11px; color: #6B7280; }
          .geo-map-compass { position: absolute; top: 8px; right: 12px; font-size: 10px; color: #4B5563; }
          .geo-osint-box { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px 20px; margin-top: 14px; }
          .geo-osint-header { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; color: #EAB308; margin-bottom: 10px; }
          .geo-osint-dot { width: 8px; height: 8px; border-radius: 50%; background: #EAB308; animation: geo-pulse 2s infinite; }
          .geo-osint-content { font-size: 12px; line-height: 1.7; color: #9CA3AF; font-family: monospace; }
          .geo-fallback-box { background: #111318; border: 0.5px solid #2a2d35; border-radius: 10px; padding: 16px 20px; margin-top: 14px; }
          .geo-fallback-header { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 500; color: #6b6e78; margin-bottom: 10px; }
          .geo-fallback-content { font-size: 13px; line-height: 1.7; color: #b0b2ba; }
          .geo-flags-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 12px; }
          .geo-flag-card { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 14px 16px; }
          .geo-flag-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-bottom: 4px; }
          .geo-flag-value { font-size: 14px; font-weight: 600; color: white; font-family: monospace; }
          .geo-flag-sub { font-size: 12px; color: #4B5563; margin-top: 2px; }
          .geo-flag-sub.muted { color: #4B5563; }
          .geo-suggest-box { background: #151823; border: 1px solid #232736; border-radius: 8px; padding: 16px 20px; margin-top: 14px; }
          .geo-suggest-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #6B7280; margin-bottom: 8px; }
          .geo-suggest-content { display: flex; align-items: center; justify-content: space-between; }
          .geo-suggest-info { display: flex; align-items: center; gap: 12px; }
          .geo-suggest-icon { width: 36px; height: 36px; border-radius: 8px; background: #1A1F2E; display: flex; align-items: center; justify-content: center; color: #8B5CF6; font-size: 14px; }
          .geo-suggest-title { font-size: 14px; font-weight: 600; color: white; font-family: monospace; }
          .geo-suggest-sub { font-size: 12px; color: #6B7280; margin-top: 2px; }
          .geo-run-btn { background: #8B5CF6; border: none; border-radius: 6px; padding: 6px 16px; font-size: 13px; font-weight: 600; color: white; cursor: pointer; }
          .geo-run-btn:hover { background: #7C3AED; }
          .geo-actions-bar { display: flex; align-items: center; gap: 12px; padding-top: 14px; border-top: 1px solid #232736; margin-top: 14px; }
          .geo-copy-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .geo-copy-btn:hover { background: #1A1F2E; }
          .geo-copy-btn i { color: #8B5CF6; }
          .geo-rescan-btn { background: transparent; border: 1px solid #232736; border-radius: 999px; padding: 6px 16px; font-size: 13px; color: #9CA3AF; cursor: pointer; display: flex; align-items: center; gap: 6px; }
          .geo-rescan-btn:hover { background: #1A1F2E; }
          .geo-rescan-btn i { color: #8B5CF6; }
          .geo-meta-right { font-size: 12px; color: #4B5563; margin-left: auto; }
          .geo-loading { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #6b6e78; }
          .geo-loading i { color: #8B5CF6; }
        </style>

        <div class="geo-zone geo-zone-1">
          <div class="geo-hero">
            <div class="geo-hero-left">
              <div class="geo-hero-ip">${ip}</div>
              <div class="geo-hero-org">${org}</div>
              <div class="geo-hero-asn">AS${asn}</div>
            </div>
            <div class="geo-location-badge">
              <div class="geo-location-flag">${flag}</div>
              <div class="geo-location-country">${country}</div>
              <div class="geo-location-code">${countryCode}</div>
            </div>
          </div>
        </div>

        <div class="geo-zone geo-zone-2">
          <div class="geo-details-grid">
            <div class="geo-detail-card">
              <div class="geo-detail-label">Country</div>
              <div class="geo-detail-value">${country} (${countryCode})</div>
            </div>
            <div class="geo-detail-card">
              <div class="geo-detail-label">Region / State</div>
              <div class="geo-detail-value">${region}</div>
              ${region !== 'Unknown' && region !== '03' ? `<div class="geo-region-sub">Central Singapore</div>` : ''}
            </div>
            <div class="geo-detail-card">
              <div class="geo-detail-label">City</div>
              <div class="geo-detail-value">${city}</div>
            </div>
            <div class="geo-detail-card ${isHosting ? 'hosting' : ''}">
              <div class="geo-detail-label">Organization</div>
              <div class="geo-detail-value">${org}</div>
              ${isHosting ? `<div class="geo-hosting-note">Hosting provider detected</div>` : ''}
            </div>
          </div>
        </div>

        <div class="geo-zone geo-zone-3">
          <div class="geo-asn-card">
            <div>
              <div class="geo-asn-label">ASN Details</div>
              <div class="geo-asn-number">AS${asn}</div>
              <div class="geo-asn-org">${org}</div>
            </div>
            <div class="geo-asn-badges">
              <span class="geo-type-badge ${isHosting ? 'hosting' : 'residential'}">${ipType}</span>
              <span class="geo-type-badge residential">Not Residential</span>
            </div>
          </div>
        </div>

        <div class="geo-zone geo-zone-4">
          <div class="geo-map-container">
            <div class="geo-map-label">APPROXIMATE LOCATION</div>
            <div class="geo-map-grid"></div>
            <div class="geo-map-dot">
              <div class="geo-map-dot-outer"></div>
              <div class="geo-map-dot-inner"></div>
            </div>
            <div class="geo-map-ip">${ip}</div>
            <div class="geo-map-location">${city}, ${countryCode}</div>
            <div class="geo-map-compass">N</div>
          </div>
        </div>

        <div class="geo-zone geo-zone-5">
          <div id="geo-ai-context-container"></div>
        </div>

        <div class="geo-zone geo-zone-6">
          <div class="geo-flags-row">
            <div class="geo-flag-card">
              <div class="geo-flag-label">IP Type</div>
              <div class="geo-flag-value" style="color:${isHosting ? '#f0b860' : '#e2e3e7'}">${isHosting ? 'Hosting Provider' : 'Residential'}</div>
              <div class="geo-flag-sub">${isHosting ? 'May mask true origin' : 'Direct connection'}</div>
            </div>
            <div class="geo-flag-card">
              <div class="geo-flag-label">Jurisdiction</div>
              <div class="geo-flag-value">${country}</div>
              <div class="geo-flag-sub">PDPA data protection laws</div>
            </div>
            <div class="geo-flag-card">
              <div class="geo-flag-label">Proxy / VPN</div>
              <div class="geo-flag-value" style="color:#6b6e78">Unknown</div>
              <div class="geo-flag-sub muted">Detection not available</div>
            </div>
          </div>
        </div>

        <div class="geo-zone geo-zone-7">
          <div class="geo-suggest-box">
            <div class="geo-suggest-label">Suggested Next Step</div>
            <div class="geo-suggest-content">
              <div class="geo-suggest-info">
                <div class="geo-suggest-icon"><i class="fa-solid fa-route"></i></div>
                <div>
                  <div class="geo-suggest-title">Trace Physical Route</div>
                  <div class="geo-suggest-sub">See the network hops across countries to reach this destination</div>
                </div>
              </div>
              <button class="geo-run-btn" onclick="switchTool('traceroute')">Run Traceroute <i class="fa-solid fa-arrow-right" style="margin-left:4px"></i></button>
            </div>
          </div>
        </div>

        <div class="geo-zone geo-zone-8">
          <div class="geo-actions-bar">
            <button class="geo-copy-btn" onclick="copyToolResult('geo')"><i class="fa-solid fa-copy"></i> Copy</button>
            <button class="geo-rescan-btn" onclick="runTool('geo')"><i class="fa-solid fa-rotate-right"></i> Re-lookup</button>
            <span class="geo-meta-right">${ip} · just now</span>
          </div>
        </div>
      </div>
    `;

    setTimeout(async () => {
      const aiContainer = document.getElementById('geo-ai-context-container');
      if (!aiContainer) return;
      aiContainer.innerHTML = `<div class="geo-loading"><i class="fa-solid fa-robot fa-flip"></i> AI analyzing geographical risk...</div>`;
      
      try {
        const analyzeResponse = await fetch('/api/ai/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || localStorage.getItem('cybersec_token') || '') },
          body: JSON.stringify({ 
            message: "Analyze the GeoIP and ISP data for IP " + ip + " in " + country + " (ISP: " + org + "). Determine if this IP belongs to a residential consumer node, a cloud provider, or a high-risk jurisdiction. Write a 2-sentence tactical summary.",
            scan_id: null,
            conversation_history: []
          })
        });
        
        if (analyzeResponse.ok) {
          const reader = analyzeResponse.body.getReader();
          const decoder = new TextDecoder("utf-8");
          let aiText = '';
          aiContainer.innerHTML = `
            <div class="geo-osint-box">
              <div class="geo-osint-header"><div class="geo-osint-dot"></div> Geo-Jurisdictional Insight</div>
              <div class="geo-osint-content" id="geoAiContent"></div>
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
                  if (contentBox) contentBox.innerHTML = marked.parse(aiText);
                }
              }
            }
          }
        } else {
          throw new Error('API error');
        }
      } catch(e) {
        aiContainer.innerHTML = `
          <div class="geo-fallback-box">
            <div class="geo-fallback-header"><i class="fa-solid fa-shield-halved"></i> Geo-Jurisdictional Insight</div>
            <div class="geo-fallback-content">${generateGeoFallback({ ip, org, asn, city, country })}</div>
          </div>
        `;
      }
    }, 300);

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
