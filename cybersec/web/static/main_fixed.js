(function() {
        // State
        let scanResults = { critical: [], high: [], medium: [], low: [] };
        let currentScanId = null;
        let scanInterval = null;
        let chatHistory = [];
        let osChatHistory = [];
        let fullScanRunning = false;
        let toolResults = {};
        let toolResultIds = {};

        function normalizeDomain(target) {
            if (!target) return '';
            target = target.trim();
            if (!target.startsWith('http://') && !target.startsWith('https://')) {
                target = 'https://' + target;
            }
            try {
                const url = new URL(target);
                return url.hostname;
            } catch {
                return target.replace(/^https?:\/\//, '');
            }
        }

        function normalizeWebTarget(target) {
            if (!target) return '';
            target = target.trim();
            if (!target.startsWith('http://') && !target.startsWith('https://')) {
                target = 'https://' + target;
            }
            return target;
        }

        function showInputError(inputId, message) {
            const inputEl = document.getElementById(inputId);
            if (!inputEl) return;
            let errorEl = inputEl.parentElement.querySelector('.input-error');
            if (!errorEl) {
                errorEl = document.createElement('div');
                errorEl.className = 'input-error';
                inputEl.parentElement.appendChild(errorEl);
            }
            errorEl.textContent = message;
            errorEl.style.opacity = '1';
        }

        function clearInputError(inputId) {
            const inputEl = document.getElementById(inputId);
            if (!inputEl) return;
            const errorEl = inputEl.parentElement.querySelector('.input-error');
            if (errorEl) errorEl.style.opacity = '0';
        }

        async function runTool(tool) {
            let params = {};
            let target = '';
            let inputId = '';

            switch (tool) {
                case 'portscanner':
                    target = document.getElementById('portscanner-target')?.value?.trim();
                    inputId = 'portscanner-target';
                    params.portRange = document.getElementById('portscanner-ports')?.value || 'common';
                    params.scanType = document.getElementById('scanner-type')?.value || 'port';
                    
                    params.options = {
                        rate_preset: document.getElementById('portscanner-rate')?.value || 'normal',
                        timeout: parseFloat(document.getElementById('portscanner-timeout')?.value) || 3.0,
                        concurrency: parseInt(document.getElementById('portscanner-concurrency')?.value) || 500,
                        enable_banner_grabbing: document.getElementById('portscanner-banner')?.checked,
                        enable_service_detection: document.getElementById('portscanner-service-detect')?.checked,
                        enable_os_fingerprinting: document.getElementById('portscanner-os-fingerprint')?.checked,
                        enable_tls_fingerprinting: document.getElementById('portscanner-tls-fingerprint')?.checked,
                        enable_cve_lookup: document.getElementById('portscanner-cve-lookup')?.checked,
                        max_retries: parseInt(document.getElementById('portscanner-retries')?.value) || 3
                    };
                    
                    const customRate = parseFloat(document.getElementById('portscanner-custom-rate')?.value);
                    if (customRate && customRate > 0) {
                        params.options.rate_pps = customRate;
                    }
                    
                    target = normalizeDomain(target);
                    break;
                case 'osfp':
                    target = document.getElementById('osfp-target')?.value?.trim();
                    inputId = 'osfp-target';
                    target = normalizeDomain(target);
                    break;
                case 'webscan':
                    const webscanInput = document.getElementById('webscan-target')?.value?.trim();
                    inputId = 'webscan-target';
                    target = normalizeWebTarget(webscanInput);
                    document.getElementById('webscan-target').value = target;
                    params.maxPages = parseInt(document.getElementById('webscan-maxpages')?.value) || 20;
                    break;
                case 'dns':
                    target = document.getElementById('dns-target')?.value?.trim();
                    inputId = 'dns-target';
                    target = normalizeDomain(target);
                    params.recordType = document.getElementById('dns-record-type')?.value || 'A';
                    break;
                case 'whois':
                    target = document.getElementById('whois-target')?.value?.trim();
                    inputId = 'whois-target';
                    target = normalizeDomain(target);
                    break;
                case 'ping':
                    target = document.getElementById('ping-target')?.value?.trim();
                    inputId = 'ping-target';
                    target = normalizeDomain(target);
                    params.count = parseInt(document.getElementById('ping-count')?.value) || 4;
                    break;
                case 'traceroute':
                    target = document.getElementById('traceroute-target')?.value?.trim();
                    inputId = 'traceroute-target';
                    target = normalizeDomain(target);
                    params.maxHops = parseInt(document.getElementById('traceroute-hops')?.value) || 30;
                    break;
                case 'ssl':
                    const sslInput = document.getElementById('ssl-host')?.value?.trim();
                    inputId = 'ssl-host';
                    target = normalizeWebTarget(sslInput);
                    document.getElementById('ssl-host').value = target;
                    params.port = parseInt(document.getElementById('ssl-port')?.value) || 443;
                    break;
                case 'headers':
                    const headersInput = document.getElementById('headers-url')?.value?.trim();
                    inputId = 'headers-url';
                    target = normalizeWebTarget(headersInput);
                    document.getElementById('headers-url').value = target;
                    break;
                case 'subdomains':
                    target = document.getElementById('subdomains-domain')?.value?.trim();
                    inputId = 'subdomains-domain';
                    target = normalizeDomain(target);
                    params.wordlist = document.getElementById('subdomains-wordlist')?.value || 'small';
                    break;
                case 'geo':
                    target = document.getElementById('geo-ip')?.value?.trim();
                    inputId = 'geo-ip';
                    target = normalizeDomain(target);
                    break;
            }

            if (inputId) {
                const inputEl = document.getElementById(inputId);
                if (inputEl) {
                    inputEl.addEventListener('input', () => clearInputError(inputId), { once: true });
                }
            }

            if (!target || target.length < 4) {
                showInputError(inputId, 'Please enter a valid target');
                return;
            }

            const webTools = ['webscan', 'ssl', 'headers'];
            if (webTools.includes(tool)) {
                try {
                    new URL(target);
                } catch {
                    showInputError(inputId, 'Invalid URL — try https://' + normalizeDomain(target));
                    return;
                }
            }

            const output = document.getElementById(tool + '-output');
            output.innerHTML = '<div class="placeholder"><i class="fa-solid fa-circle-notch fa-spin"></i>Running ' + tool + '...</div>';
            const actions = document.getElementById(tool + '-actions');
            if (actions) actions.style.display = 'none';

            if (tool === 'webscan') {
                window.webscanStartTime = Date.now();
                window.webscanVulns = { vulnerabilities: [], critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, pages_crawled: 0, target: target };
                initWebscanLog();
            }

            try {
                if (tool === 'portscanner') {
                    await startPortscannerStream(target, params.portRange, params.scanType, params.options);
                    return;
                }

                let apiResult;
                switch (tool) {
                    case 'osfp': apiResult = await api.tools.osfp(target); break;
                    case 'webscan':
                        let webScanChecksRun = 0;
                        apiResult = await api.tools.webscanStream(target, params.maxPages, {
                            onProgress: (data) => {
                                const stageColors = {
                                    'INIT': '',
                                    'CONFIG': '',
                                    'CRAWL': 'running',
                                    'CHECK': '',
                                    'SCAN': 'running',
                                    'VULN': 'warning',
                                    'DONE': 'success',
                                    'ERROR': 'error'
                                };
                                appendWebscanLog(data.stage, data.message, stageColors[data.stage] || '');
                                
                                if (data.stage === 'CHECK' || data.stage === 'SCAN') {
                                    webScanChecksRun++;
                                }
                                
                                if (data.result) {
                                    window.webscanVulns = data.result;
                                    toolsModule.renderWebscan({ result: data.result }, false);
                                } else {
                                    const output = document.getElementById('webscan-output');
                                    if (output && output.querySelector('.ws-summary-bar')) {
                                        const totalVulns = window.webscanVulns ? 
                                            (window.webscanVulns.critical_count || 0) + 
                                            (window.webscanVulns.high_count || 0) + 
                                            (window.webscanVulns.medium_count || 0) + 
                                            (window.webscanVulns.low_count || 0) : 0;
                                        const pagesCrawled = data.pages_found || window.webscanVulns?.pages_crawled || 0;
                                        const scanDuration = window.webscanStartTime ? ((Date.now() - window.webscanStartTime) / 1000).toFixed(1) : '0.0';
                                        
                                        const statCards = output.querySelectorAll('.ws-stat-card');
                                        if (statCards[0]) statCards[0].querySelector('.ws-stat-value').textContent = totalVulns;
                                        if (statCards[1]) statCards[1].querySelector('.ws-stat-value').textContent = pagesCrawled;
                                        if (statCards[2]) statCards[2].querySelector('.ws-stat-value').textContent = webScanChecksRun;
                                        if (statCards[3]) statCards[3].querySelector('.ws-stat-value').textContent = scanDuration + 's';
                                        
                                        if (totalVulns > 0 && !output.querySelector('.ws-vuln-table')) {
                                            output.querySelector('.ws-no-vulns')?.remove();
                                        }
                                    }
                                }
                            }
                        });
                        break;
                    case 'dns': apiResult = await api.tools.dns(target, params.recordType); break;
                    case 'whois': apiResult = await api.tools.whois(target); break;
                    case 'ping': apiResult = await api.tools.ping(target, params.count); break;
                    case 'traceroute': apiResult = await api.tools.traceroute(target, params.maxHops); break;
                    case 'ssl': apiResult = await api.tools.ssl(target, params.port); break;
                    case 'headers': apiResult = await api.tools.headers(target); break;
                    case 'subdomains': apiResult = await api.tools.subdomains(target, params.wordlist); break;
                    case 'geo': apiResult = await api.tools.geo(target); break;
                }

                const payload = apiResult?.data || apiResult;
                if (apiResult?.tool_result_id) {
                    toolResultIds[tool] = apiResult.tool_result_id;
                }
                toolResults[tool] = payload;
                
                toolsModule.renderResult(tool, payload);
            } catch (error) {
                const output = document.getElementById(tool + '-output');
                output.innerHTML = '<div class="placeholder" style="color: var(--error)"><i class="fa-solid fa-exclamation-triangle"></i> Error: ' + error.message + '</div>';
                const actions = document.getElementById(tool + '-actions');
                if (actions) actions.style.display = 'block';
            }
        }
        window.runTool = runTool;

        window.currentPortScannerFilter = 'ALL';
        window.currentPortScannerSort = 'PORT_ASC';
        window.currentPortTargetCache = '';

        window.setPortScannerFilter = (val) => {
            window.currentPortScannerFilter = val;
            if(window.currentPortCache) renderPortscannerRows(document.getElementById('portscanner-output'), window.currentPortTargetCache, window.currentPortCache, false);
        };
        
        window.setPortScannerSort = (val) => {
            window.currentPortScannerSort = val;
            if(window.currentPortCache) renderPortscannerRows(document.getElementById('portscanner-output'), window.currentPortTargetCache, window.currentPortCache, false);
        };

        function getPortInsight(port) {
            const p = port.port;
            if (p === 21 || p === 20) return 'FTP server';
            if (p === 22) return 'SSH remote access';
            if (p === 23) return 'Unencrypted telnet';
            if (p === 25 || p === 587) return 'Email server';
            if (p === 53) return 'DNS server';
            if (p === 80 || p === 8080 || p === 8000) return 'Web server';
            if (p === 110) return 'POP3 email';
            if (p === 143) return 'IMAP email';
            if (p === 443 || p === 8443) return 'Secure web (HTTPS)';
            if (p === 445) return 'Windows file sharing';
            if (p === 3306) return 'MySQL database';
            if (p === 3389) return 'RDP remote desktop';
            if (p === 5432) return 'PostgreSQL database';
            if (p === 6379) return 'Redis database';
            if (p === 27017) return 'MongoDB database';
            return 'Standard service';
        }

        window.portRowsCache = [];

        function renderPortscannerRows(outputEl, target, rows, isFinal = false) {
            if (!rows.length) return;
            
            if (!isFinal) {
                window.portRowsCache = rows;
                window._debugPortCount = rows.length;
                console.log('[SSE RAW] ports received:', rows.length, '| rows in table:', rows.length);
            }
            
            window.currentPortCache = rows;
            window.currentPortTargetCache = target;

            const rVal = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1 };

            let highCount = 0, medCount = 0, lowInfoCount = 0;
            rows.forEach(r => {
                const risk = r.risk_level || 'INFO';
                if (risk === 'CRITICAL' || risk === 'HIGH') highCount++;
                else if (risk === 'MEDIUM') medCount++;
                else lowInfoCount++;
            });

            let filtered = rows.filter(r => {
                const risk = r.risk_level || 'INFO';
                if (window.currentPortScannerFilter === 'CRIT_HIGH') return risk === 'CRITICAL' || risk === 'HIGH';
                if (window.currentPortScannerFilter === 'MEDIUM') return risk === 'MEDIUM';
                if (window.currentPortScannerFilter === 'LOW_INFO') return risk === 'LOW' || risk === 'INFO';
                return true;
            });

            if (window.currentPortScannerSort === 'PORT_ASC') filtered.sort((a, b) => a.port - b.port);
            else if (window.currentPortScannerSort === 'PORT_DESC') filtered.sort((a, b) => b.port - a.port);
            else if (window.currentPortScannerSort === 'RISK_DESC') filtered.sort((a, b) => (rVal[b.risk_level || 'INFO'] || 0) - (rVal[a.risk_level || 'INFO'] || 0));

            const riskBadge = (level) => {
                const l = (level || 'INFO').toUpperCase();
                const badgeClass = l === 'CRITICAL'
                    ? 'ps-risk-badge-critical'
                    : l === 'HIGH'
                        ? 'ps-risk-badge-high'
                        : 'ps-risk-badge-neutral';
                return '<span class="ps-risk-badge ' + badgeClass + '">' + l + '</span>';
            };

            const tableRows = filtered.map((port, index) => {
                const riskLevel = (port.risk_level || 'INFO').toUpperCase();
                const insight = getPortInsight(port);
                const versionStr = port.version && port.version !== '-'
                    ? (port.protocol || 'tcp') + ' · ' + port.version
                    : (port.protocol || 'tcp');
                const rowToneClass = index % 2 === 0 ? 'ps-row-even' : 'ps-row-odd';
                const rowRiskClass = riskLevel === 'CRITICAL'
                    ? 'ps-row-risk-critical'
                    : riskLevel === 'HIGH'
                        ? 'ps-row-risk-high'
                        : '';

                let cveList = '';
                if (port.cves && port.cves.length > 0) {
                    const cveBadges = port.cves.slice(0, 3).map(cve => {
                        const severity = cve.severity || 'INFO';
                        const severityClass = severity.toLowerCase() === 'critical' ? 'cve-critical' :
                                           severity.toLowerCase() === 'high' ? 'cve-high' :
                                           severity.toLowerCase() === 'medium' ? 'cve-medium' : 'cve-low';
                        return '<span class="cve-badge ' + severityClass + '" title="' + (cve.description || '') + '">' + cve.id + '</span>';
                    }).join('');
                    const moreCount = port.cves.length > 3 ? '+' + (port.cves.length - 3) : '';
                    cveList = '<div class="ps-cve-list">' + cveBadges + ' ' + moreCount + '</div>';
                }

                let tlsInfo = '';
                if (port.tls_info) {
                    const tls = port.tls_info;
                    tlsInfo = '<div class="ps-tls-info">' +
                        '<i class="fa-solid fa-shield-halved"></i> ' +
                        'JA3: ' + (tls.ja3_hash ? tls.ja3_hash.substring(0, 8) + '...' : 'N/A') +
                        (tls.certificate ? ' · ' + (tls.certificate.subject?.CN || 'Unknown') : '') +
                        '</div>';
                }

                let bannerInfo = '';
                if (port.banner && port.banner.length > 0) {
                    const truncated = port.banner.length > 50 ? port.banner.substring(0, 50) + '...' : port.banner;
                    bannerInfo = '<div class="ps-banner" title="' + port.banner.replace(/"/g, '&quot;') + '">' + truncated + '</div>';
                }

                return '<div class="ps-row ' + rowToneClass + ' ' + rowRiskClass + '" onclick="showPortDetail && showPortDetail(' + JSON.stringify(port).replace(/"/g, '&quot;') + ')">' +
                    '<div class="ps-port-number">' + port.port + '</div>' +
                    '<div>' +
                        '<div class="ps-service-name">' + (port.service || 'unknown') + '</div>' +
                        '<div class="ps-service-meta">' + versionStr + '</div>' +
                        bannerInfo +
                        tlsInfo +
                        cveList +
                    '</div>' +
                    '<div class="ps-insight">' + insight + '</div>' +
                    riskBadge(port.risk_level) +
                    '</div>';
            }).join('');

            let resultsContainer = outputEl.querySelector('.ps-results');
            if (!resultsContainer) {
                resultsContainer = document.createElement('div');
                resultsContainer.className = 'ps-results';
                outputEl.appendChild(resultsContainer);
            }
            resultsContainer.innerHTML = tableRows;

            if (isFinal) {
                const openCount = rows.filter(r => r.state === 'open').length;
                const filteredCount = rows.filter(r => r.state === 'filtered').length;
                const closedCount = rows.filter(r => r.state === 'closed').length;
                const totalScanned = openCount + filteredCount + closedCount;
                
                const summaryBar = '<div class="ps-summary-bar">' +
                    '<div class="ps-summary-stat"><span class="ps-stat-value" style="color:#10B981">' + openCount + '</span><span class="ps-stat-label">Open</span></div>' +
                    '<div class="ps-summary-stat"><span class="ps-stat-value" style="color:#F59E0B">' + filteredCount + '</span><span class="ps-stat-label">Filtered</span></div>' +
                    '<div class="ps-summary-stat"><span class="ps-stat-value" style="color:#9CA3AF">' + closedCount + '</span><span class="ps-stat-label">Closed</span></div>' +
                    '<div class="ps-summary-stat"><span class="ps-stat-value">' + totalScanned + '</span><span class="ps-stat-label">Total</span></div>' +
                    '</div>';
                outputEl.insertAdjacentHTML('afterbegin', summaryBar);
            }
        }

        function getTotalPorts(portRange) {
            if (portRange === 'common') return 100;
            if (portRange === 'top1000') return 1000;
            if (portRange === 'all') return 65535;
            
            if (portRange.includes('-')) {
                const parts = portRange.split('-');
                const start = parseInt(parts[0]);
                const end = parseInt(parts[1]);
                return end - start + 1;
            } else if (portRange.includes(',')) {
                return portRange.split(',').length;
            }
            return 1000;
        }

        function addScanLog(message, type = 'info') {
            const logEl = document.getElementById('scan-log');
            if (!logEl) return;
            
            const timestamp = new Date().toLocaleTimeString();
            const entry = document.createElement('div');
            entry.className = 'scan-log-entry scan-log-' + type;
            entry.innerHTML = '<span class="scan-log-time">[' + timestamp + ']</span> ' + message;
            
            logEl.appendChild(entry);
            logEl.scrollTop = logEl.scrollHeight;
            
            while (logEl.children.length > 50) {
                logEl.removeChild(logEl.firstChild);
            }
        }

        async function finalizePortScan(scanId, target, rows, actions, output) {
            try {
                const data = await api.scans.get(scanId);
                const payload = data.results || [];
                
                const adaptiveStats = window._adaptiveScanStats || {};
                window._adaptiveScanStats = null;
                const enrichedData = {
                    ...data,
                    target,
                    results: payload.length ? payload : rows,
                    avg_latency_ms: adaptiveStats.avg_latency_ms || null,
                    peak_concurrency: adaptiveStats.peak_concurrency || null,
                    scan_duration: adaptiveStats.scan_duration || data.scan_duration || null,
                };
                
                toolResults['portscanner'] = enrichedData;
                toolsModule.allResults['portscanner'] = enrichedData;
                renderPortscannerRows(output, target, enrichedData.results, true);
                if (actions) actions.style.display = 'flex';
            } catch (error) {
                console.error('Error finalizing port scan:', error);
            }

            const container = document.getElementById('port-ai-analysis-container');
            if (container) {
                container.innerHTML = '<div class="ai-insight-box">' +
                    '<div class="ai-insight-header"><i class="fa-solid fa-robot fa-fade"></i> AI is analyzing scan results...</div>' +
                    '<div class="ai-insight-content">Groq is generating insights based on exposed ports and vulnerabilities.</div>' +
                    '</div>';
                
                try {
                    const analyzeResponse = await fetch('/api/ai/analyze', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
                        body: JSON.stringify({ scan_id: scanId })
                    });
                    
                    if (analyzeResponse.ok) {
                        const aiDataRaw = await analyzeResponse.json();
                        let parsedAnalysis = {};
                        try {
                            const analysisStr = aiDataRaw.analysis || '';
                            if (!analysisStr.startsWith('[') && !analysisStr.startsWith('{') && !analysisStr.includes('{')) {
                                parsedAnalysis = { executive_summary: analysisStr || 'AI analysis unavailable.', port_remediations: {} };
                            } else {
                                let str = analysisStr.trim();
                                const firstBrace = str.indexOf('{');
                                const lastBrace = str.lastIndexOf('}');
                                if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
                                    str = str.substring(firstBrace, lastBrace + 1);
                                    parsedAnalysis = JSON.parse(str);
                                } else {
                                    parsedAnalysis = { executive_summary: analysisStr || 'AI analysis unavailable.', port_remediations: {} };
                                }
                            }
                        } catch (e) {
                            console.error('Failed to parse AI JSON:', e);
                            parsedAnalysis = { executive_summary: 'AI analysis unavailable due to rate limiting.', port_remediations: {} };
                        }
                        
                        window.aiAnalysisCompleted = true;
                        window.aiPortRemediations = parsedAnalysis.port_remediations || {};

                        if (window.currentOpenPort && document.getElementById('portDetailModal').style.display === 'flex') {
                            showPortDetail(window.currentOpenPort);
                        }

                        const formattedSummary = marked ? marked.parse(parsedAnalysis.executive_summary || 'No executive summary provided.') : (parsedAnalysis.executive_summary || 'No executive summary provided.');
                        container.innerHTML = '<div class="ai-insight-box port-ai-summary">' +
                            '<div class="ai-insight-header"><i class="fa-solid fa-brain"></i> AI Executive Summary</div>' +
                            '<div class="ai-insight-content">' + formattedSummary + '</div>' +
                            '<div class="ps-summary-note"><i class="fa-solid fa-info-circle"></i> Click on any open port row above to view specific remediation steps and auto-generated fix scripts.</div>' +
                            '</div>';
                    } else {
                        container.innerHTML = '';
                    }
                } catch (aiErr) {
                    console.error('AI Analysis Failed:', aiErr);
                    container.innerHTML = '';
                }
            }
        }

        window.aiAnalysisCompleted = false;
        window.aiPortRemediations = {};

        async function startPortscannerStream(target, portRange, scanType = 'port', options = {}) {
            window.aiAnalysisCompleted = false;
            window.aiPortRemediations = {};
            const output = document.getElementById('portscanner-output');
            const actions = document.getElementById('portscanner-actions');
            let rows = [];
            window.portRowsCache = [];
            let scanStartTime = Date.now();
            let portsScanned = 0;
            let openPortsFound = 0;
            
            output.innerHTML = '<div class="scan-progress-container">' +
                '<div class="scan-progress-header">' +
                    '<h4><i class="fa-solid fa-shield-halved"></i> Scanning ' + target + '</h4>' +
                    '<div class="scan-progress-stats">' +
                        '<span id="scan-ports-scanned">0 ports scanned</span>' +
                        '<span>·</span>' +
                        '<span id="scan-open-ports">0 open found</span>' +
                        '<span>·</span>' +
                        '<span id="scan-elapsed-time">0s</span>' +
                    '</div>' +
                '</div>' +
                '<div class="progress-bar-container">' +
                    '<div class="progress-bar" id="scan-progress-bar" style="width: 0%"></div>' +
                '</div>' +
                '<div class="scan-current-port" id="scan-current-port">Initializing...</div>' +
                '<div class="scan-log" id="scan-log"></div>' +
                '</div>';
            
            if (actions) actions.style.display = 'none';
            
            const timeInterval = setInterval(() => {
                const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
                const el = document.getElementById('scan-elapsed-time');
                if (el) el.textContent = elapsed + 's';
            }, 1000);

            try {
                const scan = await api.scans.create(target, scanType, portRange, options);
                const scanId = scan.id || scan.scan_id;
                const es = new EventSource('/api/scans/' + scanId + '/stream');

                es.onmessage = (evt) => {
                    if (evt.data === '[DONE]') {
                        clearInterval(timeInterval);
                        es.close();
                        finalizePortScan(scanId, target, rows, actions, output);
                        return;
                    }
                    // Skip SSE keepalive/comments
                    if (!evt.data || evt.data.startsWith(':')) {
                        return;
                    }
                    try {
                        const data = JSON.parse(evt.data);
                        
                        if (data.type === 'scan_start') {
                            addScanLog('Scan started on ' + target, 'info');
                        } else if (data.type === 'heartbeat') {
                            if (data.open_ports_found !== undefined) {
                                openPortsFound = data.open_ports_found;
                                const el = document.getElementById('scan-open-ports');
                                if (el) el.textContent = openPortsFound + ' open found';
                            }
                        } else if (data.type === 'scan_complete') {
                            window._adaptiveScanStats = {
                                scan_duration: data.scan_duration,
                                avg_latency_ms: data.avg_latency_ms,
                                peak_concurrency: data.peak_concurrency,
                            };
                            clearInterval(timeInterval);
                            return;
                        } else if (data.port) {
                            portsScanned++;
                            rows.push(data);
                            
                            const totalPorts = getTotalPorts(portRange);
                            const progress = Math.min((portsScanned / totalPorts) * 100, 100);
                            const pbEl = document.getElementById('scan-progress-bar');
                            if (pbEl) pbEl.style.width = progress + '%';
                            const psEl = document.getElementById('scan-ports-scanned');
                            if (psEl) psEl.textContent = portsScanned + ' ports scanned';
                            const cpEl = document.getElementById('scan-current-port');
                            if (cpEl) cpEl.textContent = 'Scanning port ' + data.port + '...';
                            
                            if (data.state === 'open') {
                                openPortsFound++;
                                const opEl = document.getElementById('scan-open-ports');
                                if (opEl) opEl.textContent = openPortsFound + ' open found';
                                addScanLog('Port ' + data.port + '/' + (data.protocol || 'tcp') + ' OPEN - ' + (data.service || 'unknown'), 'success');
                            }
                            
                            renderPortscannerRows(output, target, rows);
                        } else if (data.message) {
                            addScanLog(data.message, 'info');
                        }
                    } catch (e) {
                        console.warn('SSE parse error:', e.message, '- data:', evt.data);
                    }
                };

                es.onerror = (error) => {
                    clearInterval(timeInterval);
                    es.close();
                    addScanLog('SSE connection lost. Attempting to finalize scan...', 'warning');
                    finalizePortScan(scanId, target, rows, actions, output);
                };
            } catch (error) {
                clearInterval(timeInterval);
                console.error('Scan initiation error:', error);
                
                let errorMessage = error.message || 'Unknown error occurred';
                let errorDetails = '';
                
                if (errorMessage.includes('fetch')) {
                    errorMessage = 'Network Error';
                    errorDetails = 'Unable to connect to the scan server. Please check your internet connection.';
                } else if (errorMessage.includes('422')) {
                    errorMessage = 'Invalid Parameters';
                    errorDetails = 'Please check your target and scan parameters.';
                } else if (errorMessage.includes('403') || errorMessage.includes('401')) {
                    errorMessage = 'Authentication Required';
                    errorDetails = 'Please log in to start a scan.';
                } else if (errorMessage.includes('429')) {
                    errorMessage = 'Rate Limited';
                    errorDetails = 'Too many scan requests. Please wait a moment and try again.';
                }
                
                output.innerHTML = '<div class="alert alert-error">' +
                    '<i class="fa-solid fa-circle-exclamation"></i>' +
                    '<strong>' + errorMessage + '</strong><br>' +
                    '<span style="color: var(--text-secondary); font-size: 0.9rem;">' + errorDetails + '</span>' +
                    '<div style="margin-top: 1rem;">' +
                        '<button onclick="location.reload()" class="btn-secondary">' +
                            '<i class="fa-solid fa-refresh"></i> Try Again' +
                        '</button>' +
                    '</div>' +
                    '</div>';
            }
        }
        window.startPortscannerStream = startPortscannerStream;

        // Port Scanner
        async function startScan() {
            const target = document.getElementById('target').value.trim();
            const ports = document.getElementById('ports').value || 'common';
            const enhancedDetection = document.getElementById('enhancedDetection').checked;
            const osDetection = document.getElementById('osDetection').checked;
            
            if (!target) {
                alert('Please enter a target host');
                return;
            }

            document.getElementById('emptyState').classList.add('hidden');
            document.getElementById('resultsContainer').classList.remove('hidden');
            document.getElementById('scanTips').classList.add('hidden');
            document.getElementById('allPorts').innerHTML = '';
            document.getElementById('scanProgress').classList.remove('hidden');
            document.getElementById('startBtn').classList.add('hidden');
            
            // Show cancel button
            let cancelBtn = document.getElementById('cancelScanBtn');
            if (!cancelBtn) {
                cancelBtn = document.createElement('button');
                cancelBtn.id = 'cancelScanBtn';
                cancelBtn.className = 'cancel-button';
                cancelBtn.textContent = 'Cancel';
                cancelBtn.onclick = cancelScan;
                document.querySelector('#portScannerView .control-panel').appendChild(cancelBtn);
            } else {
                cancelBtn.classList.remove('hidden');
            }

            scanResults = { critical: [], high: [], medium: [], low: [] };
            updateStatus(`Starting scan on ${target}...`, 'scanning');

            try {
                const response = await fetch('/api/scans/', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        target: target,
                        scan_type: 'port',
                        port_range: ports,
                        options: {
                            enhanced_service_detection: enhancedDetection,
                            os_detection: osDetection
                        }
                    })
                });

                if (!response.ok) {
                    let detail = 'Failed to start scan';
                    try {
                        const err = await response.json();
                        if (err?.detail) detail = err.detail;
                    } catch (e) {}
                    throw new Error(detail);
                }

                const scan = await response.json();
                currentScanId = scan.id;
                pollScanStatus(scan.id);
            } catch (err) {
                updateStatus(`Error: ${err.message}`, 'error');
                document.getElementById('allPorts').innerHTML = `<div class="error-message">${err.message}</div>`;
                document.getElementById('startBtn').classList.remove('hidden');
                document.getElementById('cancelScanBtn')?.classList.add('hidden');
            }
        }

        function cancelScan() {
            if (scanInterval) {
                clearInterval(scanInterval);
                scanInterval = null;
            }
            updateStatus('Scan cancelled', 'error');
            document.getElementById('startBtn').classList.remove('hidden');
            document.getElementById('cancelScanBtn')?.classList.add('hidden');
        }

        async function pollScanStatus(scanId) {
            scanInterval = setInterval(async () => {
                try {
                    const response = await fetch(`/api/scans/${scanId}`);
                    if (!response.ok) throw new Error('Failed to get scan status');

                    const data = await response.json();
                    const pct = data.progress_pct || 0;
                    
                    const progressBar = document.getElementById('scanProgressBar');
                    const progressPercent = document.getElementById('scanProgressPercent');
                    if (progressBar) progressBar.style.width = pct + '%';
                    if (progressPercent) progressPercent.textContent = Math.round(pct) + '%';
                    
                    if (data.status === 'running') {
                        updateStatus(`Scanning... ${Math.round(pct)}%`, 'scanning');
                    } else {
                        updateStatus(`Status: ${data.status}`);
                    }

                    if (data.status === 'completed' || data.status === 'failed') {
                        clearInterval(scanInterval);
                        scanInterval = null;
                        const startBtn = document.getElementById('startBtn');
                        const cancelBtn = document.getElementById('cancelScanBtn');
                        if (startBtn) startBtn.classList.remove('hidden');
                        if (cancelBtn) cancelBtn.classList.add('hidden');
                        
                        if (data.status === 'completed') {
                            updateStatus('Scan completed successfully!', 'complete');
                            setTimeout(() => {
                                const scanProgress = document.getElementById('scanProgress');
                                if (scanProgress) scanProgress.classList.add('hidden');
                            }, 2000);
                            displayScanResults(data);
                        } else {
                            const errMsg = data.error || 'Scan failed. Please try again.';
                            updateStatus(errMsg, 'error');
                            const allPortsEl = document.getElementById('allPorts');
                            if (allPortsEl) allPortsEl.innerHTML = `<div class="error-message">${errMsg}</div>`;
                        }
                    }
                } catch (err) {
                    clearInterval(scanInterval);
                    console.error('Poll error:', err);
                }
            }, 1500);
        }

        function displayScanResults(scan) {
            const container = document.getElementById('allPorts');
            if (!scan.results || scan.results.length === 0) {
                container.innerHTML = '<div class="empty-state"><h3 style="color:#10B981">No open ports found</h3><p style="color:var(--text-secondary)">The target appears to have all scanned ports closed</p></div>';
                return;
            }

            // Categorize ports by risk
            const criticalPorts = [21, 22, 23, 25, 110, 143, 445, 3306, 3389, 5432, 8080, 8443];
            const highRiskPorts = [53, 80, 111, 135, 139, 443, 993, 995, 1723, 1433, 5985, 6379];
            const mediumRiskPorts = [110, 111, 123, 137, 138, 161, 162, 389, 636, 993, 995, 2121, 3306, 5432];

            const critical = scan.results.filter(p => criticalPorts.includes(p.port));
            const high = scan.results.filter(p => highRiskPorts.includes(p.port) && !criticalPorts.includes(p.port));
            const medium = scan.results.filter(p => mediumRiskPorts.includes(p.port) && !criticalPorts.includes(p.port) && !highRiskPorts.includes(p.port));
            const low = scan.results.filter(p => !criticalPorts.includes(p.port) && !highRiskPorts.includes(p.port) && !mediumRiskPorts.includes(p.port));

            let html = '';
            let portIndex = 0;
            const portDataCache = {};

            if (critical.length > 0) {
                html += '<div class="results-section critical"><div class="results-title" style="color:#DC2626"><i class="fa-solid fa-triangle-exclamation"></i> Critical Risk Ports</div>';
                critical.forEach(p => { html += createPortElement(p, 'critical', portIndex); portDataCache[portIndex] = p; portIndex++; });
                html += '</div>';
                scanResults.critical = critical;
            }

            if (high.length > 0) {
                html += '<div class="results-section high"><div class="results-title" style="color:#EF4444"><i class="fa-solid fa-exclamation-circle"></i> High Risk Ports</div>';
                high.forEach(p => { html += createPortElement(p, 'high', portIndex); portDataCache[portIndex] = p; portIndex++; });
                html += '</div>';
                scanResults.high = high;
            }

            if (medium.length > 0) {
                html += '<div class="results-section medium"><div class="results-title" style="color:#F59E0B"><i class="fa-solid fa-exclamation-triangle"></i> Medium Risk Ports</div>';
                medium.forEach(p => { html += createPortElement(p, 'medium', portIndex); portDataCache[portIndex] = p; portIndex++; });
                html += '</div>';
                scanResults.medium = medium;
            }

            if (low.length > 0) {
                html += '<div class="results-section low"><div class="results-title" style="color:#10B981"><i class="fa-solid fa-info-circle"></i> Low Risk Ports</div>';
                low.forEach(p => { html += createPortElement(p, 'low', portIndex); portDataCache[portIndex] = p; portIndex++; });
                html += '</div>';
                scanResults.low = low;
            }

            window.portDetailCache = portDataCache;
            container.innerHTML = html;
        }

        function createPortElement(port, risk, index) {
            let riskLabel = 'Low';
            if (risk === 'critical') riskLabel = 'Critical';
            else if (risk === 'high') riskLabel = 'High';
            else if (risk === 'medium') riskLabel = 'Medium';

            return `
                <div class="port-item" data-risk="${risk}" data-port-index="${index}">
                    <div class="port-header">
                        <div class="port-info-main">
                            <span class="port-number">Port ${port.port}</span>
                            <span class="port-service">${port.service || 'Unknown'}</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:0.6rem;">
                            <span class="port-risk risk-${risk}">${riskLabel}</span>
                            <i class="fa-solid fa-chevron-right port-chevron"></i>
                        </div>
                    </div>
                </div>
            `;
        }

        function togglePortDetail(el) {
            el.classList.toggle('open');
        }

        function showPortDetail(port) {
            console.log('showPortDetail called with:', port);
            const modal = document.getElementById('portDetailModal');
            const riskLevel = port.risk_level || 'INFO';

            document.getElementById('portModalTitle').textContent = `Port ${port.port}`;
            document.getElementById('portModalService').textContent = port.service || 'Unknown Service';
            document.getElementById('portModalPort').textContent = port.port;
            document.getElementById('portModalProtocol').textContent = (port.protocol || 'TCP').toUpperCase();
            document.getElementById('portModalState').textContent = (port.state || 'Open').charAt(0).toUpperCase() + (port.state || 'Open').slice(1);
            document.getElementById('portModalVersion').textContent = port.version || 'N/A';

            const riskBadge = document.getElementById('portModalRiskBadge');
            riskBadge.textContent = riskLevel === 'HIGH' ? 'HIGH' : riskLevel;
            riskBadge.style.background = '#8B5CF6';
            riskBadge.style.color = '#fff';

            const riskScore = port.risk_score || 0;
            document.getElementById('portModalRiskScore').textContent = `${Math.round(riskScore * 100)}%`;
            const riskBar = document.getElementById('portModalRiskBar');
            riskBar.style.width = `${riskScore * 100}%`;
            riskBar.style.background = 'linear-gradient(to right, #EAB308, #F59E0B)';

            const mitreSection = document.getElementById('portModalMitreSection');
            const mitreContainer = document.getElementById('portModalMitre');
            const mitreTechs = port.mitre_techniques || [];
            if (mitreTechs.length > 0) {
                mitreSection.style.display = 'block';
                mitreContainer.innerHTML = mitreTechs.map(t => `
                    <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.05);">
                        <span style="background:#4C1D95;color:#C4B5FD;padding:2px 8px;border-radius:4px;font-size:11px;font-family:monospace;">${t.id}</span>
                        <div>
                            <div style="font-weight:500;">${t.name || 'Unknown'}</div>
                            <div style="font-size:0.8rem;color:var(--text-secondary);">Tactics: ${(t.tactics || []).join(', ') || 'N/A'}</div>
                        </div>
                    </div>
                `).join('');
            } else {
                mitreSection.style.display = 'none';
            }

            const cveSection = document.getElementById('portModalCVESection');
            const cveContainer = document.getElementById('portModalCVE');
            const cves = port.cves || [];
            document.getElementById('portModalCVECount').textContent = cves.length;
            if (cves.length > 0) {
                cveSection.style.display = 'block';
                const severityBadgeColors = {
                    'CRITICAL': '#DC2626',
                    'HIGH': '#EAB308',
                    'MEDIUM': '#F59E0B',
                    'LOW': '#10B981',
                    'INFO': '#9CA3AF'
                };
                cveContainer.innerHTML = cves.map(c => `
                    <div style="padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.05);">
                        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
                            <span style="color:#fff;font-weight:600;">${c.id}</span>
                            <span style="font-size:0.8rem;padding:2px 8px;border-radius:4px;background:#EAB308;color:#0E1016;font-weight:700;">${c.severity}</span>
                            ${c.cvss_score ? `<span style="font-size:0.8rem;color:#9CA3AF;">CVSS: ${c.cvss_score}</span>` : ''}
                        </div>
                        <div style="font-size:0.85rem;color:var(--text-secondary);">${c.description || 'No description available'}</div>
                    </div>
                `).join('');
            } else {
                cveSection.style.display = 'block';
                cveContainer.innerHTML = '<div style="color:var(--text-secondary);text-align:center;padding:10px;">No known CVEs for this service</div>';
            }

            const banner = port.banner || '';
            const bannerEl = document.getElementById('portModalBanner');
            if (banner) {
                const lines = banner.split('\n');
                let html = '';
                lines.forEach((line, idx) => {
                    if (idx === 0) {
                        html += `<span style="color:#EAB308;">${line}</span>\n`;
                    } else {
                        const keyMatch = line.match(/^([^:]+):(.*)$/);
                        if (keyMatch) {
                            html += `<span style="color:#4ADE80;">${keyMatch[1]}:</span><span style="color:#9CA3AF;">${keyMatch[2]}</span>\n`;
                        } else {
                            html += `<span style="color:#9CA3AF;">${line}</span>\n`;
                        }
                    }
                });
                bannerEl.innerHTML = html.trim();
            } else {
                bannerEl.innerHTML = '<span style="color:#9CA3AF;">No banner information available</span>';
            }

            // AI Action Plan Injector
            const aiRemediationSection = document.getElementById('portModalAIRemediationSection');
            if (aiRemediationSection) {
                // Store globally so finalizePortScan can refresh it if it's open
                window.currentOpenPort = port;
                
                if (window.aiPortRemediations && window.aiPortRemediations[port.port]) {
                    const aiData = window.aiPortRemediations[port.port];
                    aiRemediationSection.style.display = 'block';
                    document.getElementById('portModalAIRemediationText').innerHTML = marked.parse(aiData.remediation || 'No remediation provided.');
                    
                    const fixScriptContainer = document.getElementById('portModalAIFixScriptContainer');
                    if (aiData.fix_script && aiData.fix_script.trim().length > 0) {
                        fixScriptContainer.style.display = 'block';
                        document.getElementById('portModalAIFixScript').textContent = aiData.fix_script;
                    } else {
                        fixScriptContainer.style.display = 'none';
                    }
                } else if (!window.aiAnalysisCompleted) {
                    aiRemediationSection.style.display = 'block';
                    document.getElementById('portModalAIRemediationText').innerHTML = '<div style="display:flex;align-items:center;gap:10px;color:var(--accent-blue)"><i class="fa-solid fa-circle-notch fa-spin"></i> AI is currently analyzing this port...</div>';
                    document.getElementById('portModalAIFixScriptContainer').style.display = 'none';
                } else {
                    aiRemediationSection.style.display = 'block';
                    document.getElementById('portModalAIRemediationText').innerHTML = '<span style="color:var(--text-muted)">No automated remediation available or necessary.</span>';
                    document.getElementById('portModalAIFixScriptContainer').style.display = 'none';
                }
            }

            modal.style.display = 'flex';
        }

        function hidePortDetailModal() {
            window.currentOpenPort = null;
            document.getElementById('portDetailModal').style.display = 'none';
        }

        function updateStatus(message, type = 'info') {
            const statusEl = document.getElementById('statusText');
            const percentEl = document.getElementById('scanProgressPercent');
            if (statusEl) {
                statusEl.textContent = message;
                statusEl.className = 'progress-text';
                if (type === 'scanning') statusEl.classList.add('status-scanning');
                else if (type === 'complete') statusEl.classList.add('status-complete');
                else if (type === 'error') statusEl.classList.add('status-error');
                else if (type === 'warning') statusEl.classList.add('status-warning');
            }
            if (type === 'complete' && percentEl) percentEl.textContent = '100%';
        }

        // OS Fingerprinting
        async function startOsFingerprint() {
            const target = document.getElementById('osTarget').value.trim();
            if (!target) { alert('Please enter a target host'); return; }

            const enhanced = document.getElementById('osEnhancedDetection').checked;
            const serviceDetect = document.getElementById('osServiceDetection').checked;

            document.getElementById('osEmptyState').classList.add('hidden');
            document.getElementById('osResultsContainer').classList.remove('hidden');

            // Show loading state
            document.getElementById('osResultsContainer').innerHTML = `
                <div style="padding:60px 20px; text-align:center; color:var(--text-secondary);">
                    <i class="fa-solid fa-circle-notch fa-spin fa-3x" style="margin-bottom:20px; color:var(--accent-blue)"></i>
                    <p style="font-size:1.1rem; font-weight:500">Fingerprinting OS via active probe analysis...</p>
                    <p style="font-size:0.9rem; margin-top:8px; opacity:0.7">This engages the port scanner natively before analyzing SYN patterns.</p>
                </div>
            `;

            try {
                // Run a port scan first to get open ports for OS detection
                const scanResponse = await fetch('/api/scans/', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        target: target,
                        scan_type: 'port',
                        port_range: 'common'
                    })
                });

                if (!scanResponse.ok) throw new Error('Unable to start background scan for OS fingerprinting');

                const scanData = await scanResponse.json();

                // Poll for scan completion
                let scanComplete = false;
                let openPorts = [];

                while (!scanComplete) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    const statusResponse = await fetch(`/api/scans/${scanData.id}`);
                    const statusData = await statusResponse.json();

                    if (statusData.status === 'completed') {
                        scanComplete = true;
                        openPorts = statusData.results || [];
                    } else if (statusData.status === 'failed') {
                        scanComplete = true;
                    }
                }

                // Analyze OS based on open ports
                const guesses = analyzeOsFromPorts(openPorts, target);
                const primary = guesses[0];
                
                let confidenceClass = 'low';
                let confidenceLabel = 'Low Confidence';
                let confColor = 'var(--text-muted)';
                if (primary.confidence >= 70) { confidenceClass = 'high'; confidenceLabel = 'High Confidence'; confColor = 'var(--accent-green)'; }
                else if (primary.confidence >= 40) { confidenceClass = 'medium'; confidenceLabel = 'Medium Confidence'; confColor = 'var(--accent-yellow)'; }
                else { confColor = 'var(--accent-red)'; }
                
                const warningHtml = primary.confidence < 70 ? `
                    <div class="os-warning-box">
                       <i class="fa-solid fa-triangle-exclamation" style="font-size:1.5rem"></i>
                       <div><strong>${confidenceLabel}</strong><br>Result may not be fully accurate. Consider running Advanced Fingerprinting.</div>
                    </div>
                ` : '';

                const alternativeHtml = guesses.length > 1 ? `
                    <div class="os-secondary-guesses" id="osSecondaryGuesses">
                         <h5>Alternative Matches</h5>
                         ${guesses.slice(1).map(g => `
                         <div class="os-guess-item">
                             <span><i class="${g.icon}" style="margin-right:6px;"></i> ${g.name}</span>
                             <span>${g.confidence}%</span>
                         </div>
                         `).join('')}
                    </div>
                ` : '';

                const structureHtml = `
                <div class="os-fingerprint-panel">
                    <div class="os-header-card">
                        <div class="os-header-left">
                            <div class="os-header-icon">
                                <i class="${primary.icon}"></i>
                            </div>
                            <div>
                                <h3 class="os-header-title">${primary.name}</h3>
                                <p class="os-header-subtitle">Detected via unknown</p>
                            </div>
                        </div>
                        <div class="os-confidence-widget">
                            <div class="os-confidence-label">CONFIDENCE</div>
                            <div class="os-confidence-value">${primary.confidence}% confident</div>
                            <div class="os-confidence-bar">
                                <div class="os-confidence-fill" style="width: ${primary.confidence}%"></div>
                            </div>
                        </div>
                    </div>

                    <div class="os-info-grid">
                        <div class="os-info-card">
                            <div class="os-info-label">TTL ANALYSIS</div>
                            <div class="os-info-value">Not performed</div>
                        </div>
                        <div class="os-info-card">
                            <div class="os-info-label">TCP WINDOW SIZE</div>
                            <div class="os-info-value">Not detected</div>
                        </div>
                        <div class="os-info-card">
                            <div class="os-info-label">SYN PACKET LOGIC</div>
                            <div class="os-info-value">${primary.explanation.substring(0, 20)}...</div>
                        </div>
                        <div class="os-info-card">
                            <div class="os-info-label">DETECTION METHOD</div>
                            <div class="os-info-value">Port Pattern</div>
                        </div>
                        <div class="os-info-card">
                            <div class="os-info-label">SCAN MODE</div>
                            <div class="os-info-value">Basic</div>
                        </div>
                        <div class="os-info-card">
                            <div class="os-info-label">OBSERVED PORTS</div>
                            <div class="os-info-value">
                                ${openPorts.length > 0 ? openPorts.map(p => `<span class="os-port-pill">${p.port}</span>`).join(' ') : 'None'}
                            </div>
                        </div>
                    </div>

                    <div class="os-collapsible-row os-tech-details" onclick="this.classList.toggle('open')">
                        <div class="os-collapsible-left">
                            <i class="fa-solid fa-gear os-collapsible-icon"></i>
                            <span class="os-collapsible-label">Technical Details</span>
                        </div>
                        <i class="fa-solid fa-chevron-down os-collapsible-chevron"></i>
                    </div>
                    <div class="os-collapsible-content">
                        <p><strong>TTL Analysis:</strong> Not performed in basic mode</p>
                        <p><strong>TCP Window Size:</strong> Not detected</p>
                        <p><strong>SYN Packet Logic:</strong> ${primary.explanation}</p>
                        <p><strong>Detection Method:</strong> Port pattern analysis</p>
                        <p><strong>Scan Mode:</strong> Basic fingerprinting</p>
                    </div>

                    <div class="os-collapsible-row os-ai-insight" onclick="this.classList.toggle('open')">
                        <div class="os-collapsible-left">
                            <div class="os-ai-dot"></div>
                            <span class="os-ai-label">AI Insight</span>
                        </div>
                        <i class="fa-solid fa-chevron-down os-collapsible-chevron"></i>
                    </div>
                    <div class="os-collapsible-content" id="os-ai-analysis-container">
                        <div style="color: #9CA3AF; font-style: italic;">AI analysis loading...</div>
                    </div>

                    <div class="os-actions">
                        <div class="os-action-buttons">
                            <button class="os-action-btn" onclick="navigator.clipboard.writeText('${primary.name} (${primary.confidence}% confidence)'); showToast('Results copied!')">
                                <i class="fa-regular fa-copy"></i> Copy
                            </button>
                            <button class="os-action-btn" onclick="document.getElementById('osEnhancedDetection').checked=true;startOsFingerprint()">
                                <i class="fa-solid fa-refresh"></i> Re-scan
                            </button>
                        </div>
                        <div class="os-scan-info">
                            Scanned · ${target} · just now
                        </div>
                    </div>
                </div>
                `;

                document.getElementById('osResultsContainer').innerHTML = structureHtml;
                
                // AI OS Analysis integration
                const aiContainer = document.getElementById('os-ai-analysis-container');
                if (aiContainer) {
                    aiContainer.innerHTML = `<div style="color: #9CA3AF; font-style: italic;">AI is analyzing fingerprint...</div>`;
                    try {
                        const analyzeResponse = await fetch('/api/ai/chat', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (localStorage.getItem('token') || '') },
                            body: JSON.stringify({ 
                                message: "Based on open ports detected, confirm if primary OS guess of " + primary.name + " (" + primary.confidence + "% confidence) is accurate. Write a strict 2-3 sentence technical intuition and whether deep scans are advised.",
                                scan_id: scanData.id,
                                conversation_history: []
                            })
                        });
                        
                        if (analyzeResponse.ok) {
                            const reader = analyzeResponse.body.getReader();
                            const decoder = new TextDecoder("utf-8");
                            let aiText = '';
                            while(true) {
                                const { done, value } = await reader.read();
                                if (done) break;
                                const chunk = decoder.decode(value, {stream: true});
                                const lines = chunk.split('\\n\\n');
                                for (const line of lines) {
                                    if (line.startsWith('data: ')) {
                                        const text = line.replace('data: ', '');
                                        if (text !== '[DONE]') {
                                            aiText += text;
                                            aiContainer.innerHTML = `<div style="color: #9CA3AF; font-style: italic;">${marked.parse(aiText)}</div>`;
                                        }
                                    }
                                }
                            }
                        } else {
                            aiContainer.innerHTML = `<div style="color: #9CA3AF; font-style: italic;">AI analysis unavailable</div>`;
                        }
                    } catch(e) { 
                        aiContainer.innerHTML = `<div style="color: #9CA3AF; font-style: italic;">AI analysis failed</div>`;
                    }
                }

            } catch (err) {
                document.getElementById('osResultsContainer').innerHTML = `
                    <div style="padding:20px; background:rgba(248,81,73,0.1); border:1px solid rgba(248,81,73,0.3); border-radius:8px; color:#ff7b72;">
                        <i class="fa-solid fa-circle-exclamation"></i> Error: ${err.message}
                    </div>
                `;
            }
        }

        function analyzeOsFromPorts(ports, target) {
            const portNumbers = ports.map(p => p.port);
            let guesses = [];
            
            // Simple OS fingerprinting based on common port signatures
            if (portNumbers.includes(22) && portNumbers.includes(80)) {
                guesses.push({ name: 'Linux / Unix', icon: 'fa-brands fa-linux', confidence: 85, explanation: 'SSH and HTTP are open, typical for a Linux web server.' });
                guesses.push({ name: 'FreeBSD', icon: 'fa-solid fa-server', confidence: 30, explanation: 'BSD systems frequently run identical edge services.' });
            } else if (portNumbers.includes(3389) && portNumbers.includes(445)) {
                guesses.push({ name: 'Windows Server', icon: 'fa-brands fa-windows', confidence: 80, explanation: 'RDP and SMB point to an exposed Windows Server infrastructure.' });
                guesses.push({ name: 'Windows Desktop', icon: 'fa-brands fa-windows', confidence: 40, explanation: 'Could be a desktop running RDP on an internal network.' });
            } else if (portNumbers.includes(445) && portNumbers.includes(139)) {
                guesses.push({ name: 'Windows', icon: 'fa-brands fa-windows', confidence: 75, explanation: 'SMB (File Sharing) is highly indicative of Windows Active Directory / File servers.' });
                guesses.push({ name: 'Linux/Samba', icon: 'fa-brands fa-linux', confidence: 35, explanation: 'Samba service sharing network paths on Linux.' });
            } else if (portNumbers.includes(22)) {
                guesses.push({ name: 'Linux / Unix', icon: 'fa-brands fa-linux', confidence: 70, explanation: 'SSH is standard on Unix-like operating systems and rarely runs independently on Windows without 445.' });
                guesses.push({ name: 'macOS', icon: 'fa-brands fa-apple', confidence: 25, explanation: 'macOS can run SSH remotely, though less prevalent.' });
            } else if (portNumbers.includes(80) || portNumbers.includes(443)) {
                guesses.push({ name: 'Linux / Unix', icon: 'fa-brands fa-linux', confidence: 60, explanation: 'High probability of Linux running NGINX or Apache.' });
                guesses.push({ name: 'Windows/IIS', icon: 'fa-brands fa-windows', confidence: 40, explanation: 'Windows server running Internet Information Services (IIS) is also likely.' });
            } else {
                guesses.push({ name: 'Unknown OS', icon: 'fa-solid fa-circle-question', confidence: 10, explanation: 'Not enough data to confidently fingerprint OS without TTL analysis.' });
                guesses.push({ name: 'Custom Hardware', icon: 'fa-solid fa-microchip', confidence: 5, explanation: 'Could be embedded IoT/router software.' });
            }
            
            return guesses;
        }

        // Web App Scanner
        async function startWebAppScan() {
            const url = document.getElementById('webappTarget').value.trim();
            if (!url) { alert('Please enter a target URL'); return; }

            const maxPages = parseInt(document.getElementById('webappMaxPages').value) || 20;
            const crawl = document.getElementById('webappCrawl').checked;
            const fullScan = document.getElementById('webappFullScan').checked;
            const passive = document.getElementById('webappPassive').checked;

            const btn = document.getElementById('webappScanBtn');
            btn.textContent = 'Scanning...';
            btn.disabled = true;

            document.getElementById('webappEmptyState').style.display = 'none';
            const container = document.getElementById('webappResultsContainer');
            container.classList.remove('hidden');
            container.innerHTML = '<div class="empty-state"><i class="fa-solid fa-circle-notch fa-spin" style="font-size:2.5rem;color:var(--purple-gradient-start)"></i><p style="margin-top:1rem;color:var(--text-secondary)">Scanning ' + url + '...</p><p style="font-size:0.8rem;color:var(--text-muted);margin-top:0.5rem">Crawling pages, testing for vulnerabilities</p></div>';

            try {
                const target = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
                
                // Run multiple checks
                const [headersRes, sslRes] = await Promise.all([
                    fetch('/api/tools/http_headers', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ target: target, path: '/' })
                    }).catch(() => ({ json: () => ({}) })),
                    fetch('/api/tools/ssl', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ host: target, port: url.startsWith('https') ? 443 : 80 })
                    }).catch(() => ({ json: () => ({}) }))
                ]);

                const headers = await headersRes.json();
                const ssl = await sslRes.json();

                const findings = [];
                
                // Security header checks
                if (headers.headers) {
                    if (!headers.headers['Strict-Transport-Security']) findings.push({ severity: 'medium', title: 'Missing HSTS Header', path: '/', description: 'HTTP Strict Transport Security header is not set. This helps protect against man-in-the-middle attacks.', remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to your server configuration.' });
                    if (!headers.headers['X-Content-Type-Options']) findings.push({ severity: 'low', title: 'Missing X-Content-Type-Options', path: '/', description: 'Content-Type sniffing is allowed, which could lead to MIME type confusion attacks.', remediation: 'Add "X-Content-Type-Options: nosniff" to response headers.' });
                    if (!headers.headers['X-Frame-Options']) findings.push({ severity: 'medium', title: 'Missing Clickjacking Protection', path: '/', description: 'X-Frame-Options header is missing. Your site could be embedded in an iframe on a malicious site.', remediation: 'Add "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" to response headers.' });
                    if (!headers.headers['Content-Security-Policy']) findings.push({ severity: 'medium', title: 'Missing Content Security Policy', path: '/', description: 'CSP header is not set. This helps prevent XSS and data injection attacks.', remediation: 'Implement a Content-Security-Policy header appropriate for your application.' });
                    if (!headers.headers['X-XSS-Protection']) findings.push({ severity: 'low', title: 'Missing X-XSS-Protection', path: '/', description: 'X-XSS-Protection header is not set (deprecated but still recommended).', remediation: 'Add "X-XSS-Protection: 1; mode=block" to response headers.' });
                }

                // SSL checks
                if (ssl.status === 'success') {
                    if (ssl.tls_versions && !ssl.tls_versions.includes('TLSv1.3')) findings.push({ severity: 'medium', title: 'Outdated TLS Version', path: '/', description: 'Server does not support TLS 1.3. Consider upgrading for better security.', remediation: 'Enable TLS 1.3 on your server.' });
                    if (ssl.valid_to) {
                        const expiry = new Date(ssl.valid_to);
                        const daysLeft = Math.floor((expiry - new Date()) / (1000 * 60 * 60 * 24));
                        if (daysLeft < 30) findings.push({ severity: 'high', title: 'SSL Certificate Expiring Soon', path: '/', description: 'SSL certificate expires in ' + daysLeft + ' days.', remediation: 'Renew your SSL certificate before it expires.' });
                    }
                } else if (url.startsWith('https')) {
                    findings.push({ severity: 'critical', title: 'SSL/TLS Error', path: '/', description: 'Unable to establish secure connection: ' + (ssl.error || 'Unknown error'), remediation: 'Check your SSL/TLS configuration and certificate.' });
                }

                // HTTP vs HTTPS check
                if (url.startsWith('http://') && !url.includes('localhost')) {
                    findings.push({ severity: 'critical', title: 'Insecure HTTP Connection', path: '/', description: 'Site is accessible over HTTP. All data is transmitted in plain text.', remediation: 'Enable HTTPS and redirect HTTP to HTTPS.' });
                }

                renderWebappResults(url, findings, headers.headers || {}, ssl);
            } catch (err) {
                container.innerHTML = '<div class="error-message">Error: ' + err.message + '</div>';
            }

            btn.textContent = 'Scan Web App';
            btn.disabled = false;
        }

        function renderWebappResults(url, findings, headers, ssl) {
            const container = document.getElementById('webappResultsContainer');
            const critical = findings.filter(f => f.severity === 'critical').length;
            const high = findings.filter(f => f.severity === 'high').length;
            const medium = findings.filter(f => f.severity === 'medium').length;
            const low = findings.filter(f => f.severity === 'low').length;
            const total = findings.length;
            
            const score = total === 0 ? 100 : Math.max(0, 100 - (critical * 20) - (high * 15) - (medium * 10) - (low * 5));
            const scoreColor = score >= 80 ? '#34D399' : score >= 50 ? '#FBBF24' : score >= 20 ? '#FB923C' : '#F87171';

            let html = '';
            
            // Summary
            html += '<div class="webapp-summary">';
            html += '<div class="webapp-stat-card"><div class="webapp-stat-num critical">' + critical + '</div><div class="webapp-stat-label">Critical</div></div>';
            html += '<div class="webapp-stat-card"><div class="webapp-stat-num high">' + high + '</div><div class="webapp-stat-label">High</div></div>';
            html += '<div class="webapp-stat-card"><div class="webapp-stat-num medium">' + medium + '</div><div class="webapp-stat-label">Medium</div></div>';
            html += '<div class="webapp-stat-card"><div class="webapp-stat-num" style="color:' + scoreColor + '">' + score + '</div><div class="webapp-stat-label">Security Score</div></div>';
            html += '</div>';

            // Risk bar
            html += '<div class="risk-bar-wrap">';
            html += '<div class="risk-bar-label"><span>Security Score</span><span style="color:' + scoreColor + ';font-weight:600">' + score + ' / 100</span></div>';
            html += '<div class="risk-bar-track"><div class="risk-bar-fill" style="width:' + score + '%;background:' + scoreColor + '"></div></div>';
            html += '</div>';

            // Meta info
            html += '<div style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:1rem">';
            html += 'Scanned <strong style="color:var(--text-primary)">' + url + '</strong>';
            html += ' · ' + findings.length + ' findings';
            html += ' · ' + (url.startsWith('https') ? 'HTTPS' : 'HTTP');
            html += '</div>';

            // Headers info
            if (Object.keys(headers).length > 0) {
                html += '<div class="webapp-section-title">Security Headers</div>';
                const securityHeaders = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection'];
                securityHeaders.forEach(h => {
                    const status = headers[h] ? '<span style="color:#34D399">✓ Present</span>' : '<span style="color:#EF4444">✗ Missing</span>';
                    html += '<div style="display:flex;justify-content:space-between;padding:0.25rem 0;font-size:0.85rem"><span>' + h + '</span>' + status + '</div>';
                });
            }

            // Findings
            if (findings.length === 0) {
                html += '<div class="empty-state" style="padding:2rem;margin-top:1rem"><i class="fa-solid fa-shield-check" style="font-size:2.5rem;color:#34D399"></i><p style="margin-top:0.5rem;color:#34D399;font-size:1.1rem">No vulnerabilities found</p><p style="font-size:0.85rem;color:var(--text-secondary)">Your web application appears to be secure</p></div>';
            } else {
                html += '<div class="webapp-section-title">Findings (' + findings.length + ')</div>';
                findings.forEach((f, i) => {
                    html += '<div class="finding-card">';
                    html += '<div class="finding-header" onclick="this.nextElementSibling.classList.toggle(\'open\')">';
                    html += '<span class="sev-badge ' + f.severity + '">' + f.severity + '</span>';
                    html += '<span class="finding-title">' + f.title + '</span>';
                    html += '<span class="finding-path">' + f.path + '</span>';
                    html += '</div>';
                    html += '<div class="finding-body">';
                    html += '<div class="finding-row"><span class="finding-row-label">Description</span><span class="finding-row-val">' + f.description + '</span></div>';
                    html += '<div class="finding-row"><span class="finding-row-label">Fix</span><span class="finding-row-val">' + f.remediation + '</span></div>';
                    html += '</div></div>';
                });
            }

            container.innerHTML = html;
        }

        // View switching
        function switchView(viewId) {
            document.querySelectorAll('.view-section').forEach(s => s.classList.remove('active'));
            document.getElementById(viewId + 'View').classList.add('active');
            document.querySelectorAll('.nav-menu a').forEach(l => l.classList.remove('active'));
            const navMap = { portScanner: 'PortScanner', osFingerprint: 'OsFingerprint', webAppScanner: 'WebAppScanner', fullScan: 'FullScan', tools: 'Tools', ai: 'AI', history: 'History' };
            document.getElementById('nav' + navMap[viewId])?.classList.add('active');
        }

        // Chat functions
        function toggleChat() {
            document.getElementById('resultsWindow').classList.toggle('chat-active');
        }

        function toggleOsChat() {
            document.getElementById('osResultsWindow').classList.toggle('chat-active');
        }

        function handleChatKey(e) {
            if (e.key === 'Enter') sendChatMessage();
        }

        function handleOsChatKey(e) {
            if (e.key === 'Enter') sendOsChatMessage();
        }

        function clearChat() {
            document.getElementById('chatMessages').innerHTML = '<div class="chat-message ai">Chat cleared. How can I help you analyze your scan results?</div>';
            chatHistory = [];
        }

        function clearOsChat() {
            document.getElementById('osChatMessages').innerHTML = '<div class="chat-message ai">Chat cleared. What would you like to know about OS fingerprinting?</div>';
            osChatHistory = [];
        }

        function sendChatMessage() {
            const input = document.getElementById('chatInput');
            const text = input.value.trim();
            if (!text) return;

            const messages = document.getElementById('chatMessages');
            messages.innerHTML += '<div class="chat-message user">' + escapeHtml(text) + '</div>';
            chatHistory.push({ role: 'user', content: text });
            
            messages.innerHTML += '<div class="chat-message ai"><div class="typing-indicator"><div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div></div></div>';
            messages.scrollTop = messages.scrollHeight;
            input.value = '';

            // Build context from scan results
            let context = '';
            if (Object.values(scanResults).some(arr => arr.length > 0)) {
                context = "Scan Results:\n";
                Object.entries(scanResults).forEach(([severity, ports]) => {
                    if (ports.length > 0) {
                        context += `${severity}: Ports ${ports.map(p => p.port).join(', ')}\n`;
                    }
                });
            }

            setTimeout(() => {
                const lastMsg = messages.querySelector('.chat-message.ai:last-child');
                
                // Simple AI response based on context
                let response = "I can help analyze your scan results. ";
                if (scanResults.critical.length > 0) {
                    response += `I see you have ${scanResults.critical.length} critical risk ports. These typically include remote access services like SSH (22), RDP (3389), or database ports (3306, 5432). `;
                    response += "I recommend: 1) Restrict access to these services via firewall, 2) Use strong authentication, 3) Keep services updated. ";
                }
                if (scanResults.high.length > 0) {
                    response += `You also have ${scanResults.high.length} high risk ports. These are often web services (80, 443) or Windows file sharing (445). `;
                    response += "Ensure web services use HTTPS and disable SMB if not needed. ";
                }
                response += "What would you like to know more about?";
                
                lastMsg.innerHTML = response;
                chatHistory.push({ role: 'assistant', content: response });
            }, 1500);
        }

        function sendOsChatMessage() {
            const input = document.getElementById('osChatInput');
            const text = input.value.trim();
            if (!text) return;

            const messages = document.getElementById('osChatMessages');
            messages.innerHTML += '<div class="chat-message user">' + escapeHtml(text) + '</div>';
            osChatHistory.push({ role: 'user', content: text });
            
            messages.innerHTML += '<div class="chat-message ai"><div class="typing-indicator"><div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div></div></div>';
            messages.scrollTop = messages.scrollHeight;
            input.value = '';

            setTimeout(() => {
                const lastMsg = messages.querySelector('.chat-message.ai:last-child');
                const osName = document.getElementById('osName').textContent;
                
                let response = "I can help analyze OS fingerprinting results. ";
                if (osName && osName !== '-' && osName !== 'Scanning...') {
                    response += `Based on the scan, the target appears to be running <strong>${osName}</strong>. `;
                    response += "OS fingerprinting works by analyzing network responses like TCP/IP stack characteristics, open ports, and service banners. ";
                } else {
                    response += "Run an OS fingerprinting scan first to get detailed information about the target's operating system. ";
                }
                response += "Would you like to know more about how OS detection works or get security recommendations?";
                
                lastMsg.innerHTML = response;
                osChatHistory.push({ role: 'assistant', content: response });
            }, 1500);
        }

        // Filters
        function toggleFilters(e) {
            e.stopPropagation();
            document.getElementById('filterPopover').classList.toggle('active');
        }

        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                applyFilter(this.dataset.filter);

            });
        });

        function summarizeToolResult(tool, result) {
            switch (tool) {
                case 'dns':
                    return result.target + ': DNS records - ' + (result.a_records?.join(', ') || 'No A records');
                case 'ssl':
                    return result.target + ': SSL ' + (result.status || 'unknown') + ' using ' + (result.cipher_suite || 'unknown cipher');
                case 'geo':
                    return result.ip + ': ' + (result.city || 'Unknown') + ', ' + (result.country || 'Unknown');
                case 'whois':
                    return 'Domain ' + result.target + ': registered by ' + (result.registrar || 'Unknown');
                default:
                    return JSON.stringify(result).substring(0, 200);
            }
        }

        // Full Scan (runs all tools together)
        const fullScanResults = {};

        function resetFullScanCards() {
            const tools = ['port','os','webapp','headers','ssl','dns','whois','ping','traceroute','subdomains','geo'];
            tools.forEach(t => setFullScanStatus(t, 'pending', 'Not started'));
            Object.keys(fullScanResults).forEach(k => delete fullScanResults[k]);
            const log = document.getElementById('fullscanLog');
            if (log) log.innerHTML = 'Ready. Click Run Full Scan to start.';
        }

        function setFullScanStatus(tool, state, detail) {
            const statusEl = document.getElementById(`fullscan-status-${tool}`);
            const detailEl = document.getElementById(`fullscan-detail-${tool}`);
            if (statusEl) {
                statusEl.className = `status-pill ${state}`;
                statusEl.textContent = state === 'running' ? 'Running' : state === 'success' ? 'Done' : state === 'error' ? 'Error' : 'Pending';
            }
            if (detailEl && detail !== undefined) {
                detailEl.textContent = detail;
            }
        }

        function appendFullScanLog(message) {
            const log = document.getElementById('fullscanLog');
            if (!log) return;
            const ts = new Date().toLocaleTimeString();
            const entry = document.createElement('div');
            entry.textContent = `[${ts}] ${message}`;
            log.appendChild(entry);
            log.scrollTop = log.scrollHeight;
        }

        async function pollFullScan(scanId) {
            let attempts = 0;
            while (attempts < 120) { // ~3 minutes
                const data = await api.scans.get(scanId);
                if (data.status === 'completed') return data;
                if (data.status === 'failed') throw new Error(data.error || 'Scan failed');
                await new Promise(r => setTimeout(r, 1500));
                attempts += 1;
            }
            throw new Error('Scan timed out');
        }

        // Web App Scanner Logging
        let lastWebscanLogEntry = null;
        let lastWebscanLogTime = null;
        
        function initWebscanLog() {
            const logEl = document.getElementById('webscan-log');
            if (!logEl) return;
            logEl.classList.remove('hidden');
            logEl.innerHTML = `
                <style>
                    .webscan-log { background: #0a0a0f; border: 1px solid #1e1e28; border-radius: 8px; padding: 0; font-size: 12px; overflow: hidden; }
                    .webscan-log-header { background: #13131a; padding: 10px 14px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #1e1e28; font-size: 12px; color: #a78bfa; }
                    .webscan-log-header i { color: #6b6e78; }
                    .webscan-log-body { max-height: 200px; overflow-y: auto; padding: 8px 0; }
                    .webscan-log-entry { display: flex; gap: 10px; padding: 6px 14px; border-bottom: 1px solid #12121a; }
                    .webscan-log-entry:last-child { border-bottom: none; }
                    .webscan-log-entry:hover { background: #0f0f15; }
                    .webscan-log-time { color: #4a4a58; min-width: 65px; }
                    .webscan-log-stage { color: #a78bfa; min-width: 70px; display: flex; align-items: center; gap: 6px; }
                    .webscan-log-msg { color: #b0b2ba; flex: 1; }
                    .webscan-log-entry.success .webscan-log-msg { color: #6acf80; }
                    .webscan-log-entry.error .webscan-log-msg { color: #f07070; }
                    .webscan-log-entry.warning .webscan-log-msg { color: #f0b860; }
                    .ws-dot-running { background: #a78bfa; animation: pulse-dot 1s infinite; }
                    .ws-dot-success { background: #6acf80; }
                    .ws-dot-error { background: #f07070; }
                    .ws-dot-warning { background: #f0b860; }
                    @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
                </style>
                <div class="webscan-log-body" id="webscan-log-body"></div>
            `;
            lastWebscanLogEntry = null;
            lastWebscanLogTime = null;
        }

        function appendWebscanLog(stage, message, type = '') {
            let logBody = document.getElementById('webscan-log-body');
            const logEl = document.getElementById('webscan-log');
            
            if (!logEl) return;
            
            if (!logBody) {
                logEl.innerHTML = `
                    <style>
                        .webscan-log { background: #0a0a0f; border: 1px solid #1e1e28; border-radius: 8px; padding: 0; font-size: 12px; overflow: hidden; }
                        .webscan-log-body { max-height: 200px; overflow-y: auto; padding: 8px 0; }
                        .webscan-log-entry { display: flex; gap: 10px; padding: 6px 14px; border-bottom: 1px solid #12121a; }
                        .webscan-log-entry:last-child { border-bottom: none; }
                        .webscan-log-entry:hover { background: #0f0f15; }
                        .webscan-log-time { color: #4a4a58; min-width: 65px; }
                        .webscan-log-stage { color: #a78bfa; min-width: 70px; display: flex; align-items: center; gap: 6px; }
                        .webscan-log-msg { color: #b0b2ba; flex: 1; }
                        .webscan-log-entry.success .webscan-log-msg { color: #6acf80; }
                        .webscan-log-entry.error .webscan-log-msg { color: #f07070; }
                        .webscan-log-entry.warning .webscan-log-msg { color: #f0b860; }
                        .ws-dot-running { background: #a78bfa; animation: pulse-dot 1s infinite; }
                        .ws-dot-success { background: #6acf80; }
                        .ws-dot-error { background: #f07070; }
                        .ws-dot-warning { background: #f0b860; }
                        @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
                    </style>
                    <div class="webscan-log-body" id="webscan-log-body"></div>
                `;
                logBody = document.getElementById('webscan-log-body');
            }
            
            const entryKey = stage + '|' + message;
            const nowMs = Date.now();
            if (lastWebscanLogEntry === entryKey && lastWebscanLogTime && (nowMs - lastWebscanLogTime) < 500) return;
            lastWebscanLogEntry = entryKey;
            lastWebscanLogTime = nowMs;
            
            const now = new Date();
            const timeStr = now.toLocaleTimeString('en-US', { hour12: false });
            const entry = document.createElement('div');
            entry.className = `webscan-log-entry ${type}`;
            
            let dotClass = 'ws-dot-running';
            if (type === 'success') dotClass = 'ws-dot-success';
            else if (type === 'error') dotClass = 'ws-dot-error';
            else if (type === 'warning') dotClass = 'ws-dot-warning';
            
            entry.innerHTML = `
                <span class="webscan-log-time">${timeStr}</span>
                <span class="webscan-log-stage"><span class="ws-progress-dot ${dotClass}" style="display:inline-block"></span>${stage}</span>
                <span class="webscan-log-msg">${message}</span>
            `;
            logBody.appendChild(entry);
            logBody.scrollTop = logBody.scrollHeight;
        }

        function hideWebscanLog() {
            const logEl = document.getElementById('webscan-log');
            if (logEl) logEl.classList.add('hidden');
        }

        function clearWebscanLog() {
            const logEl = document.getElementById('webscan-log');
            if (logEl) logEl.innerHTML = '';
        }

        function countDnsRecords(data) {
            return (data?.a_records?.length || 0) +
                   (data?.aaaa_records?.length || 0) +
                   (data?.mx_records?.length || 0) +
                   (data?.ns_records?.length || 0) +
                   (data?.txt_records?.length || 0) +
                   (data?.cname_records?.length || 0);
        }

        function summarizeHeadersMissing(headersObj) {
            if (!headersObj) return 'No headers';
            const required = ['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','x-xss-protection'];
            const present = Object.keys(headersObj).map(h => h.toLowerCase());
            const missing = required.filter(h => !present.includes(h));
            return missing.length === 0 ? 'All key headers present' : `${missing.length} missing`;
        }

        function buildWebappFindings(url, headersData, sslData) {
            const headers = headersData?.headers || headersData || {};
            const findings = [];
            const addFinding = (severity, title, description) => findings.push({ severity, title, description });
            const needHeader = (name, severity, desc) => {
                const key = Object.keys(headers).find(k => k.toLowerCase() === name.toLowerCase());
                if (!key) addFinding(severity, `Missing ${name}`, desc);
            };

            needHeader('Strict-Transport-Security', 'medium', 'HSTS header is missing.');
            needHeader('X-Content-Type-Options', 'low', 'X-Content-Type-Options is missing.');
            needHeader('X-Frame-Options', 'medium', 'Clickjacking protection header missing.');
            needHeader('Content-Security-Policy', 'medium', 'CSP header is missing.');
            needHeader('X-XSS-Protection', 'low', 'X-XSS-Protection header is missing.');

            if (sslData && sslData.status === 'success') {
                if (sslData.tls_versions && !sslData.tls_versions.includes('TLSv1.3')) addFinding('medium', 'Old TLS version', 'Server does not support TLS 1.3');
                if (sslData.valid_to) {
                    const daysLeft = Math.floor((new Date(sslData.valid_to) - new Date()) / (1000 * 60 * 60 * 24));
                    if (daysLeft < 30) addFinding('high', 'SSL expiring soon', `Certificate expires in ${daysLeft} days`);
                }
            } else if (url.startsWith('https')) {
                addFinding('critical', 'SSL/TLS error', sslData?.error || 'Could not establish TLS');
            }

            if (url.startsWith('http://') && !url.includes('localhost')) {
                addFinding('critical', 'Insecure HTTP', 'Traffic is not encrypted');
            }

            const counts = { critical: 0, high: 0, medium: 0, low: 0 };
            findings.forEach(f => counts[f.severity] = (counts[f.severity] || 0) + 1);
            const score = findings.length === 0 ? 100 : Math.max(0, 100 - counts.critical * 20 - counts.high * 15 - counts.medium * 10 - counts.low * 5);

            return { findings, total: findings.length, score };
        }

        function renderFullScanData(tool, data) {
            if (!data) return 'No data captured for this tool.';
            try {
                switch (tool) {
                    case 'port':
                        return JSON.stringify({ open_ports: data.results || [], target: data.target }, null, 2);
                    case 'os':
                        return JSON.stringify(data, null, 2);
                    case 'webapp':
                        return JSON.stringify(data, null, 2);
                    case 'headers':
                    case 'ssl':
                    case 'dns':
                    case 'whois':
                    case 'ping':
                    case 'traceroute':
                    case 'subdomains':
                    case 'geo':
                        return JSON.stringify(data, null, 2);
                    default:
                        return JSON.stringify(data, null, 2);
                }
            } catch (e) {
                return 'Could not render data.';
            }
        }

        function showFullScanModal(tool, data) {
            const modal = document.getElementById('fullscanModal');
            const body = document.getElementById('fullscanModalBody');
            const title = document.getElementById('fullscanModalTitle');
            title.textContent = `Result — ${tool.toUpperCase()}`;
            body.textContent = renderFullScanData(tool, data);
            modal.style.display = 'flex';
        }

        function hideFullScanModal() {
            const modal = document.getElementById('fullscanModal');
            modal.style.display = 'none';
        }

        async function runFullTool(tool, fn, detailBuilder) {
            try {
                setFullScanStatus(tool, 'running', 'Running...');
                const data = await fn();
                const detail = detailBuilder ? detailBuilder(data) : 'Completed';
                setFullScanStatus(tool, 'success', detail);
                fullScanResults[tool] = data;
                appendFullScanLog(`${tool.toUpperCase()} done`);
                return data;
            } catch (err) {
                setFullScanStatus(tool, 'error', err.detail || err.message);
                appendFullScanLog(`${tool.toUpperCase()} error: ${err.message}`);
                return null;
            }
        }

        async function runFullScan() {
            if (fullScanRunning) return;
            let target = document.getElementById('fullTarget').value.trim();
            let url = document.getElementById('fullUrl').value.trim();

            if (!target && !url) {
                alert('Please enter a target host or URL');
                return;
            }

            if (!target && url) {
                try { target = new URL(url).hostname; }
                catch (e) { target = url.replace(/^https?:\/\//, '').split('/')[0]; }
            }
            if (!url && target) {
                url = target.startsWith('http') ? target : 'https://' + target;
            }

            const btn = document.getElementById('fullScanBtn');
            fullScanRunning = true;
            btn.textContent = 'Running...';
            btn.disabled = true;
            resetFullScanCards();
            appendFullScanLog('Starting full scan on ' + target);

            const portRange = document.getElementById('fullPortRange').value || 'common';
            const enhanced = document.getElementById('fullEnhanced').checked;

            const portPromise = (async () => {
                const scan = await api.scans.create(target, 'port', portRange, { enhanced_service_detection: enhanced, os_detection: true });
                appendFullScanLog('Port scan started (ID ' + scan.id + ')');
                const result = await pollFullScan(scan.id);
                const openCount = result.results?.length || 0;
                setFullScanStatus('port', 'success', `${openCount} open ports`);
                appendFullScanLog('Port scan completed with ' + openCount + ' open ports');
                fullScanResults['port'] = result;
                return result;
            })().catch(err => {
                setFullScanStatus('port', 'error', err.detail || err.message);
                appendFullScanLog('Port scan error: ' + err.message);
                fullScanResults['port'] = null;
                return null;
            });

            const osPromise = portPromise.then(res => {
                if (!res) throw new Error('Port scan unavailable');
                const osInfo = analyzeOsFromPorts(res.results || [], target);
                setFullScanStatus('os', 'success', `${osInfo.name} (${osInfo.accuracy})`);
                appendFullScanLog('OS fingerprint suggests ' + osInfo.name);
                fullScanResults['os'] = osInfo;
                return osInfo;
            }).catch(err => {
                setFullScanStatus('os', 'error', err.message);
                appendFullScanLog('OS fingerprint error: ' + err.message);
                fullScanResults['os'] = null;
                return null;
            });

            const dnsPromise = runFullTool('dns', () => api.tools.dns(target, 'ALL'), data => `${countDnsRecords(data)} records`);
            const whoisPromise = runFullTool('whois', () => api.tools.whois(target), data => data?.registrar ? `Registrar: ${data.registrar}` : 'Done');
            const pingPromise = runFullTool('ping', () => api.tools.ping(target, 4), data => data?.avg_ms != null ? `Avg ${data.avg_ms} ms` : 'Done');
            const traceroutePromise = runFullTool('traceroute', () => api.tools.traceroute(target, 20), data => data?.hops?.length ? `${data.hops.length} hops` : 'Done');
            const subdomainsPromise = runFullTool('subdomains', () => api.tools.subdomains(target, 'small'), data => `${data?.total_found || 0} found`);
            const geoPromise = runFullTool('geo', () => api.tools.geo(target), data => data?.country ? `${data.city || ''} ${data.country}`.trim() : 'Done');
            const headersPromise = runFullTool('headers', () => api.tools.headers(url), data => summarizeHeadersMissing(data.headers));
            const sslPromise = runFullTool('ssl', () => api.tools.ssl(target, url.startsWith('https') ? 443 : 80), data => {
                if (!data) return 'Error';
                if (data.status === 'failed' || data.status === 'ssl_error') return 'SSL error';
                const days = data.valid_to ? Math.ceil((new Date(data.valid_to) - new Date()) / 86400000) : null;
                return days != null ? `Expires in ${days}d` : 'Checked';
            });

            const webappPromise = Promise.all([headersPromise, sslPromise]).then(([headers, ssl]) => {
                const findings = buildWebappFindings(url, headers || {}, ssl || {});
                const score = findings.score;
                setFullScanStatus('webapp', 'success', `${findings.total} issues, score ${score}`);
                appendFullScanLog('Web app check finished: score ' + score);
                fullScanResults['webapp'] = findings;
                return findings;
            }).catch(err => {
                setFullScanStatus('webapp', 'error', err.message);
                appendFullScanLog('Web app check error: ' + err.message);
                fullScanResults['webapp'] = null;
                return null;
            });

            await Promise.allSettled([
                portPromise,
                osPromise,
                dnsPromise,
                whoisPromise,
                pingPromise,
                traceroutePromise,
                subdomainsPromise,
                geoPromise,
                headersPromise,
                sslPromise,
                webappPromise
            ]);

            appendFullScanLog('Full scan finished.');
            btn.textContent = 'Run Full Scan';
            btn.disabled = false;
            fullScanRunning = false;
        }

        // AI Chat
        let aiChatHistory = [];

        function handleAIChatKey(e) {
            if (e.key === 'Enter') sendAIChatMessage();
        }

        function clearAIChat() {
            document.getElementById('aiChatMessages').innerHTML = '<div class="chat-message ai">Chat cleared. How can I help you?</div>';
            aiChatHistory = [];
        }

        async function sendAIChatMessage() {
            const input = document.getElementById('aiChatInput');
            const text = input.value.trim();
            if (!text) return;

            const messages = document.getElementById('aiChatMessages');
            messages.innerHTML += '<div class="chat-message user">' + escapeHtml(text) + '</div>';
            aiChatHistory.push({ role: 'user', content: text });
            
            messages.innerHTML += '<div class="chat-message ai"><div class="typing-indicator"><div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div></div></div>';
            messages.scrollTop = messages.scrollHeight;
            input.value = '';

            try {
                const response = await fetch('/api/ai/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message: text,
                        conversation_history: aiChatHistory.slice(0, -1)
                    })
                });

                if (!response.ok) throw new Error('AI request failed');

                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let fullResponse = '';

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    const chunk = decoder.decode(value, { stream: true });
                    const lines = chunk.split('\n\n');
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            const data = line.slice(6);
                            if (data && data !== '[DONE]') {
                                fullResponse += data;
                            }
                        }
                    }
                }

                const lastMsg = messages.querySelector('.chat-message.ai:last-child');
                if (lastMsg) {
                    lastMsg.innerHTML = fullResponse || 'I apologize, but I could not generate a response.';
                }
                aiChatHistory.push({ role: 'assistant', content: fullResponse });
            } catch (error) {
                const lastMsg = messages.querySelector('.chat-message.ai:last-child');
                if (lastMsg) {
                    lastMsg.innerHTML = 'Error: ' + error.message + '. Make sure the Groq API key is configured.';
                }
            }
        }

        // Scan History
        async function loadScanHistory() {
            const tbody = document.getElementById('history-tbody');
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;"><i class="fa-solid fa-circle-notch fa-spin"></i> Loading...</td></tr>';

            try {
                const data = await api.scans.list(1);
                renderHistory(data.scans || []);
            } catch (error) {
                tbody.innerHTML = '<tr><td colspan="6" class="alert alert-error">' + error.message + '</td></tr>';
            }
        }

        function renderHistory(scans) {
            const tbody = document.getElementById('history-tbody');

            if (!scans || scans.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No scans found</td></tr>';
                return;
            }

            tbody.innerHTML = scans.map(scan => {
                const statusClass = scan.status === 'completed' ? 'badge-green' : scan.status === 'running' ? 'badge-info' : scan.status === 'failed' ? 'badge-critical' : 'badge-medium';
                return '<tr>' +
                    '<td><strong>' + scan.target + '</strong></td>' +
                    '<td><span class="badge badge-info">' + (scan.scan_type || 'port') + '</span></td>' +
                    '<td><span class="badge ' + statusClass + '">' + scan.status + '</span></td>' +
                    '<td>' + (scan.results?.length || 0) + '</td>' +
                    '<td>' + new Date(scan.created_at).toLocaleDateString() + '</td>' +
                    '<td><button class="btn-secondary" onclick="viewScanHistory(\'' + scan.id + '\')"><i class="fa-solid fa-eye"></i></button></td>' +
                    '</tr>';
            }).join('');
        }

        function viewScanHistory(scanId) {
            switchView('portScanner');
            // Load scan results into port scanner
        }

        // Toast notification
        function showToast(message) {
            const toast = document.createElement('div');
            toast.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#1a1b26;color:#fff;padding:12px 24px;border-radius:8px;z-index:9999;animation:fadeIn 0.3s';
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => {
                toast.style.animation = 'fadeOut 0.3s';
                setTimeout(() => toast.remove(), 300);
            }, 2000);
        }

        // Load history on view switch
        const originalSwitchView = switchView;
        switchView = function(viewId) {
            document.querySelectorAll('.view-section').forEach(s => s.classList.remove('active'));
            document.getElementById(viewId + 'View').classList.add('active');
            document.querySelectorAll('.nav-menu a').forEach(l => l.classList.remove('active'));
            const navMap = { portScanner: null, osFingerprint: null, webAppScanner: null, fullScan: 'FullScan', tools: 'Tools', ai: 'AI', history: 'History' };
            const navEl = document.getElementById('nav' + navMap[viewId]);
            if (navEl) navEl.classList.add('active');
        
            if (viewId === 'history') {
            loadScanHistory();
            }
        };

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            loadScanHistory();
            
            // Add event listeners for tool buttons
            const portscannerBtn = document.getElementById('portscanner-run-btn');
            if (portscannerBtn) {
                portscannerBtn.addEventListener('click', () => runTool('portscanner'));
            }
            
            // Hook card clicks to show per-tool detail
            document.querySelectorAll('#fullscanGrid .fullscan-card').forEach(card => {
                card.addEventListener('click', () => {
                    const tool = card.dataset.tool;
                    if (!tool) return;
                    showFullScanModal(tool, fullScanResults[tool]);
                });
            });
            // Port detail modal handlers
            const portModal = document.getElementById('portDetailModal');
            if (portModal) {
                portModal.addEventListener('click', function(e) {
                    if (e.target === this) {
                        hidePortDetailModal();
                    }
                });
            }
            // Port item click handler
            document.addEventListener('click', function(e) {
                const portItem = e.target.closest('.port-item');
                if (portItem && portItem.dataset.portIndex !== undefined && window.portDetailCache) {
                    const portData = window.portDetailCache[portItem.dataset.portIndex];
                    if (portData) {
                        showPortDetail(portData);
                    }
                }
            });
});

})();