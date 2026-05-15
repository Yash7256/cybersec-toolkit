const scannerModule = {
  currentScanId: null,
  pollInterval: null,
  cancelled: false,

  async runScan() {
    const target = document.getElementById('portscanner-target')?.value;
    const scanType = document.getElementById('scanner-type')?.value || 'port';
    const portRange = document.getElementById('port-range')?.value || 'quick';

    if (!target) {
      app.showError('scanner', 'Please enter a target');
      return;
    }

    const runBtn = document.getElementById('run-scan-btn');
    runBtn.disabled = true;
    runBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';
    this.cancelled = false;

    document.getElementById('cancel-scan-btn').style.display = 'inline-block';
    document.getElementById('scan-progress').style.display = 'block';
    document.getElementById('scan-progress-fill').style.width = '0%';
    document.getElementById('scan-status-text').textContent = 'Creating scan...';
    document.getElementById('scan-ports-found').textContent = '0 ports found';
    document.getElementById('scanner-output').innerHTML = '<div class="loading-spinner"><div class="spinner"></div>Initializing scan...</div>';
    document.getElementById('scanner-actions').style.display = 'none';

    try {
      const scan = await api.scans.create(target, scanType, portRange);
      this.currentScanId = scan.id;
      this.startPolling();
    } catch (error) {
      app.showError('scanner', error.message);
      this.resetScanButton();
    }
  },

  async cancelScan() {
    if (!this.currentScanId) return;
    this.cancelled = true;
    try {
      await api.scans.delete(this.currentScanId);
      document.getElementById('scan-status-text').textContent = 'Cancelling...';
    } catch (e) {
      console.error('Cancel failed:', e);
    }
  },

  startPolling() {
    this.pollInterval = setInterval(() => this.checkStatus(), 2000);
    this.checkStatus();
  },

  stopPolling() {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  },

  async checkStatus() {
    if (!this.currentScanId) return;

    try {
      const status = await api.scans.getStatus(this.currentScanId);
      this.updateProgress(status);

      if (['completed', 'failed', 'cancelled', 'timed_out'].includes(status.status)) {
        this.stopPolling();
        this.fetchResults();
      }
    } catch (error) {
      console.error('Status check failed:', error);
    }
  },

  updateProgress(status) {
    const progressFill = document.getElementById('scan-progress-fill');
    const statusText = document.getElementById('scan-status-text');
    const portsFound = document.getElementById('scan-ports-found');

    let progress = 0;
    switch (status.status) {
      case 'queued':
      case 'pending':
        progress = 5;
        statusText.textContent = 'Waiting in queue...';
        break;
      case 'running':
        progress = status.progress_pct || 50;
        statusText.textContent = 'Scanning...';
        break;
      case 'completed':
        progress = 100;
        statusText.textContent = 'Scan complete!';
        break;
      case 'failed':
        progress = 100;
        statusText.textContent = 'Scan failed: ' + (status.error || 'unknown error');
        break;
      case 'cancelled':
        progress = 100;
        statusText.textContent = 'Scan cancelled';
        break;
      case 'timed_out':
        progress = 100;
        statusText.textContent = 'Scan timed out (worker lost)';
        break;
    }

    progressFill.style.width = `${progress}%`;
    portsFound.textContent = `${status.open_ports_found || 0} ports found`;
  },

  async fetchResults() {
    if (!this.currentScanId) return;

    try {
      const data = await api.scans.get(this.currentScanId);
      this.displayResults(data);
    } catch (error) {
      app.showError('scanner', 'Failed to fetch results: ' + error.message);
    } finally {
      this.resetScanButton();
    }
  },

  displayResults(data) {
    const scan = data.scan || data;
    const results = data.results || [];
    const output = document.getElementById('scanner-output');
    const targetLabel = scan.target || 'target';

    if (!results || results.length === 0) {
      output.innerHTML = `<div class="alert alert-success">No open ports found on ${targetLabel}</div>`;
      document.getElementById('scanner-actions').style.display = 'flex';
      return;
    }

    const openPorts = results.filter(r => r.state === 'open');
    const tableRows = openPorts.map(port => {
      const cves = port.cves || [];
      const topCve = cves.length > 0 ? cves[0] : null;
      const riskScore = port.risk_score || 0;
      const riskClass = riskScore >= 0.8 ? 'critical' : riskScore >= 0.6 ? 'high' : riskScore >= 0.3 ? 'medium' : 'low';

      return `
        <tr>
          <td><strong>${port.port}</strong></td>
          <td>${port.protocol || 'tcp'}</td>
          <td><span class="badge badge-${port.state === 'open' ? 'low' : 'info'}">${port.state}</span></td>
          <td>${port.service || 'unknown'}</td>
          <td>${port.version || '-'}</td>
          <td><span class="badge badge-${riskClass}">${(riskScore * 100).toFixed(0)}%</span></td>
          <td>${topCve ? `<code>${topCve.id}</code>` : '-'}</td>
        </tr>
      `;
    }).join('');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">Scan Summary: ${targetLabel}</div>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">Open Ports</div>
            <div class="stat-value">${openPorts.length}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Closed/Filtered</div>
            <div class="stat-value">${results.length - openPorts.length}</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Services</div>
            <div class="stat-value">${new Set(openPorts.map(p => p.service)).size}</div>
          </div>
        </div>
      </div>
      <div class="result-section">
        <div class="table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>State</th>
                <th>Service</th>
                <th>Version</th>
                <th>Risk</th>
                <th>Top CVE</th>
              </tr>
            </thead>
            <tbody>${tableRows}</tbody>
          </table>
        </div>
      </div>
    `;

    document.getElementById('scanner-actions').style.display = 'flex';
    app.scanResults[this.currentScanId] = { scan, results };
  },

  resetScanButton() {
    const runBtn = document.getElementById('run-scan-btn');
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.innerHTML = '<i class="fa-solid fa-play"></i> Start Scan';
    }
    document.getElementById('cancel-scan-btn').style.display = 'none';
  },

  copyResults() {
    if (!this.currentScanId || !app.scanResults[this.currentScanId]) return;
    const data = app.scanResults[this.currentScanId];
    app.copyToClipboard(JSON.stringify(data, null, 2));
  },

  sendToAI() {
    if (!this.currentScanId || !app.scanResults[this.currentScanId]) return;
    const data = app.scanResults[this.currentScanId];
    const target = data.scan?.target || 'target';
    const openCount = data.results?.filter(r => r.state === 'open').length || 0;
    window.aiModule?.sendMessage(`Analyse this port scan: ${target} has ${openCount} open ports.`, this.currentScanId);
  },

  exportResults(format) {
    if (!this.currentScanId) return;
    api.scans.export(this.currentScanId, format);
  },
};

window.scannerModule = scannerModule;
