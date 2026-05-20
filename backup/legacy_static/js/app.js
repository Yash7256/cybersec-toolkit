const app = {
  currentTab: 'dashboard',
  toolResults: {},
  scanResults: {},

  init() {
    this.setupNavigation();
    this.setupToolButtons();
    this.setupToolActions();
    this.restoreSession();
  },

  setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
      item.addEventListener('click', () => {
        const tab = item.dataset.tab;
        this.switchTab(tab);
      });
    });
  },

  switchTab(tabId) {
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.tab === tabId);
    });

    document.querySelectorAll('.tab-panel').forEach(panel => {
      panel.classList.toggle('active', panel.id === `panel-${tabId}`);
    });

    this.currentTab = tabId;

    if (tabId === 'history') {
      window.historyModule?.loadHistory();
    }
  },

  setupToolButtons() {
    document.querySelectorAll('[data-tool]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tool = btn.dataset.tool;
        await this.runTool(tool);
      });
    });

    const scannerBtn = document.getElementById('run-scan-btn');
    if (scannerBtn) {
      scannerBtn.addEventListener('click', () => window.scannerModule?.runScan());
    }

    const webscannerBtn = document.getElementById('run-webscan-btn');
    if (webscannerBtn) {
      webscannerBtn.addEventListener('click', () => {
        const target = document.getElementById('webscanner-target').value;
        window.toolsModule?.runTool('webscan', { target });
      });
    }
  },

  setupToolActions() {
    document.querySelectorAll('.tool-actions').forEach(container => {
      container.querySelectorAll('[data-action]').forEach(btn => {
        btn.addEventListener('click', () => {
          const action = btn.dataset.action;
          const tool = container.id.replace('-actions', '');
          this.handleToolAction(action, tool);
        });
      });
    });
  },

  handleToolAction(action, tool) {
    const result = this.toolResults[tool];
    if (!result) return;

    switch (action) {
      case 'copy':
        this.copyToClipboard(JSON.stringify(result, null, 2));
        break;
      case 'send-to-ai':
        this.sendToAI(tool, result);
        break;
      case 'export-json':
        this.downloadJSON(result, `tool_${tool}_result.json`);
        break;
    }
  },

  copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
      this.showToast('Copied to clipboard');
    }).catch(err => {
      console.error('Failed to copy:', err);
    });
  },

  downloadJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  },

  sendToAI(tool, result) {
    const summary = this.summarizeToolResult(tool, result);
    window.aiModule?.sendMessage(`Analyse these ${tool} results: ${summary}`);
    this.switchTab('dashboard');
    setTimeout(() => {
      document.querySelector('.ai-input')?.focus();
    }, 100);
  },

  summarizeToolResult(tool, result) {
    switch (tool) {
      case 'dns':
        const records = result.records || [];
        return `${result.target}: ${result.record_type} records - ${records.join(', ') || 'No records'}`;
      case 'ssl':
        return `${result.target}: ${result.protocol_version || 'Unknown'} using ${result.cipher || 'Unknown cipher'}`;
      case 'geo':
        return `${result.ip || result.target}: ${result.city || 'Unknown'}, ${result.country || 'Unknown'}`;
      case 'whois':
        return `Domain ${result.target}: registered by ${result.registrar || 'Unknown'}`;
      default:
        return JSON.stringify(result).substring(0, 200);
    }
  },

  showLoading(tool) {
    const output = document.getElementById(`${tool}-output`);
    if (output) {
      output.innerHTML = `<div class="loading-spinner"><div class="spinner"></div>Running...</div>`;
    }
    const actions = document.getElementById(`${tool}-actions`);
    if (actions) actions.style.display = 'none';
  },

  showError(tool, message) {
    const output = document.getElementById(`${tool}-output`);
    if (output) {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${message}</div>`;
    }
  },

  showResult(tool, html) {
    const output = document.getElementById(`${tool}-output`);
    if (output) {
      output.innerHTML = html;
    }
    const actions = document.getElementById(`${tool}-actions`);
    if (actions) actions.style.display = 'flex';
  },

  async runTool(tool) {
    let result, params = {};

    switch (tool) {
      case 'portscanner':
        params.target = document.getElementById('portscanner-target')?.value;
        params.portRange = document.getElementById('port-range')?.value || 'quick';
        break;
            case 'webscan':
        params.target = document.getElementById('webscan-target')?.value;
        params.maxPages = parseInt(document.getElementById('webscan-maxpages')?.value) || 20;
        break;
      case 'dns':
        params.target = document.getElementById('dns-target')?.value;
        params.recordType = document.getElementById('dns-record-type')?.value || 'A';
        break;
      case 'whois':
        params.target = document.getElementById('whois-target')?.value;
        break;
      case 'ping':
        params.target = document.getElementById('ping-target')?.value;
        params.count = parseInt(document.getElementById('ping-count')?.value) || 4;
        break;
      case 'traceroute':
        params.target = document.getElementById('traceroute-target')?.value;
        params.maxHops = parseInt(document.getElementById('traceroute-hops')?.value) || 30;
        break;
      case 'ssl':
        params.host = document.getElementById('ssl-host')?.value;
        params.port = parseInt(document.getElementById('ssl-port')?.value) || 443;
        break;
      case 'headers':
        params.url = document.getElementById('headers-url')?.value;
        break;
      case 'subdomains':
        params.domain = document.getElementById('subdomains-domain')?.value;
        params.wordlistSize = document.getElementById('subdomains-wordlist')?.value || 'small';
        break;
      case 'geo':
        params.ip = document.getElementById('geo-ip')?.value;
        break;
    }

    if (!params.target && !params.host && !params.url && !params.domain && !params.ip) {
      this.showError(tool, 'Please enter a target value');
      return;
    }

    // For portscanner we show loading in its own box and return if missing target handled above.
    this.showLoading(tool);

    try {
      switch (tool) {
        case 'portscanner': result = await api.tools.portscanner(params.target, params.portRange, params.scanType); break;
                case 'webscan': result = await api.tools.webscan(params.target, params.maxPages); break;
        case 'dns': result = await api.tools.dns(params.target, params.recordType); break;
        case 'whois': result = await api.tools.whois(params.target); break;
        case 'ping': result = await api.tools.ping(params.target, params.count); break;
        case 'traceroute': result = await api.tools.traceroute(params.target, params.maxHops); break;
        case 'ssl': result = await api.tools.ssl(params.host, params.port); break;
        case 'headers': result = await api.tools.headers(params.url); break;
        case 'subdomains': result = await api.tools.subdomains(params.domain, params.wordlistSize); break;
        case 'geo': result = await api.tools.geo(params.ip); break;
      }

      this.toolResults[tool] = result;
      window.toolsModule?.renderResult(tool, result);
    } catch (error) {
      this.showError(tool, error.message);
    }
  },

  restoreSession() {
    api.auth.restoreSession();
  },

  showToast(message, duration = 2000) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    toast.style.cssText = `
      position: fixed;
      bottom: 20px;
      left: 50%;
      transform: translateX(-50%);
      background: var(--bg-secondary);
      color: var(--text-primary);
      padding: 12px 24px;
      border-radius: 6px;
      border: 1px solid var(--border-default);
      z-index: 9999;
      animation: fadeIn 0.3s ease;
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.style.animation = 'fadeOut 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  },
};

document.addEventListener('DOMContentLoaded', () => app.init());
