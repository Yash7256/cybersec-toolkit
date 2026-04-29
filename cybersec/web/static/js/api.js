const API_BASE = window.location.origin;

class ApiError extends Error {
  constructor(message, detail) {
    super(message);
    this.detail = detail;
  }
}

const api = {
  token: null,
  _withTimeout(promise, ms, message = 'Request timed out') {
    return Promise.race([
      promise,
      new Promise((_, reject) => setTimeout(() => reject(new ApiError(message, message)), ms))
    ]);
  },

  async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      if (!response.ok) {
        let errorDetail = 'Request failed';
        try {
          const errorData = await response.json();
          errorDetail = errorData.detail || errorDetail;
        } catch (e) {
          errorDetail = `HTTP ${response.status}`;
        }
        throw new ApiError(errorDetail, errorDetail);
      }

      if (response.status === 204) {
        return null;
      }

      return await response.json();
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      throw new ApiError('Network error', error.message);
    }
  },

  auth: {
    async login(email, password) {
      const formData = new URLSearchParams();
      formData.append('username', email);
      formData.append('password', password);

      const response = await fetch(`${API_BASE}/api/auth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new ApiError('Login failed', errorData.detail || 'Invalid credentials');
      }

      const data = await response.json();
      api.token = data.access_token;
      localStorage.setItem('cybersec_token', data.access_token);
      return data;
    },

    async register(email, password) {
      return api.request('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
    },

    logout() {
      api.token = null;
      localStorage.removeItem('cybersec_token');
    },

    restoreSession() {
      api.token = localStorage.getItem('cybersec_token');
      return !!api.token;
    },
  },

  scans: {
    async create(target, scanType, portRange, options = {}) {
      return api.request('/api/scans/', {
        method: 'POST',
        body: JSON.stringify({
          target,
          scan_type: scanType,
          port_range: portRange,
          options,
        }),
      });
    },

    async get(scanId) {
      const data = await api.request(`/api/scans/${scanId}`);
      // Normalize shape so UI code can access both `scan` and top-level fields.
      return {
        ...data,
        scan: data.scan || data,
        results: data.results || data.data || [],
      };
    },

    async getStatus(scanId) {
      return api.request(`/api/scans/${scanId}/status`);
    },

    async list(page = 1, status = null) {
      // Backend accepts `limit`; keep `page` for future pagination compatibility.
      const params = new URLSearchParams({ limit: 20, page });
      if (status) params.append('status_filter', status);
      const data = await api.request(`/api/scans/?${params}`);
      if (Array.isArray(data)) {
        return { scans: data, total: data.length };
      }
      return {
        scans: data.scans || [],
        total: data.total ?? (data.scans ? data.scans.length : 0),
      };
    },

    async delete(scanId) {
      return api.request(`/api/scans/${scanId}`, { method: 'DELETE' });
    },

    async export(scanId, format) {
      const response = await fetch(`${API_BASE}/api/reports/scan/${scanId}/${format}`, {
        headers: {
          'Authorization': `Bearer ${api.token}`,
        },
      });

      if (!response.ok) {
        throw new ApiError('Export failed', `HTTP ${response.status}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan_${scanId}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    },
  },

  tools: {
    async portscanner(target, portRange = 'common', scanType = 'port') {
      const scan = await api.request('/api/scans/', {
        method: 'POST',
        body: JSON.stringify({
          target,
          scan_type: scanType,
          port_range: portRange,
        }),
      });
      // poll status & results
      const scanId = scan.id || scan.scan_id;
      let attempts = 0;
      while (attempts < 120) {
        const status = await api.scans.get(scanId);
        if (status.status === 'completed') return { ...status, target };
        if (status.status === 'failed') throw new ApiError('Scan failed', status.error || 'Scan failed');
        await new Promise(r => setTimeout(r, 1500));
        attempts += 1;
      }
      throw new ApiError('Timeout', 'Port scan timed out');
    },

    
    async webscan(target, maxPages = 20) {
      return api.request('/api/webapp/scan', {
        method: 'POST',
        body: JSON.stringify({ target, max_pages: maxPages }),
      });
    },

    async webscanStream(target, maxPages = 20, callbacks = {}) {
      return new Promise(async (resolve, reject) => {
        try {
          const scanResponse = await api.request('/api/webapp/start-scan', {
            method: 'POST',
            body: JSON.stringify({ target, max_pages: maxPages }),
          });
          
          const scanId = scanResponse.scan_id;
          const es = new EventSource(`/api/webapp/stream/${scanId}`);
          let finalResult = null;
          let isDone = false;
          
          es.onmessage = (evt) => {
            if (evt.data === '[DONE]') {
              isDone = true;
              es.close();
              if (finalResult) {
                resolve(finalResult);
              } else {
                resolve({ result: null });
              }
              return;
            }
            
            try {
              const data = JSON.parse(evt.data);
              if (data.stage === 'DONE' && data.result) {
                finalResult = data.result;
              }
              if (callbacks.onProgress) callbacks.onProgress(data);
            } catch (e) {
              console.error('Webscan stream parse error:', e);
            }
          };
          
          es.onerror = (err) => {
            if (!isDone) {
              es.close();
              if (finalResult) {
                resolve(finalResult);
              } else {
                reject(new Error('Webscan stream connection error'));
              }
            }
          };
        } catch (err) {
          reject(err);
        }
      });
    },
    async dns(target, recordType = 'A') {
      const resp = await api.request('/api/tools/dns', {
        method: 'POST',
        body: JSON.stringify({ target, record_type: recordType }),
      });
      return { tool_result_id: resp.tool_result_id, ...(resp.data || resp) };
    },

    async whois(target) {
      const resp = await api.request('/api/tools/whois', {
        method: 'POST',
        body: JSON.stringify({ target }),
      });
      return { tool_result_id: resp.tool_result_id, ...(resp.data || resp) };
    },

    async ping(target, count = 4) {
      const resp = await api.request('/api/tools/ping', {
        method: 'POST',
        body: JSON.stringify({ target, count }),
      });
      return { tool_result_id: resp.tool_result_id, ...(resp.data || resp) };
    },

    async traceroute(target, maxHops = 30) {
      const resp = await api.request('/api/tools/traceroute', {
        method: 'POST',
        body: JSON.stringify({ target, max_hops: maxHops }),
      });
      return { tool_result_id: resp.tool_result_id, ...(resp.data || resp) };
    },

    async ssl(host, port = 443) {
      const resp = await api.request('/api/tools/ssl', {
        method: 'POST',
        body: JSON.stringify({ host, port }),
      });
      return { tool_result_id: resp.tool_result_id, ...(resp.data || resp) };
    },

    async headers(url) {
      const resp = await api.request('/api/tools/http_headers', {
        method: 'POST',
        body: JSON.stringify({ target: url }),
      });
      return { tool_result_id: resp.tool_result_id, ...(resp.data || resp) };
    },

    async subdomains(domain, wordlistSize = 'small') {
      const resp = await api.request('/api/tools/subdomain', {
        method: 'POST',
        body: JSON.stringify({ domain, wordlist: wordlistSize }),
      });
      return { tool_result_id: resp.tool_result_id, ...(resp.data || resp) };
    },

    async geo(ip) {
      const resp = await api.request('/api/tools/geoip', {
        method: 'POST',
        body: JSON.stringify({ target: ip }),
      });
      return { tool_result_id: resp.tool_result_id, ...(resp.data || resp) };
    },
  },

  async streamChat(message, scanId = null, toolName = null, toolResultId = null, toolResultIds = null, history = []) {
    const response = await fetch(`${API_BASE}/api/ai/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${api.token}`,
      },
      body: JSON.stringify({
        message,
        scan_id: scanId,
        tool_name: toolName,
        tool_result_id: toolResultId,
        tool_result_ids: toolResultIds,
        conversation_history: history,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new ApiError('AI request failed', errorData.detail || 'AI service unavailable');
    }

    return response.body;
  },
};

// Ensure request always has correct context even if extracted
api.request = api.request.bind(api);
window.api = api;
