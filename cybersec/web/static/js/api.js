const API_BASE = window.location.origin;

class ApiError extends Error {
  constructor(message, detail) {
    super(message);
    this.detail = detail;
  }
}

const api = {
  token: null,

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

      const response = await fetch(`${API_BASE}/auth/token`, {
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
      this.token = data.access_token;
      localStorage.setItem('cybersec_token', data.access_token);
      return data;
    },

    async register(email, password) {
      return this.request('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
    },

    logout() {
      this.token = null;
      localStorage.removeItem('cybersec_token');
    },

    restoreSession() {
      this.token = localStorage.getItem('cybersec_token');
      return !!this.token;
    },
  },

  scans: {
    async create(target, scanType, portRange, options = {}) {
      return this.request('/scans/', {
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
      return this.request(`/scans/${scanId}`);
    },

    async getStatus(scanId) {
      return this.request(`/scans/${scanId}/status`);
    },

    async list(page = 1, status = null) {
      const params = new URLSearchParams({ page, page_size: 20 });
      if (status) params.append('status_filter', status);
      return this.request(`/scans/?${params}`);
    },

    async delete(scanId) {
      return this.request(`/scans/${scanId}`, { method: 'DELETE' });
    },

    async export(scanId, format) {
      const response = await fetch(`${API_BASE}/reports/scan/${scanId}/${format}`, {
        headers: {
          'Authorization': `Bearer ${this.token}`,
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
    async dns(target, recordType = 'A') {
      return this.request('/tools/dns', {
        method: 'POST',
        body: JSON.stringify({ target, record_type: recordType }),
      });
    },

    async whois(target) {
      return this.request('/tools/whois', {
        method: 'POST',
        body: JSON.stringify({ target }),
      });
    },

    async ping(target, count = 4) {
      return this.request('/tools/ping', {
        method: 'POST',
        body: JSON.stringify({ target, count }),
      });
    },

    async traceroute(target, maxHops = 30) {
      return this.request('/tools/traceroute', {
        method: 'POST',
        body: JSON.stringify({ target, max_hops: maxHops }),
      });
    },

    async ssl(host, port = 443) {
      return this.request('/tools/ssl', {
        method: 'POST',
        body: JSON.stringify({ host, port }),
      });
    },

    async headers(url) {
      return this.request('/tools/http_headers', {
        method: 'POST',
        body: JSON.stringify({ target: url }),
      });
    },

    async subdomains(domain, wordlistSize = 'small') {
      return this.request('/tools/subdomain', {
        method: 'POST',
        body: JSON.stringify({ domain, wordlist: wordlistSize }),
      });
    },

    async geo(ip) {
      return this.request('/tools/geoip', {
        method: 'POST',
        body: JSON.stringify({ target: ip }),
      });
    },
  },

  async streamChat(message, scanId = null, toolName = null, toolResultId = null, history = []) {
    const response = await fetch(`${API_BASE}/ai/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`,
      },
      body: JSON.stringify({
        message,
        scan_id: scanId,
        tool_name: toolName,
        tool_result_id: toolResultId,
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

window.api = api;
