const toolsModule = {
  renderResult(tool, data) {
    switch (tool) {
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
      case 'webscan':
        this.renderWebscan(data);
        break;
    }
  },

    renderDNS(data) {
    const output = document.getElementById('dns-output');
    if (data.error) {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error}</div>`;
      return;
    }

    const allRecords = [
      ...(data.a_records || []).map(r => ({ type: 'A', value: r })),
      ...(data.aaaa_records || []).map(r => ({ type: 'AAAA', value: r })),
      ...(data.mx_records || []).map(r => ({ type: 'MX', value: r })),
      ...(data.ns_records || []).map(r => ({ type: 'NS', value: r })),
      ...(data.txt_records || []).map(r => ({ type: 'TXT', value: r })),
      ...(data.cname_records || []).map(r => ({ type: 'CNAME', value: r })),
      ...(data.soa_record ? [{ type: 'SOA', value: data.soa_record }] : []),
    ];

    if (allRecords.length === 0) {
      output.innerHTML = `<div class="alert alert-warning">No DNS records found for ${data.target}</div>`;
      return;
    }

    const rows = allRecords.map(r => `<tr><td>${r.type}</td><td><code>${r.value}</code></td></tr>`).join('');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">DNS Records for ${data.target}</div>
        <div class="table-container">
          <table class="data-table">
            <thead><tr><th>Type</th><th>Value</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div class="result-item" style="margin-top: 12px;">
          <span class="result-key">Query Time</span>
          <span class="result-value">${data.query_time_ms ? data.query_time_ms.toFixed(2) + ' ms' : 'N/A'}</span>
        </div>
      </div>
    `;
  },

  renderWhois(data) {
    const output = document.getElementById('whois-output');
    if (data.status === 'failed') {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error}</div>`;
      return;
    }

    const fields = [
      { key: 'Domain Name', value: data.domain_name },
      { key: 'Registrar', value: data.registrar },
      { key: 'Created', value: data.creation_date },
      { key: 'Expires', value: data.expiration_date },
      { key: 'Name Servers', value: Array.isArray(data.name_servers) ? data.name_servers.join('<br>') : data.name_servers },
    ].filter(f => f.value);

    const rows = fields.map(f => `
      <div class="result-item">
        <span class="result-key">${f.key}</span>
        <span class="result-value">${f.value}</span>
      </div>
    `).join('');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">WHOIS Information: ${data.target}</div>
        <div class="result-grid">${rows}</div>
      </div>
    `;
  },

  renderPing(data) {
    const output = document.getElementById('ping-output');
    if (data.status === 'failed') {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error}</div>`;
      return;
    }

    const lossStr = data.packet_loss || '0%';
    const lossClass = lossStr.includes('100%') ? 'critical' : lossStr.includes('%') && parseInt(lossStr) > 0 ? 'medium' : 'low';

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">Ping Results: ${data.target}</div>
        <div class="ping-stats">
          <div class="ping-stat">
            <div class="ping-stat-value">${data.min_ms ?? '-'}</div>
            <div class="ping-stat-label">Min (ms)</div>
          </div>
          <div class="ping-stat">
            <div class="ping-stat-value">${data.avg_ms ?? '-'}</div>
            <div class="ping-stat-label">Avg (ms)</div>
          </div>
          <div class="ping-stat">
            <div class="ping-stat-value">${data.max_ms ?? '-'}</div>
            <div class="ping-stat-label">Max (ms)</div>
          </div>
          <div class="ping-stat">
            <div class="ping-stat-value" style="color: var(--accent-${lossClass === 'critical' ? 'red' : 'green'})">${lossStr}</div>
            <div class="ping-stat-label">Loss</div>
          </div>
        </div>
        <pre class="raw-output">${data.raw_output || ''}</pre>
      </div>
    `;
  },

  renderTraceroute(data) {
    const output = document.getElementById('traceroute-output');
    if (data.status === 'failed') {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error}</div>`;
      return;
    }

    const hops = data.hops || [];
    const hopRows = hops.map(h => `
      <div class="traceroute-hop">
        <div class="hop-number">${h.hop_number}</div>
        <div class="hop-address">${h.ip || '* * *'}</div>
        <div class="hop-rtt">${h.rtt_ms != null ? h.rtt_ms + ' ms' : '-'}</div>
      </div>
    `).join('');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">Traceroute to ${data.target}</div>
        ${hopRows || '<div class="alert alert-warning">No hops recorded</div>'}
      </div>
    `;
  },

  renderSSL(data) {
    const output = document.getElementById('ssl-output');
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
        ${isOldProtocol ? '<div class="alert alert-warning"><i class="fa-solid fa-exclamation-triangle"></i> Older TLS version detected. Consider upgrading to TLS 1.2 or higher.</div>' : ''}
      </div>
    `;
  },

  renderHeaders(data) {
    const output = document.getElementById('headers-output');
    if (data.status === 'failed' || data.status === 'timeout') {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error || 'Connection failed'}</div>`;
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

    const headerItems = Object.entries(securityHeaders).map(([header, name]) => {
      const found = Object.keys(headers).find(h => h.toLowerCase() === header);
      if (found) {
        return `<li class="present"><span class="check-icon"><i class="fa-solid fa-check"></i></span><span class="header-name">${name}</span><span class="header-value">${headers[found]}</span></li>`;
      }
      return `<li class="missing"><span class="check-icon"><i class="fa-solid fa-times"></i></span><span class="header-name">${name}</span></li>`;
    }).join('');

    const otherHeaders = Object.entries(headers)
      .filter(([k]) => !Object.keys(securityHeaders).includes(k.toLowerCase()))
      .map(([k, v]) => `<tr><td><code>${k}</code></td><td><code>${v}</code></td></tr>`)
      .join('');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">HTTP Headers: ${data.url}</div>
        <div class="result-item" style="margin-bottom: 16px;">
          <span class="result-key">Status Code</span>
          <span class="result-value badge badge-${data.status_code === 200 ? 'low' : 'medium'}">${data.status_code || 'Unknown'}</span>
        </div>
        <div class="result-title" style="font-size: 1rem; margin-top: 20px;">Security Headers</div>
        <ul class="headers-checklist">${headerItems}</ul>
        ${otherHeaders ? `
          <div class="result-title" style="font-size: 1rem; margin-top: 20px;">Other Headers</div>
          <div class="table-container">
            <table class="data-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>${otherHeaders}</tbody></table>
          </div>
        ` : ''}
      </div>
    `;
  },

  renderSubdomains(data) {
    const output = document.getElementById('subdomains-output');
    const subdomains = data.subdomains_found || [];
    const rows = subdomains.map(s => `<tr><td><code>${s}</code></td></tr>`).join('');

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">Subdomains for ${data.domain}</div>
        <div class="stat-card" style="margin-bottom: 16px;">
          <div class="stat-label">Total Found</div>
          <div class="stat-value">${data.total_found || 0}</div>
        </div>
        ${subdomains.length > 0 ? `
          <div class="table-container">
            <table class="data-table">
              <thead><tr><th>Subdomain</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        ` : '<div class="alert alert-warning">No subdomains found</div>'}
      </div>
    `;
  },

  renderGeo(data) {
    const output = document.getElementById('geo-output');
    if (data.status === 'failed') {
      output.innerHTML = `<div class="alert alert-error"><i class="fa-solid fa-circle-exclamation"></i> ${data.error}</div>`;
      return;
    }

    const flag = this.getFlagEmoji(data.country_code);

    output.innerHTML = `
      <div class="result-section">
        <div class="result-title">Geolocation: ${data.ip || data.target}</div>
        <div class="geo-card">
          <div class="geo-flag">${flag}</div>
          <div class="geo-info">
            <h4>${data.city || 'Unknown'}, ${data.country || 'Unknown'}</h4>
            <p><span class="label">Region:</span> ${data.region || 'Unknown'}</p>
            <p><span class="label">ISP:</span> ${data.isp || 'Unknown'}</p>
            <p><span class="label">Organization:</span> ${data.org || 'Unknown'}</p>
            <p><span class="label">Coordinates:</span> ${data.lat || '?'}, ${data.lon || '?'}</p>
            <p><span class="label">Timezone:</span> ${data.timezone || 'Unknown'}</p>
            <p><span class="label">ASN:</span> ${data.asn || 'Unknown'}</p>
          </div>
        </div>
      </div>
    `;
  },

  getFlagEmoji(countryCode) {
    if (!countryCode) return '';
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map(char => 127397 + char.charCodeAt());
    return String.fromCodePoint(...codePoints);
  },

  renderWebscan(data) {
    const output = document.getElementById('webscanner-output');
    output.innerHTML = `<pre class="raw-output">${JSON.stringify(data, null, 2)}</pre>`;
  },
};

window.toolsModule = toolsModule;
