import { useState } from 'react';
import { Zap, Route, Lock, Heading, Search, MapPin, X, ArrowRight, Fingerprint } from 'lucide-react';

const TOOL_META = {
  ping:       { name: 'Ping',        icon: Zap,     endpoint: '/api/tools/ping',         param: 'target', placeholder: 'Hostname or IP (e.g. 8.8.8.8)' },
  traceroute: { name: 'Traceroute',  icon: Route,   endpoint: '/api/tools/traceroute',   param: 'target', placeholder: 'Hostname or IP (e.g. example.com)' },
  ssl:        { name: 'SSL Check',   icon: Lock,    endpoint: '/api/tools/ssl',          param: 'host',   placeholder: 'Domain (e.g. example.com)' },
  headers:    { name: 'HTTP Headers',icon: Heading, endpoint: '/api/tools/http_headers', param: 'target', placeholder: 'URL (e.g. https://example.com)' },
  subdomains: { name: 'Subdomains',  icon: Search,  endpoint: '/api/tools/subdomain',    param: 'domain', placeholder: 'Domain (e.g. example.com)' },
  geo:        { name: 'GeoIP',       icon: MapPin,  endpoint: '/api/tools/geoip',        param: 'target', placeholder: 'Public IP address or hostname (e.g. 8.8.8.8)' },
  osfingerprint: { name: 'OS Fingerprinting', icon: Fingerprint, endpoint: '/api/scans/os-fingerprint', param: 'target', placeholder: 'Hostname or IP (e.g. scanme.nmap.org)' },
};

export default function GenericTool({ toolId }) {
  const meta = TOOL_META[toolId];
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [copied, setCopied] = useState('');

  if (!meta) return <div className="text-gray-500 text-center mt-20">Tool not found: {toolId}</div>;

  const Icon = meta.icon;

  const run = async () => {
    if (!target) return;
    setLoading(true);
    try {
      const r = await fetch(meta.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [meta.param]: target }),
      });
      const contentType = r.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        throw new Error(`Expected JSON from ${meta.endpoint}, but received ${contentType || 'an HTML response'}. Check that the API server is running and the Vite proxy is pointing at it.`);
      }
      const payload = await r.json();
      if (!r.ok) {
        throw new Error(payload.detail || payload.error || `Request failed with HTTP ${r.status}`);
      }
      setResults(payload.data || payload);
    } catch (e) { setResults({ error: e.message }); } finally { setLoading(false); }
  };

  const renderValue = (val) => {
    if (typeof val === 'object' && val !== null) return <pre className="text-gray-300 text-sm font-mono whitespace-pre-wrap">{JSON.stringify(val, null, 2)}</pre>;
    return <span className="text-gray-200 text-sm font-mono break-all">{String(val)}</span>;
  };

  const renderField = (label, value) => {
    if (value === null || value === undefined || value === '') return null;
    return (
      <div className="flex gap-4 p-4 bg-dark-800/50 border border-dark-600 rounded-xl hover:bg-dark-700/50 transition-colors">
        <span className="w-36 text-xs text-gray-500 font-mono shrink-0 pt-0.5">{label}</span>
        {Array.isArray(value) ? (
          <span className="text-gray-200 text-sm font-mono break-all">{value.join(', ')}</span>
        ) : typeof value === 'boolean' ? (
          <span className={`text-sm font-mono ${value ? 'text-amber-300' : 'text-emerald-300'}`}>{value ? 'Yes' : 'No'}</span>
        ) : String(value).startsWith('http') ? (
          <a className="text-sm font-mono text-purple-300 hover:text-purple-200 break-all" href={String(value)} target="_blank" rel="noreferrer">{String(value)}</a>
        ) : (
          <span className="text-gray-200 text-sm font-mono break-all">{String(value)}</span>
        )}
      </div>
    );
  };

  const renderSection = (title, fields) => {
    const visible = fields.filter(Boolean);
    if (!visible.length) return null;
    return (
      <section className="space-y-3">
        <h3 className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500">{title}</h3>
        <div className="space-y-3">{visible}</div>
      </section>
    );
  };

  const copyText = async (label, text) => {
    if (!text) return;
    await navigator.clipboard.writeText(text);
    setCopied(label);
    window.setTimeout(() => setCopied(''), 1200);
  };

  const renderIpResult = (item) => (
    <div key={item.ip || item.target} className="space-y-3 border border-dark-600 bg-dark-800/40 rounded-xl p-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm font-mono text-gray-100">{item.ip || item.target}</span>
        {item.cdn_provider && <span className="text-xs font-mono text-amber-300">{item.cdn_provider}</span>}
        {item.country_code && <span className="text-xs font-mono text-gray-400">{item.country_code}</span>}
      </div>
      {item.summary && <p className="text-sm text-gray-300">{item.summary}</p>}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
        {renderField('asn', item.asn)}
        {renderField('org', item.org)}
        {renderField('city', item.city)}
        {renderField('rdap_cidr', item.rdap_cidr)}
        {renderField('reverse_dns', item.reverse_dns || 'No PTR record')}
        {renderField('abuse', item.abuse_contact)}
      </div>
    </div>
  );

  const renderGeoResults = (data) => (
    <div className="p-6 space-y-6">
      {(data.summary || data.infrastructure_note) && (
        <section className="space-y-2 border border-dark-600 bg-dark-800/60 rounded-xl p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            {data.summary && <p className="text-sm text-gray-100">{data.summary}</p>}
            <div className="flex gap-2">
              <button type="button" className="px-3 py-2 text-xs font-mono text-gray-300 border border-dark-600 rounded-lg hover:bg-dark-700" onClick={() => copyText('summary', data.summary)}>
                {copied === 'summary' ? 'Copied' : 'Copy summary'}
              </button>
              <button type="button" className="px-3 py-2 text-xs font-mono text-gray-300 border border-dark-600 rounded-lg hover:bg-dark-700" onClick={() => copyText('json', JSON.stringify(data, null, 2))}>
                {copied === 'json' ? 'Copied' : 'Copy JSON'}
              </button>
            </div>
          </div>
          {data.infrastructure_note && <p className="text-sm text-amber-200">{data.infrastructure_note}</p>}
        </section>
      )}

      {renderSection('Location', [
        renderField('ip', data.ip),
        renderField('country', [data.flag_emoji, data.country, data.country_code && `(${data.country_code})`].filter(Boolean).join(' ')),
        renderField('continent', [data.continent, data.continent_code && `(${data.continent_code})`].filter(Boolean).join(' ')),
        renderField('region', data.region),
        renderField('city', data.city),
        renderField('postal', data.postal),
        renderField('coordinates', data.lat !== null && data.lon !== null ? `${data.lat}, ${data.lon}` : null),
        renderField('accuracy_radius', data.accuracy_radius),
        renderField('map', data.map_url),
        renderField('timezone', data.timezone),
        renderField('local_time', data.local_time),
        renderField('timezone_utc', data.timezone_utc),
      ])}

      {renderSection('Network', [
        renderField('isp', data.isp),
        renderField('organization', data.org),
        renderField('asn', data.asn),
        renderField('asn_route', data.asn_route),
        renderField('asn_domain', data.asn_domain),
        renderField('asn_type', data.asn_type),
        renderField('rdap_name', data.rdap_name),
        renderField('rdap_cidr', data.rdap_cidr),
        renderField('rdap_registry', data.rdap_registry),
        renderField('rdap_range', data.rdap_start_address && data.rdap_end_address ? `${data.rdap_start_address} - ${data.rdap_end_address}` : null),
        renderField('currency', data.currency),
        renderField('calling_code', data.calling_code),
      ])}

      {renderSection('Security', [
        renderField('cdn', data.is_cdn),
        renderField('cdn_provider', data.cdn_provider),
        renderField('proxy', data.is_proxy),
        renderField('vpn', data.is_vpn),
        renderField('tor', data.is_tor),
        renderField('hosting', data.is_hosting),
        renderField('mobile', data.is_mobile),
        renderField('threat_score', data.threat_score),
        renderField('abuse_contact', data.abuse_contact),
        renderField('rdap_abuse_email', data.rdap_abuse_email),
        renderField('rdap_abuse_phone', data.rdap_abuse_phone),
        renderField('confidence', data.confidence),
        renderField('location_accuracy', data.location_accuracy),
      ])}

      {renderSection('DNS', [
        renderField('target', data.target),
        renderField('resolved_ips', data.resolved_ips),
        renderField('reverse_dns', data.reverse_dns || 'No PTR record'),
      ])}

      {Array.isArray(data.ip_results) && data.ip_results.length > 1 && (
        <section className="space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500">All Resolved IPs</h3>
          <div className="space-y-3">{data.ip_results.map(renderIpResult)}</div>
        </section>
      )}

      {renderSection('Provider', [
        renderField('provider', data.provider),
        renderField('cached', data.cached),
      ])}
    </div>
  );

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot">
          <Icon className="w-3 h-3" />
        </span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>{meta.name}</span>
      </div>
      <div className="scanner-control-shell">
        <div className="relative flex-1 min-w-[320px]">
          <input type="text" className="scan-input" placeholder={meta.placeholder} value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
          {target && <button onClick={() => setTarget('')} className="clear-input-btn" aria-label="Clear target"><X className="w-4 h-4" /></button>}
        </div>
        <button onClick={run} disabled={loading || !target} className="run-btn">
          <span>{loading ? 'Running' : 'Run'}</span>
          {loading ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <ArrowRight className="w-4 h-4" />}
        </button>
      </div>
      <div className="scanner-results-panel flex-1 overflow-auto">
        {results === null ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
            <img src="/assets/logo.svg" alt="" className="empty-logo w-auto" style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }} />
            <span className="text-xs font-medium uppercase" style={{ color: '#6d579b' }}>Your {meta.name} results will appear here</span>
          </div>
        ) : results.error ? (
          <div className="p-6 text-red-400 font-mono text-sm">{results.error}</div>
        ) : toolId === 'geo' ? (
          renderGeoResults(results)
        ) : (
          <div className="p-6 space-y-3">
            {Object.entries(results).map(([key, val]) => (
              <div key={key} className="flex gap-4 p-4 bg-dark-800/50 border border-dark-600 rounded-xl hover:bg-dark-700/50 transition-colors">
                <span className="w-36 text-xs text-gray-500 font-mono shrink-0 pt-0.5">{key}</span>
                {renderValue(val)}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
