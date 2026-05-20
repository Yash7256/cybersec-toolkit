import { useState } from 'react';
import { Server, X, ArrowRight } from 'lucide-react';

export default function Whois() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [copied, setCopied] = useState('');

  const run = async () => {
    if (!target) return;
    setLoading(true);
    try {
      const r = await fetch('/api/tools/whois', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      });
      const contentType = r.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        throw new Error(`Expected JSON from /api/tools/whois, but received ${contentType || 'an HTML response'}. Check that the API server is running.`);
      }
      const payload = await r.json();
      if (!r.ok) {
        throw new Error(payload.detail || payload.error || `Request failed with HTTP ${r.status}`);
      }
      setResults(payload.data || payload);
    } catch (e) { setResults({ error: e.message }); } finally { setLoading(false); }
  };

  const copyText = async (label, text) => {
    if (!text) return;
    await navigator.clipboard.writeText(text);
    setCopied(label);
    window.setTimeout(() => setCopied(''), 1200);
  };

  const renderValue = (value) => {
    if (value === null || value === undefined || value === '') return null;
    if (Array.isArray(value)) return value.length ? value.join(', ') : null;
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (typeof value === 'object') return JSON.stringify(value, null, 2);
    return String(value);
  };

  const field = (label, value) => {
    const rendered = renderValue(value);
    if (!rendered) return null;
    const isBlock = typeof value === 'object' && value !== null && !Array.isArray(value);
    return (
      <div className="flex gap-4 p-4 bg-dark-800/50 border border-dark-600 rounded-xl">
        <span className="w-44 text-xs text-gray-500 font-mono shrink-0 pt-0.5">{label}</span>
        {String(rendered).startsWith('http') ? (
          <a className="text-purple-300 hover:text-purple-200 text-sm font-mono break-all" href={rendered} target="_blank" rel="noreferrer">{rendered}</a>
        ) : isBlock ? (
          <pre className="text-gray-200 text-sm font-mono whitespace-pre-wrap break-all">{rendered}</pre>
        ) : (
          <span className="text-gray-200 text-sm font-mono break-all">{rendered}</span>
        )}
      </div>
    );
  };

  const section = (title, fields) => {
    const visible = fields.filter(Boolean);
    if (!visible.length) return null;
    return (
      <section className="space-y-3">
        <h3 className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500">{title}</h3>
        <div className="space-y-3">{visible}</div>
      </section>
    );
  };

  const renderWhois = (data) => (
    <div className="p-6 space-y-6">
      <section className="space-y-3 border border-dark-600 bg-dark-800/60 rounded-xl p-5">
        {data.summary && <p className="text-sm text-gray-100">{data.summary}</p>}
        {Array.isArray(data.risk_indicators) && data.risk_indicators.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {data.risk_indicators.map((risk) => (
              <span key={risk.id} className="px-3 py-1 text-xs font-mono rounded-lg border border-amber-500/40 text-amber-200 bg-amber-500/10">{risk.label}</span>
            ))}
          </div>
        )}
        <div className="flex flex-wrap gap-2">
          <button type="button" className="px-3 py-2 text-xs font-mono text-gray-300 border border-dark-600 rounded-lg hover:bg-dark-700" onClick={() => copyText('summary', data.summary)}>
            {copied === 'summary' ? 'Copied' : 'Copy summary'}
          </button>
          <button type="button" className="px-3 py-2 text-xs font-mono text-gray-300 border border-dark-600 rounded-lg hover:bg-dark-700" onClick={() => copyText('json', JSON.stringify(data, null, 2))}>
            {copied === 'json' ? 'Copied' : 'Copy JSON'}
          </button>
        </div>
      </section>

      {section('Registration', [
        field('domain', data.domain),
        field('available', data.available),
        field('creation_date', data.creation_date),
        field('updated_date', data.updated_date),
        field('expiration_date', data.expiration_date),
        field('domain_age_days', data.domain_age_days),
        field('days_until_expiry', data.days_until_expiry),
        field('expiry_status', data.expiry_status),
        field('privacy_protected', data.privacy_protected),
      ])}

      {section('Registrar', [
        field('registrar', data.registrar),
        field('registrar_iana_id', data.registrar_iana_id),
        field('registrar_url', data.registrar_url),
        field('registrar_abuse_email', data.registrar_abuse_email),
        field('registrar_abuse_phone', data.registrar_abuse_phone),
        field('registry', data.registry),
      ])}

      {section('Contacts', [
        field('registrant_org', data.registrant_org),
        field('registrant_country', data.registrant_country),
        field('emails', data.emails),
        field('admin_contact', data.admin_contact),
        field('tech_contact', data.tech_contact),
        field('abuse_contact', data.abuse_contact),
      ])}

      {section('Name Servers', [
        field('name_servers', data.name_servers),
        field('dnssec', data.dnssec),
      ])}

      {section('Status', [
        field('status', data.status),
        field('status_explanations', data.status_explanations),
      ])}

      {section('Risk', [
        field('risk_indicators', data.risk_indicators),
        field('historical_whois', data.historical_whois),
        field('related_domains', data.related_domains),
      ])}

      {section('RDAP / IANA', [
        field('rdap_available', data.rdap_available),
        field('iana', data.iana),
        field('normalized', data.normalized),
      ])}

      {section('Provider', [
        field('cached', data.cached),
      ])}

      {data.raw_text && (
        <section className="space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500">Raw WHOIS</h3>
          <pre className="p-4 bg-dark-800/50 border border-dark-600 rounded-xl text-gray-300 text-xs font-mono whitespace-pre-wrap break-all max-h-[420px] overflow-auto">{data.raw_text}</pre>
        </section>
      )}
    </div>
  );

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><Server className="w-3 h-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>WHOIS Lookup</span>
      </div>
      <div className="scanner-control-shell">
        <div className="relative flex-1 min-w-[320px]">
          <input type="text" className="scan-input" placeholder="Domain or IP (e.g. example.com)" value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
          {target && <button onClick={() => setTarget('')} className="clear-input-btn" aria-label="Clear target"><X className="w-4 h-4" /></button>}
        </div>
        <button onClick={run} disabled={loading || !target} className="run-btn">
          <span>{loading ? 'Looking Up' : 'Lookup'}</span>
          {loading ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <ArrowRight className="w-4 h-4" />}
        </button>
      </div>
      <div className="scanner-results-panel flex-1 overflow-auto">
        {results === null ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
            <img src="/assets/logo.svg" alt="" className="empty-logo w-auto" style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }} />
            <span className="text-xs font-medium uppercase" style={{ color: '#6d579b' }}>Your WHOIS results will appear here</span>
          </div>
        ) : results.error ? (
          <div className="p-6 text-red-400 font-mono text-sm">{results.error}</div>
        ) : (
          renderWhois(results)
        )}
      </div>
    </div>
  );
}
