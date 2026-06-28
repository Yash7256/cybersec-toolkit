import React, { useState } from 'react';
import { ShieldHalf, X, AlertTriangle, CheckCircle, ArrowRight, Info,
         Globe, Lock, Server, Code2, Cpu, ChevronDown, ChevronRight } from 'lucide-react';
import clsx from 'clsx';

// ---------------------------------------------------------------------------
// Style maps
// ---------------------------------------------------------------------------
const SEV = {
  critical: { row: 'bg-red-500/10 text-red-300 border-red-500/30',    badge: 'bg-red-500/20 text-red-300 border-red-500/40' },
  high:     { row: 'bg-orange-500/10 text-orange-300 border-orange-500/30', badge: 'bg-orange-500/20 text-orange-300 border-orange-500/40' },
  medium:   { row: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30', badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40' },
  low:      { row: 'bg-blue-500/10 text-blue-300 border-blue-500/30',   badge: 'bg-blue-500/20 text-blue-300 border-blue-500/40' },
  info:     { row: 'bg-gray-500/10 text-gray-400 border-gray-500/20',   badge: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
};
const sev = (s) => SEV[s?.toLowerCase()] ?? SEV.info;

const CATEGORY_ICONS = {
  'tls':            <Lock className="w-3.5 h-3.5" />,
  'headers':        <Globe className="w-3.5 h-3.5" />,
  'injection':      <Code2 className="w-3.5 h-3.5" />,
  'access-control': <Server className="w-3.5 h-3.5" />,
  'cors':           <Globe className="w-3.5 h-3.5" />,
  'dns':            <Cpu className="w-3.5 h-3.5" />,
};
const CATEGORY_LABELS = {
  'tls':            'TLS / Certificate',
  'headers':        'HTTP Headers & Cookies',
  'injection':      'Injection',
  'access-control': 'Access Control',
  'cors':           'CORS',
  'dns':            'DNS / Email Security',
  '':               'Other',
};

const VULN_LABELS = {
  MISSING_HEADER:            'Missing Security Header',
  WEAK_CSP:                  'Weak Content-Security-Policy',
  WEAK_HSTS:                 'Weak HSTS Policy',
  INSECURE_COOKIE:           'Insecure Cookie',
  INFO_DISCLOSURE:           'Server Information Disclosure',
  PLAINTEXT_HTTP:            'Plaintext HTTP',
  CACHEABLE_SENSITIVE_PAGE:  'Cacheable Sensitive Page',
  TLS_CERT_EXPIRED:          'TLS Certificate Expired',
  TLS_CERT_EXPIRING_SOON:    'TLS Certificate Expiring Soon',
  TLS_SELF_SIGNED:           'Self-Signed Certificate',
  TLS_NO_TLS12:              'TLS 1.2 Not Supported',
  TLS_WEAK_VERSION:          'Deprecated TLS Version',
  TLS_WEAK_CIPHER:           'Weak TLS Cipher Suite',
  TLS_CERT_HOSTNAME_MISMATCH:'Certificate Hostname Mismatch',
  TLS_ERROR:                 'TLS Configuration Error',
  TLS_AUDIT_FAILED:          'TLS Audit Failed',
  CORS_WILDCARD:             'CORS Wildcard Origin',
  CORS_WILDCARD_WITH_CREDENTIALS: 'CORS: Wildcard + Credentials',
  CORS_REFLECTED_ORIGIN:     'CORS: Reflected Origin',
  EXPOSED_FILE:              'Exposed Sensitive File',
  ADMIN_PANEL_EXPOSED:       'Admin Panel Exposed',
  ADMIN_PANEL_FORBIDDEN:     'Admin Panel (403)',
  DIRECTORY_LISTING:         'Directory Listing Enabled',
  HTTP_TRACE_ENABLED:        'HTTP TRACE Enabled',
  DANGEROUS_HTTP_METHOD:     'Dangerous HTTP Method Allowed',
  OPEN_REDIRECT:             'Open Redirect',
  SQL_INJECTION:             'SQL Injection',
  XSS:                       'Cross-Site Scripting (XSS)',
  CSRF:                      'CSRF — Missing Token',
  SSTI:                      'Server-Side Template Injection',
  PATH_TRAVERSAL:            'Path Traversal',
  MISSING_SPF:               'Missing SPF Record',
  WEAK_SPF:                  'Weak SPF Policy',
  MISSING_DMARC:             'Missing DMARC Record',
  WEAK_DMARC:                'Weak DMARC Policy',
  ROBOTS_SENSITIVE_PATHS:    'Sensitive Paths in robots.txt',
  REQUEST_FAILED:            'Request Failed',
  SCAN_NOTE:                 'Scan Note',
};

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------
function SeverityPill({ sev: s }) {
  return (
    <span className={clsx('text-xs font-mono uppercase px-2 py-0.5 rounded-full border shrink-0', SEV[s]?.badge ?? SEV.info.badge)}>
      {s}
    </span>
  );
}

function VulnCard({ vuln }) {
  const [open, setOpen] = useState(false);
  const styles = sev(vuln.severity);
  const label = VULN_LABELS[vuln.vuln_type] ?? vuln.vuln_type;
  const isInfo = vuln.severity?.toLowerCase() === 'info';

  return (
    <div className={clsx('rounded-xl border overflow-hidden', styles.row)}>
      <button
        className="w-full flex items-center gap-3 p-3.5 text-left"
        onClick={() => setOpen(o => !o)}
      >
        {isInfo
          ? <Info className="w-4 h-4 shrink-0 opacity-50" />
          : <AlertTriangle className="w-4 h-4 shrink-0" />}
        <span className="flex-1 font-medium text-sm truncate">{label}</span>
        {vuln.parameter && (
          <span className="text-xs font-mono opacity-60 shrink-0 hidden sm:block">{vuln.parameter}</span>
        )}
        <SeverityPill sev={vuln.severity?.toLowerCase()} />
        {open ? <ChevronDown className="w-3.5 h-3.5 shrink-0 opacity-50" /> : <ChevronRight className="w-3.5 h-3.5 shrink-0 opacity-50" />}
      </button>

      {open && (
        <div className="px-4 pb-4 pt-0 space-y-2 border-t border-white/5">
          {vuln.url && (
            <div className="text-xs font-mono opacity-60 break-all">{vuln.url}</div>
          )}
          {vuln.evidence && (
            <div className="text-xs bg-black/20 rounded p-2 font-mono break-all">{vuln.evidence}</div>
          )}
          {vuln.recommendation && (
            <div className="text-xs opacity-70 italic">💡 {vuln.recommendation}</div>
          )}
        </div>
      )}
    </div>
  );
}

function FingerprintPanel({ fp }) {
  if (!fp) return null;
  const rows = [
    fp.cms       && { label: 'CMS',       value: fp.cms },
    fp.framework && { label: 'Framework', value: fp.framework },
    fp.server    && { label: 'Server',    value: fp.server },
    fp.languages?.length && { label: 'Languages', value: fp.languages.join(', ') },
    fp.libraries?.length && { label: 'Libraries', value: fp.libraries.join(', ') },
  ].filter(Boolean);

  if (!rows.length) return null;

  return (
    <div className="rounded-xl border border-white/10 bg-white/3 p-4 space-y-2">
      <div className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-3">Technology Fingerprint</div>
      {rows.map(({ label, value }) => (
        <div key={label} className="flex gap-3 text-xs">
          <span className="text-gray-500 w-20 shrink-0">{label}</span>
          <span className="text-gray-200 font-mono">{value}</span>
        </div>
      ))}
      {fp.login_paths?.length > 0 && (
        <div className="flex gap-3 text-xs pt-1">
          <span className="text-gray-500 w-20 shrink-0">Login</span>
          <span className="text-yellow-400 font-mono">{fp.login_paths.join(', ')}</span>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function WebAppScanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [filter, setFilter] = useState('all');
  const [catFilter, setCatFilter] = useState('all');

  const run = async () => {
    if (!url) return;
    setLoading(true);
    setResults(null);
    setFilter('all');
    setCatFilter('all');
    try {
      const r = await fetch('/api/webapp/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: url, max_pages: 20 }),
      });
      setResults(await r.json());
    } catch (e) {
      setResults({ error: e.message });
    } finally {
      setLoading(false);
    }
  };

  const scan = results?.result;
  const allVulns = scan?.vulnerabilities ?? [];

  const visible = allVulns.filter(v => {
    const sevOk = filter === 'all' || v.severity?.toLowerCase() === filter;
    const catOk = catFilter === 'all' || (v.category ?? '') === catFilter;
    return sevOk && catOk;
  });

  const counts = scan
    ? { critical: scan.critical_count, high: scan.high_count,
        medium: scan.medium_count, low: scan.low_count, info: scan.info_count ?? 0 }
    : {};

  const cats = [...new Set(allVulns.map(v => v.category ?? ''))];

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      {/* title */}
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><ShieldHalf className="w-3 h-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>Web App Scanner</span>
      </div>

      {/* input */}
      <div className="scanner-control-shell">
        <div className="relative flex-1 min-w-[320px]">
          <input type="url" className="scan-input" placeholder="https://example.com"
            value={url} onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && run()} />
          {url && <button onClick={() => setUrl('')} className="clear-input-btn" aria-label="Clear"><X className="w-4 h-4" /></button>}
        </div>
        <button onClick={run} disabled={loading || !url} className="run-btn">
          <span>{loading ? 'Scanning' : 'Scan'}</span>
          {loading
            ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            : <ArrowRight className="w-4 h-4" />}
        </button>
      </div>

      {/* results */}
      <div className="scanner-results-panel flex-1 overflow-auto">
        {results === null && !loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
            <img src="/assets/logo.svg" alt="" className="empty-logo w-auto"
              style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }} />
            <span className="text-xs font-medium uppercase" style={{ color: '#6d579b' }}>
              Web App Scanner results will appear here
            </span>
          </div>

        ) : loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-4">
            <div className="w-8 h-8 border-4 border-primary-500/20 border-t-primary-500 rounded-full animate-spin" />
            <div className="text-primary-400 font-mono text-sm animate-pulse">Running all checks…</div>
          </div>

        ) : results?.error ? (
          <div className="p-6 text-red-400 font-mono text-sm">{results.error}</div>

        ) : (
          <div className="p-5 space-y-4">
            {/* summary */}
            {scan && (
              <div className="flex flex-wrap gap-3 pb-3 border-b border-white/5 items-center">
                <span className="text-xs text-gray-400 font-mono">
                  <span className="text-white font-semibold">{scan.pages_crawled}</span> pages
                </span>
                <span className="text-xs text-gray-400 font-mono">
                  <span className="text-white font-semibold">{scan.scan_duration?.toFixed(1)}s</span>
                </span>
                {Object.entries(counts).filter(([, n]) => n > 0).map(([s, n]) => (
                  <span key={s} className={clsx('text-xs font-mono px-2 py-0.5 rounded-full border', SEV[s]?.badge ?? SEV.info.badge)}>
                    {n} {s}
                  </span>
                ))}
                {scan.error && <span className="text-xs text-yellow-400">⚠ {scan.error}</span>}
              </div>
            )}

            {/* fingerprint */}
            {scan?.fingerprint && <FingerprintPanel fp={scan.fingerprint} />}

            {/* filters */}
            {allVulns.length > 0 && (
              <div className="space-y-2">
                {/* severity pills */}
                <div className="flex flex-wrap gap-1.5">
                  {['all', 'critical', 'high', 'medium', 'low', 'info'].map(f => {
                    const cnt = f === 'all' ? allVulns.length : (counts[f] ?? 0);
                    if (f !== 'all' && !cnt) return null;
                    return (
                      <button key={f} onClick={() => setFilter(f)}
                        className={clsx('text-xs px-2.5 py-1 rounded-full border transition-colors',
                          filter === f
                            ? (SEV[f === 'all' ? 'info' : f]?.badge ?? SEV.info.badge)
                            : 'border-white/10 text-gray-500 hover:text-gray-300')}>
                        {f === 'all' ? `All (${cnt})` : `${f} (${cnt})`}
                      </button>
                    );
                  })}
                </div>
                {/* category pills */}
                {cats.length > 1 && (
                  <div className="flex flex-wrap gap-1.5">
                    {['all', ...cats].map(c => (
                      <button key={c} onClick={() => setCatFilter(c)}
                        className={clsx('text-xs px-2.5 py-1 rounded-full border transition-colors flex items-center gap-1',
                          catFilter === c
                            ? 'border-purple-500/60 bg-purple-500/10 text-purple-300'
                            : 'border-white/10 text-gray-500 hover:text-gray-300')}>
                        {c !== 'all' && CATEGORY_ICONS[c]}
                        {c === 'all' ? 'All categories' : (CATEGORY_LABELS[c] ?? c)}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* no findings */}
            {allVulns.length === 0 && (
              <div className="flex items-center gap-3 p-4 bg-green-500/5 border border-green-500/20 rounded-xl">
                <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
                <span className="text-green-400 text-sm">No vulnerabilities detected</span>
              </div>
            )}

            {/* vuln cards */}
            <div className="space-y-2">
              {visible.map((v, i) => <VulnCard key={i} vuln={v} />)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
