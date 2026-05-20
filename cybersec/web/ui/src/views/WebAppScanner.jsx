import React, { useState } from 'react';
import { ShieldHalf, X, AlertTriangle, CheckCircle, ArrowRight } from 'lucide-react';
import clsx from 'clsx';

const SEVERITY_STYLES = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/30',
  high:     'bg-orange-500/10 text-orange-400 border-orange-500/30',
  medium:   'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  low:      'bg-blue-500/10 text-blue-400 border-blue-500/30',
  info:     'bg-gray-500/10 text-gray-400 border-gray-500/30',
};

export default function WebAppScanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const run = async () => {
    if (!url) return;
    setLoading(true);
    setResults(null);
    try {
      const r = await fetch('/api/webapp/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
      const data = await r.json();
      setResults(data);
    } catch (e) { setResults({ error: e.message }); } finally { setLoading(false); }
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><ShieldHalf className="w-3 h-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>Web App Scanner</span>
      </div>
      <div className="scanner-control-shell">
        <div className="relative flex-1 min-w-[320px]">
          <input type="url" className="scan-input" placeholder="https://example.com" value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
          {url && <button onClick={() => setUrl('')} className="clear-input-btn" aria-label="Clear URL"><X className="w-4 h-4" /></button>}
        </div>
        <button onClick={run} disabled={loading || !url} className="run-btn">
          <span>{loading ? 'Scanning' : 'Scan'}</span>
          {loading ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <ArrowRight className="w-4 h-4" />}
        </button>
      </div>
      <div className="scanner-results-panel flex-1 overflow-auto">
        {results === null && !loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
            <img src="/assets/logo.svg" alt="" className="empty-logo w-auto" style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }} />
            <span className="text-xs font-medium uppercase" style={{ color: '#6d579b' }}>Your Web App Scanner results will appear here</span>
          </div>
        ) : loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-4">
            <div className="w-8 h-8 border-4 border-primary-500/20 border-t-primary-500 rounded-full animate-spin"></div>
            <div className="text-primary-400 font-mono text-sm animate-pulse">Scanning for vulnerabilities...</div>
          </div>
        ) : results?.error ? (
          <div className="p-6 text-red-400 font-mono text-sm">{results.error}</div>
        ) : (
          <div className="p-6 space-y-3">
            {(results?.vulnerabilities || []).map((vuln, i) => (
              <div key={i} className={clsx("p-4 rounded-xl border", SEVERITY_STYLES[vuln.severity] || SEVERITY_STYLES.info)}>
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                  <div>
                    <div className="font-semibold mb-1">{vuln.name || vuln.type}</div>
                    <div className="text-xs opacity-80">{vuln.description}</div>
                  </div>
                  <div className={clsx("ml-auto text-xs font-mono uppercase px-2 py-0.5 rounded-full border shrink-0", SEVERITY_STYLES[vuln.severity] || SEVERITY_STYLES.info)}>{vuln.severity}</div>
                </div>
              </div>
            ))}
            {results?.passed && results.passed.length > 0 && (
              <div className="pt-4">
                <div className="text-xs text-gray-500 uppercase tracking-wider mb-3">Passed Checks</div>
                {results.passed.map((check, i) => (
                  <div key={i} className="flex items-center gap-3 p-3 bg-green-500/5 border border-green-500/20 rounded-xl mb-2">
                    <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
                    <span className="text-green-400 text-sm">{check}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
