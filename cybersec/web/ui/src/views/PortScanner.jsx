import React, { useState } from 'react';
import { ScanLine, X, ArrowRight } from 'lucide-react';

const RISK_COLORS = {
  critical: { bg: 'rgba(239,68,68,0.12)', text: '#f87171', border: 'rgba(239,68,68,0.25)' },
  high:     { bg: 'rgba(249,115,22,0.12)', text: '#fb923c', border: 'rgba(249,115,22,0.25)' },
  medium:   { bg: 'rgba(234,179,8,0.12)',  text: '#facc15', border: 'rgba(234,179,8,0.25)' },
  low:      { bg: 'rgba(34,197,94,0.12)',  text: '#4ade80', border: 'rgba(34,197,94,0.25)' },
  open:     { bg: 'rgba(124,58,237,0.12)', text: '#a78bfa', border: 'rgba(124,58,237,0.3)' },
};

function RiskBadge({ label = 'open', color = 'open' }) {
  const c = RISK_COLORS[color] || RISK_COLORS.open;
  return (
    <span
      className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded-full"
      style={{ background: c.bg, color: c.text, border: `1px solid ${c.border}` }}
    >
      {label}
    </span>
  );
}

export default function PortScanner() {
  const [target, setTarget] = useState('');
  const [portRange, setPortRange] = useState('common');
  const [customPortRange, setCustomPortRange] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleScan = async () => {
    if (!target.trim() || isScanning) return;
    
    if (portRange === 'custom' && !customPortRange.trim()) {
      return;
    }
    
    setIsScanning(true);
    setResults([]);
    setErrorMsg(null);
    setProgress(0);

    let progressInterval = null;
    if (portRange !== 'all') {
      progressInterval = setInterval(() => {
        setProgress(p => Math.min(p + Math.random() * 8, 90));
      }, 400);
    }

    try {
      const targetClean = target.trim();
      let allOpenPorts = [];

      if (portRange === 'all') {
        const BATCH_SIZE = 5000;
        const MAX_PORT = 65535;
        let currentStart = 1;

        while (currentStart <= MAX_PORT) {
          const currentEnd = Math.min(currentStart + BATCH_SIZE - 1, MAX_PORT);
          const body = {
            target: targetClean,
            start_port: currentStart,
            end_port: currentEnd,
            timeout: 0.8,
            max_concurrent: 1000
          };

          const createResp = await fetch('/api/tools/port_scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });

          if (!createResp.ok) {
            const errData = await createResp.json().catch(() => ({}));
            throw new Error(errData.detail || `Scan failed (${createResp.status})`);
          }

          const responseData = await createResp.json();
          if (responseData.data && responseData.data.error) {
            throw new Error(responseData.data.error);
          }

          if (responseData.data && responseData.data.open_ports) {
            const ports = responseData.data.open_ports.map(p => ({
              port: p.port_number,
              state: p.status,
              service: p.service,
              version: '',
            }));
            allOpenPorts.push(...ports);
            setResults([...allOpenPorts]);
          }

          setProgress(Math.floor((currentEnd / MAX_PORT) * 100));
          currentStart += BATCH_SIZE;
        }

        setTimeout(() => {
          setIsScanning(false);
          setProgress(0);
        }, 400);

      } else {
        let body = { target: targetClean };
        
        if (portRange === 'custom') {
          if (customPortRange.includes('-')) {
            const parts = customPortRange.split('-');
            body.start_port = parseInt(parts[0], 10);
            body.end_port = parseInt(parts[1], 10);
          } else {
            body.ports = customPortRange.split(',').map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p));
          }
        }

        const createResp = await fetch('/api/tools/port_scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });

        if (!createResp.ok) {
          const errData = await createResp.json().catch(() => ({}));
          throw new Error(errData.detail || `Scan failed (${createResp.status})`);
        }

        const responseData = await createResp.json();
        
        if (responseData.data && responseData.data.error) {
          throw new Error(responseData.data.error);
        }

        if (progressInterval) clearInterval(progressInterval);
        setProgress(100);

        let ports = [];
        if (responseData.data && responseData.data.open_ports) {
          ports = responseData.data.open_ports.map(p => ({
            port: p.port_number,
            state: p.status,
            service: p.service,
            version: '',
          }));
        }

        setTimeout(() => {
          setResults(ports);
          setIsScanning(false);
          setProgress(0);
        }, 400);
      }
    } catch (err) {
      console.error(err);
      if (progressInterval) clearInterval(progressInterval);
      setProgress(0);
      setIsScanning(false);
      setErrorMsg(err.message || 'An error occurred during scan.');
      // Keep results if any were accumulated
    }
  };

  return (
    <div className="flex flex-col h-full port-scanner-page">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot">
          <ScanLine className="w-3 h-3" />
        </span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>
          Port Scanner
        </span>
      </div>

      <div className="scanner-control-shell">
        <div className="target-field relative">
          <input
            className="scan-input pr-10"
            type="text"
            placeholder="Target IP or domain (eg. 192.168.1.1)"
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
          />
          {target && (
            <button
              onClick={() => setTarget('')}
              className="clear-input-btn"
              aria-label="Clear target"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        <div className="select-field relative">
          <select
            className="scan-select"
            value={portRange}
            onChange={e => setPortRange(e.target.value)}
          >
            <option value="common">Common Ports</option>
            <option value="all">All Ports (1-65535)</option>
            <option value="custom">Custom Range</option>
          </select>
        </div>

        {portRange === 'custom' && (
          <div className="target-field relative">
            <input
              className="scan-input"
              type="text"
              placeholder="e.g., 80,443,8080 or 1-1000"
              value={customPortRange}
              onChange={e => setCustomPortRange(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleScan()}
            />
          </div>
        )}

        <button
          onClick={handleScan}
          disabled={isScanning || !target.trim()}
          className="run-btn"
        >
          <span>{isScanning ? 'Scanning' : 'Run Scan'}</span>
          {isScanning ? (
            <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          ) : (
            <ArrowRight className="w-5 h-5" />
          )}
        </button>
      </div>

      {isScanning && (
        <div
          className="h-[2px] rounded-full mb-3 overflow-hidden"
          style={{ background: 'rgba(124,58,237,0.15)' }}
        >
          <div
            className="h-full rounded-full transition-all duration-300"
            style={{
              width: `${progress}%`,
              background: 'linear-gradient(90deg, #7c3aed, #a855f7)',
            }}
          />
        </div>
      )}

      <div
        className="scanner-results-panel flex-1 overflow-hidden flex flex-col"
      >
        {results === null && !errorMsg && (
          <div className="flex flex-col items-center justify-center flex-1 gap-4">
            <img
              src="/assets/logo.svg"
              alt=""
              className="empty-logo h-20 w-auto"
              style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }}
            />
            <span
              className="text-xs font-medium uppercase"
              style={{ color: '#6d579b' }}
            >
              Your scan results will appear here
            </span>
          </div>
        )}
        
        {errorMsg && (
          <div className="flex flex-col items-center justify-center flex-1 gap-3 p-6 text-center">
            <div className="w-12 h-12 flex items-center justify-center rounded-full" style={{ background: 'rgba(239,68,68,0.1)' }}>
              <X className="w-6 h-6 text-red-500" />
            </div>
            <span className="text-sm font-medium text-red-400">Scan Error</span>
            <span className="text-xs" style={{ color: '#9ca3af' }}>{errorMsg}</span>
          </div>
        )}

        {results !== null && (
          <div className="flex flex-col flex-1 overflow-hidden">
            {results.length > 0 && (
              <div
                className="grid px-5 py-3 text-[10px] font-semibold tracking-wider uppercase"
                style={{
                  gridTemplateColumns: '80px 90px 1fr 140px 100px',
                  color: '#6b5fa0',
                  borderBottom: '1px solid rgba(124,58,237,0.12)',
                }}
              >
                <span>Port</span>
                <span>State</span>
                <span>Service</span>
                <span>Version</span>
                <span>Risk</span>
              </div>
            )}

            <div className="flex-1 overflow-y-auto">
              {isScanning && results.length === 0 && (
                <div className="flex flex-col items-center justify-center h-40 gap-3">
                  <div
                    className="w-7 h-7 border-[3px] rounded-full animate-spin"
                    style={{
                      borderColor: 'rgba(124,58,237,0.2)',
                      borderTopColor: '#8b5cf6',
                    }}
                  />
                  <span className="text-xs font-mono animate-pulse" style={{ color: '#8b5cf6' }}>
                    Scanning ports...
                  </span>
                </div>
              )}

              {results.map((r, i) => {
                const risk = (r.risk_level || '').toLowerCase() || (r.state === 'open' ? 'open' : 'low');
                return (
                  <div
                    key={i}
                    className="result-row grid"
                    style={{ gridTemplateColumns: '80px 90px 1fr 140px 100px' }}
                  >
                    <span className="font-mono text-sm font-semibold" style={{ color: '#ddd6fe' }}>
                      {r.port}
                    </span>
                    <span>
                      <RiskBadge label={r.state || 'open'} color={r.state === 'open' ? 'open' : 'low'} />
                    </span>
                    <span className="text-sm font-medium" style={{ color: '#c4b5fd' }}>
                      {r.service || r.name || '—'}
                    </span>
                    <span className="text-xs font-mono" style={{ color: '#6b5fa0' }}>
                      {r.version || r.banner || '—'}
                    </span>
                    <span>
                      <RiskBadge label={risk} color={risk} />
                    </span>
                  </div>
                );
              })}
            </div>

            {!isScanning && results.length > 0 && (
              <div
                className="flex items-center gap-6 px-5 py-3 text-xs font-mono"
                style={{
                  borderTop: '1px solid rgba(124,58,237,0.12)',
                  color: '#6b5fa0',
                }}
              >
                <span>
                  <span style={{ color: '#a78bfa' }}>{results.filter(r => r.state === 'open').length}</span> open
                </span>
                <span>
                  <span style={{ color: '#6b7280' }}>{results.length}</span> total
                </span>
                <span className="ml-auto">
                  Target: <span style={{ color: '#c4b5fd' }}>{target}</span>
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
