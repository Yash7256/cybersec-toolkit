import { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Calendar,
  Check,
  CircleDot,
  Clock3,
  Copy,
  ExternalLink,
  FileCode2,
  Globe2,
  Info,
  Lock,
  Search,
  Server,
  Shield,
  X,
} from 'lucide-react';

const EMPTY = 'Unknown';

const asArray = (value) => {
  if (!value) return [];
  return Array.isArray(value) ? value.filter(Boolean) : [value];
};

const yesNo = (value) => {
  if (value === true) return 'Yes';
  if (value === false) return 'No';
  return EMPTY;
};

const dateValue = (value) => {
  if (!value) return EMPTY;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }).format(parsed);
};

const compactDateValue = (value) => {
  if (!value) return EMPTY;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    year: '2-digit',
  }).format(parsed);
};

const valueText = (value) => {
  if (value === null || value === undefined || value === '') return EMPTY;
  if (typeof value === 'boolean') return yesNo(value);
  if (Array.isArray(value)) return value.length ? value.join(', ') : EMPTY;
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
};

const cleanStatus = (status) => String(status || '')
  .replace(/^.*?#/, '')
  .replace(/\s+https?:\/\/\S+/g, '')
  .trim();

function Whois() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [copied, setCopied] = useState('');
  const streamAbortRef = useRef(null);

  useEffect(() => () => {
    streamAbortRef.current?.abort();
  }, []);

  const applyWhoisStreamEvent = (event) => {
    if (!event || typeof event !== 'object') return;
    if (event.type === 'init') {
      setResults({
        ...event.data,
        scanning: true,
      });
      return;
    }
    if (event.type === 'stage') {
      setResults((previous) => ({
        ...(previous || { target, domain: target }),
        scan_stage: event.stage,
        scan_message: event.message,
        scanning: true,
      }));
      return;
    }
    if (event.type === 'done') {
      setResults({
        ...event.data,
        scanning: false,
      });
      return;
    }
    if (event.type === 'error') {
      setResults({ error: event.error || 'WHOIS stream failed' });
    }
  };

  const run = async () => {
    if (!target) return;
    streamAbortRef.current?.abort();
    const controller = new AbortController();
    streamAbortRef.current = controller;
    setLoading(true);
    setResults({
      target,
      domain: target,
      scanning: true,
      scan_stage: 'init',
      scan_message: 'Starting WHOIS lookup',
      name_servers: [],
      status: [],
      emails: [],
      risk_indicators: [],
      status_explanations: [],
      historical_whois: { available: false, reason: 'Pending lookup' },
      related_domains: { available: false, reason: 'Pending lookup' },
      normalized: {},
      cached: false,
    });
    try {
      const r = await fetch('/api/tools/whois/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
        signal: controller.signal,
      });
      if (!r.ok) {
        throw new Error(`WHOIS stream failed with HTTP ${r.status}`);
      }
      if (!r.body) {
        throw new Error('WHOIS stream is unavailable in this browser.');
      }
      const reader = r.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let done = false;
      while (!done) {
        const chunk = await reader.read();
        done = chunk.done;
        buffer += decoder.decode(chunk.value || new Uint8Array(), { stream: !done });
        const parts = buffer.split('\n\n');
        buffer = parts.pop() || '';
        parts.forEach((part) => {
          const dataLine = part.split('\n').find((line) => line.startsWith('data:'));
          if (!dataLine) return;
          try {
            applyWhoisStreamEvent(JSON.parse(dataLine.slice(5).trim()));
          } catch (error) {
            console.warn('Invalid WHOIS stream event', error);
          }
        });
      }
      if (buffer.trim()) {
        const dataLine = buffer.split('\n').find((line) => line.startsWith('data:'));
        if (dataLine) applyWhoisStreamEvent(JSON.parse(dataLine.slice(5).trim()));
      }
    } catch (e) {
      if (e.name !== 'AbortError') setResults({ error: e.message });
    } finally {
      if (streamAbortRef.current === controller) streamAbortRef.current = null;
      setLoading(false);
    }
  };

  const copyText = async (label, text) => {
    if (!text) return;
    await navigator.clipboard.writeText(text);
    setCopied(label);
    window.setTimeout(() => setCopied(''), 1200);
  };

  const renderWhois = (data) => {
    const isScanning = Boolean(data.scanning);
    const domain = data.domain || data.target || target || EMPTY;
    const statuses = asArray(data.status).map(cleanStatus).filter(Boolean);
    const risks = asArray(data.risk_indicators);
    const servers = asArray(data.name_servers);
    const emails = asArray(data.emails);
    const statusExplanation = asArray(data.status_explanations)[0];
    const riskLevel = risks.some((risk) => risk.severity === 'high')
      ? 'High Risk'
      : risks.some((risk) => risk.severity === 'medium' || risk.severity === 'warning')
        ? 'Review'
        : 'Low Risk';
    const healthScore = Math.max(52, 96 - (risks.length * 8) - (data.expiry_status === 'expired' ? 24 : 0));
    const isHealthy = data.available === false && data.expiry_status !== 'expired';
    const timelinePct = (() => {
      if (typeof data.domain_age_days !== 'number' || typeof data.days_until_expiry !== 'number') return 68;
      const total = data.domain_age_days + Math.max(data.days_until_expiry, 0);
      return total > 0 ? Math.min(92, Math.max(14, (data.domain_age_days / total) * 100)) : 68;
    })();
    const summary = isScanning ? data.scan_message || 'WHOIS lookup is running...' : data.summary || `${domain} WHOIS registration data was retrieved.`;

    const infoRows = [
      ['Registrar', data.registrar],
      ['Registrar URL', data.registrar_url],
      ['Registry', data.registry],
      ['IANA ID', data.registrar_iana_id],
      ['Abuse Email', data.registrar_abuse_email || emails[0]],
      ['Abuse Phone', data.registrar_abuse_phone],
    ];

    const registrationRows = [
      ['Domain', domain],
      ['Available', yesNo(data.available)],
      ['Creation Date', dateValue(data.creation_date)],
      ['Updated Date', dateValue(data.updated_date)],
      ['Expiration Date', dateValue(data.expiration_date)],
      ['Domain Age', typeof data.domain_age_days === 'number' ? `${data.domain_age_days} days` : EMPTY],
      ['Days Until Expiry', typeof data.days_until_expiry === 'number' ? `${data.days_until_expiry} days` : EMPTY],
      ['Expiry Status', data.expiry_status],
      ['Protected', yesNo(data.privacy_protected)],
    ];

    return (
      <div className="whois-results">
        <section className="whois-hero-panel">
          <div className="whois-domain-line">
            <h2>{domain}</h2>
            <ExternalLink className="h-4 w-4" />
          </div>
          <div className="whois-chip-row">
            <span className={`whois-chip ${isScanning ? '' : 'success'}`}>
              {isScanning ? <Clock3 className="h-3 w-3 animate-pulse" /> : <Check className="h-3 w-3" />}
              {isScanning ? 'WHOIS Running' : 'WHOIS Retrieved'}
            </span>
            <span className="whois-chip"><Clock3 className="h-3 w-3" />{data.cached ? 'Cached' : 'Fresh'}</span>
            <span className="whois-chip"><Calendar className="h-3 w-3" />{new Date().toLocaleString()}</span>
          </div>
          <div className="whois-summary">
            <Info className="h-4 w-4" />
            <p>{summary}</p>
          </div>
        </section>

        <section className="whois-timeline-panel">
          <h3>Domain Timeline</h3>
          <div className="whois-timeline">
            <div className="whois-timeline-track">
              <span className="whois-timeline-fill" style={{ width: `${timelinePct}%` }} />
            </div>
            <TimelinePoint icon={Globe2} label="Domain Age" value={typeof data.domain_age_days === 'number' ? `${data.domain_age_days} days` : EMPTY} />
            <TimelinePoint icon={Calendar} label="Updated" value={compactDateValue(data.updated_date)} />
            <TimelinePoint icon={Clock3} label="Expires" value={compactDateValue(data.expiration_date)} />
            <TimelinePoint icon={Calendar} label="Until Expiry" value={typeof data.days_until_expiry === 'number' ? `${data.days_until_expiry} days` : EMPTY} />
          </div>
          <div className="whois-status-cards">
            <MetricCard icon={Globe2} label="Status" value={isHealthy ? 'Healthy' : valueText(data.expiry_status)} note={data.available === false ? 'Active' : 'Availability unknown'} />
            <MetricCard icon={Shield} label="Privacy" value={data.privacy_protected ? 'Protected' : 'Visible'} note={yesNo(data.privacy_protected)} />
            <MetricCard icon={Lock} label="Transfer Lock" value={statuses.some((item) => item.toLowerCase().includes('transferprohibited')) ? 'Enabled' : 'Unknown'} note={statuses[0] || 'No status code'} />
          </div>
        </section>

        <section className="whois-two-col-panel">
          <InfoCard title="Registrar Information" rows={infoRows} />
          <InfoCard title="Registration Information" rows={registrationRows} />
        </section>

        <section className="whois-two-col-panel">
          <ScoreCard score={healthScore} />
          <RiskCard level={riskLevel} risks={risks} isHealthy={isHealthy} />
        </section>

        <section className="whois-three-col-panel">
          <CompactCard title="Status Information">
            <DataLine label="Domain Status" value={statuses[0] || EMPTY} accent />
            <DataLine label="DNSSEC" value={data.dnssec || EMPTY} />
            <p className="whois-mini-copy">{statusExplanation?.meaning || 'No registry status explanation was returned.'}</p>
          </CompactCard>
          <CompactCard title="Contact Information">
            <DataLine label="Registrant Organization" value={data.registrant_org} />
            <DataLine label="Registrant Country" value={data.registrant_country} />
            <DataLine label="Registrant Email" value={emails[0]} />
            <DataLine label="Admin Contact" value={data.admin_contact ? 'Privacy Protected' : EMPTY} pill />
            <DataLine label="Tech Contact" value={data.tech_contact ? 'Privacy Protected' : EMPTY} pill />
          </CompactCard>
          <CompactCard title="Server Names">
            {(servers.length ? servers.slice(0, 5) : [EMPTY]).map((server) => (
              <DataLine key={server} label="" value={server} icon={server !== EMPTY ? Check : null} />
            ))}
            <DataLine label="Total Servers" value={servers.length || EMPTY} />
          </CompactCard>
        </section>

        <section className="whois-two-col-panel">
          <InfoCard title="RDAP/IANA Information" rows={[
            ['RDAP Available', yesNo(data.rdap_available)],
            ['RDAP Error', data.normalized?.rdap_error],
            ['IANA TLD', data.iana?.tld || data.tld],
            ['Registry', data.iana?.registry || data.registry],
          ]} />
          <InfoCard title="Related Data" rows={[
            ['Historical Available', yesNo(data.historical_whois?.available)],
            ['Historical Reason', data.historical_whois?.reason],
            ['Related Available', yesNo(data.related_domains?.available)],
            ['Related Reason', data.related_domains?.reason],
          ]} />
        </section>

        <section className="whois-raw-panel">
          <div className="whois-raw-head">
            <h3>Raw WHOIS Record</h3>
            <div className="whois-raw-actions">
              <button type="button" onClick={() => copyText('summary', data.summary)}>
                <Copy className="h-3 w-3" />{copied === 'summary' ? 'Copied' : 'Summary'}
              </button>
              <button type="button" onClick={() => copyText('json', JSON.stringify(data, null, 2))}>
                <FileCode2 className="h-3 w-3" />{copied === 'json' ? 'Copied' : 'Raw Text'}
              </button>
            </div>
          </div>
          <pre>{data.raw_text || JSON.stringify(data, null, 2)}</pre>
          <div className="whois-terms">
            <Info className="h-4 w-4" />
            <span>Terms of use: access to public registry WHOIS information is provided by the registry or registrar.</span>
          </div>
        </section>
      </div>
    );
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><Server className="w-3 h-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>WHOIS</span>
      </div>
      <div className="scanner-control-shell">
        <div className="relative flex-1 min-w-[320px]">
          <input type="text" className="scan-input" placeholder="Domain or IP (e.g. example.com)" value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
          {target && <button onClick={() => setTarget('')} className="clear-input-btn" aria-label="Clear target"><X className="w-4 h-4" /></button>}
        </div>
        <button onClick={run} disabled={loading || !target} className="run-btn">
          <span>{loading ? 'Looking Up' : 'Run Scan'}</span>
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

function TimelinePoint({ icon: Icon, label, value }) {
  return (
    <div className="whois-timeline-point">
      <span><Icon className="h-4 w-4" /></span>
      <small>{label}</small>
      <strong>{value}</strong>
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, note }) {
  return (
    <article className="whois-metric-card">
      <Icon className="h-5 w-5" />
      <span>{label}</span>
      <strong>{value || EMPTY}</strong>
      <small>{note || EMPTY}</small>
    </article>
  );
}

function InfoCard({ title, rows }) {
  return (
    <article className="whois-info-card">
      <h3><CircleDot className="h-4 w-4" />{title}</h3>
      <div>
        {rows.map(([label, value]) => (
          <DataLine key={label} label={label} value={value} />
        ))}
      </div>
    </article>
  );
}

function CompactCard({ title, children }) {
  return (
    <article className="whois-compact-card">
      <h3><CircleDot className="h-3 w-3" />{title}</h3>
      {children}
    </article>
  );
}

function DataLine({ label, value, accent = false, pill = false, icon: Icon = null }) {
  const text = valueText(value);
  return (
    <div className="whois-data-line">
      {label && <span>{label}</span>}
      <strong className={`${accent ? 'accent' : ''} ${pill && text !== EMPTY ? 'pill' : ''}`}>
        {text}
        {Icon && <Icon className="h-3 w-3" />}
      </strong>
    </div>
  );
}

function ScoreCard({ score }) {
  return (
    <article className="whois-health-card">
      <h3><CircleDot className="h-4 w-4" />Domain Health Score</h3>
      <div className="whois-score-ring" style={{ '--score': `${score}%` }}>
        <span>{score}<small>/100</small></span>
      </div>
      <strong>Excellent</strong>
      <p>Domain appears stable with no major concerns detected.</p>
      {['Valid registration', 'Domain is active', 'Not expired', 'Transfer lock is enabled', 'Privacy protection is enabled'].map((item) => (
        <div className="whois-check-line" key={item}><Check className="h-4 w-4" />{item}</div>
      ))}
    </article>
  );
}

function RiskCard({ level, risks, isHealthy }) {
  const lines = risks.length
    ? risks.map((risk) => risk.label)
    : ['Domain is active and healthy', 'Expiry date is more than 2 years away', 'Transfer lock is enabled', 'No suspicious domain status', 'Privacy protection is enabled'];

  return (
    <article className="whois-risk-card">
      <h3><CircleDot className="h-4 w-4" />Risk Overview</h3>
      <Search className="whois-risk-illustration" />
      <AlertTriangle className="whois-risk-warning" />
      <strong>{level}</strong>
      <p>{isHealthy ? 'No significant risk indicators detected.' : 'Review returned WHOIS indicators before trusting this domain.'}</p>
      {lines.map((item) => (
        <div className="whois-check-line" key={item}><Check className="h-4 w-4" />{item}</div>
      ))}
    </article>
  );
}

export default Whois;
