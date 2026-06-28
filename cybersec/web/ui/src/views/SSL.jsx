import { useState } from 'react';
import {
  ArrowRight,
  Building2,
  Calendar,
  CheckCircle2,
  Download,
  FileJson,
  FileText,
  Globe2,
  Hash,
  Lock,
  Server,
  Share2,
  ShieldAlert,
  ShieldCheck,
  X,
  XCircle,
} from 'lucide-react';

/* ─── helpers ────────────────────────────────────────────────────── */
const fmt = (v, fallback = '—') =>
  v === null || v === undefined || v === '' ? fallback : String(v);

const fmtDate = (iso) => {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
};

const daysColor = (days) => {
  if (days == null) return '#a78bfa';
  if (days > 60)   return '#34d399';
  if (days > 14)   return '#fbbf24';
  return '#f87171';
};

/* ─── small atoms ────────────────────────────────────────────────── */
function Chip({ label, tone = 'neutral' }) {
  const map = {
    good:    'bg-[rgba(52,211,153,0.12)] text-[#34d399] border-[rgba(52,211,153,0.3)]',
    warn:    'bg-[rgba(251,191,36,0.12)] text-[#fbbf24] border-[rgba(251,191,36,0.3)]',
    bad:     'bg-[rgba(248,113,113,0.12)] text-[#f87171] border-[rgba(248,113,113,0.3)]',
    info:    'bg-[rgba(34,211,238,0.12)] text-[#22d3ee] border-[rgba(34,211,238,0.3)]',
    neutral: 'bg-[rgba(167,139,250,0.1)] text-[#c4b5fd] border-[rgba(167,139,250,0.26)]',
  };
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-[10px] font-mono font-semibold uppercase tracking-wide ${map[tone] || map.neutral}`}>
      {label}
    </span>
  );
}

function InfoRow({ label, value, mono = false }) {
  if (!value && value !== 0) return null;
  return (
    <div className="ssl-info-row">
      <span>{label}</span>
      <strong className={mono ? 'font-mono' : ''}>{value}</strong>
    </div>
  );
}

/* ─── TLS Protocol Card ──────────────────────────────────────────── */
function TlsCard({ label, supported, note }) {
  return (
    <div className={`ssl-tls-card ${supported ? 'ssl-tls-supported' : 'ssl-tls-unsupported'}`}>
      <div className="ssl-tls-card-header">
        {supported
          ? <CheckCircle2 className="w-4 h-4 text-[#34d399]" />
          : <XCircle      className="w-4 h-4 text-[#f87171]" />}
        <span className="ssl-tls-version">{label}</span>
      </div>
      <div className={`ssl-tls-status ${supported ? 'text-[#34d399]' : 'text-[#f87171]'}`}>
        {supported ? 'Supported' : 'Not Supported'}
      </div>
      {note && <div className="ssl-tls-note">{note}</div>}
    </div>
  );
}

/* ─── Results view ───────────────────────────────────────────────── */
function SSLResults({ data }) {
  const cert = data.certificate || data.cert || {};
  const san  = Array.isArray(cert.san) ? cert.san
             : Array.isArray(data.san) ? data.san : [];

  const subject = cert.subject || data.subject || {};
  const issuer  = cert.issuer  || data.issuer  || {};

  const cn  = subject.commonName || subject.common_name || data.host || '—';
  const org = issuer.organizationName || issuer.organization_name || issuer.O || '—';

  const validFrom  = cert.valid_from  || data.valid_from  || '';
  const validTo    = cert.valid_to    || cert.valid_until || data.valid_until || '';
  const days       = cert.days_remaining ?? data.days_remaining;
  const isExpired  = cert.is_expired  || data.is_expired  || false;
  const isSelfSigned = Boolean(data.is_self_signed);

  /* overall grade */
  const overallValid = !isExpired && !isSelfSigned && (data.supports_tls12 || data.supports_tls13);
  const gradeTone    = overallValid ? 'good' : isExpired ? 'bad' : 'warn';
  const gradeLabel   = overallValid ? 'Valid' : isExpired ? 'Expired' : 'Warning';

  /* export */
  const exportJson = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url;
    a.download = `ssl-${data.host || 'result'}.json`; a.click();
    URL.revokeObjectURL(url);
  };
  const exportCsv = () => {
    const rows = [
      ['Field', 'Value'],
      ['Host', data.host], ['Port', data.port],
      ['TLS Version', data.tls_version], ['Cipher Suite', data.cipher_suite],
      ['Valid', overallValid], ['Self-Signed', isSelfSigned],
      ['TLS 1.2', data.supports_tls12], ['TLS 1.3', data.supports_tls13],
      ['Valid From', validFrom], ['Valid To', validTo], ['Days Remaining', days],
      ['Common Name', cn], ['Issuer Org', org],
      ['SANs', san.join('; ')],
    ];
    const csv  = rows.map((r) => r.map((c) => `"${String(c ?? '').replaceAll('"','""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url;
    a.download = `ssl-${data.host || 'result'}.csv`; a.click();
    URL.revokeObjectURL(url);
  };
  const [copied, setCopied] = useState(false);
  const copyShare = async () => {
    const text = `SSL Check: ${data.host}\nValid: ${overallValid}\nTLS: ${data.tls_version}\nCipher: ${data.cipher_suite}\nExpires: ${fmtDate(validTo)} (${days ?? '?'} days)`;
    await navigator.clipboard.writeText(text).catch(() => {});
    setCopied(true); setTimeout(() => setCopied(false), 1400);
  };

  return (
    <div className="ssl-results">

      {/* ── Hero panel ─────────────────────────────────────────── */}
      <section className="ssl-hero-panel">
        <div className="ssl-hero-glow" />
        <div className="ssl-hero-body">
          <div className="ssl-hero-left">
            {/* chips row */}
            <div className="flex flex-wrap gap-2 mb-3">
              <Chip label={gradeLabel} tone={gradeTone} />
              {isSelfSigned && <Chip label="Self-Signed" tone="warn" />}
              {data.tls_version && <Chip label={data.tls_version} tone="info" />}
              {data.supports_tls13 && <Chip label="TLS 1.3 Ready" tone="good" />}
            </div>
            {/* domain */}
            <h2 className="ssl-hero-domain">
              <Lock className="w-5 h-5 text-[#a78bfa]" />
              {data.host || cn}
            </h2>
            {/* sub-line */}
            <div className="ssl-hero-sub">
              {fmt(cn)} &nbsp;·&nbsp; {fmtDate(validFrom)} – {fmtDate(validTo)}
            </div>
          </div>

          {/* metric tiles */}
          <div className="ssl-hero-tiles">
            <div className="ssl-tile">
              <div className="ssl-tile-icon"><Server className="w-4 h-4" /></div>
              <div className="ssl-tile-label">Port</div>
              <div className="ssl-tile-value">{data.port ?? 443}</div>
              <div className="ssl-tile-sub">HTTPS</div>
            </div>
            <div className="ssl-tile">
              <div className="ssl-tile-icon"><Hash className="w-4 h-4" /></div>
              <div className="ssl-tile-label">ASN</div>
              <div className="ssl-tile-value ssl-tile-value--sm">{fmt(data.asn || subject.serialNumber, 'Unknown')}</div>
              <div className="ssl-tile-sub">{fmt(data.cipher_suite, '—')}</div>
            </div>
            <div className="ssl-tile">
              <div className="ssl-tile-icon"><Building2 className="w-4 h-4" /></div>
              <div className="ssl-tile-label">Organization</div>
              <div className="ssl-tile-value ssl-tile-value--sm">{fmt(issuer.organizationName || issuer.O, 'Unknown')}</div>
              <div className="ssl-tile-sub">{fmt(issuer.localityName || issuer.L)}</div>
            </div>
            <div className="ssl-tile">
              <div className="ssl-tile-icon"><Globe2 className="w-4 h-4" /></div>
              <div className="ssl-tile-label">Country</div>
              <div className="ssl-tile-value ssl-tile-value--sm">{fmt(issuer.countryName || issuer.C, 'Unknown')}</div>
              <div className="ssl-tile-sub">{fmt(issuer.stateOrProvinceName || issuer.ST)}</div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Three detail panels ────────────────────────────────── */}
      <section className="ssl-detail-grid">

        {/* Certificate Info */}
        <div className="ssl-panel">
          <div className="ssl-panel-header">
            <ShieldCheck className="w-4 h-4" />
            <span>Certificate Location</span>
          </div>
          <InfoRow label="Common Name"   value={fmt(cn)}                          mono />
          <InfoRow label="Organization"  value={fmt(issuer.organizationName || issuer.O)} />
          <InfoRow label="Issuer"        value={fmt(issuer.commonName || issuer.CN)} />
          <InfoRow label="Country"       value={fmt(issuer.countryName || issuer.C)} />
          <InfoRow label="State"         value={fmt(issuer.stateOrProvinceName || issuer.ST)} />
          <InfoRow label="Self-Signed"   value={isSelfSigned ? 'Yes' : 'No'} />
        </div>

        {/* Validity */}
        <div className="ssl-panel">
          <div className="ssl-panel-header">
            <Calendar className="w-4 h-4" />
            <span>Validity Period</span>
          </div>
          <InfoRow label="Valid From"    value={fmtDate(validFrom)} />
          <InfoRow label="Valid To"      value={fmtDate(validTo)} />
          <InfoRow label="Days Remaining" value={days != null ? String(days) : '—'} />
          <div className="ssl-days-bar-wrap">
            <div className="ssl-days-bar-track">
              <div className="ssl-days-bar-fill"
                style={{ width: `${Math.min(100, Math.max(2, days > 0 ? Math.min(days, 365) / 365 * 100 : 0))}%`, background: daysColor(days) }} />
            </div>
            <span style={{ color: daysColor(days), fontSize: 11, fontFamily: 'Fira Code, monospace' }}>
              {isExpired ? 'EXPIRED' : days != null ? `${days}d left` : '—'}
            </span>
          </div>
          <InfoRow label="Status" value={isExpired ? 'Expired' : 'Active'} />
        </div>

        {/* Protocol / Cipher */}
        <div className="ssl-panel">
          <div className="ssl-panel-header">
            <Lock className="w-4 h-4" />
            <span>Site Protocols</span>
          </div>
          <InfoRow label="TLS Version"   value={fmt(data.tls_version)} mono />
          <InfoRow label="Cipher Suite"  value={fmt(data.cipher_suite)} mono />
          <InfoRow label="TLS 1.2"       value={data.supports_tls12 ? 'Supported' : 'Not supported'} />
          <InfoRow label="TLS 1.3"       value={data.supports_tls13 ? 'Supported' : 'Not supported'} />
          <InfoRow label="Subject CN"    value={fmt(subject.commonName || subject.CN)} mono />
          <InfoRow label="Serial No."    value={fmt(subject.serialNumber)} mono />
        </div>

      </section>

      {/* ── TLS Protocol cards ─────────────────────────────────── */}
      <section className="ssl-panel">
        <div className="ssl-panel-header">
          <ShieldAlert className="w-4 h-4" />
          <span>TLS Protocol Support</span>
        </div>
        <div className="ssl-tls-grid">
          <TlsCard label="TLS 1.2" supported={!!data.supports_tls12}
            note={data.supports_tls12 ? 'Widely compatible' : 'Older clients may fail'} />
          <TlsCard label="TLS 1.3" supported={!!data.supports_tls13}
            note={data.supports_tls13 ? 'Best performance & security' : 'Upgrade recommended'} />
          <TlsCard label="TLS 1.1" supported={false}
            note="Deprecated — disabled" />
        </div>
      </section>

      {/* ── Subject Alternative Names ───────────────────────────── */}
      {san.length > 0 && (
        <section className="ssl-panel">
          <div className="ssl-panel-header">
            <Globe2 className="w-4 h-4" />
            <span>Subject Alternative Names</span>
            <span className="ssl-panel-count">{san.length}</span>
          </div>
          <div className="ssl-san-grid">
            {san.map((name) => (
              <span key={name} className="ssl-san-tag">{name}</span>
            ))}
          </div>
        </section>
      )}

      {/* ── Export & Share ──────────────────────────────────────── */}
      <section className="ssl-panel ssl-export-panel">
        <div>
          <h3 className="ssl-export-title">Export &amp; Share</h3>
          <p className="ssl-export-sub">Download or share your scan report.</p>
        </div>
        <div className="ssl-export-actions">
          <button type="button" className="ssl-export-btn" onClick={() => window.print()}>
            <FileText className="w-4 h-4" /> Export PDF
          </button>
          <button type="button" className="ssl-export-btn" onClick={exportJson}>
            <FileJson className="w-4 h-4" /> Export JSON
          </button>
          <button type="button" className="ssl-export-btn" onClick={exportCsv}>
            <Download className="w-4 h-4" /> Export CSV
          </button>
          <button type="button" className="ssl-export-btn ssl-export-share" onClick={copyShare}>
            <Share2 className="w-4 h-4" />
            {copied ? 'Copied!' : 'Share Report'}
          </button>
        </div>
      </section>

    </div>
  );
}

/* ─── Main view ──────────────────────────────────────────────────── */
export default function SSL() {
  const [host,    setHost]    = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const run = async () => {
    if (!host.trim()) return;
    setLoading(true);
    setResults(null);
    try {
      const r = await fetch('/api/tools/ssl', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ host: host.trim() }),
      });
      const payload = await r.json();
      if (!r.ok) throw new Error(payload.detail || payload.error || `HTTP ${r.status}`);
      setResults(payload.data || payload);
    } catch (e) {
      setResults({ error: e.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      {/* breadcrumb */}
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><Lock className="w-3 h-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>SSL Check</span>
      </div>

      {/* controls */}
      <div className="scanner-control-shell">
        <div className="relative flex-1 min-w-[260px]">
          <input type="text" className="scan-input"
            placeholder="Domain (e.g. example.com)"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && run()} />
          {host && (
            <button onClick={() => setHost('')} className="clear-input-btn" aria-label="Clear">
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
        <button onClick={run} disabled={loading || !host} className="run-btn">
          <span>{loading ? 'Checking…' : 'Run Scan'}</span>
          {loading
            ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            : <ArrowRight className="w-4 h-4" />}
        </button>
      </div>

      {/* results */}
      <div className="scanner-results-panel flex-1 overflow-auto">
        {results === null ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 p-8">
            <img src="/assets/logo.svg" alt="" className="empty-logo w-auto"
              style={{ opacity: 0.28, filter: 'grayscale(22%) saturate(90%)' }} />
            <span className="text-xs font-medium uppercase" style={{ color: '#6d579b' }}>
              Your SSL results will appear here
            </span>
          </div>
        ) : results.error ? (
          <div className="p-6 text-red-400 font-mono text-sm">{results.error}</div>
        ) : (
          <SSLResults data={results} />
        )}
      </div>
    </div>
  );
}
