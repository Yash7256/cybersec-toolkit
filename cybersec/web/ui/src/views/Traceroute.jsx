import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Activity,
  ArrowRight,
  BarChart3,
  ChevronDown,
  Download,
  FileJson,
  FileText,
  Gauge,
  Network,
  Radio,
  Route,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react';

/* ─── helpers ───────────────────────────────────────────────────── */
const roundMs = (v) => (Number.isFinite(v) ? Number(v.toFixed(1)) : null);

const hopColor = (hop) => {
  if (hop.is_hidden) return '#64748b';
  const q = hop.quality_color;
  if (q === 'green')  return '#34d399';
  if (q === 'cyan')   return '#22d3ee';
  if (q === 'yellow') return '#fbbf24';
  if (q === 'red')    return '#f87171';
  return '#a78bfa';
};

const locationLabel = (hop) =>
  [hop.city, hop.region, hop.country_code || hop.country].filter(Boolean).join(', ');

const traceSignature = (data) =>
  (data?.hops || []).map((h) => h.ip || '*').join('>');

const calcLiveResult = (prev, next) => {
  const prevSig = traceSignature(prev);
  const nextSig = traceSignature(next);
  const routeChanged = Boolean(prevSig && nextSig && prevSig !== nextSig);
  const prevFinal = (prev?.hops || []).filter((h) => h.rtt_ms != null).at(-1)?.rtt_ms;
  const nextFinal = (next?.hops || []).filter((h) => h.rtt_ms != null).at(-1)?.rtt_ms;
  const delta = Number.isFinite(prevFinal) && Number.isFinite(nextFinal)
    ? roundMs(nextFinal - prevFinal) : null;
  return {
    ...next,
    live_samples: (prev?.live_samples || 1) + 1,
    route_changed: routeChanged,
    route_change_summary: routeChanged
      ? 'Route path changed during live monitoring.'
      : 'Route path unchanged during live monitoring.',
    final_latency_delta_ms: delta,
    live_started: prev?.live_started || 'active',
  };
};

/* ─── StatusChip ────────────────────────────────────────────────── */
function StatusChip({ label, tone = 'neutral' }) {
  const tones = {
    good:    'bg-[rgba(52,211,153,0.12)] text-[#34d399] border-[rgba(52,211,153,0.3)]',
    warn:    'bg-[rgba(251,191,36,0.12)] text-[#fbbf24] border-[rgba(251,191,36,0.3)]',
    bad:     'bg-[rgba(248,113,113,0.12)] text-[#f87171] border-[rgba(248,113,113,0.3)]',
    info:    'bg-[rgba(34,211,238,0.12)] text-[#22d3ee] border-[rgba(34,211,238,0.3)]',
    neutral: 'bg-[rgba(167,139,250,0.1)] text-[#c4b5fd] border-[rgba(167,139,250,0.28)]',
    high:    'bg-[rgba(52,211,153,0.14)] text-[#34d399] border-[rgba(52,211,153,0.35)]',
  };
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full border text-[10px] font-mono font-semibold uppercase tracking-wide ${tones[tone] || tones.neutral}`}>
      {label}
    </span>
  );
}

/* ─── MetricCard ─────────────────────────────────────────────────── */
function MetricCard({ icon: Icon, label, value, sub, accent }) {
  return (
    <div className="tr-metric-card">
      <div className="tr-metric-label"><Icon className="w-3.5 h-3.5" />{label}</div>
      <div className="tr-metric-value" style={accent ? { color: accent } : {}}>{value ?? '—'}</div>
      {sub && <div className="tr-metric-sub">{sub}</div>}
    </div>
  );
}

/* ─── HopRow ─────────────────────────────────────────────────────── */
function HopRow({ hop, index, total, expanded, onToggle }) {
  const color = hopColor(hop);
  const loc = locationLabel(hop);
  const isLast = index === total - 1;
  const chipTone = hop.is_hidden ? 'neutral'
    : hop.quality_color === 'red' ? 'bad'
    : hop.quality_color === 'yellow' ? 'warn' : 'good';

  return (
    <div className="tr-hop-row">
      <div className="tr-hop-stem">
        <div className="tr-hop-badge" style={{ borderColor: color, color, boxShadow: `0 0 18px ${color}44` }}>
          {hop.hop}
        </div>
        {!isLast && (
          <>
            <div className="tr-hop-line" />
            <span className="tr-hop-pulse" style={{ background: color, boxShadow: `0 0 14px ${color}cc` }} />
          </>
        )}
      </div>
      <div className="tr-hop-content">
        <button type="button" className="tr-hop-header" onClick={onToggle} aria-expanded={expanded}>
          <div className="tr-hop-title-row">
            <span className="tr-hop-ip">{hop.is_hidden ? 'No ICMP response' : hop.ip}</span>
            <StatusChip label={hop.quality || 'Unknown'} tone={chipTone} />
            {hop.hop_type && <StatusChip label={hop.hop_type} tone="info" />}
          </div>
          <div className="tr-hop-meta">
            {[loc, hop.provider, hop.asn, hop.hostname].filter(Boolean).join(' · ') || hop.hidden_reason || 'Public router'}
          </div>
          {hop.latency_added_ms >= 40 && (
            <div className="tr-hop-spike">⚡ Latency spike: +{hop.latency_added_ms}ms at this hop</div>
          )}
          <ChevronDown className={`tr-hop-chevron ${expanded ? 'rotate-180' : ''}`} />
        </button>
        {expanded && (
          <div className="tr-hop-details">
            {[
              ['RTT',         hop.rtt_ms != null ? `${hop.rtt_ms} ms` : 'Filtered'],
              ['Hostname',    hop.hostname],
              ['Provider',    hop.provider],
              ['ASN',         hop.asn],
              ['Location',    loc],
              ['Packet Loss', `${hop.packet_loss_pct ?? 0}%`],
              ['Samples',     hop.rtt_samples_ms ? String(hop.rtt_samples_ms) : null],
              ['Hop Type',    hop.hop_type],
              ['Insight',     hop.insight || hop.hidden_reason],
            ].map(([l, v]) => v ? (
              <div key={l} className="tr-detail-row">
                <span>{l}</span>
                <strong>{v}</strong>
              </div>
            ) : null)}
          </div>
        )}
      </div>
    </div>
  );
}

function HopTimeline({ hops }) {
  const [expandedHops, setExpandedHops] = useState({});
  const toggle = (idx) => setExpandedHops((p) => ({ ...p, [idx]: !p[idx] }));
  return (
    <div className="tr-hops-list">
      {hops.map((hop, i) => (
        <HopRow key={`${hop.hop}-${hop.ip || 'x'}`} hop={hop} index={i} total={hops.length}
          expanded={!!expandedHops[i]} onToggle={() => toggle(i)} />
      ))}
    </div>
  );
}

/* ─── Segment Breakdown ──────────────────────────────────────────── */
function buildSegments(hops) {
  if (!hops.length) return [];
  const segments = [];
  let start = 0;
  const types = hops.map((h) => h.hop_type || (h.is_hidden ? 'filtered' : 'transit'));
  while (start < hops.length) {
    let end = start;
    while (end + 1 < hops.length && types[end + 1] === types[start]) end++;
    const slice = hops.slice(start, end + 1);
    const rtts  = slice.filter((h) => h.rtt_ms != null).map((h) => Number(h.rtt_ms));
    const avgRtt = rtts.length ? rtts.reduce((a, b) => a + b, 0) / rtts.length : null;
    const firstLoc = [slice[0].city, slice[0].country_code].filter(Boolean).join(', ');
    const lastLoc  = [slice.at(-1).city, slice.at(-1).country_code].filter(Boolean).join(', ');
    segments.push({
      type:     types[start],
      label:    types[start].replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
      hopRange: slice.length === 1 ? `Hop ${slice[0].hop}` : `Hop ${slice[0].hop}–${slice.at(-1).hop}`,
      avgRtt,
      location: firstLoc && lastLoc && firstLoc !== lastLoc
        ? `${firstLoc} → ${lastLoc}` : firstLoc || lastLoc || null,
      loss: Math.round(slice.filter((h) => h.is_hidden).length / slice.length * 100),
    });
    start = end + 1;
  }
  return segments;
}

function segmentColor(type) {
  const t = (type || '').toLowerCase();
  if (t.includes('local'))             return { bar: '#a78bfa', badge: 'rgba(167,139,250,0.15)', text: '#a78bfa', border: 'rgba(167,139,250,0.3)' };
  if (t.includes('cdn') || t.includes('cloud'))
                                       return { bar: '#22d3ee', badge: 'rgba(34,211,238,0.12)',  text: '#22d3ee', border: 'rgba(34,211,238,0.28)' };
  if (t.includes('backbone') || t.includes('isp'))
                                       return { bar: '#34d399', badge: 'rgba(52,211,153,0.12)',  text: '#34d399', border: 'rgba(52,211,153,0.28)' };
  if (t.includes('filtered') || t.includes('hidden'))
                                       return { bar: '#64748b', badge: 'rgba(100,116,139,0.12)', text: '#64748b', border: 'rgba(100,116,139,0.22)' };
  return                                      { bar: '#fbbf24', badge: 'rgba(251,191,36,0.1)',   text: '#fbbf24', border: 'rgba(251,191,36,0.25)' };
}

function SegmentBreakdown({ hops }) {
  const segments = buildSegments(hops);
  if (!segments.length) return <p className="tr-empty-note">No segments yet</p>;
  return (
    <div className="tr-segment-list">
      {segments.map((seg, i) => {
        const c = segmentColor(seg.type);
        return (
          <div key={i} className="tr-segment-row">
            <div className="tr-segment-bar-wrap">
              <div className="tr-segment-bar" style={{ background: c.bar, boxShadow: `0 0 8px ${c.bar}55` }} />
            </div>
            <div className="tr-segment-info">
              <div className="tr-segment-top">
                <span className="tr-segment-name" style={{ background: c.badge, color: c.text, borderColor: c.border }}>
                  {seg.label}
                </span>
                <span className="tr-segment-hops">{seg.hopRange}</span>
              </div>
              <div className="tr-segment-meta">
                {seg.avgRtt != null && <span>Avg latency <strong>{seg.avgRtt.toFixed(1)} ms</strong></span>}
                {seg.location && <span>{seg.location}</span>}
                {seg.loss > 0  && <span className="text-[#f87171]">{seg.loss}% loss</span>}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ─── ASN / Provider Flow (vertical blocks, Figma-style) ─────────── */
function AsnFlowDiagram({ hops }) {
  const seen = new Set();
  const nodes = [];
  hops.forEach((h) => {
    const key = h.asn || h.provider || (h.is_hidden ? '* hidden' : null);
    if (!key || seen.has(key)) return;
    seen.add(key);
    // derive segment type from the hop to colour the block
    const type = h.hop_type || (h.is_hidden ? 'filtered' : 'transit');
    nodes.push({ key, asn: h.asn, provider: h.provider, type, color: hopColor(h) });
  });

  if (!nodes.length) return <p className="tr-empty-note">No ASN data available</p>;

  return (
    <div className="tr-asn-flow-vertical">
      {nodes.map((n, i) => {
        const c = segmentColor(n.type);
        return (
          <div key={n.key} className="tr-asn-flow-entry">
            {/* colored block */}
            <div className="tr-asn-block" style={{ background: c.badge, borderColor: c.border, boxShadow: `0 0 18px ${c.bar}22` }}>
              <span className="tr-asn-block-provider" style={{ color: c.text }}>
                {n.provider || n.asn || 'Unknown'}
              </span>
              {n.asn && n.provider && (
                <span className="tr-asn-block-asn">{n.asn}</span>
              )}
            </div>
            {/* connector arrow */}
            {i < nodes.length - 1 && (
              <div className="tr-asn-connector">
                <div className="tr-asn-connector-line" />
                <ChevronDown className="w-3 h-3 text-[#5a4d72] mt-[-2px]" />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ─── MITRE Attack Mapping ───────────────────────────────────────── */
function MitrePanel({ hops, routeRisk }) {
  // Build findings from hop data
  const findings = [];
  hops.forEach((h) => {
    if (h.latency_added_ms >= 60)
      findings.push({ hop: h.hop, label: `Hop ${h.hop} — Latency increased by +${h.latency_added_ms}ms`, severity: 'warn' });
    if (h.packet_loss_pct > 10)
      findings.push({ hop: h.hop, label: `Hop ${h.hop} — ${h.packet_loss_pct}% probe loss detected`, severity: 'bad' });
    if (h.is_hidden)
      findings.push({ hop: h.hop, label: `Hop ${h.hop} — ICMP suppressed (firewall / filtering)`, severity: 'neutral' });
  });

  if (!findings.length) return <p className="tr-empty-note">No anomalies detected on this route</p>;

  const colors = { warn: '#fbbf24', bad: '#f87171', neutral: '#8b7ec8' };
  return (
    <ul className="tr-mitre-list">
      {findings.map((f, i) => (
        <li key={i} className="tr-mitre-item" style={{ '--dot-color': colors[f.severity] }}>
          <span className="tr-mitre-dot" style={{ background: colors[f.severity], boxShadow: `0 0 6px ${colors[f.severity]}88` }} />
          <span style={{ color: colors[f.severity] }}>{f.label}</span>
        </li>
      ))}
      {routeRisk && (
        <li className="tr-mitre-item tr-mitre-summary">
          <span className="tr-mitre-dot" style={{ background: '#a78bfa' }} />
          <span className="text-[#c4b5fd]">Overall risk: <strong style={{ color: '#e9d5ff' }}>{routeRisk}</strong></span>
        </li>
      )}
    </ul>
  );
}

/* ─── Monitoring tab ─────────────────────────────────────────────── */
function MonitoringTab({ data, liveMode, hops }) {
  const visible = hops.filter((h) => h.rtt_ms != null);
  const finalHop = visible.at(-1);
  const maxRtt = Math.max(10, ...visible.map((h) => Number(h.rtt_ms)));

  const stabilityColor = (s) => {
    if (s == null) return '#a78bfa';
    if (s >= 80) return '#34d399';
    if (s >= 55) return '#fbbf24';
    return '#f87171';
  };

  return (
    <div className="tr-tab-body">
      {/* stat tiles */}
      <div className="tr-stat-grid">
        <MetricCard icon={Gauge}       label="Route Stability"
          value={data.route_stability_score != null ? `${data.route_stability_score}/100` : '—'}
          sub={data.route_efficiency}
          accent={stabilityColor(data.route_stability_score)} />
        <MetricCard icon={Activity}    label="Final Latency"
          value={finalHop?.rtt_ms != null ? `${finalHop.rtt_ms} ms` : 'Hidden'}
          sub="Last visible hop" />
        <MetricCard icon={Route}       label="Visible Hops"
          value={`${visible.length}/${hops.length}`}
          sub={`${data.hidden_hops || 0} filtered`} />
        <MetricCard icon={ShieldAlert} label="Loss Hops"
          value={data.packet_loss_hops ?? 0}
          sub="Probe non-response" />
        {liveMode && (
          <MetricCard icon={Radio} label="Live Samples" value={data.live_samples ?? 1} sub="Active" />
        )}
      </div>

      {/* RTT bar chart */}
      <div className="tr-panel">
        <div className="tr-card-header"><BarChart3 className="w-4 h-4" /><span>Hop Response Time</span></div>
        <div className="space-y-2.5">
          {hops.map((hop) => (
            <div key={`bar${hop.hop}`} className="grid grid-cols-[52px_1fr_72px] items-center gap-3">
              <span className="text-[11px] font-mono text-[#7a6d8a]">Hop {hop.hop}</span>
              <div className="h-2.5 rounded-full bg-[rgba(124,58,237,0.14)] overflow-hidden">
                <div className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${hop.rtt_ms == null ? 3 : Math.max(4, (hop.rtt_ms / maxRtt) * 100)}%`,
                    background: hopColor(hop),
                    boxShadow: `0 0 14px ${hopColor(hop)}55`,
                  }} />
              </div>
              <span className="text-[11px] font-mono text-[#c4b5fd] text-right">
                {hop.rtt_ms == null ? 'Filtered' : `${hop.rtt_ms} ms`}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* routing intelligence */}
      <div className="tr-panel">
        <div className="tr-card-header"><ShieldCheck className="w-4 h-4" /><span>Routing Intelligence</span></div>
        <div className="tr-intel-list">
          {[
            ...(data.routing_intelligence || []),
            ...(data.security_insights || []),
            ...(data.route_risk_factors || []),
            data.route_change_summary,
          ].filter(Boolean).map((item, i) => (
            <div key={i} className="tr-intel-item">{item}</div>
          ))}
          {!data.routing_intelligence?.length && !data.security_insights?.length && (
            <p className="tr-empty-note">No routing intelligence yet.</p>
          )}
        </div>
      </div>

      {/* hop timeline */}
      <div className="tr-panel">
        <div className="tr-card-header">
          <Route className="w-4 h-4" /><span>Hop Timeline</span>
          <span className="tr-card-header-sub ml-auto">{data.route_efficiency || ''}</span>
        </div>
        <HopTimeline hops={hops} />
      </div>
    </div>
  );
}

/* ─── TracerouteResults ──────────────────────────────────────────── */
function TracerouteResults({ data, liveMode }) {
  const [activeTab, setActiveTab] = useState('network');
  const hops = Array.isArray(data.hops) ? data.hops : [];
  const visible = hops.filter((h) => h.rtt_ms != null);

  /* confidence badge */
  const confidence = data.ai_confidence || data.confidence;
  const confidenceLabel = confidence
    ? String(confidence).toUpperCase()
    : hops.length >= 8 ? 'HIGH' : hops.length >= 4 ? 'MEDIUM' : 'LOW';
  const confidenceTone = confidenceLabel === 'HIGH' ? 'high' : confidenceLabel === 'MEDIUM' ? 'warn' : 'neutral';

  /* export helpers */
  const exportJson = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `traceroute-${data.target || 'result'}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const exportCsv = () => {
    const rows = [['Hop','IP','Hostname','RTT (ms)','Provider','ASN','Location','Quality','Loss %']];
    hops.forEach((h) => rows.push([
      h.hop, h.ip || '*', h.hostname || '', h.rtt_ms ?? '',
      h.provider || '', h.asn || '', locationLabel(h),
      h.quality || '', h.packet_loss_pct ?? 0,
    ]));
    const csv  = rows.map((r) => r.map((c) => `"${String(c).replaceAll('"','""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `traceroute-${data.target || 'result'}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  const copyShare = async () => {
    const text = `Traceroute: ${data.target}\n` +
      hops.map((h) => `Hop ${h.hop}: ${h.ip || '*'} ${h.rtt_ms != null ? h.rtt_ms + 'ms' : 'filtered'} ${locationLabel(h)}`).join('\n');
    await navigator.clipboard.writeText(text).catch(() => {});
  };

  /* AI summary bullet lines */
  const aiLines = data.ai_summary
    ? data.ai_summary.split(/\.\s+/).filter(Boolean).map((s) => s.replace(/\.$/, ''))
    : [
        `This traceroute reveals a route to ${data.target || 'the destination'}.`,
        visible.length > 0 ? `${visible.length} of ${hops.length} hops responded to probes.` : null,
        data.route_risk ? `Route risk is assessed as ${data.route_risk}.` : null,
        data.cdn_detected ? `CDN detected: ${data.cdn_detected}.` : null,
        ...(data.routing_intelligence || []).slice(0, 3),
      ].filter(Boolean);

  return (
    <div className="tr-results">

      {/* ── tab bar ──────────────────────────────────────────────── */}
      <div className="tr-tab-bar">
        <button type="button" className={`tr-tab ${activeTab === 'network' ? 'active' : ''}`}
          onClick={() => setActiveTab('network')}>
          <Network className="w-3.5 h-3.5" />
          Network Analysis
        </button>
        <button type="button" className={`tr-tab ${activeTab === 'monitoring' ? 'active' : ''}`}
          onClick={() => setActiveTab('monitoring')}>
          <Activity className="w-3.5 h-3.5" />
          Monitoring &amp; Reporting
          {liveMode && <span className="tr-tab-live-dot" />}
        </button>
      </div>

      {/* ── NETWORK ANALYSIS TAB ─────────────────────────────────── */}
      {activeTab === 'network' && (
        <div className="tr-tab-body">

          {/* three-column row */}
          <div className="tr-analysis-grid">

            {/* col 1 — Segment Breakdown */}
            <div className="tr-panel">
              <div className="tr-card-header">
                <BarChart3 className="w-4 h-4" />
                <span>Segment Breakdown</span>
              </div>
              <SegmentBreakdown hops={hops} />
            </div>

            {/* col 2 — ASN / Provider Flow */}
            <div className="tr-panel">
              <div className="tr-card-header">
                <Share2 className="w-4 h-4" />
                <span>ASN / Provider Flow</span>
              </div>
              <AsnFlowDiagram hops={hops} />
            </div>

            {/* col 3 — MITRE Attack Mapping */}
            <div className="tr-panel">
              <div className="tr-card-header">
                <ShieldAlert className="w-4 h-4" />
                <span>MITRE Attack Mapping</span>
                {data.route_risk && (
                  <span className="tr-card-header-badge">{data.route_risk}</span>
                )}
              </div>
              <MitrePanel hops={hops} routeRisk={data.route_risk} />
            </div>

          </div>

          {/* AI Summary */}
          <div className="tr-ai-panel">
            <div className="tr-ai-header">
              <div className="tr-ai-icon-wrap">
                <Sparkles className="w-4 h-4" />
              </div>
              <span className="tr-ai-title">AI Summary</span>
              <div className="ml-auto">
                <StatusChip label={`Confidence: ${confidenceLabel}`} tone={confidenceTone} />
              </div>
            </div>
            <ul className="tr-ai-lines">
              {aiLines.map((line, i) => (
                <li key={i} className="tr-ai-line">
                  <span className="tr-ai-line-dot" />
                  <span>{line}.</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Export & Share */}
          <div className="tr-export-panel">
            <div>
              <h3 className="tr-export-title">Export &amp; Share</h3>
              <p className="tr-export-sub">Download or share your scan report.</p>
            </div>
            <div className="tr-export-actions">
              <button type="button" className="tr-export-btn" onClick={() => window.print()}>
                <FileText className="w-4 h-4" /> Export PDF
              </button>
              <button type="button" className="tr-export-btn" onClick={exportJson}>
                <FileJson className="w-4 h-4" /> Export JSON
              </button>
              <button type="button" className="tr-export-btn" onClick={exportCsv}>
                <Download className="w-4 h-4" /> Export CSV
              </button>
              <button type="button" className="tr-export-btn tr-export-share" onClick={copyShare}>
                <Share2 className="w-4 h-4" /> Share Report
              </button>
            </div>
          </div>

        </div>
      )}

      {/* ── MONITORING & REPORTING TAB ───────────────────────────── */}
      {activeTab === 'monitoring' && (
        <MonitoringTab data={data} liveMode={liveMode} hops={hops} />
      )}

    </div>
  );
}

/* ─── Main view ──────────────────────────────────────────────────── */
export default function Traceroute() {
  const [target,   setTarget]   = useState('');
  const [maxHops,  setMaxHops]  = useState(30);
  const [liveMode, setLiveMode] = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [results,  setResults]  = useState(null);
  const liveRef = useRef(false);

  const run = useCallback(async ({ silent = false, appendLive = false } = {}) => {
    if (!target) return;
    if (appendLive && liveRef.current) return;
    if (appendLive) liveRef.current = true;
    if (!silent) setLoading(true);
    try {
      const r = await fetch('/api/tools/traceroute', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ target, max_hops: maxHops }),
      });
      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        throw new Error(err.detail || err.error || `HTTP ${r.status}`);
      }
      const payload = await r.json();
      const next    = payload.data || payload;
      setResults((prev) =>
        appendLive && prev && !prev.error ? calcLiveResult(prev, next) : next,
      );
    } catch (e) {
      setResults((prev) =>
        appendLive && prev && !prev.error
          ? { ...prev, live_error: e.message }
          : { error: e.message },
      );
    } finally {
      if (appendLive) liveRef.current = false;
      if (!silent) setLoading(false);
    }
  }, [target, maxHops]);

  useEffect(() => {
    if (!liveMode || !target) return undefined;
    const id = window.setInterval(() => run({ silent: true, appendLive: true }), 7000);
    return () => window.clearInterval(id);
  }, [liveMode, target, run]);

  const toggleLive = () => {
    if (!target) return;
    if (liveMode) { setLiveMode(false); liveRef.current = false; return; }
    setResults(null);
    setLiveMode(true);
    run({ silent: false, appendLive: true });
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      {/* breadcrumb */}
      <div className="scanner-title-row flex items-center">
        <span className="breadcrumb-dot"><Route className="w-3 h-3" /></span>
        <span className="text-xs font-medium" style={{ color: '#a98be8' }}>Traceroute</span>
      </div>

      {/* controls */}
      <div className="scanner-control-shell">
        <div className="relative flex-1 min-w-[260px]">
          <input type="text" className="scan-input"
            placeholder="Hostname or IP (e.g. example.com)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && run()} />
          {target && (
            <button onClick={() => setTarget('')} className="clear-input-btn" aria-label="Clear">
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        <select className="scan-select" style={{ maxWidth: 148 }}
          value={maxHops} onChange={(e) => setMaxHops(Number(e.target.value))} aria-label="Max hops">
          {[15, 20, 25, 30, 40, 64].map((n) => (
            <option key={n} value={n}>{n} hops</option>
          ))}
        </select>

        <button type="button" onClick={toggleLive} disabled={!target}
          className={`tr-live-btn ${liveMode ? 'active' : ''}`}
          title={liveMode ? 'Stop live monitoring' : 'Start live monitoring'}>
          <Radio className="w-4 h-4" />
          <span>{liveMode ? 'Live On' : 'Live'}</span>
        </button>

        <button onClick={() => run()} disabled={loading || !target} className="run-btn">
          <span>{loading ? 'Tracing…' : 'Trace Route'}</span>
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
              Your traceroute results will appear here
            </span>
          </div>
        ) : results.error ? (
          <div className="p-6 text-red-400 font-mono text-sm">{results.error}</div>
        ) : (
          <TracerouteResults data={results} liveMode={liveMode} />
        )}
      </div>
    </div>
  );
}
