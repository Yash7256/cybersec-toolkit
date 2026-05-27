import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Activity,
  ArrowRight,
  BarChart3,
  Building2,
  CheckCircle2,
  CircleDot,
  Cloud,
  Cpu,
  Database,
  ExternalLink,
  FileText,
  Fingerprint,
  Gauge,
  Globe2,
  Heading,
  Info,
  Lock,
  MapPin,
  Network,
  Radio,
  Route,
  Search,
  Server,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Timer,
  X,
  Zap,
} from 'lucide-react';

const TOOL_META = {
  ping:       { name: 'Ping',        icon: Zap,     endpoint: '/api/tools/ping',         param: 'target', placeholder: 'Hostname or IP (e.g. 8.8.8.8)' },
  traceroute: { name: 'Traceroute',  icon: Route,   endpoint: '/api/tools/traceroute',   param: 'target', placeholder: 'Hostname or IP (e.g. example.com)' },
  ssl:        { name: 'SSL Check',   icon: Lock,    endpoint: '/api/tools/ssl',          param: 'host',   placeholder: 'Domain (e.g. example.com)' },
  headers:    { name: 'HTTP Headers',icon: Heading, endpoint: '/api/tools/http_headers', param: 'target', placeholder: 'URL (e.g. https://example.com)' },
  subdomains: { name: 'Subdomains',  icon: Search,  endpoint: '/api/tools/subdomain',    param: 'domain', placeholder: 'Domain (e.g. example.com)' },
  geo:        { name: 'GeoIP',       icon: MapPin,  endpoint: '/api/tools/geoip',        param: 'target', placeholder: 'Public IP address or hostname (e.g. 8.8.8.8)' },
  osfingerprint: { name: 'OS Fingerprinting', icon: Fingerprint, endpoint: '/api/tools/os-fingerprint', param: 'target', placeholder: 'Hostname or IP (e.g. scanme.nmap.org)' },
};

const PING_LIVE_WINDOW = 48;

const roundMetric = (value, digits = 2) => (
  Number.isFinite(value) ? Number(value.toFixed(digits)) : null
);

const classifyPingQuality = (avg) => {
  if (avg == null) return 'Unknown';
  if (avg <= 20) return 'Excellent';
  if (avg <= 50) return 'Good';
  if (avg <= 100) return 'Moderate';
  return 'Poor';
};

const classifyLossSeverity = (loss) => {
  if (loss <= 0) return 'Stable';
  if (loss <= 2) return 'Minor';
  if (loss <= 5) return 'Noticeable';
  return 'Severe';
};

const classifyJitter = (jitter) => {
  if (jitter == null) return 'Unknown';
  if (jitter <= 5) return 'Stable';
  if (jitter <= 20) return 'Variable';
  return 'Unstable';
};

const summarizeLiveDistribution = (values) => {
  if (!values.length) return null;
  if (values.length === 1) return `Single response at ${values[0].toFixed(1)}ms`;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted[Math.floor(sorted.length / 2)];
  const near = sorted.filter((value) => Math.abs(value - mid) <= Math.max(2, mid * 0.12));
  if (near.length >= Math.max(2, Math.floor(values.length / 2))) {
    return `Most responses between ${Math.min(...near).toFixed(1)}-${Math.max(...near).toFixed(1)}ms`;
  }
  return `Responses ranged from ${Math.min(...values).toFixed(1)}-${Math.max(...values).toFixed(1)}ms`;
};

const detectLiveTrend = (values, loss) => {
  if (loss >= 5) return 'Packet loss detected';
  if (values.length < 3) return 'Collecting live samples';
  const baseline = [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
  if (values.some((value) => value > baseline * 1.8 && value - baseline > 20)) return 'Latency spike detected';
  if (values[values.length - 1] > values[0] + Math.max(15, values[0] * 0.4)) return 'Connection becoming slower';
  if (Math.max(...values) - Math.min(...values) <= Math.max(3, baseline * 0.15)) return 'Consistent latency';
  return 'Minor latency variation';
};

const calculateLivePingResult = (previous, next) => {
  const prevTimeline = Array.isArray(previous?.response_timeline) ? previous.response_timeline : [];
  const nextTimeline = Array.isArray(next?.response_timeline) ? next.response_timeline : [];
  const combined = [...prevTimeline, ...nextTimeline]
    .slice(-PING_LIVE_WINDOW)
    .map((item, index) => ({ ...item, packet: index + 1 }));
  const values = combined
    .map((item) => Number(item.latency_ms))
    .filter((value) => Number.isFinite(value));
  const sent = combined.length;
  const received = values.length;
  const loss = sent ? ((sent - received) / sent) * 100 : 0;
  const avg = values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
  const jitter = values.length > 1
    ? values.slice(1).reduce((sum, value, index) => sum + Math.abs(value - values[index]), 0) / (values.length - 1)
    : null;
  const variance = values.length > 1
    ? values.reduce((sum, value) => sum + ((value - avg) ** 2), 0) / values.length
    : values.length ? 0 : null;
  const stddev = variance == null ? null : Math.sqrt(variance);
  const stability = Math.max(0, Math.min(100, Math.round(
    100
    - Math.min(55, loss * 9)
    - (jitter == null ? 0 : Math.min(25, jitter * 1.5))
    - (stddev == null ? 0 : Math.min(15, stddev))
    - (avg != null && avg > 100 ? Math.min(20, (avg - 100) / 10) : 0)
  )));

  return {
    ...next,
    response_timeline: combined,
    packets_sent: sent,
    packets_received: received,
    packet_loss_pct: roundMetric(loss),
    min_ms: values.length ? roundMetric(Math.min(...values)) : null,
    avg_ms: roundMetric(avg),
    max_ms: values.length ? roundMetric(Math.max(...values)) : null,
    jitter_ms: roundMetric(jitter),
    jitter_label: classifyJitter(jitter),
    packet_loss_severity: classifyLossSeverity(loss),
    connection_quality: classifyPingQuality(avg),
    availability_pct: sent ? roundMetric((received / sent) * 100, 1) : 0,
    std_deviation_ms: roundMetric(stddev),
    variance_ms: roundMetric(variance),
    latency_distribution: summarizeLiveDistribution(values),
    latency_trend: detectLiveTrend(values, loss),
    stability_score: stability,
    heat_indicator: stability >= 85 ? 'green' : stability >= 65 ? 'yellow' : 'red',
    status_badges: [
      received ? 'ONLINE' : 'OFFLINE',
      received ? (stability >= 85 ? 'STABLE' : stability >= 65 ? 'VARIABLE' : 'UNSTABLE') : null,
      avg != null && avg <= 50 ? 'LOW LATENCY' : avg != null && avg > 100 ? 'HIGH LATENCY' : null,
    ].filter(Boolean),
    last_checked: 'live',
  };
};

const traceRouteSignature = (data) => (
  (data?.hops || []).map((hop) => hop.ip || '*').join('>')
);

const calculateLiveTracerouteResult = (previous, next) => {
  const previousSignature = traceRouteSignature(previous);
  const nextSignature = traceRouteSignature(next);
  const routeChanged = Boolean(previousSignature && nextSignature && previousSignature !== nextSignature);
  const previousVisible = (previous?.hops || []).filter((hop) => hop?.rtt_ms != null);
  const nextVisible = (next?.hops || []).filter((hop) => hop?.rtt_ms != null);
  const previousFinal = previousVisible.at(-1)?.rtt_ms;
  const nextFinal = nextVisible.at(-1)?.rtt_ms;
  const latencyDelta = Number.isFinite(previousFinal) && Number.isFinite(nextFinal)
    ? roundMetric(nextFinal - previousFinal, 1)
    : null;
  return {
    ...next,
    live_samples: (previous?.live_samples || 1) + 1,
    route_changed: routeChanged,
    previous_route_signature: previousSignature || null,
    current_route_signature: nextSignature || null,
    route_change_summary: routeChanged ? 'Route path changed during live monitoring.' : 'Route path unchanged during live monitoring.',
    final_latency_delta_ms: latencyDelta,
    live_started: previous?.live_started || 'active',
  };
};

export default function GenericTool({ toolId }) {
  const meta = TOOL_META[toolId];
  const [target, setTarget] = useState('');
  const [count, setCount] = useState(4);
  const [maxHops, setMaxHops] = useState(30);
  const [liveMode, setLiveMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [copied, setCopied] = useState('');
  const liveRequestActive = useRef(false);

  const Icon = meta?.icon;

  const run = useCallback(async ({ silent = false, appendLive = false } = {}) => {
    if (!target || !meta) return;
    if (appendLive && liveRequestActive.current) return;
    if (appendLive) liveRequestActive.current = true;
    if (!silent) setLoading(true);
    try {
      const body = { [meta.param]: target };
      if (toolId === 'ping') body.count = count;
      if (toolId === 'traceroute') body.max_hops = maxHops;
      const r = await fetch(meta.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const contentType = r.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        throw new Error(`Expected JSON from ${meta.endpoint}, but received ${contentType || 'an HTML response'}. Check that the API server is running and the Vite proxy is pointing at it.`);
      }
      const payload = await r.json();
      if (!r.ok) {
        throw new Error(payload.detail || payload.error || `Request failed with HTTP ${r.status}`);
      }
      const nextData = payload.data || payload;
      setResults((previous) => (
        appendLive && toolId === 'ping' && previous && !previous.error
          ? calculateLivePingResult(previous, nextData)
          : appendLive && toolId === 'traceroute' && previous && !previous.error
            ? calculateLiveTracerouteResult(previous, nextData)
          : nextData
      ));
    } catch (e) {
      setResults((previous) => (appendLive && previous && !previous.error ? { ...previous, live_error: e.message } : { error: e.message }));
    } finally {
      if (appendLive) liveRequestActive.current = false;
      if (!silent) setLoading(false);
    }
  }, [count, maxHops, meta, target, toolId]);

  useEffect(() => {
    if (!['ping', 'traceroute'].includes(toolId) || !liveMode || !target) return undefined;
    const id = window.setInterval(() => run({ silent: true, appendLive: true }), toolId === 'traceroute' ? 7000 : 3000);
    return () => window.clearInterval(id);
  }, [toolId, liveMode, target, run]);

  if (!meta) return <div className="text-gray-500 text-center mt-20">Tool not found: {toolId}</div>;

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

  const copyText = async (label, text) => {
    if (!text) return;
    await navigator.clipboard.writeText(text);
    setCopied(label);
    window.setTimeout(() => setCopied(''), 1200);
  };

  const toggleLiveMode = () => {
    if (!target) return;
    if (liveMode) {
      setLiveMode(false);
      liveRequestActive.current = false;
      return;
    }
    setResults(null);
    setLiveMode(true);
    run({ silent: false, appendLive: true });
  };

  const hasCoordinates = (data) => Number.isFinite(Number(data.lat)) && Number.isFinite(Number(data.lon));

  const renderLocationDetail = (label, value) => {
    if (value === null || value === undefined || value === '') return null;
    return (
      <div className="grid grid-cols-[120px_minmax(0,1fr)] items-center gap-4 border-b border-[#554365]/55 py-2.5 last:border-b-0">
        <span className="text-[11px] text-[#92859d]">{label}</span>
        <span className="text-[11px] text-[#ded4e9] break-words">{String(value)}</span>
      </div>
    );
  };

  const geoText = (value, fallback = 'Unknown') => (
    value === null || value === undefined || value === '' ? fallback : String(value)
  );

  const geoBool = (value) => (value === true ? 'Yes' : value === false ? 'No' : 'Unknown');

  const geoCard = (title, children, IconCmp = CircleDot) => (
    <div className="rounded-lg border border-[#63516e]/80 bg-[#13091f]/78 p-5">
      <div className="mb-4 flex items-center gap-3 text-[11px] font-semibold uppercase text-[#b79aff]">
        <IconCmp className="h-4 w-4" />
        <span>{title}</span>
      </div>
      {children}
    </div>
  );

  const geoInfoRow = (label, value) => (
    <div className="grid grid-cols-[116px_minmax(0,1fr)] gap-3 border-b border-[#554365]/55 py-2.5 last:border-b-0">
      <span className="text-[11px] text-[#8f839b]">{label}</span>
      <span className="whitespace-pre-line text-[11px] text-[#ded4e9] break-words">{geoText(value)}</span>
    </div>
  );

  const geoMetricTile = (IconCmp, title, value, subtext, extra) => (
    <div className="min-h-[84px] rounded-lg border border-[#5f4c6c]/80 bg-[#13091f]/72 p-4">
      <div className="flex items-center gap-2 text-[10px] font-bold text-[#efe9f5]">
        <IconCmp className="h-3.5 w-3.5" />
        <span>{title}</span>
      </div>
      <div className="mt-4 text-[12px] font-semibold leading-snug text-[#f4eef7] break-words">{geoText(value)}</div>
      {subtext && <div className="mt-1 text-[9px] text-[#8f839b] break-words">{subtext}</div>}
      {extra}
    </div>
  );

  const geoPill = (children, tone = 'neutral') => {
    const tones = {
      neutral: 'border-[#5f4c6c] bg-[#13091f] text-[#d6cbe2]',
      good: 'border-[#4a6a45] bg-[#101c18] text-[#5ee166]',
      info: 'border-[#5f4c6c] bg-[#160d24] text-[#d6cbe2]',
      warn: 'border-[#6e5a35] bg-[#1d1514] text-[#ffbf6b]',
    };
    return (
      <span className={`inline-flex h-6 items-center gap-1.5 rounded-full border px-3 py-1 text-[10px] ${tones[tone] || tones.neutral}`}>
        {children}
      </span>
    );
  };

  const renderLocationMap = (data) => {
    const coordinatesReady = hasCoordinates(data);
    const coordinates = coordinatesReady ? `${data.lat},${data.lon}` : '';
    const mapEmbedUrl = coordinatesReady
      ? `https://maps.google.com/maps?q=${encodeURIComponent(coordinates)}&z=10&output=embed`
      : '';
    const mapUrl = data.map_url || (coordinatesReady ? `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(coordinates)}` : null);
    const earthUrl = coordinatesReady ? `https://earth.google.com/web/search/${encodeURIComponent(coordinates)}` : null;

    return (
      <>
        <div className="mb-6 text-[18px] font-medium uppercase text-[#b79aff]">Location</div>
        <div className="grid grid-cols-1 xl:grid-cols-[minmax(290px,390px)_minmax(0,1fr)] gap-6">
          <div className="min-w-0 rounded-lg border border-[#63516e]/80 bg-[#13091f]/74 p-5">
            {renderLocationDetail('Country', [data.flag_emoji, data.country, data.country_code && `(${data.country_code})`].filter(Boolean).join(' '))}
            {renderLocationDetail('Continent', [data.continent, data.continent_code && `(${data.continent_code})`].filter(Boolean).join(' '))}
            {renderLocationDetail('Region', data.region)}
            {renderLocationDetail('City', data.city)}
            {renderLocationDetail('Postal code', data.postal)}
            {renderLocationDetail('Coordinates', coordinatesReady ? coordinates : null)}
            {renderLocationDetail('Timezone', data.timezone)}
            {renderLocationDetail('UTC offset', data.timezone_utc)}
            <div className="flex flex-wrap gap-6 pt-3">
              {mapUrl && (
                <a className="inline-flex items-center gap-1.5 text-[11px] text-[#a98be8] hover:text-[#cab7ff]" href={mapUrl} target="_blank" rel="noreferrer">
                  Open in google maps <ExternalLink className="h-3 w-3" />
                </a>
              )}
              {earthUrl && (
                <a className="inline-flex items-center gap-1.5 text-[11px] text-[#a98be8] hover:text-[#cab7ff]" href={earthUrl} target="_blank" rel="noreferrer">
                  Open in google earth <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </div>
          </div>

          <div className="relative min-h-[300px] overflow-hidden rounded-lg border border-[#684f82] bg-[#12091f]">
            {coordinatesReady ? (
              <>
                <iframe
                  title={`Google map for ${[data.city, data.region, data.country].filter(Boolean).join(', ') || coordinates}`}
                  src={mapEmbedUrl}
                  className="absolute inset-0 h-full w-full grayscale invert-[0.86] hue-rotate-[226deg] saturate-[2.2] brightness-[0.72] contrast-[1.15]"
                  loading="lazy"
                  referrerPolicy="no-referrer-when-downgrade"
                  allowFullScreen
                />
                <div className="pointer-events-none absolute inset-0 bg-[#3b0b6f]/24 mix-blend-screen" />
                <div className="pointer-events-none absolute left-[54%] top-[54%] h-20 w-20 -translate-x-1/2 -translate-y-1/2 rounded-full border border-[#b46cff]/45 bg-[#7c3aed]/20 shadow-[0_0_34px_rgba(172,92,255,0.9)]">
                  <div className="absolute inset-4 rounded-full border border-[#cba5ff]/55 bg-[#7c3aed]/30" />
                  <MapPin className="absolute left-1/2 top-1/2 h-5 w-5 -translate-x-1/2 -translate-y-1/2 text-[#e9d5ff]" />
                </div>
                <div className="pointer-events-none absolute right-8 top-[45%] max-w-[175px] rounded-md border border-[#684f82] bg-[#1f1235]/88 p-4 shadow-[0_14px_34px_rgba(0,0,0,0.35)]">
                  <div className="text-[11px] font-semibold text-[#f4eef7]">{geoText(data.city, data.region || data.country || 'Location')}</div>
                  <div className="mt-1 text-[10px] text-[#c6b8d5]">{[data.region, data.country].filter(Boolean).join(', ')}</div>
                  <div className="mt-1 text-[10px] text-[#c6b8d5]">{coordinates}</div>
                </div>
              </>
            ) : (
              <div className="absolute inset-0 grid place-items-center p-6 text-center">
                <div>
                  <MapPin className="mx-auto h-8 w-8 text-purple-300" />
                  <p className="mt-3 text-sm text-gray-300">Coordinates unavailable for this lookup.</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </>
    );
  };

  const renderGeoResolvedIp = (item, index, data) => {
    const ip = item.ip || item.target || data.ip;
    return (
      <div key={`${ip}-${index}`} className="grid grid-cols-1 gap-5 rounded-lg border border-[#63516e]/80 bg-[#13091f]/78 p-5 xl:grid-cols-[minmax(220px,1.2fr)_minmax(280px,1.6fr)_repeat(4,minmax(70px,.55fr))]">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-lg font-semibold text-[#f4eef7]">
            <span className="h-3 w-3 rounded-full bg-[#5add56]" />
            <span>{geoText(ip)}</span>
          </div>
          <div className="mt-3 flex items-center gap-2 text-[11px] text-[#c6b8d5]">
            <span>{[item.country || data.country, item.country_code || data.country_code].filter(Boolean).join(' ')}</span>
            <span>{item.flag_emoji || data.flag_emoji}</span>
          </div>
          {(item.is_cdn || data.is_cdn) && <span className="mt-5 inline-flex rounded-full bg-[#2d7a3b] px-7 py-2 text-[11px] text-[#bfffc6]">Edge/CDN</span>}
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap gap-2">
            {item.asn_type && <span className="rounded-full bg-[#7a5a1e]/80 px-4 py-1 text-[10px] text-[#f2c078]">{item.asn_type}</span>}
            {(item.cdn_provider || data.cdn_provider) && <span className="rounded-full bg-[#27425e] px-4 py-1 text-[10px] text-[#9cc8ff]">{item.cdn_provider || data.cdn_provider}</span>}
          </div>
          <p className="mt-4 max-w-[420px] text-[11px] leading-5 text-[#d2c5dc]">{item.summary || data.summary}</p>
        </div>
        {[
          ['ASN', item.asn || data.asn],
          ['Org', item.org || data.org],
          ['City', item.city || data.city],
          ['Reverse DNS', item.reverse_dns || data.reverse_dns || 'No PTR record'],
        ].map(([label, value]) => (
          <div key={label} className="min-w-0">
            <div className="text-[11px] text-[#8f839b]">{label}</div>
            <div className="mt-2 text-[11px] text-[#ded4e9] break-words">{geoText(value)}</div>
          </div>
        ))}
      </div>
    );
  };

  const renderGeoResults = (data) => {
    const resolvedRows = Array.isArray(data.ip_results) && data.ip_results.length ? data.ip_results : [data];
    const confidencePct = data.confidence === 'high' ? 86 : data.confidence === 'medium' ? 62 : 34;

    return (
      <div className="space-y-8 p-1 md:p-2">
        <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-[24px] font-semibold leading-tight text-[#f4eef7]">{geoText(data.target)}</h2>
                {data.map_url && (
                  <a href={data.map_url} target="_blank" rel="noreferrer" aria-label="Open map">
                    <ExternalLink className="h-4 w-4 text-[#b79aff]" />
                  </a>
                )}
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {geoPill(<><span className="h-2 w-2 rounded-full bg-[#56dc4f]" /> Lookup Completed</>, 'good')}
                {geoPill(<><MapPin className="h-3 w-3" /> {geoText(data.ip)}</>, 'info')}
                {geoPill(<><Timer className="h-3 w-3" /> 1.3s</>, 'info')}
                {geoPill(<><Database className="h-3 w-3" /> {data.cached ? 'Cached (IPWHOIS)' : 'Fresh (IPWHOIS)'}</>, 'info')}
              </div>
            </div>
          </div>

          {(data.infrastructure_note || data.summary) && (
            <div className="mt-5 flex gap-4 rounded-xl border border-[#6f4a9a] bg-[#44206d]/82 px-6 py-6 text-[#ded4e9]">
              <Info className="mt-0.5 h-5 w-5 shrink-0 text-[#b79aff]" />
              <p className="text-sm leading-6">{data.infrastructure_note || data.summary}</p>
            </div>
          )}

          <div className="mt-6 grid grid-cols-1 gap-1.5 md:grid-cols-2 xl:grid-cols-6">
            {geoMetricTile(Globe2, 'IP Address', data.ip, data.ip?.includes(':') ? 'IPv6' : 'IPv4')}
            {geoMetricTile(Network, 'ASN', data.asn, data.org)}
            {geoMetricTile(Radio, 'ISP', data.isp)}
            {geoMetricTile(Building2, 'Organization', data.org)}
            {geoMetricTile(MapPin, 'IP Type', data.is_cdn ? 'Proxy/CDN' : geoText(data.asn_type), data.cdn_provider)}
            {geoMetricTile(ShieldCheck, 'Confidence Score', geoText(data.confidence), null, (
              <div className="mt-3 h-1.5 rounded-full bg-[#5a4a60]">
                <div className="h-full rounded-full bg-[#5add56]" style={{ width: `${confidencePct}%` }} />
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
          {renderLocationMap(data)}
          <div className="mt-6 grid grid-cols-1 gap-5 xl:grid-cols-3">
            {geoCard('Network Information', (
              <div>
                {geoInfoRow('ISP', data.isp)}
                {geoInfoRow('Organization', data.org)}
                {geoInfoRow('ASN', data.asn)}
                {geoInfoRow('ASN Domain', data.asn_domain)}
                {geoInfoRow('Calling Code', data.calling_code)}
              </div>
            ))}
            {geoCard('Security Information', (
              <div>
                {geoInfoRow('CDN', geoBool(data.is_cdn))}
                {geoInfoRow('CDN Provider', data.cdn_provider)}
                {geoInfoRow('Proxy', geoBool(data.is_proxy))}
                {geoInfoRow('Hosting', geoBool(data.is_hosting))}
                {geoInfoRow('Confidence', data.confidence)}
                {geoInfoRow('Location Accuracy', data.location_accuracy)}
              </div>
            ))}
            {geoCard('DNS Information', (
              <div>
                {geoInfoRow('Target', data.target)}
                {geoInfoRow('Resolved IPs', Array.isArray(data.resolved_ips) ? data.resolved_ips.join('\n') : data.resolved_ips)}
                {geoInfoRow('Reverse DNS', data.reverse_dns || 'No PTR record')}
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
          <div className="mb-6 text-[18px] font-medium uppercase text-[#b79aff]">All Resolved IPs</div>
          <div className="space-y-4">{resolvedRows.map((item, index) => renderGeoResolvedIp(item, index, data))}</div>
        </section>

        <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
          <div className="mb-7 text-[18px] font-medium uppercase text-[#b79aff]">Provider Information</div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {geoMetricTile(Building2, 'Provider', geoText(data.provider).toUpperCase())}
            {geoMetricTile(Database, 'Cached', geoBool(data.cached))}
          </div>
        </section>

        <section className="rounded-lg border border-[#382748] bg-[#1b0d2b]/78 p-8">
          <div className="mb-2 text-[18px] font-medium uppercase text-[#b79aff]">Export & Share</div>
          <p className="text-sm text-[#d2c5dc]">Download or share your scan report.</p>
          <div className="mt-7 grid grid-cols-1 gap-4 md:grid-cols-4">
            {['Export PDF', 'Export JSON', 'Export CSV'].map((label) => (
              <button
                key={label}
                type="button"
                onClick={() => label === 'Export JSON' && copyText('json', JSON.stringify(data, null, 2))}
                className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:border-[#9f7aea]"
              >
                <FileText className="h-4 w-4" />
                {copied === 'json' && label === 'Export JSON' ? 'Copied JSON' : label}
              </button>
            ))}
            <button
              type="button"
              onClick={() => copyText('summary', data.summary)}
              className="flex h-12 items-center justify-center gap-2 rounded-lg border border-[#63516e]/80 bg-[#13091f]/72 text-sm text-[#ded4e9] transition hover:border-[#9f7aea]"
            >
              <Share2 className="h-4 w-4" />
              {copied === 'summary' ? 'Copied' : 'Share report'}
            </button>
          </div>
        </section>
      </div>
    );
  };

  const pct = (value) => Math.max(0, Math.min(100, Number(value || 0)));

  const chip = (text, tone = 'neutral') => {
    const colors = {
      neutral: 'border-dark-600 text-gray-300 bg-dark-800/60',
      good: 'border-emerald-500/25 text-emerald-200 bg-emerald-500/10',
      warn: 'border-amber-500/25 text-amber-200 bg-amber-500/10',
      bad: 'border-red-500/25 text-red-200 bg-red-500/10',
      info: 'border-purple-400/25 text-purple-200 bg-purple-500/10',
    };
    return <span className={`text-xs font-mono px-2.5 py-1 rounded-lg border ${colors[tone] || colors.neutral}`}>{text}</span>;
  };

  const renderMetricCard = (IconCmp, label, value, subtext) => (
    <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-4 min-w-0">
      <div className="flex items-center gap-2 text-gray-500 text-xs font-mono uppercase">
        <IconCmp className="w-4 h-4" />
        <span>{label}</span>
      </div>
      <div className="text-gray-100 text-sm font-semibold mt-3 break-words">{value || 'Unknown'}</div>
      {subtext && <div className="text-gray-500 text-xs mt-1 break-words">{subtext}</div>}
    </div>
  );

  const pingSeries = (data) => Array.isArray(data.response_timeline) ? data.response_timeline : [];

  const renderPingGraph = (data) => {
    const series = pingSeries(data);
    const values = series.map((item) => Number(item.latency_ms || 0));
    const max = Math.max(10, ...values, Number(data.max_ms || 0));
    const points = series.map((item, index) => {
      const x = series.length <= 1 ? 50 : (index / (series.length - 1)) * 100;
      const latency = Number(item.latency_ms || 0);
      const y = item.status === 'dropped' ? 92 : 92 - (latency / max) * 74;
      return `${x},${y}`;
    }).join(' ');

    return (
      <div className="border border-dark-600 bg-dark-900/30 rounded-lg p-5 overflow-hidden">
        <div className="flex items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500">
            <BarChart3 className="w-4 h-4" />
            Live Latency Graph
          </div>
          <span className="text-xs font-mono text-purple-200">{data.latency_trend || 'Waiting for trend'}</span>
        </div>
        <svg viewBox="0 0 100 100" className="w-full h-56 overflow-visible" preserveAspectRatio="none">
          {[18, 36, 54, 72, 90].map((y) => (
            <line key={y} x1="0" x2="100" y1={y} y2={y} stroke="rgba(148, 113, 210, 0.16)" strokeDasharray="2 2" />
          ))}
          <polyline points={points} fill="none" stroke="#a78bfa" strokeWidth="2.5" vectorEffect="non-scaling-stroke" />
          {series.map((item, index) => {
            const x = series.length <= 1 ? 50 : (index / (series.length - 1)) * 100;
            const latency = Number(item.latency_ms || 0);
            const y = item.status === 'dropped' ? 92 : 92 - (latency / max) * 74;
            return (
              <g key={`${item.packet}-${index}`}>
                <circle cx={x} cy={y} r={item.status === 'dropped' ? 2.5 : 2} fill={item.status === 'dropped' ? '#f87171' : '#22d3ee'} vectorEffect="non-scaling-stroke" />
                {item.status === 'dropped' && <line x1={x - 2} x2={x + 2} y1={y - 2} y2={y + 2} stroke="#f87171" vectorEffect="non-scaling-stroke" />}
              </g>
            );
          })}
        </svg>
        <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-2">
          {series.map((item) => (
            <div key={item.packet} className={`rounded-lg border px-3 py-2 ${item.status === 'dropped' ? 'border-red-500/30 bg-red-500/10' : 'border-purple-400/20 bg-purple-500/10'}`}>
              <div className="text-[10px] text-gray-500 font-mono">Packet {item.packet}</div>
              <div className={`text-sm font-mono mt-1 ${item.status === 'dropped' ? 'text-red-200' : 'text-gray-100'}`}>
                {item.status === 'dropped' ? 'Dropped' : `${item.latency_ms}ms`}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const renderPacketFlow = (data) => {
    const series = pingSeries(data);
    return (
      <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-5">
          <Radio className="w-4 h-4" />
          ICMP Packet Flow
        </div>
        <div className="relative h-14 rounded-lg border border-purple-400/20 bg-dark-900/50 overflow-hidden">
          <div className="absolute left-4 right-4 top-1/2 h-px bg-purple-300/25" />
          {series.map((item, index) => (
            <span
              key={item.packet}
              className={`absolute top-1/2 w-3 h-3 -mt-1.5 rounded-full ${item.status === 'dropped' ? 'bg-red-400' : 'bg-cyan-300 shadow-[0_0_18px_rgba(34,211,238,0.8)]'}`}
              style={{ left: `${8 + (index / Math.max(1, series.length - 1)) * 84}%`, animation: `pulse 1.4s ease-in-out ${index * 120}ms infinite` }}
              title={`Packet ${item.packet}: ${item.status === 'dropped' ? 'dropped' : `${item.latency_ms}ms`}`}
            />
          ))}
        </div>
      </div>
    );
  };

  const renderPingResults = (data) => {
    const heatClass = {
      green: 'bg-emerald-500/10 border-emerald-400/25',
      yellow: 'bg-amber-500/10 border-amber-400/25',
      red: 'bg-red-500/10 border-red-400/25',
    }[data.heat_indicator] || 'bg-dark-800/55 border-dark-600';
    const geo = data.geo || {};
    const history = typeof data.history_delta_ms === 'number'
      ? `${data.history_delta_ms >= 0 ? '+' : ''}${data.history_delta_ms.toFixed(1)}ms since last check`
      : 'Baseline captured';

    return (
      <div className="p-6 space-y-6">
        <section className={`border rounded-lg p-5 ${heatClass}`}>
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="flex flex-wrap gap-2 mb-4">
                {(data.status_badges || []).map((badge) => chip(badge, badge === 'ONLINE' || badge === 'STABLE' || badge === 'LOW LATENCY' ? 'good' : badge === 'VARIABLE' ? 'warn' : 'bad'))}
                {liveMode && chip('LIVE MODE', 'info')}
              </div>
              <h2 className="text-3xl font-semibold text-gray-100">{data.avg_ms ?? 'N/A'}ms Avg</h2>
              <p className="text-sm text-gray-300 mt-2 max-w-3xl">{data.health_summary}</p>
            </div>
            <div className="grid grid-cols-2 gap-3 min-w-[260px]">
              {renderMetricCard(Gauge, 'Stability', data.stability_score != null ? `${data.stability_score}/100` : 'Unknown', data.connection_quality)}
              {renderMetricCard(Activity, 'Availability', data.availability_pct != null ? `${data.availability_pct}%` : 'Unknown', data.last_checked || 'just now')}
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-3">
          {renderMetricCard(Activity, 'Min', data.min_ms != null ? `${data.min_ms}ms` : 'N/A', 'Fastest response')}
          {renderMetricCard(Gauge, 'Avg', data.avg_ms != null ? `${data.avg_ms}ms` : 'N/A', data.connection_quality)}
          {renderMetricCard(Activity, 'Max', data.max_ms != null ? `${data.max_ms}ms` : 'N/A', 'Slowest response')}
          {renderMetricCard(BarChart3, 'Jitter', data.jitter_ms != null ? `${data.jitter_ms}ms` : 'N/A', data.jitter_label)}
          {renderMetricCard(ShieldAlert, 'Loss', `${data.packet_loss_pct ?? 0}%`, data.packet_loss_severity)}
          {renderMetricCard(Network, 'TTL', data.ttl || 'Unknown', data.estimated_hops)}
        </section>

        {renderPingGraph(data)}

        <section className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5 xl:col-span-2">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Intelligence Panel</div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {renderField('target', data.target)}
              {renderField('ip', data.ip)}
              {renderField('dns_lookup_ms', data.dns_lookup_ms != null ? `${data.dns_lookup_ms} ms` : null)}
              {renderField('likely_os', data.likely_os_family)}
              {renderField('location', [geo.city, geo.region, geo.country].filter(Boolean).join(', '))}
              {renderField('hosting', geo.cdn_provider || geo.org || geo.isp)}
              {renderField('asn', geo.asn)}
              {renderField('network_type', data.network_type_guess)}
              {renderField('distribution', data.latency_distribution)}
              {renderField('history', history)}
              {renderField('std_deviation_ms', data.std_deviation_ms)}
              {renderField('variance_ms', data.variance_ms)}
            </div>
          </div>

          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Suitable For</div>
            <div className="space-y-2">
              {(data.suitable_for || []).map((item) => (
                <div key={item} className="flex items-center gap-2 text-sm text-emerald-200">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>{item}</span>
                </div>
              ))}
              {(!data.suitable_for || data.suitable_for.length === 0) && <p className="text-sm text-gray-500">No quality labels matched this run.</p>}
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {renderPacketFlow(data)}
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Recommendations</div>
            <div className="space-y-3">
              {[...(data.recommendations || []), ...(data.security_insights || []), data.route_insight].filter(Boolean).map((item, index) => (
                <div key={`${item}-${index}`} className="text-sm text-gray-300 border border-dark-700 rounded-lg p-3">{item}</div>
              ))}
            </div>
          </div>
        </section>
      </div>
    );
  };

  const renderTracerouteResults = (data) => {
    const hops = Array.isArray(data.hops) ? data.hops : [];
    const visible = hops.filter((hop) => hop.rtt_ms != null);
    const maxRtt = Math.max(10, ...visible.map((hop) => Number(hop.rtt_ms || 0)));
    const finalHop = visible.at(-1);
    const routePoints = hops.map((hop, index) => ({
      hop,
      x: hops.length <= 1 ? 50 : 8 + (index / (hops.length - 1)) * 84,
      y: hop.lat != null && hop.lon != null
        ? 84 - Math.max(-60, Math.min(75, Number(hop.lat))) + ((index % 3) * 3)
        : 22 + ((index * 29) % 54),
    }));
    const routePolyline = routePoints.map((point) => `${point.x},${point.y}`).join(' ');
    const colorForHop = (hop) => {
      if (hop.is_hidden) return '#64748b';
      if (hop.quality_color === 'green') return '#34d399';
      if (hop.quality_color === 'cyan') return '#22d3ee';
      if (hop.quality_color === 'yellow') return '#fbbf24';
      if (hop.quality_color === 'red') return '#f87171';
      return '#a78bfa';
    };
    const locationLabel = (hop) => [hop.city, hop.region, hop.country_code || hop.country].filter(Boolean).join(', ');

    return (
      <div className="p-6 space-y-6">
        <section className="border border-purple-400/25 bg-dark-800/65 rounded-lg p-5 overflow-hidden relative">
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent" />
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div className="min-w-0 max-w-4xl">
              <div className="flex flex-wrap gap-2 mb-4">
                {(data.health_indicators || []).map((item) => chip(item, item.includes('WATCH') || item.includes('CONGESTION') || item.includes('SUBOPTIMAL') ? 'warn' : 'good'))}
                {data.cdn_detected && chip(data.cdn_detected, 'info')}
                {liveMode && chip('LIVE ROUTE MONITORING', 'info')}
                {data.route_changed && chip('ROUTE CHANGED', 'warn')}
              </div>
              <h2 className="text-3xl font-semibold text-gray-100 break-words">
                {data.target} Route
              </h2>
              <p className="text-sm text-gray-300 mt-3 leading-6">{data.ai_summary || 'Traceroute intelligence will appear after a successful run.'}</p>
            </div>
            <div className="grid grid-cols-2 gap-3 min-w-[280px]">
              {renderMetricCard(Gauge, 'Stability', data.route_stability_score != null ? `${data.route_stability_score}/100` : 'Unknown', data.route_efficiency)}
              {renderMetricCard(Activity, 'Final Latency', finalHop?.rtt_ms != null ? `${finalHop.rtt_ms}ms` : 'Hidden', data.final_latency_delta_ms != null ? `${data.final_latency_delta_ms >= 0 ? '+' : ''}${data.final_latency_delta_ms}ms live delta` : 'Latest visible hop')}
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-3">
          {renderMetricCard(Route, 'Visible Hops', `${visible.length}/${hops.length || 0}`, `${data.hidden_hops || 0} filtered`)}
          {renderMetricCard(ShieldAlert, 'Packet Loss Hops', data.packet_loss_hops || 0, 'Traceroute probe loss')}
          {renderMetricCard(Network, 'Route Risk', data.route_risk || 'Unknown', (data.route_risk_factors || [])[0])}
          {renderMetricCard(Cloud, 'CDN / Cloud', data.cdn_detected || 'Not detected', 'Cloud edge inference')}
          {renderMetricCard(MapPin, 'Geo Route', data.international_route ? 'Cross-border' : 'Local/unknown', 'Based on resolved hop GeoIP')}
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)] gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5 overflow-hidden">
            <div className="flex items-center justify-between gap-3 mb-5">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500">
                <Route className="w-4 h-4" />
                Hop Visualization Timeline
              </div>
              <span className="text-xs font-mono text-purple-200">{data.route_efficiency || 'Analyzing route'}</span>
            </div>
            <div className="space-y-0">
              {hops.map((hop, index) => (
                <div key={`${hop.hop}-${hop.ip || 'hidden'}`} className="grid grid-cols-[42px_1fr] gap-4 min-h-[76px]">
                  <div className="relative flex justify-center">
                    <div className="w-9 h-9 rounded-full border grid place-items-center text-xs font-mono mt-1"
                      style={{ borderColor: colorForHop(hop), color: colorForHop(hop), boxShadow: `0 0 20px ${colorForHop(hop)}55` }}>
                      {hop.hop}
                    </div>
                    {index < hops.length - 1 && <div className="absolute top-11 bottom-0 w-px bg-gradient-to-b from-purple-300/60 to-cyan-300/20" />}
                    {index < hops.length - 1 && (
                      <span className="absolute top-12 w-2 h-2 rounded-full bg-cyan-300 shadow-[0_0_16px_rgba(34,211,238,0.9)] animate-pulse" />
                    )}
                  </div>
                  <div className="pb-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-mono text-gray-100">{hop.is_hidden ? 'No ICMP response' : hop.ip}</span>
                      {chip(hop.quality || 'Unknown', hop.quality_color === 'red' ? 'bad' : hop.quality_color === 'yellow' ? 'warn' : hop.is_hidden ? 'neutral' : 'good')}
                      {hop.hop_type && chip(hop.hop_type, 'info')}
                    </div>
                    <div className="text-xs text-gray-400 mt-2 break-words">
                      {[locationLabel(hop), hop.provider, hop.asn, hop.hostname].filter(Boolean).join(' · ') || hop.hidden_reason || 'Public router'}
                    </div>
                    {hop.latency_added_ms >= 40 && <div className="text-xs text-amber-200 mt-2">Latency spike: +{hop.latency_added_ms}ms at this hop.</div>}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="border border-dark-600 bg-dark-900/35 rounded-lg p-5 overflow-hidden">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">
              <MapPin className="w-4 h-4" />
              Interactive Network Map
            </div>
            <div className="relative rounded-lg border border-purple-400/20 bg-[radial-gradient(circle_at_50%_45%,rgba(34,211,238,0.16),rgba(19,9,33,0.18)_42%,rgba(9,4,18,0.8))] h-[360px] overflow-hidden">
              <svg viewBox="0 0 100 100" className="absolute inset-0 w-full h-full" preserveAspectRatio="none">
                {[20, 40, 60, 80].map((x) => <line key={x} x1={x} x2={x} y1="0" y2="100" stroke="rgba(167,139,250,0.08)" />)}
                {[25, 50, 75].map((y) => <line key={y} x1="0" x2="100" y1={y} y2={y} stroke="rgba(167,139,250,0.08)" />)}
                <polyline points={routePolyline} fill="none" stroke="rgba(34,211,238,0.72)" strokeWidth="1.4" strokeDasharray="3 2" vectorEffect="non-scaling-stroke" />
                {routePoints.map(({ hop, x, y }) => (
                  <g key={`map-${hop.hop}`}>
                    <circle cx={x} cy={y} r="2.7" fill={colorForHop(hop)} vectorEffect="non-scaling-stroke" />
                    <circle cx={x} cy={y} r="5.6" fill="none" stroke={colorForHop(hop)} opacity="0.35" vectorEffect="non-scaling-stroke" />
                  </g>
                ))}
              </svg>
              <div className="absolute left-4 right-4 bottom-4 grid grid-cols-2 gap-2">
                {(data.ownership_chain || []).slice(0, 4).map((owner) => (
                  <div key={owner} className="rounded-lg border border-dark-600 bg-dark-900/80 px-3 py-2 text-xs font-mono text-gray-300 truncate">{owner}</div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-5">
              <BarChart3 className="w-4 h-4" />
              Hop Response Time Graph
            </div>
            <div className="space-y-3">
              {hops.map((hop) => (
                <div key={`bar-${hop.hop}`} className="grid grid-cols-[64px_1fr_84px] items-center gap-3">
                  <span className="text-xs font-mono text-gray-500">Hop {hop.hop}</span>
                  <div className="h-3 rounded-full bg-dark-700 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{ width: `${hop.rtt_ms == null ? 4 : Math.max(5, (hop.rtt_ms / maxRtt) * 100)}%`, background: colorForHop(hop), boxShadow: `0 0 18px ${colorForHop(hop)}66` }}
                    />
                  </div>
                  <span className="text-xs font-mono text-gray-300 text-right">{hop.rtt_ms == null ? 'Filtered' : `${hop.rtt_ms}ms`}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Routing Intelligence</div>
            <div className="space-y-3">
              {[...(data.routing_intelligence || []), ...(data.security_insights || []), ...(data.route_risk_factors || []), data.route_change_summary].filter(Boolean).map((item, index) => (
                <div key={`${item}-${index}`} className="text-sm text-gray-300 border border-dark-700 rounded-lg p-3">{item}</div>
              ))}
            </div>
          </div>
        </section>

        <section className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Expandable Hop Cards</div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
            {hops.map((hop) => (
              <details key={`detail-${hop.hop}`} className="group border border-dark-700 rounded-lg bg-dark-900/25 p-4">
                <summary className="cursor-pointer list-none flex flex-wrap items-center justify-between gap-3">
                  <span className="text-sm font-mono text-gray-100">Hop {hop.hop} · {hop.ip || 'Filtered'}</span>
                  <span className="text-xs font-mono" style={{ color: colorForHop(hop) }}>{hop.rtt_ms == null ? 'No response' : `${hop.rtt_ms}ms`}</span>
                </summary>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
                  {renderField('hostname', hop.hostname)}
                  {renderField('provider', hop.provider)}
                  {renderField('asn', hop.asn)}
                  {renderField('location', locationLabel(hop))}
                  {renderField('packet_loss', `${hop.packet_loss_pct || 0}%`)}
                  {renderField('samples', hop.rtt_samples_ms)}
                  {renderField('type', hop.hop_type)}
                  {renderField('insight', hop.insight || hop.hidden_reason)}
                </div>
              </details>
            ))}
          </div>
        </section>
      </div>
    );
  };

  const renderHeadersResults = (data) => {
    const headers = data.headers || {};
    const present = data.security_headers?.present || [];
    const missing = data.security_headers?.missing || [];
    const securityRows = [...present.map((item) => ({ ...item, present: true })), ...missing.map((item) => ({ ...item, present: false }))];
    const score = Number(data.security_score ?? (data.risk_score != null ? 100 - data.risk_score : 0));
    const riskTone = data.risk_level === 'High' ? 'bad' : data.risk_level === 'Medium' ? 'warn' : 'good';
    const scoreColor = score >= 80 ? '#34d399' : score >= 55 ? '#fbbf24' : '#f87171';

    const severityTone = (severity) => {
      if (String(severity).toUpperCase() === 'HIGH') return 'bad';
      if (String(severity).toUpperCase() === 'MEDIUM') return 'warn';
      return 'neutral';
    };

    const headerExplanation = (name) => {
      const lower = name.toLowerCase();
      if (lower === 'server') return 'Can reveal edge, server, or framework details useful for fingerprinting.';
      if (lower === 'content-security-policy') return 'Controls trusted content sources and reduces script injection risk.';
      if (lower === 'strict-transport-security') return 'Forces HTTPS on future browser visits.';
      if (lower === 'x-frame-options') return 'Protects against clickjacking in older browsers.';
      if (lower === 'set-cookie') return 'Session and state data; flags determine browser-side cookie protection.';
      if (lower.includes('cache')) return 'Controls browser, proxy, or CDN cache behavior.';
      if (lower.includes('cors') || lower.includes('access-control')) return 'Controls cross-origin browser access.';
      return 'Response metadata returned by the server or upstream edge network.';
    };

    return (
      <div className="p-6 space-y-6">
        <section className="border border-purple-400/25 bg-dark-800/65 rounded-lg p-5 overflow-hidden relative">
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-purple-300/70 to-transparent" />
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div className="min-w-0 max-w-4xl">
              <div className="flex flex-wrap gap-2 mb-4">
                {chip(`Risk: ${data.risk_level || 'Unknown'}`, riskTone)}
                {data.cdn && chip(`CDN: ${data.cdn}`, 'info')}
                {data.waf && chip(`WAF: ${data.waf}`, 'good')}
                {data.protocol && chip(data.protocol, 'neutral')}
              </div>
              <h2 className="text-3xl font-semibold text-gray-100 break-words">HTTP Header Intelligence</h2>
              <p className="text-sm text-gray-300 mt-3 leading-6">{data.ai_summary || 'Header analysis will appear after a successful run.'}</p>
            </div>
            <div className="grid grid-cols-2 gap-3 min-w-[300px]">
              <div className="border border-dark-600 bg-dark-900/35 rounded-lg p-4">
                <div className="text-xs text-gray-500 font-mono uppercase">Header Security</div>
                <div className="mt-4 flex items-center gap-4">
                  <div className="w-20 h-20 rounded-full grid place-items-center shrink-0"
                    style={{ background: `conic-gradient(${scoreColor} ${score * 3.6}deg, rgba(55,48,80,0.9) 0deg)` }}>
                    <div className="w-14 h-14 rounded-full bg-dark-900 grid place-items-center border border-dark-600">
                      <span className="text-sm font-mono text-gray-100">{score}</span>
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-100 text-sm font-semibold">{score}/100</div>
                    <div className="text-xs text-gray-500 mt-1">{present.length}/{present.length + missing.length || 0} controls present</div>
                  </div>
                </div>
              </div>
              {renderMetricCard(Timer, 'Response', data.response_time_ms != null ? `${data.response_time_ms}ms` : 'Unknown', data.response_time_rating)}
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-3">
          {renderMetricCard(Activity, 'Status', data.status_code, data.final_url || data.url)}
          {renderMetricCard(Server, 'Server', data.server || 'Hidden', data.powered_by ? `Powered by ${data.powered_by}` : 'Disclosure check')}
          {renderMetricCard(Cloud, 'Infrastructure', data.cloud_provider || data.cdn || 'Unknown', data.waf || 'WAF not detected')}
          {renderMetricCard(ShieldCheck, 'Security Headers', `${present.length}/${present.length + missing.length || 0}`, `${missing.length} missing`)}
          {renderMetricCard(Network, 'CORS', data.cors?.risk || 'none', data.cors?.allow_origin || 'No ACAO header')}
          {renderMetricCard(BarChart3, 'Compression', data.compression?.type || 'None', data.caching?.summary)}
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_380px] gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="flex items-center justify-between gap-3 mb-5">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500">
                <ShieldCheck className="w-4 h-4" />
                Security Header Matrix
              </div>
              <span className="text-xs font-mono text-purple-200">OWASP {data.compliance?.owasp_secure_headers?.passed ?? 0}/{data.compliance?.owasp_secure_headers?.total ?? 0}</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {securityRows.map((item) => (
                <div key={item.header} className={`border rounded-lg p-4 ${item.present ? 'border-emerald-400/25 bg-emerald-500/10' : 'border-red-400/25 bg-red-500/10'}`}>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-sm font-mono text-gray-100">{item.present ? '✓' : '✗'} {item.header}</div>
                      <div className="text-xs text-gray-400 mt-2">{item.description}</div>
                    </div>
                    {chip(item.present ? item.strength || 'present' : item.severity, item.present ? 'good' : severityTone(item.severity))}
                  </div>
                  {item.value && <div className="text-xs font-mono text-gray-300 mt-3 break-all">{item.value}</div>}
                  {!item.present && <div className="text-xs text-amber-200 mt-3">{item.recommendation}</div>}
                </div>
              ))}
            </div>
          </div>

          <div className="border border-dark-600 bg-dark-900/35 rounded-lg p-5">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">
              <Activity className="w-4 h-4" />
              Header Timeline
            </div>
            <div className="space-y-0">
              {(data.timeline || []).map((step, index) => (
                <div key={`${step.step}-${index}`} className="grid grid-cols-[34px_1fr] gap-3 min-h-[58px]">
                  <div className="relative flex justify-center">
                    <div className="w-7 h-7 rounded-full border border-cyan-300/60 bg-cyan-300/10 grid place-items-center text-[10px] font-mono text-cyan-200">{index + 1}</div>
                    {index < (data.timeline || []).length - 1 && <div className="absolute top-8 bottom-0 w-px bg-cyan-300/20" />}
                  </div>
                  <div>
                    <div className="text-sm text-gray-100">{step.step}</div>
                    <div className="text-xs text-gray-500 mt-1">{step.duration_ms != null ? `${step.duration_ms}ms` : step.count != null ? `${step.count} redirect(s)` : step.status}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Technology Fingerprint</div>
            <div className="flex flex-wrap gap-2">
              {(data.technologies || []).map((tech) => chip(tech, tech.includes('Cloudflare') || tech.includes('WAF') ? 'info' : 'neutral'))}
              {(!data.technologies || data.technologies.length === 0) && <span className="text-sm text-gray-500">No framework headers detected.</span>}
            </div>
            <div className="grid grid-cols-1 gap-3 mt-4">
              {renderField('cdn', data.cdn)}
              {renderField('waf', data.waf)}
              {renderField('cloud', data.cloud_provider)}
              {renderField('api', data.api_detection)}
            </div>
          </div>

          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Cookie Security</div>
            <div className="space-y-3">
              {(data.cookies || []).map((cookie) => (
                <div key={cookie.name} className="border border-dark-700 rounded-lg p-3">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-sm font-mono text-gray-100">{cookie.name}</span>
                    {chip(cookie.risk, cookie.risk === 'high' ? 'bad' : cookie.risk === 'medium' ? 'warn' : 'good')}
                  </div>
                  <div className="flex flex-wrap gap-2 mt-3">
                    {chip(`Secure ${cookie.secure ? '✓' : '✗'}`, cookie.secure ? 'good' : 'bad')}
                    {chip(`HttpOnly ${cookie.httponly ? '✓' : '✗'}`, cookie.httponly ? 'good' : 'bad')}
                    {chip(`SameSite ${cookie.samesite || 'Missing'}`, cookie.samesite ? 'good' : 'warn')}
                  </div>
                </div>
              ))}
              {(!data.cookies || data.cookies.length === 0) && <p className="text-sm text-gray-500">No Set-Cookie headers observed.</p>}
            </div>
          </div>

          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Policy Analysis</div>
            <div className="space-y-3">
              <div className="border border-dark-700 rounded-lg p-3 text-sm text-gray-300">{data.clickjacking?.summary || 'Clickjacking status unknown.'}</div>
              <div className="border border-dark-700 rounded-lg p-3 text-sm text-gray-300">CSP: {data.csp?.strength || 'missing'}</div>
              <div className="border border-dark-700 rounded-lg p-3 text-sm text-gray-300">CORS: {data.cors?.risk || 'none'}</div>
              {(data.dangerous_methods || []).length > 0 && <div className="border border-red-500/30 bg-red-500/10 rounded-lg p-3 text-sm text-red-200">Dangerous methods: {data.dangerous_methods.join(', ')}</div>}
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Redirect Chain Visualization</div>
            <div className="space-y-3">
              {(data.redirect_chain || []).map((step, index) => (
                <div key={`${step.url}-${index}`} className="flex items-center gap-3 border border-dark-700 rounded-lg p-3">
                  <span className="w-8 h-8 rounded-full border border-purple-400/40 grid place-items-center text-xs font-mono text-purple-200 shrink-0">{index + 1}</span>
                  <div className="min-w-0">
                    <div className="text-xs font-mono text-gray-100 break-all">{step.url}</div>
                    <div className="text-xs text-gray-500 mt-1">HTTP {step.status_code}{step.location ? ` → ${step.location}` : ''}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Security Recommendations</div>
            <div className="space-y-3">
              {(data.recommendations || []).map((item, index) => (
                <div key={`${item}-${index}`} className="text-sm text-gray-300 border border-dark-700 rounded-lg p-3">{item}</div>
              ))}
              {(!data.recommendations || data.recommendations.length === 0) && <p className="text-sm text-emerald-200">No major recommendations for this response.</p>}
            </div>
          </div>
        </section>

        <section className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Response Header Explorer</div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
            {Object.entries(headers).map(([key, value]) => (
              <details key={key} className="border border-dark-700 rounded-lg bg-dark-900/25 p-4">
                <summary className="cursor-pointer list-none flex flex-wrap items-center justify-between gap-3">
                  <span className="text-sm font-mono text-gray-100">{key}</span>
                  <span className="text-xs font-mono text-purple-200 max-w-[320px] truncate">{String(value)}</span>
                </summary>
                <div className="mt-4 space-y-3">
                  <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap break-all">{String(value)}</pre>
                  <div className="text-xs text-gray-400">{headerExplanation(key)}</div>
                </div>
              </details>
            ))}
          </div>
        </section>
      </div>
    );
  };

  const renderProbabilityBars = (items = []) => (
    <div className="space-y-3">
      {items.map((item) => (
        <div key={item.name} className="space-y-1.5">
          <div className="flex items-center justify-between gap-3">
            <span className="text-sm text-gray-200">{item.name}</span>
            <span className="text-xs font-mono text-purple-200">{pct(item.probability)}%</span>
          </div>
          <div className="h-2 rounded-full bg-dark-700 overflow-hidden">
            <div
              className="h-full rounded-full"
              style={{ width: `${pct(item.probability)}%`, background: 'linear-gradient(90deg, #8b5cf6, #22d3ee)' }}
            />
          </div>
        </div>
      ))}
    </div>
  );

  const renderOsFingerprintResults = (data) => {
    const confidence = pct(data.confidence);
    const risk = data.risk_score || {};
    const tcp = data.tcp_ip_stack || {};
    const exposure = data.internet_exposure || {};
    const geo = data.geolocation || {};
    const sourceSections = Array.isArray(data.fingerprint_sources) ? data.fingerprint_sources : [];

    return (
      <div className="p-6 space-y-6">
        <section className="grid grid-cols-1 xl:grid-cols-[320px_minmax(0,1fr)] gap-4">
          <div className="border border-purple-400/25 bg-dark-800/70 rounded-lg p-5">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 text-purple-200 text-xs font-mono uppercase">
                  <Fingerprint className="w-4 h-4" />
                  Visual OS Card
                </div>
                <h2 className="text-2xl font-semibold text-gray-100 mt-4 break-words">{data.detected_os || 'Unknown OS'}</h2>
                <p className="text-sm text-gray-400 mt-1">{data.os_version_estimate || data.distribution_family || 'Version estimate unavailable'}</p>
              </div>
              <div
                className="w-24 h-24 rounded-full grid place-items-center shrink-0"
                style={{ background: `conic-gradient(#a78bfa ${confidence * 3.6}deg, rgba(55,48,80,0.9) 0deg)` }}
                title={`${confidence}% confidence`}
              >
                <div className="w-[72px] h-[72px] rounded-full bg-dark-900 grid place-items-center border border-dark-600">
                  <span className="text-lg font-mono text-gray-100">{confidence}%</span>
                </div>
              </div>
            </div>
            <div className="flex flex-wrap gap-2 mt-5">
              {chip(data.confidence_label || 'Unknown confidence', confidence >= 70 ? 'good' : confidence >= 45 ? 'warn' : 'bad')}
              {chip(data.detection_mode || data.method || 'Passive Fingerprinting', 'info')}
              {data.family && chip(data.family, 'neutral')}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
            {renderMetricCard(Cpu, 'Kernel', data.kernel_estimate, 'Kernel fingerprinting')}
            {renderMetricCard(Server, 'Device Type', data.device_type, 'Server/router/firewall/NAS/printer signal')}
            {renderMetricCard(Cloud, 'Hosting', data.hosting_provider || geo.provider, [geo.asn, geo.org].filter(Boolean).join(' · '))}
            {renderMetricCard(ShieldAlert, 'Exposure Score', risk.score != null ? `${risk.score}/100` : 'Unknown', risk.level)}
          </div>
        </section>

        {data.ai_summary && (
          <section className="border border-dark-600 bg-dark-800/55 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-2">AI Summary</div>
            <p className="text-sm leading-6 text-gray-200">{data.ai_summary}</p>
          </section>
        )}

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">
              <Gauge className="w-4 h-4" />
              OS Probability Engine
            </div>
            {renderProbabilityBars(data.os_probabilities || [])}
          </div>

          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">
              <Network className="w-4 h-4" />
              Network Distance
            </div>
            <div className="grid grid-cols-2 gap-3">
              {renderField('observed_ttl', data.network_distance?.observed_ttl)}
              {renderField('initial_ttl', data.network_distance?.estimated_initial_ttl)}
              {renderField('hop_range', data.network_distance?.range)}
              {renderField('method', data.method)}
            </div>
          </div>
        </section>

        <section className="border border-dark-600 bg-dark-800/45 rounded-lg p-5 space-y-4">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500">Fingerprinting Sources Breakdown</div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
            {sourceSections.map((source) => (
              <div key={source.name} className="border border-dark-600 bg-dark-900/30 rounded-lg p-4">
                <div className="flex items-center justify-between gap-3">
                  <h3 className="text-sm font-semibold text-gray-100">{source.name}</h3>
                  {chip(source.status || 'observed', source.status === 'limited' || source.status === 'not observed' ? 'warn' : 'good')}
                </div>
                {source.inference && <p className="text-sm text-gray-300 mt-3">{source.inference}</p>}
                {source.observed_ttl !== undefined && (
                  <div className="grid grid-cols-2 gap-2 mt-3">
                    {renderField('observed_ttl', source.observed_ttl)}
                    {renderField('initial_ttl', source.estimated_initial_ttl)}
                  </div>
                )}
                {Array.isArray(source.items) && source.items.length > 0 && (
                  <div className="space-y-2 mt-3">
                    {source.items.map((item, index) => (
                      <div key={`${item.service}-${index}`} className="text-xs text-gray-300 border border-dark-700 rounded-lg p-3">
                        <span className="text-purple-200">{item.service}</span>: {item.reason}
                      </div>
                    ))}
                  </div>
                )}
                {source.details && <pre className="text-xs text-gray-300 mt-3 whitespace-pre-wrap">{JSON.stringify(source.details, null, 2)}</pre>}
              </div>
            ))}
          </div>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">TCP/IP Stack Fingerprint</div>
            {renderField('window_size', tcp.window_size)}
            {renderField('mss', tcp.mss)}
            {renderField('sack', tcp.sack_permitted)}
            {renderField('timestamps', tcp.timestamps_enabled)}
            {renderField('tcp_options', tcp.tcp_options)}
          </div>
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Environment</div>
            {renderField('virtualization', data.environment)}
            {renderField('signals', data.virtualization_signals)}
            {renderField('uptime', data.uptime_estimate?.value || data.uptime_estimate?.confidence)}
            {data.uptime_estimate?.note && <p className="text-xs text-gray-500 mt-3">{data.uptime_estimate.note}</p>}
          </div>
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Internet Exposure Context</div>
            {renderField('classification', exposure.classification)}
            {renderField('public', exposure.is_public)}
            {renderField('country', [geo.country, geo.country_code && `(${geo.country_code})`].filter(Boolean).join(' '))}
            {renderField('asn', geo.asn)}
          </div>
        </section>

        <section className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Timeline / Detection Flow</div>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            {(data.fingerprint_timeline || []).map((step, index) => (
              <div key={step.step} className="relative border border-dark-600 bg-dark-900/30 rounded-lg p-4">
                <div className="text-[10px] font-mono text-purple-300">Step {index + 1}</div>
                <div className="text-sm font-semibold text-gray-100 mt-2">{step.step}</div>
                <div className="text-xs text-gray-400 mt-2">{step.detail}</div>
                <div className="text-xs font-mono text-gray-300 mt-3">{pct(step.confidence_after)}%</div>
              </div>
            ))}
          </div>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">
              <ShieldCheck className="w-4 h-4" />
              Security Indicators
            </div>
            <div className="flex flex-wrap gap-2 mb-4">
              {chip(`Firewall: ${data.firewall_detection?.possible ? 'Possible' : 'Not obvious'}`, data.firewall_detection?.possible ? 'warn' : 'good')}
              {chip(`Honeypot: ${data.honeypot_detection?.possible ? 'Possible' : 'No obvious signal'}`, data.honeypot_detection?.possible ? 'warn' : 'good')}
              {chip(`Quality: ${data.scan_quality?.label || 'Unknown'}`, 'info')}
            </div>
            {(data.hardening_indicators || []).map((item) => (
              <div key={item.name} className="text-sm text-gray-300 border border-dark-700 rounded-lg p-3 mb-2">
                <span className="text-purple-200">{item.name}</span>: {item.detail}
              </div>
            ))}
            {data.scan_quality?.reason && <p className="text-xs text-gray-500 mt-3">{data.scan_quality.reason}</p>}
          </div>

          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">
              <Activity className="w-4 h-4" />
              Attack Surface by OS
            </div>
            <div className="space-y-2">
              {(data.attack_surface_by_os || []).map((item) => (
                <div key={item} className="text-sm text-gray-300 border border-dark-700 rounded-lg p-3">{item}</div>
              ))}
              {(!data.attack_surface_by_os || data.attack_surface_by_os.length === 0) && <p className="text-sm text-gray-500">No OS-specific attack surface rules matched.</p>}
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">CPE Mapping</div>
            {(data.cpe_matches || []).map((item) => (
              <div key={item.cpe} className="flex items-center justify-between gap-3 border border-dark-700 rounded-lg p-3 mb-2">
                <span className="text-xs font-mono text-gray-200 break-all">{item.cpe}</span>
                <span className="text-xs text-purple-200">{item.confidence}%</span>
              </div>
            ))}
          </div>
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">MITRE ATT&CK Mapping</div>
            {(data.mitre_attack || []).map((item, index) => (
              <div key={`${item.id}-${index}`} className="border border-dark-700 rounded-lg p-3 mb-2">
                <div className="text-sm text-gray-100">{item.id} · {item.name}</div>
                <div className="text-xs text-gray-500 mt-1">{item.tactic} · {item.reason}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">EOL & Vulnerability Correlation</div>
            {[...(data.eol_findings || []), ...(data.vulnerability_correlation || [])].map((item, index) => (
              <div key={`${item.component}-${index}`} className="border border-dark-700 rounded-lg p-3 mb-2">
                <div className="text-sm text-gray-100">{item.component}</div>
                <div className="text-xs text-gray-400 mt-1">{item.reason || item.finding}</div>
              </div>
            ))}
          </div>
          <div className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Open Services</div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {(data.open_ports || []).map((port) => (
                <div key={port.port} className="border border-dark-700 rounded-lg p-3">
                  <div className="text-sm text-gray-100">TCP/{port.port} · {port.service}</div>
                  <div className="text-xs text-gray-500 mt-1 break-words">{port.version || port.fingerprint?.detected || 'No version captured'}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="border border-dark-600 bg-dark-800/45 rounded-lg p-5">
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-500 mb-4">Historical Fingerprint Comparison</div>
          <p className="text-sm text-gray-300">{data.historical_comparison?.summary || 'No baseline available.'}</p>
        </section>
      </div>
    );
  };

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
        {toolId === 'ping' && (
          <>
              <input
                type="number"
                min="1"
                max="100"
                className="scan-input max-w-[120px]"
                value={count}
                onChange={(e) => setCount(Math.max(1, Math.min(100, Number(e.target.value) || 4)))}
                disabled={liveMode}
                aria-label="Ping packet count"
              />
          </>
        )}
        {toolId === 'traceroute' && (
          <input
            type="number"
            min="1"
            max="64"
            className="scan-input max-w-[136px]"
            value={maxHops}
            onChange={(e) => setMaxHops(Math.max(1, Math.min(64, Number(e.target.value) || 30)))}
            disabled={liveMode}
            aria-label="Traceroute max hops"
          />
        )}
        {['ping', 'traceroute'].includes(toolId) && (
          <button
            type="button"
            onClick={toggleLiveMode}
            disabled={!target}
            className={`run-btn min-w-[132px] ${liveMode ? 'shadow-[0_0_24px_rgba(34,211,238,0.35)]' : ''}`}
          >
            <span>{liveMode ? 'Live On' : 'Live'}</span>
            <Radio className="w-4 h-4" />
          </button>
        )}
        <button onClick={() => run()} disabled={loading || !target} className="run-btn">
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
        ) : toolId === 'osfingerprint' ? (
          renderOsFingerprintResults(results)
        ) : toolId === 'ping' ? (
          renderPingResults(results)
        ) : toolId === 'traceroute' ? (
          renderTracerouteResults(results)
        ) : toolId === 'headers' ? (
          renderHeadersResults(results)
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
