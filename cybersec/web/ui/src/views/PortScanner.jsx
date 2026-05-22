import React, { useState, useEffect } from 'react';
import { ScanLine, X, ArrowRight, FileText } from 'lucide-react';
import {
  parsePortScanResponse,
  collectDetectedTechnologies,
  hasBannerData,
  bannerPreview,
  riskBadgeProps,
} from '../utils/portScan';

const RISK_COLORS = {
  critical: { bg: 'rgba(239,68,68,0.12)', text: '#f87171', border: 'rgba(239,68,68,0.25)' },
  high:     { bg: 'rgba(249,115,22,0.12)', text: '#fb923c', border: 'rgba(249,115,22,0.25)' },
  medium:   { bg: 'rgba(234,179,8,0.12)',  text: '#facc15', border: 'rgba(234,179,8,0.25)' },
  low:      { bg: 'rgba(34,197,94,0.12)',  text: '#4ade80', border: 'rgba(34,197,94,0.25)' },
  open:     { bg: 'rgba(124,58,237,0.12)', text: '#a78bfa', border: 'rgba(124,58,237,0.3)' },
};

function RiskBadge({ label = 'medium', color = 'medium', title }) {
  const c = RISK_COLORS[color] || RISK_COLORS.medium;
  return (
    <span
      className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded-full"
      style={{ background: c.bg, color: c.text, border: `1px solid ${c.border}` }}
      title={title}
    >
      {label}
    </span>
  );
}

const PORT_RESULT_COLUMNS =
  '72px 88px minmax(90px, 1fr) 96px minmax(150px, 200px) minmax(120px, 160px) 100px 88px';

function BannerSection({ label, text }) {
  if (!text) return null;
  return (
    <div>
      <div className="banner-section-label">{label}</div>
      <pre className="banner-section-pre">{text}</pre>
    </div>
  );
}

function BannerModal({ row, target, onClose }) {
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  if (!row) return null;

  return (
    <div
      className="banner-modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="banner-modal-title"
      onClick={onClose}
    >
      <div className="banner-modal" onClick={(e) => e.stopPropagation()}>
        <div className="banner-modal-header">
          <div>
            <h2
              id="banner-modal-title"
              className="text-sm font-semibold"
              style={{ color: '#e9d5ff' }}
            >
              Port {row.port} — {row.service}
            </h2>
            <p className="text-[10px] font-mono mt-0.5" style={{ color: '#8b7ec8' }}>
              {target}
              {row.version ? ` · ${row.version}` : ''}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="clear-input-btn"
            style={{ position: 'static', transform: 'none' }}
            aria-label="Close banner"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="banner-modal-body">
          <BannerSection label="Welcome message" text={row.welcome_message} />
          <BannerSection label="Server response" text={row.server_response} />
          <BannerSection label="Raw banner" text={row.raw_banner} />
          {row.technologies?.length > 0 && (
            <div>
              <div className="banner-section-label">Detected technologies</div>
              <div className="detected-tech-chips">
                {row.technologies.map((name) => (
                  <TechChip key={name} name={name} />
                ))}
              </div>
            </div>
          )}
          {!hasBannerData(row) && (
            <p className="text-xs" style={{ color: '#6b5fa0' }}>
              No banner data was captured for this port.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function ServiceTooltip({ row }) {
  const name = row.service_name || row.service || 'Unknown';
  const title = `Port ${row.port} (${name})`;
  return (
    <span className="port-service-tooltip-wrap">
      <span className="text-sm font-medium truncate block" style={{ color: '#c4b5fd' }}>
        {row.service || '—'}
      </span>
      <div className="port-service-tooltip" role="tooltip">
        <div className="port-service-tooltip-title">{title}</div>
        <div className="port-service-tooltip-label">What it does</div>
        <p className="port-service-tooltip-text">{row.service_description}</p>
        <div className="port-service-tooltip-label">Security concern</div>
        <p className="port-service-tooltip-text">{row.service_security_concern}</p>
      </div>
    </span>
  );
}

function TechChip({ name }) {
  return <span className="tech-chip">{name}</span>;
}

function DetectedTechnologiesPanel({ technologies }) {
  if (!technologies?.length) return null;
  return (
    <div className="detected-tech-panel">
      <div className="detected-tech-panel-title">Detected Technologies</div>
      <div className="detected-tech-chips">
        {technologies.map((name) => (
          <TechChip key={name} name={name} />
        ))}
      </div>
    </div>
  );
}

function RecommendedActionsPanel({ rows, error }) {
  const recommendations = (rows || []).filter((row) => row.recommendation);
  if (!recommendations.length && !error) return null;

  return (
    <div className="recommended-actions-panel">
      <div className="recommended-actions-title">Recommended Actions</div>
      {recommendations.length > 0 ? (
        <div className="recommended-actions-list">
          {recommendations.map((row) => {
            const priority = row.recommendation_priority || row.risk_level || 'medium';
            return (
              <div key={`rec-${row.port}`} className="recommended-action-item">
                <div className="recommended-action-head">
                  <span className="recommended-action-port">
                    Port {row.port} ({row.service || 'Unknown'})
                  </span>
                  <RiskBadge label={priority} color={priority} />
                </div>
                {row.recommendation_reason && (
                  <p className="recommended-action-reason">{row.recommendation_reason}</p>
                )}
                <p className="recommended-action-text">{row.recommendation}</p>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="recommended-action-error">{error}</p>
      )}
    </div>
  );
}

function scoreColor(score) {
  if (score >= 85) return '#4ade80';
  if (score >= 70) return '#facc15';
  if (score >= 50) return '#fb923c';
  return '#f87171';
}

function SecurityScorePanel({ stats }) {
  if (!stats) return null;
  const score = Math.max(0, Math.min(100, Math.round(stats.securityScore ?? 100)));
  const factors = stats.securityScoreFactors || [];

  return (
    <div className="security-score-panel">
      <div className="security-score-main">
        <span className="security-score-label">Security Score</span>
        <span className="security-score-value" style={{ color: scoreColor(score) }}>
          {score}/100
        </span>
      </div>
      <div className="security-score-based">Based on:</div>
      {factors.length > 0 ? (
        <div className="security-score-factors">
          {factors.map((factor, index) => (
            <div key={`${factor.category}-${index}`} className="security-score-factor">
              <RiskBadge label={factor.severity || 'medium'} color={factor.severity || 'medium'} />
              <span>{factor.label}</span>
            </div>
          ))}
        </div>
      ) : (
        <p className="security-score-empty">This scan did not produce risky-port, exposed-service, weak TLS, or vulnerable-version scoring factors.</p>
      )}
    </div>
  );
}

function surfaceColor(level) {
  const normalized = (level || '').toUpperCase();
  if (normalized === 'LOW') return '#4ade80';
  if (normalized === 'MEDIUM') return '#facc15';
  if (normalized === 'HIGH') return '#fb923c';
  if (normalized === 'CRITICAL') return '#f87171';
  return '#a78bfa';
}

function combineAttackSurface(current, incoming) {
  if (!incoming) return current;
  const servicesByKey = new Map();
  [...(current?.publiclyExposedServices || []), ...(incoming.publiclyExposedServices || [])]
    .forEach((entry) => {
      servicesByKey.set(`${entry.port}-${entry.service}`, entry);
    });
  const factors = [...(current?.factors || []), ...(incoming.factors || [])];
  const score = Math.min(100, Math.max(Number(current?.score || 0), Number(incoming.score || 0)));
  const levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const currentLevel = (current?.level || 'LOW').toUpperCase();
  const incomingLevel = (incoming.level || 'LOW').toUpperCase();
  const level = levels[Math.max(levels.indexOf(currentLevel), levels.indexOf(incomingLevel), 0)];

  return {
    level,
    score,
    publiclyExposedServices: Array.from(servicesByKey.values()),
    factors: factors.slice(0, 12),
    summary: `${level} attack surface based on ${servicesByKey.size} exposed service(s).`,
  };
}

function reputationColor(reputation) {
  const value = (reputation || '').toLowerCase();
  if (value === 'malicious') return '#f87171';
  if (value === 'suspicious') return '#fb923c';
  if (value === 'clean') return '#4ade80';
  if (value === 'private/local') return '#a78bfa';
  return '#facc15';
}

function combineThreatIntelligence(current, incoming) {
  if (!incoming) return current;
  if (!current) return incoming;
  const rank = { Unknown: 0, Clean: 1, 'Private/Local': 1, Suspicious: 2, Malicious: 3 };
  const currentRank = rank[current.reputation] ?? 0;
  const incomingRank = rank[incoming.reputation] ?? 0;
  return incomingRank > currentRank ? incoming : current;
}

function ThreatIntelligencePanel({ stats }) {
  const intel = stats?.threatIntelligence;
  if (!intel) return null;

  return (
    <div className="threat-intel-panel">
      <div className="threat-intel-head">
        <span className="threat-intel-title">Threat Intelligence</span>
        <span className="threat-intel-reputation" style={{ color: reputationColor(intel.reputation) }}>
          IP Reputation: {intel.reputation}
        </span>
      </div>
      <div className="threat-intel-summary">
        {intel.summary || 'IP reputation data was not available for this target.'}
      </div>
      <div className="threat-intel-grid">
        <span>IP: <strong>{intel.ip || 'Unknown'}</strong></span>
        <span>Reported: <strong>{intel.reportedTimes || 0} time(s)</strong></span>
        <span>Abuse Score: <strong>{intel.abuseConfidenceScore ?? 'Unknown'}</strong></span>
        <span>Known Botnet: <strong>{intel.knownBotnet ? 'Yes' : 'No'}</strong></span>
      </div>
      <div className="threat-intel-sources">
        <span>Sources:</span>
        {(intel.sources?.length ? intel.sources : ['No source returned a hit']).map((source) => (
          <span key={source}>{source}</span>
        ))}
      </div>
      {intel.spamhaus?.listed && (
        <div className="threat-intel-warning">
          Spamhaus listing detected: {intel.spamhaus.zones?.map((zone) => zone.name || zone.zone).join(', ')}
        </div>
      )}
      {intel.error && <div className="threat-intel-note">{intel.error}</div>}
    </div>
  );
}

function AttackSurfacePanel({ stats }) {
  const surface = stats?.attackSurface;
  if (!surface) return null;

  return (
    <div className="attack-surface-panel">
      <div className="attack-surface-head">
        <span className="attack-surface-title">Attack Surface Analysis</span>
        <span className="attack-surface-level" style={{ color: surfaceColor(surface.level) }}>
          {surface.level}
        </span>
      </div>
      <div className="attack-surface-section-label">Publicly Exposed Services</div>
      {surface.publiclyExposedServices?.length > 0 ? (
        <div className="attack-surface-services">
          {surface.publiclyExposedServices.map((entry) => (
            <span key={`${entry.port}-${entry.service}`} className="attack-surface-service">
              {entry.service}
              <span>{entry.port}</span>
            </span>
          ))}
        </div>
      ) : (
        <p className="attack-surface-muted">No open services were exposed in this scan.</p>
      )}
      {surface.summary && <p className="attack-surface-summary">{surface.summary}</p>}
      {surface.factors?.length > 0 && (
        <div className="attack-surface-factors">
          {surface.factors.slice(0, 5).map((factor, index) => (
            <div key={`${factor.category}-${index}`} className="attack-surface-factor">
              <RiskBadge label={factor.severity || 'medium'} color={factor.severity || 'medium'} />
              <span>{factor.label}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ExposureSeverityPanel({ rows, stats }) {
  const exposures = (rows || [])
    .filter((row) => row.exposure_severity?.finding)
    .sort((a, b) => (b.exposure_severity.score || 0) - (a.exposure_severity.score || 0));
  if (!exposures.length) return null;

  const summary = stats?.exposureSummary || {};
  const highest = summary.highestSeverity || exposures[0]?.exposure_severity?.severity || 'low';

  return (
    <div className="exposure-panel">
      <div className="exposure-head">
        <span className="exposure-title">Exposure Severity Engine</span>
        <span className="exposure-score" style={{ color: scoreColor(100 - (summary.highestScore || 0)) }}>
          {String(highest).toUpperCase()} · {summary.highestScore || exposures[0].exposure_severity.score}/100
        </span>
      </div>
      <p className="exposure-lead">
        {summary.highestFinding || exposures[0].exposure_severity.finding}
      </p>
      <div className="exposure-summary">
        <span>Public Exposure: <strong>{summary.publicExposure ? 'Yes' : 'No'}</strong></span>
        {['critical', 'high', 'medium', 'low'].map((level) => (
          <span key={level}>{level}: <strong>{summary[level] || 0}</strong></span>
        ))}
      </div>
      <div className="exposure-list">
        {exposures.slice(0, 6).map((row) => {
          const exposure = row.exposure_severity;
          const severity = ['critical', 'high', 'medium', 'low'].includes(exposure.severity)
            ? exposure.severity
            : 'medium';
          return (
            <div key={`exposure-${row.port}`} className="exposure-item">
              <div className="exposure-item-head">
                <span className="exposure-port">Port {row.port} ({row.service || 'Unknown'})</span>
                <span className="exposure-item-score">
                  {exposure.score}/100
                  <RiskBadge label={severity} color={severity} />
                </span>
              </div>
              <p className="exposure-finding">{exposure.finding}</p>
              {exposure.factors?.length > 0 && (
                <div className="exposure-factors">
                  {exposure.factors.slice(0, 5).map((factor) => (
                    <span key={`${row.port}-${factor}`}>{factor}</span>
                  ))}
                </div>
              )}
              {exposure.recommendation && (
                <p className="exposure-recommendation">
                  <span>Action:</span> {exposure.recommendation}
                </p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AttackPathPanel({ stats }) {
  const graph = stats?.attackPaths;
  if (!graph?.nodes?.length || !graph?.paths?.length) return null;

  const nodeMap = new Map(graph.nodes.map((node) => [node.id, node]));
  const primaryPath = graph.paths[0];
  const steps = primaryPath.steps
    .map((id) => nodeMap.get(id))
    .filter(Boolean);
  if (!steps.length) return null;

  return (
    <div className="attack-path-panel">
      <div className="attack-path-head">
        <span className="attack-path-title">Attack Path Visualization</span>
        <RiskBadge
          label={graph.highestSeverity || primaryPath.severity || 'medium'}
          color={graph.highestSeverity || primaryPath.severity || 'medium'}
        />
      </div>
      <p className="attack-path-summary">
        {graph.summary || primaryPath.summary}
      </p>
      <div className="attack-path-flow" aria-label={primaryPath.title}>
        {steps.map((node, index) => {
          const next = steps[index + 1];
          const edge = next
            ? graph.edges.find((item) => item.source === node.id && item.target === next.id)
            : null;
          return (
            <React.Fragment key={node.id}>
              <div className={`attack-path-node attack-path-node-${node.type}`}>
                <span className="attack-path-node-type">{node.type}</span>
                <span className="attack-path-node-label">{node.label}</span>
                {node.port && <span className="attack-path-node-port">TCP/{node.port}</span>}
                {node.detail && <span className="attack-path-node-detail">{node.detail}</span>}
              </div>
              {edge && (
                <div className="attack-path-edge" aria-hidden="true">
                  <span />
                  <strong>↓</strong>
                  <em>{edge.label}</em>
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
      {graph.paths.length > 1 && (
        <div className="attack-path-alt">
          {graph.paths.slice(1, 4).map((path) => (
            <span key={path.id}>{path.summary}</span>
          ))}
        </div>
      )}
    </div>
  );
}

function AttackSimulationPanel({ stats }) {
  const simulations = stats?.attackSimulations || [];
  if (!simulations.length) return null;

  return (
    <div className="attack-sim-panel">
      <div className="attack-sim-title">Attack Simulation Recommendations</div>
      <div className="attack-sim-list">
        {simulations.slice(0, 5).map((simulation) => (
          <div key={simulation.id || simulation.chain} className="attack-sim-item">
            <div className="attack-sim-head">
              <span>{simulation.title}</span>
              <RiskBadge label={simulation.severity || 'medium'} color={simulation.severity || 'medium'} />
            </div>
            <div className="attack-sim-label">Possible Attack Chain</div>
            <div className="attack-sim-chain">
              {(simulation.steps?.length ? simulation.steps : simulation.chain.split('→')).map((step, index, arr) => (
                <React.Fragment key={`${simulation.id}-${step}-${index}`}>
                  <span>{String(step).trim()}</span>
                  {index < arr.length - 1 && <strong>→</strong>}
                </React.Fragment>
              ))}
            </div>
            <div className="attack-sim-meta">
              <span>Likelihood: <strong>{simulation.likelihood || 'Medium'}</strong></span>
              <span>Basis: <strong>{simulation.confidence || 'Inferred'}</strong></span>
              {simulation.evidence?.slice(0, 3).map((item) => (
                <span key={`${simulation.id}-${item}`}>{item}</span>
              ))}
            </div>
            {simulation.recommendation && (
              <p className="attack-sim-recommendation">
                <span>Recommendation:</span> {simulation.recommendation}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function MisconfigurationPanel({ rows, stats }) {
  const items = (rows || []).flatMap((row) =>
    (row.misconfigurations || []).map((finding, index) => ({
      ...finding,
      port: row.port,
      service: row.service,
      key: `${row.port}-${finding.category || finding.title}-${index}`,
    })),
  );
  if (!items.length) return null;

  const summary = stats?.misconfigurationSummary || {};

  return (
    <div className="misconfig-panel">
      <div className="misconfig-head">
        <span className="misconfig-title">Misconfiguration Detection</span>
        <span className="misconfig-count">
          {summary.total || items.length} finding{(summary.total || items.length) === 1 ? '' : 's'}
        </span>
      </div>
      <div className="misconfig-summary">
        {['critical', 'high', 'medium', 'low'].map((level) => (
          <span key={level}>
            {level}: <strong>{summary[level] || 0}</strong>
          </span>
        ))}
      </div>
      <div className="misconfig-list">
        {items.map((finding) => {
          const severity = ['critical', 'high', 'medium', 'low'].includes(finding.severity)
            ? finding.severity
            : 'medium';
          return (
            <div key={finding.key} className="misconfig-item">
              <div className="misconfig-item-head">
                <span className="misconfig-port">
                  Port {finding.port} ({finding.service || 'Unknown'})
                </span>
                <RiskBadge label={severity} color={severity} />
              </div>
              <div className="misconfig-finding-title">{finding.title}</div>
              {finding.evidence && <p className="misconfig-evidence">{finding.evidence}</p>}
              {finding.recommendation && (
                <p className="misconfig-recommendation">
                  <span>Recommendation:</span> {finding.recommendation}
                </p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function MitreAttackPanel({ rows }) {
  const mappedRows = (rows || []).filter((row) => row.mitre_attack?.length);
  if (!mappedRows.length) return null;

  return (
    <div className="mitre-panel">
      <div className="mitre-panel-title">MITRE ATT&amp;CK Mapping</div>
      <div className="mitre-list">
        {mappedRows.map((row) => (
          <div key={`mitre-${row.port}`} className="mitre-item">
            <div className="mitre-item-head">
              <span className="mitre-port">Port {row.port}</span>
              <span className="mitre-service">{row.service || 'Unknown'}</span>
            </div>
            <div className="mitre-techniques">
              {row.mitre_attack.slice(0, 4).map((technique) => (
                <a
                  key={`${row.port}-${technique.technique_id}`}
                  href={technique.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mitre-technique"
                  title={technique.attack_vector}
                >
                  <span className="mitre-technique-name">
                    {technique.technique_name} ({technique.technique_id})
                  </span>
                  <span className="mitre-technique-tactic">{technique.tactic}</span>
                </a>
              ))}
            </div>
            {row.potential_threat && (
              <p className="mitre-threat">
                <span>Potential Threat:</span> {row.potential_threat}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function exploitStatusColor(value) {
  if (value === true) return '#f87171';
  if (value === false) return '#4ade80';
  return '#facc15';
}

function cvssSeverity(score, fallback = 'UNKNOWN') {
  if (score == null || Number.isNaN(Number(score))) return fallback || 'UNKNOWN';
  const value = Number(score);
  if (value >= 9) return 'CRITICAL';
  if (value >= 7) return 'HIGH';
  if (value >= 4) return 'MEDIUM';
  if (value > 0) return 'LOW';
  return 'NONE';
}

function cvssLabel(score, severity) {
  if (score == null || Number.isNaN(Number(score))) return null;
  const normalized = cvssSeverity(score, severity).toLowerCase();
  const label = normalized.charAt(0).toUpperCase() + normalized.slice(1);
  return `CVSS: ${Number(score).toFixed(1)} ${label}`;
}

function ExploitAvailabilityPanel({ rows }) {
  const items = (rows || [])
    .filter((row) => row.exploit_availability)
    .filter((row) => row.exploit_availability.publicExploitAvailable !== false || row.exploit_availability.evidence?.length);
  if (!items.length) return null;

  return (
    <div className="exploit-panel">
      <div className="exploit-panel-title">Exploit Availability Check</div>
      <div className="exploit-list">
        {items.map((row) => {
          const exploit = row.exploit_availability;
          const available = exploit.publicExploitAvailable;
          return (
            <div key={`exploit-${row.port}`} className="exploit-item">
              <div className="exploit-head">
                <span className="exploit-version">
                  {exploit.serviceVersion || `${row.service} on port ${row.port}`}
                </span>
                <span className="exploit-status" style={{ color: exploitStatusColor(available) }}>
                  {available === true ? 'Curated Public Exploit Signal' : 'Exploit Status Unknown'}
                </span>
              </div>
              <div className="exploit-meta">
                <span>ExploitDB: <strong>{exploit.exploitdb}</strong></span>
                <span>Metasploit Module: <strong>{exploit.metasploit}</strong></span>
                {exploit.metasploitModule && (
                  <span>Module: <strong>{exploit.metasploitModule}</strong></span>
                )}
              </div>
              {exploit.evidence?.length > 0 && (
                <div className="exploit-evidence">
                  {exploit.evidence.slice(0, 3).map((item) => (
                    <span key={`${row.port}-${item}`}>{item}</span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function CVEModal({ row, onClose }) {
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  if (!row?.cve_result?.cves?.length) return null;

  const { cve_result } = row;

  return (
    <div
      className="banner-modal-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="cve-modal-title"
      onClick={onClose}
    >
      <div className="banner-modal" onClick={(e) => e.stopPropagation()}>
        <div className="banner-modal-header">
          <div>
            <h2
              id="cve-modal-title"
              className="text-sm font-semibold"
              style={{ color: '#e9d5ff' }}
            >
              CVE Details — {row.service} {row.version}
            </h2>
            <p className="text-[10px] font-mono mt-0.5" style={{ color: '#8b7ec8' }}>
              Port {row.port} · {cve_result.total_count} vulnerabilities found
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="clear-input-btn"
            style={{ position: 'static', transform: 'none' }}
            aria-label="Close CVE details"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="banner-modal-body">
          <div className="flex gap-2 mb-4">
            {cve_result.critical_count > 0 && (
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full" style={{ background: 'rgba(239,68,68,0.12)', color: '#f87171', border: '1px solid rgba(239,68,68,0.25)' }}>
                {cve_result.critical_count} CRITICAL
              </span>
            )}
            {cve_result.high_count > 0 && (
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full" style={{ background: 'rgba(249,115,22,0.12)', color: '#fb923c', border: '1px solid rgba(249,115,22,0.25)' }}>
                {cve_result.high_count} HIGH
              </span>
            )}
            {cve_result.medium_count > 0 && (
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full" style={{ background: 'rgba(234,179,8,0.12)', color: '#facc15', border: '1px solid rgba(234,179,8,0.25)' }}>
                {cve_result.medium_count} MEDIUM
              </span>
            )}
            {cve_result.low_count > 0 && (
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full" style={{ background: 'rgba(34,197,94,0.12)', color: '#4ade80', border: '1px solid rgba(34,197,94,0.25)' }}>
                {cve_result.low_count} LOW
              </span>
            )}
          </div>
          <div className="flex flex-col gap-3">
            {cve_result.cves.map((cve) => (
              <div key={cve.cve_id} className="p-3 rounded-lg" style={{ background: 'rgba(124,58,237,0.08)', border: '1px solid rgba(124,58,237,0.15)' }}>
                <div className="flex items-center justify-between mb-2">
                  <a
                    href={cve.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono font-semibold hover:underline"
                    style={{ color: '#c4b5fd' }}
                  >
                    {cve.cve_id}
                  </a>
                  <RiskBadge label={cve.severity} color={cve.severity.toLowerCase()} />
                </div>
                {cve.cvss_score != null && (
                  <div className="cve-cvss-line">
                    {cvssLabel(cve.cvss_score, cve.severity)}
                    {cve.cvss_vector && <span>{cve.cvss_vector}</span>}
                  </div>
                )}
                <p className="text-[11px] leading-relaxed" style={{ color: '#a78bfa' }}>
                  {cve.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function CVECell({ row, onViewCVE }) {
  if (!row.cve_count || row.cve_count === 0) {
    return <span className="text-[10px] font-mono" style={{ color: '#5b4d82' }}>—</span>;
  }

  const hasCritical = row.cve_critical_count > 0;
  const hasHigh = row.cve_high_count > 0;
  const maxCvss = row.max_cvss_score == null ? null : Number(row.max_cvss_score);
  
  return (
    <button
      type="button"
      onClick={() => onViewCVE(row)}
      className="cve-cell-btn"
      title={`${row.cve_count} CVEs detected`}
    >
      <span className="text-[10px] font-mono font-semibold" style={{ color: hasCritical ? '#f87171' : hasHigh ? '#fb923c' : '#facc15' }}>
        {row.cve_count}
      </span>
      <span className="text-[9px] font-mono" style={{ color: '#8b7ec8' }}>
        {maxCvss != null ? `CVSS ${maxCvss.toFixed(1)}` : `CVE${row.cve_count !== 1 ? 's' : ''}`}
      </span>
    </button>
  );
}

function PortTechnologies({ technologies }) {
  if (!technologies?.length) {
    return <span className="text-[10px] font-mono" style={{ color: '#5b4d82' }}>—</span>;
  }
  return (
    <div className="port-row-tech-chips">
      {technologies.map((name) => (
        <TechChip key={name} name={name} />
      ))}
    </div>
  );
}

function fingerprintColor(confidence) {
  if (confidence >= 85) return '#4ade80';
  if (confidence >= 70) return '#facc15';
  if (confidence >= 50) return '#fb923c';
  return '#f87171';
}

function VersionCell({ version, technologies, fingerprint }) {
  const hasVersion = Boolean(version);
  const confidence = Number(fingerprint?.confidence || 0);
  const detected = fingerprint?.detected || version;
  return (
    <div className="flex flex-col gap-1 min-w-0">
      <span
        className={`port-version-cell ${hasVersion ? 'has-version' : 'no-version'}`}
        title={hasVersion ? version : undefined}
      >
        {hasVersion ? version : '—'}
      </span>
      {detected && confidence > 0 && (
        <div className="fingerprint-confidence" title={fingerprint?.method || undefined}>
          <span>Detected: {detected}</span>
          <strong style={{ color: fingerprintColor(confidence) }}>
            Confidence: {Math.round(confidence)}%
          </strong>
        </div>
      )}
      <PortTechnologies technologies={technologies} />
    </div>
  );
}

function ScreenshotPreview({ row }) {
  if (!row.screenshot_url) {
    return <span className="text-[10px] font-mono" style={{ color: '#5b4d82' }}>—</span>;
  }

  return (
    <a
      href={row.screenshot_url}
      target="_blank"
      rel="noopener noreferrer"
      className="web-port-preview"
      title={`Open screenshot preview for port ${row.port}`}
    >
      <img src={row.screenshot_url} alt={`Preview of port ${row.port}`} loading="lazy" />
    </a>
  );
}

function formatScanDuration(seconds) {
  const n = Number(seconds);
  if (!Number.isFinite(n)) return '0.0s';
  return `${n.toFixed(1)}s`;
}

function formatLatency(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n)) return '—';
  return `${Math.round(n)}ms`;
}

export default function PortScanner() {
  const [target, setTarget] = useState('');
  const [portRange, setPortRange] = useState('common');
  const [customPortRange, setCustomPortRange] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [bannerRow, setBannerRow] = useState(null);
  const [cveRow, setCveRow] = useState(null);
  const [detectedTechnologies, setDetectedTechnologies] = useState([]);
  const [scanStats, setScanStats] = useState(null);

  const handleScan = async () => {
    if (!target.trim() || isScanning) return;
    
    if (portRange === 'custom' && !customPortRange.trim()) {
      return;
    }
    
    setIsScanning(true);
    setResults([]);
    setDetectedTechnologies([]);
    setErrorMsg(null);
    setBannerRow(null);
    setCveRow(null);
    setScanStats(null);
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
      const allScanStart = performance.now();
      let packetsSent = 0;
      let weightedLatencyTotal = 0;
      let weightedLatencyPackets = 0;
      let securityScore = 100;
      let securityScoreFactors = [];
      let attackSurface = null;
      let threatIntelligence = null;

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

          const { ports, stats } = parsePortScanResponse(responseData);
          packetsSent += stats.packetsSent;
          if (Number.isFinite(stats.avgLatencyMs) && stats.packetsSent > 0) {
            weightedLatencyTotal += stats.avgLatencyMs * stats.packetsSent;
            weightedLatencyPackets += stats.packetsSent;
          }
          securityScore = Math.min(securityScore, stats.securityScore);
          securityScoreFactors.push(...(stats.securityScoreFactors || []));
          attackSurface = combineAttackSurface(attackSurface, stats.attackSurface);
          threatIntelligence = combineThreatIntelligence(threatIntelligence, stats.threatIntelligence);
          if (ports.length > 0) {
            allOpenPorts.push(...ports);
            setResults([...allOpenPorts]);
            setDetectedTechnologies(collectDetectedTechnologies(allOpenPorts));
          }

          setProgress(Math.floor((currentEnd / MAX_PORT) * 100));
          currentStart += BATCH_SIZE;
        }

        setTimeout(() => {
          setScanStats({
            scanDurationSeconds: (performance.now() - allScanStart) / 1000,
            packetsSent,
            avgLatencyMs: weightedLatencyPackets > 0
              ? weightedLatencyTotal / weightedLatencyPackets
              : null,
            securityScore,
            securityScoreFactors: securityScoreFactors.slice(0, 12),
            attackSurface,
            threatIntelligence,
          });
          setIsScanning(false);
          setProgress(0);
        }, 400);

      } else {
        let body = { target: targetClean, timeout: 3.0 };
        
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

        const { ports, detectedTechnologies: scanTechs, stats } = parsePortScanResponse(responseData);

        setTimeout(() => {
          setResults(ports);
          setDetectedTechnologies(scanTechs);
          setScanStats(stats);
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
                className="port-result-grid text-[10px] font-semibold tracking-wider uppercase"
                style={{
                  gridTemplateColumns: PORT_RESULT_COLUMNS,
                  color: '#8b7ec8',
                  borderBottom: '1px solid rgba(124,58,237,0.12)',
                }}
              >
                <span>Port</span>
                <span>State</span>
                <span>Service</span>
                <span>Preview</span>
                <span>Version / Tech</span>
                <span>Banner</span>
                <span>CVEs</span>
                <span>Risk</span>
              </div>
            )}

            <div className="flex-1 overflow-y-auto port-results-scroll">
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
                const riskProps = riskBadgeProps(r);
                return (
                  <div
                    key={`${r.port}-${i}`}
                    className="port-result-grid"
                    style={{ gridTemplateColumns: PORT_RESULT_COLUMNS }}
                  >
                    <span className="font-mono text-sm font-semibold" style={{ color: '#ddd6fe' }}>
                      {r.port}
                    </span>
                    <span>
                      <RiskBadge label={r.state || 'open'} color={r.state === 'open' ? 'open' : 'low'} />
                    </span>
                    <ServiceTooltip row={r} />
                    <ScreenshotPreview row={r} />
                    <VersionCell
                      version={r.version}
                      technologies={r.technologies}
                      fingerprint={r.fingerprint}
                    />
                    <span className="flex flex-col gap-1 min-w-0">
                      <button
                        type="button"
                        className="banner-view-btn inline-flex items-center gap-1 self-start"
                        disabled={!hasBannerData(r)}
                        onClick={() => setBannerRow(r)}
                        title={
                          hasBannerData(r)
                            ? 'View captured banner'
                            : 'No banner captured'
                        }
                      >
                        <FileText className="w-3 h-3 shrink-0" />
                        View Banner
                      </button>
                      {hasBannerData(r) && (
                        <span
                          className="text-[10px] font-mono truncate port-banner-preview"
                          title={r.welcome_message || r.raw_banner}
                        >
                          {bannerPreview(r)}
                        </span>
                      )}
                    </span>
                    <CVECell row={r} onViewCVE={setCveRow} />
                    <span>
                      <RiskBadge
                        label={riskProps.label}
                        color={riskProps.color}
                        title={riskProps.title}
                      />
                    </span>
                  </div>
                );
              })}
            </div>

            {!isScanning && results.length > 0 && (
              <DetectedTechnologiesPanel technologies={detectedTechnologies} />
            )}

            {!isScanning && scanStats && (
              <SecurityScorePanel stats={scanStats} />
            )}

            {!isScanning && scanStats && (
              <ThreatIntelligencePanel stats={scanStats} />
            )}

            {!isScanning && scanStats && (
              <AttackSurfacePanel stats={scanStats} />
            )}

            {!isScanning && results.length > 0 && (
              <ExposureSeverityPanel rows={results} stats={scanStats} />
            )}

            {!isScanning && scanStats && (
              <AttackPathPanel stats={scanStats} />
            )}

            {!isScanning && scanStats && (
              <AttackSimulationPanel stats={scanStats} />
            )}

            {!isScanning && results.length > 0 && (
              <MisconfigurationPanel rows={results} stats={scanStats} />
            )}

            {!isScanning && results.length > 0 && (
              <MitreAttackPanel rows={results} />
            )}

            {!isScanning && results.length > 0 && (
              <ExploitAvailabilityPanel rows={results} />
            )}

            {!isScanning && results.length > 0 && (
              <RecommendedActionsPanel rows={results} error={scanStats?.recommendationsError} />
            )}

            {!isScanning && scanStats && (
              <div
                className="flex flex-wrap items-center gap-4 px-5 py-3 text-xs font-mono"
                style={{
                  borderTop: '1px solid rgba(124,58,237,0.12)',
                  color: '#6b5fa0',
                }}
              >
                <span>
                  <span style={{ color: '#a78bfa' }}>{results.length}</span> open
                </span>
                <span>
                  <span style={{ color: '#f87171' }}>{results.filter(r => r.risk_level === 'high').length}</span> high
                </span>
                <span>
                  <span style={{ color: '#facc15' }}>{results.filter(r => r.risk_level === 'medium').length}</span> med
                </span>
                <span>
                  <span style={{ color: '#4ade80' }}>{results.filter(r => r.risk_level === 'low').length}</span> low
                </span>
                <span>
                  Scan duration: <span style={{ color: '#c4b5fd' }}>{formatScanDuration(scanStats.scanDurationSeconds)}</span>
                </span>
                <span>
                  Packets sent: <span style={{ color: '#c4b5fd' }}>{scanStats.packetsSent}</span>
                </span>
                <span>
                  Latency: <span style={{ color: '#c4b5fd' }}>{formatLatency(scanStats.avgLatencyMs)}</span>
                </span>
                <span>
                  Security Score: <span style={{ color: scoreColor(scanStats.securityScore) }}>{Math.round(scanStats.securityScore ?? 100)}/100</span>
                </span>
                {scanStats.attackSurface && (
                  <span>
                    Attack Surface: <span style={{ color: surfaceColor(scanStats.attackSurface.level) }}>{scanStats.attackSurface.level}</span>
                  </span>
                )}
                {scanStats.exposureSummary && (
                  <span>
                    Exposure: <span style={{ color: scoreColor(100 - (scanStats.exposureSummary.highestScore || 0)) }}>{String(scanStats.exposureSummary.highestSeverity || 'low').toUpperCase()}</span>
                  </span>
                )}
                {scanStats.threatIntelligence && (
                  <span>
                    IP Reputation: <span style={{ color: reputationColor(scanStats.threatIntelligence.reputation) }}>{scanStats.threatIntelligence.reputation}</span>
                  </span>
                )}
                {scanStats.misconfigurationSummary && (
                  <span>
                    Misconfigs: <span style={{ color: '#fb923c' }}>{scanStats.misconfigurationSummary.total || 0}</span>
                  </span>
                )}
                <span className="ml-auto">
                  Target: <span style={{ color: '#c4b5fd' }}>{target}</span>
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {bannerRow && (
        <BannerModal
          row={bannerRow}
          target={target}
          onClose={() => setBannerRow(null)}
        />
      )}
      {cveRow && (
        <CVEModal
          row={cveRow}
          onClose={() => setCveRow(null)}
        />
      )}
    </div>
  );
}
