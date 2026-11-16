import type { JSX } from 'solid-js';
import { DETECTOR_LABELS } from '../../lib/config.js';
import type { Alert, DetectorType, SecurityIncident } from '../../lib/types.js';
import { fmtDateTime, fmtDuration, fmtNum, fmtTime } from '../format.js';

const SEVERITY_COLORS: Record<Alert['severity'], string> = {
  low: '#6b7280',
  medium: '#d97706',
  high: '#ea580c',
  critical: '#dc2626',
};

const TYPE_COLORS: Record<DetectorType, string> = {
  impossible_travel: '#7c3aed',
  password_spray: '#0891b2',
  brute_force: '#ea580c',
  credential_stuffing: '#dc2626',
};

export function severityColor(s: Alert['severity']): string {
  return SEVERITY_COLORS[s] ?? '#6b7280';
}

export function typeColor(t: DetectorType): string {
  return TYPE_COLORS[t] ?? '#6b7280';
}

export function TypeBadge(props: { type: DetectorType }): JSX.Element {
  return (
    <span class="badge" style={{ background: TYPE_COLORS[props.type] }}>
      {DETECTOR_LABELS[props.type]}
    </span>
  );
}

export function SeverityBadge(props: { severity: Alert['severity'] }): JSX.Element {
  return (
    <span class="badge" style={{ background: SEVERITY_COLORS[props.severity] }}>
      {props.severity.toUpperCase()}
    </span>
  );
}

/** 事件卡片：列表中的一行，点击展开时间线。 */
export function IncidentCard(props: { incident: SecurityIncident; onOpen: (id: string) => void }): JSX.Element {
  const inc = props.incident;
  return (
    <button class="incident-card" onClick={() => props.onOpen(inc.id)}>
      <div class="incident-head">
        <span class="incident-id">{inc.id}</span>
        <SeverityBadge severity={inc.severity} />
        <span class="incident-duration">{fmtDuration(inc.endTs - inc.startTs)}</span>
      </div>
      <div class="incident-types">
        {inc.types.map((t) => (
          <TypeBadge type={t} />
        ))}
      </div>
      <div class="incident-meta">
        <span>👤 {fmtNum(inc.users.length)} 账号</span>
        <span>🌐 {fmtNum(inc.ips.length)} IP</span>
        <span>🔔 {inc.alertCount} 告警</span>
        <span>📄 {fmtNum(inc.eventCount)} 事件</span>
      </div>
      <div class="incident-time">
        {fmtDateTime(inc.startTs)} → {fmtTime(inc.endTs)}
      </div>
    </button>
  );
}
