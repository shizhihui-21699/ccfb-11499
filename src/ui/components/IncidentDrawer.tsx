import type { JSX } from 'solid-js';
import { DETECTOR_LABELS } from '../../lib/config.js';
import type { SecurityIncident } from '../../lib/types.js';
import type { AnalysisReport } from '../../lib/engine.js';
import { fmtDateTime, fmtTime } from '../format.js';
import { SeverityBadge, TypeBadge, severityColor, typeColor } from './Badges';

/** 事件详情抽屉：时间线 + 关联告警证据 + 涉及实体。 */
export function IncidentDrawer(props: {
  report: AnalysisReport;
  incidentId: string | null;
  onClose: () => void;
}): JSX.Element {
  const incident = (): SecurityIncident | undefined =>
    props.report.incidents.find((i) => i.id === props.incidentId);

  const alertsFor = (inc: SecurityIncident) =>
    props.report.alerts.filter((a) => inc.alertIds.includes(a.id));

  return (
    <div class="drawer-mask" classList={{ open: props.incidentId !== null }} onClick={props.onClose}>
      <aside class="drawer" onClick={(e) => e.stopPropagation()}>
        {incident() && (
          <>
            <header class="drawer-header">
              <div>
                <h2>{incident()!.id}</h2>
                <div class="drawer-badges">
                  <SeverityBadge severity={incident()!.severity} />
                  {incident()!.types.map((t) => (
                    <TypeBadge type={t} />
                  ))}
                </div>
              </div>
              <button class="close-btn" onClick={props.onClose}>
                ✕
              </button>
            </header>

            <section>
              <h3>时间线</h3>
              <div class="timeline">
                {incident()!.timeline.map((entry) => (
                  <div class="tl-row" classList={{ [entry.kind]: true }}>
                    <span class="tl-dot" style={{ background: timelineColor(entry.kind) }} />
                    <span class="tl-time">{fmtTime(entry.ts)}</span>
                    <span class="tl-detail">
                      {entry.kind === 'alert' && '🔔 '}
                      {entry.kind === 'success' && '✅ '}
                      {entry.kind === 'failure' && '❌ '}
                      {entry.detail}
                    </span>
                  </div>
                ))}
              </div>
            </section>

            <section>
              <h3>关联告警证据（{incident()!.alertIds.length}）</h3>
              {alertsFor(incident()!).map((a) => (
                <div class="alert-evidence">
                  <div class="alert-ev-head">
                    <span class="badge" style={{ background: typeColor(a.type) }}>
                      {DETECTOR_LABELS[a.type]}
                    </span>
                    <span class="badge" style={{ background: severityColor(a.severity) }}>
                      {a.severity}
                    </span>
                    <span class="alert-subject">{a.subject}</span>
                  </div>
                  <table class="evidence-table">
                    {Object.entries(a.evidence).map(([k, v]) => (
                      <tr>
                        <td>{k}</td>
                        <td>{String(v)}</td>
                      </tr>
                    ))}
                  </table>
                  <div class="evidence-time">
                    {fmtDateTime(a.startTs)} → {fmtTime(a.endTs)}
                  </div>
                </div>
              ))}
            </section>

            <section>
              <h3>涉及实体</h3>
              <div class="entity-grid">
                <div>
                  <h4>账号（{incident()!.users.length}）</h4>
                  <div class="chip-list">
                    {incident()!.users.slice(0, 30).map((u) => (
                      <span class="chip">{u}</span>
                    ))}
                    {incident()!.users.length > 30 && <span class="chip">+{incident()!.users.length - 30}</span>}
                  </div>
                </div>
                <div>
                  <h4>源 IP（{incident()!.ips.length}）</h4>
                  <div class="chip-list">
                    {incident()!.ips.slice(0, 30).map((ip) => (
                      <span class="chip ip">{ip}</span>
                    ))}
                    {incident()!.ips.length > 30 && <span class="chip">+{incident()!.ips.length - 30}</span>}
                  </div>
                </div>
              </div>
            </section>
          </>
        )}
      </aside>
    </div>
  );
}

function timelineColor(kind: string): string {
  if (kind === 'alert') return '#dc2626';
  if (kind === 'success') return '#16a34a';
  return '#d97706';
}
