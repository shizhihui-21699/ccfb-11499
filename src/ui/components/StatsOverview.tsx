import type { JSX } from 'solid-js';
import { DETECTOR_LABELS } from '../../lib/config.js';
import type { AnalysisReport } from '../../lib/engine.js';
import { fmtNum, fmtPct } from '../format.js';
import { typeColor } from './Badges';

/** 顶部 KPI 卡片 + 检测器分布条形图。 */
export function StatsOverview(props: { report: AnalysisReport }): JSX.Element {
  const s = props.report.stats;
  const failureRate = s.totalEvents ? s.failureCount / s.totalEvents : 0;

  const kpis = [
    { label: '日志事件', value: fmtNum(s.totalEvents) },
    { label: '唯一账号', value: fmtNum(s.uniqueUsers) },
    { label: '唯一 IP', value: fmtNum(s.uniqueIps) },
    { label: '会话数', value: fmtNum(s.sessionCount) },
    { label: '告警数', value: fmtNum(s.alertCount), warn: s.alertCount > 0 },
    { label: '安全事件', value: fmtNum(s.incidentCount), warn: s.incidentCount > 0 },
  ];

  const maxTypeCount = Math.max(1, ...Object.values(s.alertsByType));

  return (
    <div class="stats-wrap">
      <div class="kpi-grid">
        {kpis.map((k) => (
          <div class="kpi-card" classList={{ warn: k.warn }}>
            <div class="kpi-value">{k.value}</div>
            <div class="kpi-label">{k.label}</div>
          </div>
        ))}
      </div>

      <div class="panel-row">
        <div class="panel">
          <h3>认证结果分布</h3>
          <div class="bar-stack">
            <div class="bar-seg success" style={{ width: `${(1 - failureRate) * 100}%` }}>
              成功 {fmtPct(1 - failureRate)}
            </div>
            <div class="bar-seg failure" style={{ width: `${failureRate * 100}%` }}>
              失败 {fmtPct(failureRate)}
            </div>
          </div>
          <div class="bar-legend">
            <span>✅ {fmtNum(s.successCount)} 成功</span>
            <span>❌ {fmtNum(s.failureCount)} 失败</span>
            <span>🔒 {fmtNum(s.privateIpEvents)} 内网地址事件</span>
          </div>
        </div>

        <div class="panel">
          <h3>各检测器告警分布</h3>
          {Object.entries(s.alertsByType).map(([type, count]) => (
            <div class="dist-row">
              <span class="dist-label">{DETECTOR_LABELS[type as keyof typeof DETECTOR_LABELS]}</span>
              <div class="dist-track">
                <div
                  class="dist-fill"
                  style={{
                    width: `${(count / maxTypeCount) * 100}%`,
                    background: typeColor(type as keyof typeof typeColor),
                  }}
                />
              </div>
              <span class="dist-count">{count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
