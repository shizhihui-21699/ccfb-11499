import { For, createMemo } from 'solid-js';
import type { Alert, AlertType } from '../src/types';
import { ALERT_TYPE_LABEL } from '../src/types';

const TYPE_COLOR: Record<AlertType, string> = {
  impossible_travel: '#f778ba',
  password_spraying: '#d29922',
  brute_force: '#f85149',
  credential_stuffing: '#a371f7',
};

/** 事件内告警的时间线：横轴为时间，每条告警一段色条 */
export default function Timeline(props: { alerts: Alert[] }) {
  const sorted = createMemo(() => [...props.alerts].sort((a, b) => a.start - b.start));
  const min = createMemo(() => Math.min(...sorted().map((a) => a.start)));
  const max = createMemo(() => Math.max(...sorted().map((a) => a.end)));
  const span = createMemo(() => Math.max(1, max() - min()));
  const W = 1000;
  const ROW_H = 26;
  const x = (ts: number) => ((ts - min()) / span()) * (W - 120) + 60;

  const ticks = createMemo(() => {
    const n = 6;
    return Array.from({ length: n + 1 }, (_, i) => min() + (span() * i) / n);
  });

  return (
    <div class="timeline">
      <svg viewBox={`0 0 ${W} ${sorted().length * ROW_H + 40}`} preserveAspectRatio="xMidYMin meet">
        <For each={ticks()}>
          {(t) => (
            <>
              <line x1={x(t)} y1={16} x2={x(t)} y2={sorted().length * ROW_H + 20} class="grid" />
              <text x={x(t)} y={12} class="tick" text-anchor="middle">
                {new Date(t).toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit' })}
              </text>
            </>
          )}
        </For>
        <For each={sorted()}>
          {(a, i) => {
            const y = 24 + i() * ROW_H;
            const x1 = x(a.start);
            const x2 = Math.max(x(a.end), x1 + 3);
            return (
              <g>
                <rect x={x1} y={y} width={x2 - x1} height={14} rx={3} fill={TYPE_COLOR[a.type]} opacity={0.85}>
                  <title>{`${ALERT_TYPE_LABEL[a.type]} · ${a.summary}`}</title>
                </rect>
                <text x={x2 + 6} y={y + 11} class="row-label">
                  {ALERT_TYPE_LABEL[a.type]}
                </text>
              </g>
            );
          }}
        </For>
      </svg>
    </div>
  );
}
