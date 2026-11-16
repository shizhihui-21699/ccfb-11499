import { For, Show, createMemo, createResource, createSignal } from 'solid-js';
import type { Alert, AlertType, AnalysisOutput, Incident, Severity } from '../src/types';
import { ALERT_TYPE_LABEL } from '../src/types';
import Timeline from './Timeline';

const SEV_LABEL: Record<Severity, string> = { low: '低', medium: '中', high: '高', critical: '严重' };
const ALL_TYPES: AlertType[] = ['impossible_travel', 'password_spraying', 'brute_force', 'credential_stuffing'];

function fmt(ts: number) {
  return new Date(ts).toLocaleString('zh-CN', { hour12: false });
}
function fmtTime(ts: number) {
  return new Date(ts).toLocaleTimeString('zh-CN', { hour12: false });
}
function dur(start: number, end: number) {
  const m = Math.round((end - start) / 60000);
  return m < 60 ? `${m} 分钟` : `${Math.floor(m / 60)} 小时 ${m % 60} 分`;
}

export default function App() {
  const [data] = createResource<AnalysisOutput>(async () => (await fetch('/incidents.json')).json());
  const [typeFilter, setTypeFilter] = createSignal<AlertType | ''>('');
  const [sevFilter, setSevFilter] = createSignal<Severity | ''>('');
  const [selectedId, setSelectedId] = createSignal<string | null>(null);

  const filtered = createMemo(() => {
    const d = data();
    if (!d) return [];
    return d.incidents.filter(
      (i) => (!typeFilter() || i.types.includes(typeFilter() as AlertType)) && (!sevFilter() || i.severity === sevFilter()),
    );
  });
  const selected = createMemo<Incident | null>(() => {
    const d = data();
    if (!d) return null;
    return d.incidents.find((i) => i.id === selectedId()) ?? filtered()[0] ?? null;
  });

  return (
    <div class="app">
      <header>
        <h1>登录异常检测</h1>
        <Show when={data()}>
          {(d) => (
            <div class="stats">
              <span>事件 <b>{d().stats.events.toLocaleString()}</b></span>
              <span>账号 <b>{d().stats.users.toLocaleString()}</b></span>
              <span>会话 <b>{d().stats.sessions.toLocaleString()}</b></span>
              <span>告警 <b>{d().stats.alerts}</b></span>
              <span>安全事件 <b>{d().stats.incidents}</b></span>
            </div>
          )}
        </Show>
      </header>

      <div class="filters">
        <select onChange={(e) => setTypeFilter(e.currentTarget.value as AlertType | '')}>
          <option value="">全部类型</option>
          <For each={ALL_TYPES}>{(t) => <option value={t}>{ALERT_TYPE_LABEL[t]}</option>}</For>
        </select>
        <select onChange={(e) => setSevFilter(e.currentTarget.value as Severity | '')}>
          <option value="">全部严重度</option>
          <For each={['critical', 'high', 'medium', 'low'] as Severity[]}>
            {(s) => <option value={s}>{SEV_LABEL[s]}</option>}
          </For>
        </select>
      </div>

      <Show when={data()} fallback={<p class="loading">加载中…（先运行 npm run analyze）</p>}>
        <div class="layout">
          <aside class="incident-list">
            <For each={filtered()} fallback={<p class="empty">无匹配事件</p>}>
              {(inc) => (
                <button
                  class={`incident sev-${inc.severity} ${selected()?.id === inc.id ? 'active' : ''}`}
                  onClick={() => setSelectedId(inc.id)}
                >
                  <div class="inc-head">
                    <span class={`badge sev-${inc.severity}`}>{SEV_LABEL[inc.severity]}</span>
                    <span class="inc-id">{inc.id}</span>
                    <span class="score">{inc.score}</span>
                  </div>
                  <div class="inc-title">{inc.title}</div>
                  <div class="inc-meta">
                    {fmt(inc.start)} · 持续 {dur(inc.start, inc.end)} · {inc.alerts.length} 条告警
                  </div>
                </button>
              )}
            </For>
          </aside>

          <main class="detail">
            <Show when={selected()} fallback={<p class="empty">请选择事件</p>}>
              {(inc) => (
                <>
                  <h2>
                    {inc().id} <span class={`badge sev-${inc().severity}`}>{SEV_LABEL[inc().severity]}</span>
                  </h2>
                  <p class="inc-title">{inc().title}</p>
                  <div class="kv">
                    <div><label>时间范围</label>{fmt(inc().start)} — {fmt(inc().end)}</div>
                    <div><label>涉及账号</label>{inc().users.slice(0, 8).join(', ')}{inc().users.length > 8 ? ` 等 ${inc().users.length} 个` : ''}</div>
                    <div><label>来源 IP</label>{inc().ips.join(', ')}</div>
                    <div><label>检测类型</label>{inc().types.map((t) => ALERT_TYPE_LABEL[t]).join('、')}</div>
                  </div>

                  <h3>告警时间线</h3>
                  <Timeline alerts={inc().alerts} />

                  <h3>告警明细（{inc().alerts.length}）</h3>
                  <div class="alert-table-wrap">
                    <table class="alert-table">
                      <thead>
                        <tr><th>时间</th><th>类型</th><th>评分</th><th>描述</th></tr>
                      </thead>
                      <tbody>
                        <For each={inc().alerts}>
                          {(a: Alert) => (
                            <tr>
                              <td class="nowrap">{fmtTime(a.start)} – {fmtTime(a.end)}</td>
                              <td class="nowrap"><span class={`type-tag t-${a.type}`}>{ALERT_TYPE_LABEL[a.type]}</span></td>
                              <td>{a.score}</td>
                              <td>{a.summary}</td>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </Show>
          </main>
        </div>
      </Show>
    </div>
  );
}
