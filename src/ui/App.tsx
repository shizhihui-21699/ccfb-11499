import { createMemo, createSignal, For, Show, type JSX } from 'solid-js';
import { DETECTOR_LABELS } from '../lib/config.js';
import type { DetectorType } from '../lib/types.js';
import { IncidentCard } from './components/Badges';
import { IncidentDrawer } from './components/IncidentDrawer';
import { StatsOverview } from './components/StatsOverview';
import { loadLogFile, loadReportFile, resetStore, useReportStore } from './store';

const ALL_TYPES = Object.keys(DETECTOR_LABELS) as DetectorType[];

export default function App(): JSX.Element {
  const { report, loadState, errorMsg, sourceName } = useReportStore();
  const [openId, setOpenId] = createSignal<string | null>(null);
  const [typeFilter, setTypeFilter] = createSignal<Set<DetectorType>>(new Set());
  const [search, setSearch] = createSignal('');

  const filteredIncidents = createMemo(() => {
    const r = report();
    if (!r) return [];
    const types = typeFilter();
    const q = search().trim().toLowerCase();
    return r.incidents.filter((inc) => {
      if (types.size > 0 && !inc.types.some((t) => types.has(t))) return false;
      if (q) {
        const haystack = `${inc.id} ${inc.users.join(' ')} ${inc.ips.join(' ')}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  });

  const toggleType = (t: DetectorType) => {
    const next = new Set(typeFilter());
    if (next.has(t)) next.delete(t);
    else next.add(t);
    setTypeFilter(next);
  };

  const onPick = (handler: (f: File) => Promise<void>) => (e: Event) => {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (file) void handler(file);
    input.value = '';
  };

  return (
    <div class="app">
      <header class="topbar">
        <div class="brand">🛡️ 认证日志安全分析台</div>
        <div class="loader">
          <label class="btn">
            上传日志分析
            <input type="file" accept=".jsonl,.csv,.log,.txt" hidden onChange={onPick(loadLogFile)} />
          </label>
          <label class="btn secondary">
            载入报告 JSON
            <input type="file" accept=".json" hidden onChange={onPick(loadReportFile)} />
          </label>
          <Show when={report()}>
            <button class="btn ghost" onClick={resetStore}>
              清除
            </button>
          </Show>
        </div>
      </header>

      <Show when={loadState() === 'parsing' || loadState() === 'analyzing'}>
        <div class="status-banner">
          {loadState() === 'parsing' ? '正在解析日志…' : '正在运行检测引擎…'}（大文件可能需要数秒）
        </div>
      </Show>
      <Show when={loadState() === 'error'}>
        <div class="status-banner error">加载失败：{errorMsg()}</div>
      </Show>

      <main class="content">
        <Show
          when={report()}
          fallback={
            <div class="empty">
              <h2>没有数据</h2>
              <p>上传 VPN / SSO 认证日志（JSONL 或 CSV），或载入 CLI 生成的 report.json。</p>
              <p class="hint">
                可用 <code>npm run gen</code> 生成带标注的示例数据，再用 <code>npm run analyze</code> 产出报告。
              </p>
            </div>
          }
        >
          {(r) => (
            <>
              <div class="source-line">
                数据源：<strong>{sourceName()}</strong> · 报告生成于 {new Date(r().generatedAt).toLocaleString('zh-CN')}
              </div>

              <StatsOverview report={r()} />

              <div class="toolbar">
                <h2>安全事件（{filteredIncidents().length}）</h2>
                <input
                  class="search"
                  placeholder="搜索事件 ID / 账号 / IP"
                  value={search()}
                  onInput={(e) => setSearch(e.currentTarget.value)}
                />
              </div>

              <div class="filter-row">
                <For each={ALL_TYPES}>
                  {(t) => (
                    <button
                      class="filter-chip"
                      classList={{ active: typeFilter().has(t) }}
                      onClick={() => toggleType(t)}
                    >
                      {DETECTOR_LABELS[t]}
                    </button>
                  )}
                </For>
              </div>

              <div class="incident-grid">
                <For each={filteredIncidents()}>
                  {(inc) => <IncidentCard incident={inc} onOpen={setOpenId} />}
                </For>
              </div>

              <IncidentDrawer report={r()} incidentId={openId()} onClose={() => setOpenId(null)} />
            </>
          )}
        </Show>
      </main>
    </div>
  );
}
