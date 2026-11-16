import { ALERT_TYPE_LABEL } from './types.js';
import type { Alert, Incident, Severity } from './types.js';

/** 告警关联窗口：共享账号或 IP 且时间间隔 ≤ 2 小时的告警合并为同一事件 */
export const CORRELATE_GAP_MS = 2 * 60 * 60 * 1000;

const SEV_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

class UnionFind {
  private parent: number[];
  constructor(n: number) {
    this.parent = Array.from({ length: n }, (_, i) => i);
  }
  find(x: number): number {
    while (this.parent[x] !== x) {
      this.parent[x] = this.parent[this.parent[x]];
      x = this.parent[x];
    }
    return x;
  }
  union(a: number, b: number) {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent[ra] = rb;
  }
}

export function correlate(alerts: Alert[]): Incident[] {
  const n = alerts.length;
  const uf = new UnionFind(n);
  // 实体 → 告警索引，同实体且时间接近则并查
  const byEntity = new Map<string, number[]>();
  const addEntity = (key: string, idx: number) => {
    let arr = byEntity.get(key);
    if (!arr) byEntity.set(key, (arr = []));
    arr.push(idx);
  };
  alerts.forEach((a, i) => {
    a.users.forEach((u) => addEntity(`u:${u}`, i));
    a.ips.forEach((ip) => addEntity(`i:${ip}`, i));
  });
  for (const idxs of byEntity.values()) {
    idxs.sort((a, b) => alerts[a].start - alerts[b].start);
    for (let k = 1; k < idxs.length; k++) {
      const prev = alerts[idxs[k - 1]];
      const cur = alerts[idxs[k]];
      if (cur.start - prev.end <= CORRELATE_GAP_MS) uf.union(idxs[k - 1], idxs[k]);
    }
  }
  const groups = new Map<number, Alert[]>();
  alerts.forEach((a, i) => {
    const r = uf.find(i);
    let g = groups.get(r);
    if (!g) groups.set(r, (g = []));
    g.push(a);
  });
  const incidents: Incident[] = [];
  let seq = 0;
  for (const group of groups.values()) {
    group.sort((a, b) => a.start - b.start);
    const users = [...new Set(group.flatMap((a) => a.users))];
    const ips = [...new Set(group.flatMap((a) => a.ips))];
    const types = [...new Set(group.map((a) => a.type))];
    const start = Math.min(...group.map((a) => a.start));
    const end = Math.max(...group.map((a) => a.end));
    const score = Math.min(100, Math.max(...group.map((a) => a.score)) + (types.length > 1 ? 10 : 0) + (group.length > 2 ? 5 : 0));
    const severity: Severity = score >= 85 ? 'critical' : score >= 65 ? 'high' : score >= 40 ? 'medium' : 'low';
    const typeLabel = types.map((t) => ALERT_TYPE_LABEL[t]).join(' + ');
    incidents.push({
      id: `INC-${String(++seq).padStart(4, '0')}`,
      title: `${typeLabel} · ${users.length} 账号 / ${ips.length} IP`,
      types,
      start,
      end,
      users,
      ips,
      score,
      severity,
      alerts: group,
    });
  }
  incidents.sort((a, b) => b.score - a.score || a.start - b.start);
  return incidents;
}
