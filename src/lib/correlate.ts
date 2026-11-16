import type { Alert, DetectorType, SecurityIncident, TimelineEntry } from './types.js';
import { SEVERITY_ORDER } from './config.js';

/**
 * 告警 -> 事件的关联合并。
 * 两条告警满足以下任一条件即连边，并查集求连通分量，每个分量产出一个事件：
 *  1. 共享至少一个账号，且时间窗重叠或间隔 < 2 小时；
 *  2. 共享至少一个源 IP，且时间窗重叠或间隔 < 2 小时。
 * 这样“喷洒命中账号 -> 该账号被暴力破解 -> 撞库成功”会自然聚成一条攻击链事件。
 */
const LINK_GAP_MS = 2 * 3_600_000;

class UnionFind {
  private parent: number[];

  constructor(n: number) {
    this.parent = Array.from({ length: n }, (_, i) => i);
  }

  find(x: number): number {
    while (this.parent[x] !== x) {
      this.parent[x] = this.parent[this.parent[x]!]!;
      x = this.parent[x]!;
    }
    return x;
  }

  union(a: number, b: number): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent[rb] = ra;
  }
}

function timeOverlap(a: Alert, b: Alert): boolean {
  return !(a.endTs + LINK_GAP_MS < b.startTs || b.endTs + LINK_GAP_MS < a.startTs);
}

function sharesEntity(a: Alert, b: Alert, key: 'users' | 'ips'): boolean {
  const set = new Set(a[key]);
  return b[key].some((v) => set.has(v));
}

export function correlateAlerts(alerts: Alert[]): SecurityIncident[] {
  const sorted = [...alerts].sort((a, b) => a.startTs - b.startTs);
  const uf = new UnionFind(sorted.length);

  // O(n²) 在告警量级（通常几千以内）完全可接受；按用户/IP 建索引剪枝。
  const byUser = new Map<string, number[]>();
  const byIp = new Map<string, number[]>();
  sorted.forEach((alert, idx) => {
    for (const u of alert.users) pushIndex(byUser, u, idx);
    for (const ip of alert.ips) pushIndex(byIp, ip, idx);
  });

  const link = (i: number, j: number) => {
    if (i !== j && timeOverlap(sorted[i]!, sorted[j]!)) uf.union(i, j);
  };
  byUser.forEach((indices) => pairEach(indices, link));
  byIp.forEach((indices) => pairEach(indices, link));

  const groups = new Map<number, number[]>();
  sorted.forEach((_, idx) => {
    const root = uf.find(idx);
    const list = groups.get(root);
    if (list) list.push(idx);
    else groups.set(root, [idx]);
  });

  let incidentSeq = 0;
  const incidents: SecurityIncident[] = [];
  for (const indices of groups.values()) {
    const groupAlerts = indices.map((i) => sorted[i]!);
    incidents.push(buildIncident(`inc-${++incidentSeq}`, groupAlerts));
  }
  return incidents.sort((a, b) => b.startTs - a.startTs);
}

function pushIndex(map: Map<string, number[]>, key: string, idx: number): void {
  const list = map.get(key);
  if (list) list.push(idx);
  else map.set(key, [idx]);
}

function pairEach(indices: number[], fn: (a: number, b: number) => void): void {
  for (let i = 0; i < indices.length; i++) {
    for (let j = i + 1; j < indices.length; j++) {
      fn(indices[i]!, indices[j]!);
    }
  }
}

function buildIncident(id: string, alerts: Alert[]): SecurityIncident {
  const startTs = Math.min(...alerts.map((a) => a.startTs));
  const endTs = Math.max(...alerts.map((a) => a.endTs));
  const users = uniq(alerts.flatMap((a) => a.users));
  const ips = uniq(alerts.flatMap((a) => a.ips));
  const types = uniq(alerts.map((a) => a.type)) as DetectorType[];
  const severity = alerts
    .map((a) => a.severity)
    .reduce((worst, s) => (SEVERITY_ORDER.indexOf(s) > SEVERITY_ORDER.indexOf(worst) ? s : worst));

  const timeline: TimelineEntry[] = alerts.map((a) => ({
    ts: a.startTs,
    kind: 'alert' as const,
    alertId: a.id,
    detail: `${a.type} @ ${a.subject}`,
    ip: a.ips[0],
    userId: a.users[0],
  }));
  timeline.sort((x, y) => x.ts - y.ts);

  return {
    id,
    types,
    severity,
    startTs,
    endTs,
    alertIds: alerts.map((a) => a.id),
    users,
    ips,
    timeline,
    eventCount: uniq(alerts.flatMap((a) => a.eventSeqs)).length,
    alertCount: alerts.length,
  };
}

function uniq<T>(items: T[]): T[] {
  return [...new Set(items)];
}
