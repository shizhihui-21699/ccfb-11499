import { distanceKm, geoLookup } from './geo.js';
import type { Alert, AlertType, LogEvent, Severity } from './types.js';

// ---------------------------------------------------------------------------
// 阈值（按 VPN/SSO 日均百万级日志的经验值设定，可在评估阶段用标注数据回调）
// ---------------------------------------------------------------------------
export const THRESHOLDS = {
  // 不可能旅行：民航巡航 ~900km/h，留余量取 800；300km 内视为地理库抖动不报
  travelMaxSpeedKmh: 800,
  travelMinDistanceKm: 300,
  // 口令喷洒：单 IP 1 小时内 ≥15 个不同账号、≥30 次尝试、平均每账号 ≤3 次、失败率 ≥70%
  sprayWindowMs: 60 * 60 * 1000,
  sprayMinUsers: 15,
  sprayMinAttempts: 30,
  sprayMaxPerUser: 3,
  sprayMinFailRatio: 0.7,
  // 分布式暴力破解：单账号 1 小时内 ≥20 次失败且来自 ≥5 个不同 IP
  bruteWindowMs: 60 * 60 * 1000,
  bruteMinFailures: 20,
  bruteMinIps: 5,
  // 撞库：同账号同 IP 10 分钟内 ≥8 次失败后 30 分钟内出现成功；
  // 或成功前 1 小时内该账号有 ≥10 次失败且来自 ≥3 个 IP
  stuffBurstWindowMs: 10 * 60 * 1000,
  stuffBurstMinFailures: 8,
  stuffSuccessWithinMs: 30 * 60 * 1000,
  stuffDistWindowMs: 60 * 60 * 1000,
  stuffDistMinFailures: 10,
  stuffDistMinIps: 3,
  // 4c. IP 信誉：某 IP 1 小时内对 ≥5 个不同账号失败且失败率 ≥30%，则该 IP 的成功登录可疑
  stuffIpWindowMs: 60 * 60 * 1000,
  stuffIpMinFailUsers: 5,
  stuffIpMinFailRatio: 0.3,
} as const;

let alertSeq = 0;
function mkAlert(
  type: AlertType,
  start: number,
  end: number,
  users: string[],
  ips: string[],
  score: number,
  summary: string,
  details: Record<string, unknown>,
): Alert {
  const severity: Severity = score >= 85 ? 'critical' : score >= 65 ? 'high' : score >= 40 ? 'medium' : 'low';
  return { id: `A${++alertSeq}`, type, start, end, users, ips, score: Math.round(score), severity, summary, details };
}

const clamp100 = (x: number) => Math.max(0, Math.min(100, x));

// ---------------------------------------------------------------------------
// 1. 不可能旅行：同一账号相邻两次成功登录的地理速度超过物理极限
// ---------------------------------------------------------------------------
export function detectImpossibleTravel(byUser: Map<string, LogEvent[]>): Alert[] {
  const alerts: Alert[] = [];
  for (const [user, evs] of byUser) {
    const succ = evs.filter((e) => e.result === 'success');
    for (let i = 1; i < succ.length; i++) {
      const prev = succ[i - 1];
      const cur = succ[i];
      const g1 = geoLookup(prev.ip);
      const g2 = geoLookup(cur.ip);
      if (g1.internal || g2.internal) continue;
      const dist = distanceKm(g1, g2);
      if (dist < THRESHOLDS.travelMinDistanceKm) continue;
      const hours = (cur.ts - prev.ts) / 3600000;
      const speed = hours <= 0 ? Infinity : dist / hours;
      if (speed > THRESHOLDS.travelMaxSpeedKmh) {
        const score = clamp100(50 + Math.min(40, (speed - 800) / 100) + (g1.country !== g2.country ? 10 : 0));
        alerts.push(
          mkAlert(
            'impossible_travel',
            prev.ts,
            cur.ts,
            [user],
            [prev.ip, cur.ip],
            score,
            `${user} 在 ${Math.round(hours * 60)} 分钟内从 ${g1.city}(${g1.country}) 到 ${g2.city}(${g2.country})，距离 ${Math.round(dist)}km，等效速度 ${speed === Infinity ? '∞' : Math.round(speed)}km/h`,
            {
              from: { ip: prev.ip, ...g1, ts: prev.ts },
              to: { ip: cur.ip, ...g2, ts: cur.ts },
              distanceKm: Math.round(dist),
              minutes: Math.round(hours * 60),
              speedKmh: speed === Infinity ? null : Math.round(speed),
            },
          ),
        );
      }
    }
  }
  return alerts;
}

// ---------------------------------------------------------------------------
// 2. 口令喷洒：单 IP 对大量账号的低频尝试（每账号只试 1-3 次，绕账号锁定）
// ---------------------------------------------------------------------------
export function detectSpraying(events: LogEvent[]): Alert[] {
  const byIp = new Map<string, LogEvent[]>();
  for (const ev of events) {
    let arr = byIp.get(ev.ip);
    if (!arr) byIp.set(ev.ip, (arr = []));
    arr.push(ev);
  }
  const alerts: Alert[] = [];
  const W = THRESHOLDS.sprayWindowMs;
  for (const [ip, evs] of byIp) {
    if (evs.length < THRESHOLDS.sprayMinAttempts) continue;
    evs.sort((a, b) => a.ts - b.ts);
    let i = 0;
    const perUser = new Map<string, number>();
    let failures = 0;
    let j = 0;
    const reset = (from: number) => {
      perUser.clear();
      failures = 0;
      i = from;
      j = from;
    };
    reset(0);
    for (; j < evs.length; j++) {
      const ev = evs[j];
      perUser.set(ev.user, (perUser.get(ev.user) ?? 0) + 1);
      if (ev.result === 'failure') failures++;
      while (ev.ts - evs[i].ts > W) {
        const old = evs[i];
        const c = perUser.get(old.user)!;
        if (c === 1) perUser.delete(old.user);
        else perUser.set(old.user, c - 1);
        if (old.result === 'failure') failures--;
        i++;
      }
      const attempts = j - i + 1;
      const users = perUser.size;
      if (users < THRESHOLDS.sprayMinUsers || attempts < THRESHOLDS.sprayMinAttempts) continue;
      const maxPerUser = Math.max(...perUser.values());
      const failRatio = failures / attempts;
      if (maxPerUser <= THRESHOLDS.sprayMaxPerUser && failRatio >= THRESHOLDS.sprayMinFailRatio) {
        const g = geoLookup(ip);
        const score = clamp100(40 + users + failRatio * 20);
        alerts.push(
          mkAlert(
            'password_spraying',
            evs[i].ts,
            ev.ts,
            [...perUser.keys()],
            [ip],
            score,
            `${ip}(${g.city}) 在 ${Math.round((ev.ts - evs[i].ts) / 60000)} 分钟内对 ${users} 个账号尝试 ${attempts} 次（失败率 ${(failRatio * 100).toFixed(0)}%，单账号最多 ${maxPerUser} 次）`,
            { attempts, distinctUsers: users, failures, failRatio: +failRatio.toFixed(2), maxPerUser, geo: g },
          ),
        );
        reset(j + 1);
      }
    }
  }
  return alerts;
}

// ---------------------------------------------------------------------------
// 3. 分布式暴力破解：多个 IP 对同一账号的高频失败
// ---------------------------------------------------------------------------
export function detectBruteForce(byUser: Map<string, LogEvent[]>): Alert[] {
  const alerts: Alert[] = [];
  const W = THRESHOLDS.bruteWindowMs;
  for (const [user, evs] of byUser) {
    const fails = evs.filter((e) => e.result === 'failure');
    if (fails.length < THRESHOLDS.bruteMinFailures) continue;
    let i = 0;
    const perIp = new Map<string, number>();
    for (let j = 0; j < fails.length; j++) {
      perIp.set(fails[j].ip, (perIp.get(fails[j].ip) ?? 0) + 1);
      while (fails[j].ts - fails[i].ts > W) {
        const c = perIp.get(fails[i].ip)!;
        if (c === 1) perIp.delete(fails[i].ip);
        else perIp.set(fails[i].ip, c - 1);
        i++;
      }
      const count = j - i + 1;
      if (count >= THRESHOLDS.bruteMinFailures && perIp.size >= THRESHOLDS.bruteMinIps) {
        const ips = [...perIp.keys()];
        const score = clamp100(45 + count / 2 + perIp.size * 2);
        alerts.push(
          mkAlert(
            'brute_force',
            fails[i].ts,
            fails[j].ts,
            [user],
            ips,
            score,
            `账号 ${user} 在 ${Math.round((fails[j].ts - fails[i].ts) / 60000)} 分钟内遭到 ${perIp.size} 个 IP 的 ${count} 次失败尝试`,
            { failures: count, distinctIps: perIp.size },
          ),
        );
        // 跳过本窗口，避免同一波攻击重复告警
        i = j + 1;
        perIp.clear();
      }
    }
  }
  return alerts;
}

// ---------------------------------------------------------------------------
// 4. 撞库：大量失败后出现成功（口令来自泄露库，试几个就中）
// ---------------------------------------------------------------------------
export function detectCredentialStuffing(byUser: Map<string, LogEvent[]>, events?: LogEvent[]): Alert[] {
  const alerts: Alert[] = [];
  const seen = new Set<string>(); // 去重：同一成功事件只报一次
  for (const [user, evs] of byUser) {
    // 4a. 同 (账号, IP)：10 分钟内 ≥8 次失败 → 30 分钟内成功
    const byIp = new Map<string, LogEvent[]>();
    for (const ev of evs) {
      let arr = byIp.get(ev.ip);
      if (!arr) byIp.set(ev.ip, (arr = []));
      arr.push(ev);
    }
    for (const [ip, list] of byIp) {
      const fails = list.filter((e) => e.result === 'failure');
      if (fails.length < THRESHOLDS.stuffBurstMinFailures) continue;
      let i = 0;
      for (let j = 0; j < fails.length; j++) {
        while (fails[j].ts - fails[i].ts > THRESHOLDS.stuffBurstWindowMs) i++;
        if (j - i + 1 >= THRESHOLDS.stuffBurstMinFailures) {
          const burstEnd = fails[j].ts;
          const succ = list.find(
            (e) => e.result === 'success' && e.ts >= burstEnd && e.ts <= burstEnd + THRESHOLDS.stuffSuccessWithinMs,
          );
          if (succ) {
            const key = `${user}|${succ.ts}`;
            if (!seen.has(key)) {
              seen.add(key);
              const g = geoLookup(ip);
              alerts.push(
                mkAlert(
                  'credential_stuffing',
                  fails[i].ts,
                  succ.ts,
                  [user],
                  [ip],
                  75,
                  `${ip}(${g.city}) 对 ${user} 在 ${Math.round((burstEnd - fails[i].ts) / 60000)} 分钟内失败 ${j - i + 1} 次后登录成功，疑似撞库命中`,
                  { burstFailures: j - i + 1, successTs: succ.ts, pattern: 'same_ip_burst' },
                ),
              );
            }
          }
          i = j + 1; // 跳过已报 burst
        }
      }
    }
    // 4b. 分布式：成功前 1 小时内 ≥10 次失败且来自 ≥3 个 IP
    const succs = evs.filter((e) => e.result === 'success');
    const fails = evs.filter((e) => e.result === 'failure');
    for (const s of succs) {
      const key = `${user}|${s.ts}`;
      if (seen.has(key)) continue;
      const prior = fails.filter((f) => f.ts >= s.ts - THRESHOLDS.stuffDistWindowMs && f.ts < s.ts);
      const ips = new Set(prior.map((f) => f.ip));
      if (prior.length >= THRESHOLDS.stuffDistMinFailures && ips.size >= THRESHOLDS.stuffDistMinIps) {
        seen.add(key);
        alerts.push(
          mkAlert(
            'credential_stuffing',
            prior[0].ts,
            s.ts,
            [user],
            [...ips],
            80,
            `${user} 登录成功前 1 小时内有来自 ${ips.size} 个 IP 的 ${prior.length} 次失败，疑似分布式撞库`,
            { priorFailures: prior.length, distinctIps: ips.size, successTs: s.ts, pattern: 'distributed' },
          ),
        );
      }
    }
  }
  // 4c. IP 信誉：对多账号高失败率的 IP 上出现的成功登录
  if (events) {
    const byIp = new Map<string, LogEvent[]>();
    for (const ev of events) {
      let arr = byIp.get(ev.ip);
      if (!arr) byIp.set(ev.ip, (arr = []));
      arr.push(ev);
    }
    const W = THRESHOLDS.stuffIpWindowMs;
    for (const [ip, evs] of byIp) {
      evs.sort((a, b) => a.ts - b.ts);
      let i = 0;
      for (let j = 0; j < evs.length; j++) {
        while (evs[j].ts - evs[i].ts > W) i++;
        if (evs[j].result !== 'success') continue;
        const win = evs.slice(i, j + 1);
        const failUsers = new Set(win.filter((e) => e.result === 'failure').map((e) => e.user));
        const failRatio = win.filter((e) => e.result === 'failure').length / win.length;
        if (failUsers.size >= THRESHOLDS.stuffIpMinFailUsers && failRatio >= THRESHOLDS.stuffIpMinFailRatio) {
          const key = `${evs[j].user}|${evs[j].ts}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const g = geoLookup(ip);
          alerts.push(
            mkAlert(
              'credential_stuffing',
              evs[i].ts,
              evs[j].ts,
              [evs[j].user],
              [ip],
              78,
              `${ip}(${g.city}) 1 小时内对 ${failUsers.size} 个账号失败（失败率 ${(failRatio * 100).toFixed(0)}%）后 ${evs[j].user} 登录成功，疑似撞库命中`,
              { failedUsers: failUsers.size, failRatio: +failRatio.toFixed(2), successTs: evs[j].ts, pattern: 'ip_reputation' },
            ),
          );
        }
      }
    }
  }
  return alerts;
}
export function mergeAlerts(alerts: Alert[], gapMs = 60 * 60 * 1000): Alert[] {
  const key = (a: Alert) => `${a.type}|${[...a.users].sort()[0]}|${[...a.ips].sort()[0]}`;
  const groups = new Map<string, Alert[]>();
  for (const a of alerts) {
    const k = key(a);
    let g = groups.get(k);
    if (!g) groups.set(k, (g = []));
    g.push(a);
  }
  const out: Alert[] = [];
  for (const g of groups.values()) {
    g.sort((a, b) => a.start - b.start);
    let cur = g[0];
    for (let i = 1; i < g.length; i++) {
      if (g[i].start - cur.end <= gapMs) {
        cur = {
          ...cur,
          end: Math.max(cur.end, g[i].end),
          users: [...new Set([...cur.users, ...g[i].users])],
          ips: [...new Set([...cur.ips, ...g[i].ips])],
          score: Math.max(cur.score, g[i].score),
        };
      } else {
        out.push(cur);
        cur = g[i];
      }
    }
    out.push(cur);
  }
  return out.sort((a, b) => a.start - b.start);
}

export function runAllDetectors(events: LogEvent[], byUser: Map<string, LogEvent[]>): Alert[] {
  const alerts = mergeAlerts([
    ...detectImpossibleTravel(byUser),
    ...detectSpraying(events),
    ...detectBruteForce(byUser),
    ...detectCredentialStuffing(byUser, events),
  ]);
  alerts.sort((a, b) => a.start - b.start);
  return alerts;
}
