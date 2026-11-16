import type { LogEvent, Session } from './types.js';

/** 会话不活动间隔：30 分钟无事件即切会话（VPN/SSO 常用值） */
export const SESSION_GAP_MS = 30 * 60 * 1000;

export function sessionize(events: LogEvent[]): { sessions: Session[]; byUser: Map<string, LogEvent[]> } {
  const byUser = new Map<string, LogEvent[]>();
  for (const ev of events) {
    let arr = byUser.get(ev.user);
    if (!arr) byUser.set(ev.user, (arr = []));
    arr.push(ev);
  }
  const sessions: Session[] = [];
  let seq = 0;
  for (const [user, evs] of byUser) {
    evs.sort((a, b) => a.ts - b.ts);
    let cur: Session | null = null;
    for (const ev of evs) {
      if (!cur || ev.ts - cur.end > SESSION_GAP_MS) {
        cur = {
          id: `S${++seq}`,
          user,
          ips: [],
          start: ev.ts,
          end: ev.ts,
          count: 0,
          successes: 0,
          failures: 0,
        };
        sessions.push(cur);
      }
      cur.end = ev.ts;
      cur.count++;
      if (ev.result === 'success') cur.successes++;
      else cur.failures++;
      if (!cur.ips.includes(ev.ip)) cur.ips.push(ev.ip);
    }
  }
  sessions.sort((a, b) => a.start - b.start);
  return { sessions, byUser };
}
