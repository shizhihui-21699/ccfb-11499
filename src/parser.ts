import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import type { LogEvent } from './types.js';

/**
 * 解析 JSONL 日志，每行形如：
 * {"ts": 1731801600000, "user": "u0042", "ip": "203.0.113.7", "service": "vpn", "result": "success"}
 * ts 支持 epoch 毫秒/秒 或 ISO 字符串。坏行跳过并计数。
 */
export async function* parseLogFile(path: string): AsyncGenerator<LogEvent> {
  const rl = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of rl) {
    const t = line.trim();
    if (!t) continue;
    const ev = parseLine(t);
    if (ev) yield ev;
  }
}

export function parseLine(line: string): LogEvent | null {
  let o: any;
  try {
    o = JSON.parse(line);
  } catch {
    return null;
  }
  if (!o || typeof o.user !== 'string' || typeof o.ip !== 'string') return null;
  let ts: number;
  if (typeof o.ts === 'number') ts = o.ts < 1e12 ? o.ts * 1000 : o.ts;
  else if (typeof o.ts === 'string') ts = Date.parse(o.ts);
  else return null;
  if (!Number.isFinite(ts)) return null;
  const result = o.result === 'success' ? 'success' : 'failure';
  const service = o.service === 'sso' ? 'sso' : 'vpn';
  return { ts, user: o.user, ip: o.ip, service, result, reason: o.reason };
}

export async function loadEvents(path: string): Promise<LogEvent[]> {
  const events: LogEvent[] = [];
  for await (const ev of parseLogFile(path)) events.push(ev);
  events.sort((a, b) => a.ts - b.ts);
  return events;
}
