#!/usr/bin/env tsx
// 用法: npx tsx src/generate.ts [--events 100000] [--day 2026-11-16] [--out data] [--seed 42]
// 生成 data/logs.jsonl（原始日志）和 data/groundtruth.json（攻击标注，用于评估误报率）
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { CITIES, geoLookup } from './geo.js';
import type { AlertType, LogEvent } from './types.js';

// ---------------- 参数 ----------------
const arg = (name: string, dflt: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : dflt;
};
const TARGET_EVENTS = parseInt(arg('events', '100000'), 10);
const DAY = arg('day', '2026-11-16');
const OUT = arg('out', 'data');
const SEED = parseInt(arg('seed', '42'), 10);
const DAY_START = Date.parse(`${DAY}T00:00:00Z`);
const DAY_MS = 24 * 3600 * 1000;

// ---------------- 可复现随机数 ----------------
function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(SEED);
const ri = (lo: number, hi: number) => lo + Math.floor(rnd() * (hi - lo + 1));
const pick = <T>(arr: T[]): T => arr[Math.floor(rnd() * arr.length)];

// ---------------- IP 池：按城市探测出 geoLookup 会映射到该城市的 IP ----------------
const ipPoolByCity = new Map<string, string[]>();
function ipForCity(city: string): string {
  let pool = ipPoolByCity.get(city);
  if (!pool) ipPoolByCity.set(city, (pool = []));
  for (let tries = 0; tries < 100000; tries++) {
    const ip = `${ri(11, 223)}.${ri(0, 255)}.${ri(0, 255)}.${ri(1, 254)}`;
    if (geoLookup(ip).city === city) {
      pool.push(ip);
      return ip;
    }
  }
  if (pool.length) return pick(pool);
  throw new Error(`no IP found for city ${city}`);
}

interface AttackLabel {
  id: string;
  type: AlertType;
  start: number;
  end: number;
  users: string[];
  ips: string[];
  note: string;
}

const events: LogEvent[] = [];
const labels: AttackLabel[] = [];
const push = (ts: number, user: string, ip: string, service: 'vpn' | 'sso', result: 'success' | 'failure', reason?: string) =>
  events.push({ ts, user, ip, service, result, reason });
const svc = () => (rnd() < 0.5 ? 'vpn' : 'sso');

// ---------------- 正常用户 ----------------
const AVG_LOGINS_PER_USER = 5; // vpn+sso 合计
const NUM_USERS = Math.max(500, Math.round(TARGET_EVENTS / AVG_LOGINS_PER_USER));
const cityNames = CITIES.filter((c) => c.weight >= 3).map((c) => c.city);

interface UserProfile {
  name: string;
  homeCity: string;
  ips: string[]; // 常用 IP（家/办公室）
}
const users: UserProfile[] = [];
for (let i = 0; i < NUM_USERS; i++) {
  const homeCity = pick(cityNames);
  users.push({
    name: `user${String(i).padStart(5, '0')}`,
    homeCity,
    ips: [ipForCity(homeCity), ipForCity(homeCity)],
  });
}

// 工作时间权重：8-19 点占 80%
function workHourTs(): number {
  const r = rnd();
  const hour = r < 0.8 ? 8 + rnd() * 11 : rnd() * 24;
  return DAY_START + Math.floor(hour * 3600 * 1000) + ri(0, 59999);
}

for (let ui = 0; ui < users.length; ui++) {
  if (ui >= 530 && ui < 550) continue; // 出差用户的行程在下面单独生成
  const u = users[ui];
  const n = ri(2, 9);
  for (let k = 0; k < n; k++) {
    const ts = workHourTs();
    const ip = pick(u.ips);
    // 2% 的登录先打错 1-2 次密码
    if (rnd() < 0.02) {
      const typos = ri(1, 2);
      for (let t = 0; t < typos; t++) push(ts + t * 8000, u.name, ip, svc(), 'failure', 'bad_password');
      push(ts + typos * 8000, u.name, ip, svc(), 'success');
    } else {
      push(ts, u.name, ip, svc(), 'success');
    }
  }
}

// ---------------- 误报陷阱（良性但长得像攻击） ----------------
// 1) 公司 NAT 出口：上海员工共用办公网出口 IP，绝大多数成功 —— 不应触发喷洒/不可能旅行
const natIp = ipForCity('Shanghai');
const shUsers = users.filter((u, i) => u.homeCity === 'Shanghai' && (i < 530 || i >= 550));
for (let i = 0; i < Math.min(500, shUsers.length); i++) {
  const u = shUsers[i];
  const ts = workHourTs();
  if (rnd() < 0.15) push(ts, u.name, natIp, svc(), 'failure', 'bad_password');
  push(ts + ri(5, 30) * 1000, u.name, natIp, svc(), 'success');
}
// 2) 30 个"手抖"用户：20 分钟内 5-7 次失败后成功（低于撞库阈值）—— 不应触发撞库
for (let i = 500; i < 530; i++) {
  const u = users[i];
  const ts = workHourTs();
  const ip = pick(u.ips);
  const fails = ri(5, 7);
  for (let t = 0; t < fails; t++) push(ts + t * ri(60, 180) * 1000, u.name, ip, svc(), 'failure', 'bad_password');
  push(ts + fails * 150 * 1000, u.name, ip, svc(), 'success');
}
// 3) 20 个正常出差用户：城际移动但时间间隔符合民航速度 —— 不应触发不可能旅行
//    出差当天只生成 家→机场前 和 到达后 的登录，不与正常循环冲突
const travelerIdx = new Set<number>();
for (let i = 530; i < 550; i++) travelerIdx.add(i);
for (const i of travelerIdx) {
  const u = users[i];
  const from = u.homeCity;
  const to = pick(cityNames.filter((c) => c !== from));
  const t1 = DAY_START + ri(6, 10) * 3600 * 1000;
  const t2 = t1 + ri(4, 10) * 3600 * 1000; // 至少隔 4 小时
  // 出发前在家 1-2 次，到达后在目的地 1-2 次
  for (let k = 0; k < ri(1, 2); k++) push(t1 - ri(30, 300) * 60 * 1000, u.name, pick(u.ips), svc(), 'success');
  push(t1, u.name, ipForCity(from), svc(), 'success');
  push(t2, u.name, ipForCity(to), svc(), 'success');
  for (let k = 0; k < ri(0, 2); k++) push(t2 + ri(30, 240) * 60 * 1000, u.name, ipForCity(to), svc(), 'success');
}

// ---------------- 攻击注入 ----------------
let attackSeq = 0;
const attackId = (p: string) => `${p}-${String(++attackSeq).padStart(3, '0')}`;

// A. 口令喷洒 ×3：每个战役 2-4 个 IP，300-900 账号，每账号 1-2 次，1-3 小时
for (let c = 0; c < 3; c++) {
  const ips = Array.from({ length: ri(2, 4) }, () => ipForCity(pick(['Moscow', 'Lagos', 'Amsterdam', 'Frankfurt'])));
  const start = DAY_START + ri(1, 20) * 3600 * 1000;
  const duration = ri(1, 3) * 3600 * 1000;
  const targets = ri(300, 900);
  const hitUsers: string[] = [];
  let maxTs = start;
  for (let t = 0; t < targets; t++) {
    const u = pick(users).name;
    hitUsers.push(u);
    const tries = ri(1, 2);
    for (let k = 0; k < tries; k++) {
      const ts = start + Math.floor(rnd() * duration);
      maxTs = Math.max(maxTs, ts);
      const success = rnd() < 0.03; // 弱口令命中率 ~3%
      push(ts, u, pick(ips), svc(), success ? 'success' : 'failure', success ? undefined : 'bad_password');
    }
  }
  labels.push({ id: attackId('SPRAY'), type: 'password_spraying', start, end: maxTs, users: [...new Set(hitUsers)], ips, note: '口令喷洒' });
}

// B. 分布式暴力破解 ×5：单账号，8-25 个 IP，40-120 次失败，1-2 小时
for (let c = 0; c < 5; c++) {
  const victim = pick(users).name;
  const ips = Array.from({ length: ri(8, 25) }, () => ipForCity(pick(['Moscow', 'Lagos', 'New York', 'London'])));
  const start = DAY_START + ri(0, 21) * 3600 * 1000;
  const duration = ri(1, 2) * 3600 * 1000;
  const attempts = ri(40, 120);
  let maxTs = start;
  for (let t = 0; t < attempts; t++) {
    const ts = start + Math.floor(rnd() * duration);
    maxTs = Math.max(maxTs, ts);
    push(ts, victim, pick(ips), svc(), 'failure', 'bad_password');
  }
  labels.push({ id: attackId('BRUTE'), type: 'brute_force', start, end: maxTs, users: [victim], ips, note: '分布式暴力破解' });
}

// C. 撞库 ×8：泄露账号密码列表，失败几次后成功
for (let c = 0; c < 8; c++) {
  const distributed = c >= 6; // 后 2 个用多 IP 分布式
  const ips = distributed
    ? Array.from({ length: ri(3, 6) }, () => ipForCity(pick(['Moscow', 'Amsterdam', 'San Jose'])))
    : [ipForCity(pick(['Moscow', 'Lagos', 'Frankfurt']))];
  const start = DAY_START + ri(0, 20) * 3600 * 1000;
  const listSize = ri(20, 80);
  const hitUsers: string[] = [];
  let maxTs = start;
  for (let t = 0; t < listSize; t++) {
    const u = pick(users).name;
    const ip = pick(ips);
    const base = start + Math.floor(rnd() * 2 * 3600 * 1000);
    if (rnd() < 0.5) {
      // 命中：先失败 1-3 次（或同 IP 密集失败 8-15 次）再成功
      const burst = !distributed && rnd() < 0.5;
      const fails = burst ? ri(8, 15) : ri(1, 3);
      const gap = burst ? ri(20, 40) * 1000 : ri(2, 10) * 60 * 1000;
      for (let k = 0; k < fails; k++) push(base + k * gap, u, ip, svc(), 'failure', 'bad_password');
      const succTs = base + fails * gap + ri(1, 5) * 60 * 1000;
      push(succTs, u, ip, svc(), 'success');
      maxTs = Math.max(maxTs, succTs);
    } else {
      // 未命中：只失败
      const fails = ri(1, 3);
      for (let k = 0; k < fails; k++) {
        const ts = base + k * ri(2, 10) * 60 * 1000;
        push(ts, u, ip, svc(), 'failure', 'bad_password');
        maxTs = Math.max(maxTs, ts);
      }
    }
    hitUsers.push(u);
  }
  labels.push({ id: attackId('STUFF'), type: 'credential_stuffing', start, end: maxTs, users: [...new Set(hitUsers)], ips, note: '撞库' });
}

// D. 不可能旅行 ×10：受害者正常登录后 10-40 分钟，攻击者从远国登录成功
const farCities = ['Moscow', 'Lagos', 'London', 'New York', 'Singapore'];
for (let c = 0; c < 10; c++) {
  const u = users[600 + c];
  const t1 = DAY_START + ri(8, 18) * 3600 * 1000;
  const homeIp = pick(u.ips);
  push(t1, u.name, homeIp, svc(), 'success');
  const atkCity = pick(farCities.filter((c2) => c2 !== u.homeCity));
  const atkIp = ipForCity(atkCity);
  const t2 = t1 + ri(10, 40) * 60 * 1000;
  push(t2, u.name, atkIp, svc(), 'success');
  labels.push({ id: attackId('TRAVEL'), type: 'impossible_travel', start: t1, end: t2, users: [u.name], ips: [homeIp, atkIp], note: '不可能旅行' });
}

// ---------------- 写出 ----------------
events.sort((a, b) => a.ts - b.ts);
mkdirSync(OUT, { recursive: true });
const logsPath = join(OUT, 'logs.jsonl');
writeFileSync(logsPath, events.map((e) => JSON.stringify(e)).join('\n') + '\n');
writeFileSync(join(OUT, 'groundtruth.json'), JSON.stringify({ day: DAY, attacks: labels }, null, 2));
console.log(`events=${events.length} users=${NUM_USERS} attacks=${labels.length}`);
console.log(`written: ${logsPath}, ${join(OUT, 'groundtruth.json')}`);
