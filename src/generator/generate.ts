import { HOUR, MINUTE } from '../lib/config.js';
import { haversineKm, ipForCity, listCities, lookupIp } from '../lib/geo.js';
import { Rng } from '../lib/rng.js';
import type { AuthEvent, AuthOutcome, AuthService } from '../lib/types.js';

/**
 * 带标注的合成认证日志生成器。
 *
 * 两部分：
 *  1. 良性背景流量：通勤、VPN 办公、出差、记错密码——其中刻意包含
 *     “看起来可疑但合法”的混淆场景，用于压测误报率；
 *  2. 注入攻击：4 类攻击各若干个带 ID 的场景，场景元数据写入 ground truth，
 *     每条攻击事件带 _scenario 标注（引擎不读取该字段）。
 */

export interface GeneratorPreset {
  /** 账号总数。 */
  users: number;
  /** 良性事件量级目标。 */
  benignEvents: number;
  /** 每类攻击注入的场景数。 */
  attacksPerType: number;
  seed: number;
}

export const PRESETS: Record<string, GeneratorPreset> = {
  small: { users: 400, benignEvents: 12_000, attacksPerType: 2, seed: 20261116 },
  medium: { users: 2_000, benignEvents: 120_000, attacksPerType: 4, seed: 20261116 },
  large: { users: 10_000, benignEvents: 800_000, attacksPerType: 8, seed: 20261116 },
};

/** Ground truth 中的攻击场景定义，评估器按它匹配告警。 */
export interface ScenarioTruth {
  scenarioId: string;
  attackType: 'impossible_travel' | 'password_spray' | 'brute_force' | 'credential_stuffing';
  startTs: number;
  endTs: number;
  users: string[];
  ips: string[];
  description: string;
}

export interface GeneratedDataset {
  events: AuthEvent[];
  groundTruth: ScenarioTruth[];
  benignConfusers: { id: string; description: string; users: string[] }[];
}

/** 城市锁定的公网 IP 分配器。 */
type IpAllocator = (cityIndex: number, salt: number, exclude?: ReadonlySet<string>) => string;

const DAY_START = Date.UTC(2026, 10, 16, 0, 0, 0); // 2026-11-16 00:00 UTC
const OFFICE_NETS = ['10.10.1.', '10.10.2.', '10.20.1.', '192.168.50.'];

export function generateDataset(preset: GeneratorPreset): GeneratedDataset {
  const rng = new Rng(preset.seed);
  const cities = listCities();
  const groundTruth: ScenarioTruth[] = [];
  const benignConfusers: GeneratedDataset['benignConfusers'] = [];
  const events: AuthEvent[] = [];

  // 公网 IP 全局登记表：避免不同 salt 探测到同一 IP（住宅 IP 与攻击 IP 撞车会制造假证据）。
  const usedPublicIps = new Set<string>();
  /**
   * 城市锁定分配：返回的 IP 保证哈希落在指定城市。
   * ipForCity 的 salt 碰撞回退可能落到别的城市，这里逐 salt 探测直到城市正确且未占用。
   */
  const uniqueIp = (cityIndex: number, salt: number, exclude: ReadonlySet<string> = new Set()): string => {
    const target = ((cityIndex % cities.length) + cities.length) % cities.length;
    let probeSalt = salt;
    for (let i = 0; i < 100_000; i++) {
      const candidate = ipForCity(target, probeSalt + i * 7_919);
      if (usedPublicIps.has(candidate) || exclude.has(candidate)) continue;
      if (lookupIp(candidate).city !== cities[target]!.city) continue;
      usedPublicIps.add(candidate);
      return candidate;
    }
    throw new Error(`uniqueIp: 城市 ${cities[target]!.city} 的可用 IP 耗尽`);
  };

  // ---- 1. 用户画像：每人一个常用城市 + 1~2 个住宅公网 IP ----
  interface Persona {
    userId: string;
    homeCity: number;
    homeIps: string[];
    vpnUser: boolean;
    typoProne: boolean;
  }
  const personas: Persona[] = [];
  for (let i = 0; i < preset.users; i++) {
    const homeCity = rng.int(0, cities.length - 1);
    const homeIps = [uniqueIp(homeCity, 10_000 + i), uniqueIp(homeCity, 20_000 + i)];
    personas.push({
      userId: `user${String(i).padStart(5, '0')}`,
      homeCity,
      homeIps,
      vpnUser: rng.chance(0.45),
      typoProne: rng.chance(0.12),
    });
  }

  // ---- 2. 良性背景流量 ----
  generateBenignTraffic(rng, personas, preset.benignEvents, events, DAY_START, benignConfusers, uniqueIp);

  // ---- 3. 注入四类攻击 ----
  // 暴力破解与撞库的受害者池互斥：避免同一账号同时承载两类攻击，
  // 造成检测器跨类型重复定性（评估时无法区分 FP 与重叠 TP）。
  const victimPool = rng.sample(personas, Math.min(preset.users, 120));
  const half = Math.floor(victimPool.length / 2);
  const brutePool = victimPool.slice(0, half);
  const stuffingPool = victimPool.slice(half);
  let sprayIdx = 0;
  let bruteIdx = 0;
  let stuffIdx = 0;
  let travelIdx = 0;

  for (let k = 0; k < preset.attacksPerType; k++) {
    injectSpray(rng, personas, events, groundTruth, DAY_START, sprayIdx++, k, uniqueIp);
    injectBruteForce(rng, brutePool, events, groundTruth, DAY_START, bruteIdx++, k, uniqueIp);
    injectCredentialStuffing(rng, stuffingPool, events, groundTruth, DAY_START, stuffIdx++, k, uniqueIp);
    injectImpossibleTravel(rng, victimPool, events, groundTruth, DAY_START, travelIdx++, k, uniqueIp);
  }

  events.sort((a, b) => a.ts - b.ts);
  return { events, groundTruth, benignConfusers };
}

// ---------------------------------------------------------------------------
// 良性流量
// ---------------------------------------------------------------------------

function generateBenignTraffic(
  rng: Rng,
  personas: { userId: string; homeCity: number; homeIps: string[]; vpnUser: boolean; typoProne: boolean }[],
  target: number,
  events: AuthEvent[],
  dayStart: number,
  confusers: GeneratedDataset['benignConfusers'],
  uniqueIp: IpAllocator,
): void {
  // 先选出差者并建立静默窗口：出差期间该用户不产生背景流量，
  // 否则背景的家用登录会“夹”在两段出差登录之间，成为不可能旅行的假证据。
  const travelers = rng.sample(personas, 6);
  interface TravelPlan {
    persona: (typeof personas)[number];
    t1: number;
    cityB: number;
    gapH: number;
    stayH: number;
  }
  const travelPlans: TravelPlan[] = [];
  const quietWindows = new Map<string, { from: number; to: number }>();
  for (const p of travelers) {
    const t1 = dayStart + 2 * HOUR + rng.int(0, 30) * MINUTE;
    let cityB = rng.int(0, listCities().length - 1);
    if (cityB === p.homeCity) cityB = (cityB + 7) % listCities().length;
    // 直接用两城坐标估算距离，不预分配 IP；正式 IP 在出差段落一次性分配。
    const homeCity = listCities()[p.homeCity]!;
    const destCity = listCities()[cityB]!;
    const distance = haversineKm(
      { ip: '', city: homeCity.city, country: homeCity.country, lat: homeCity.lat, lon: homeCity.lon, private: false },
      { ip: '', city: destCity.city, country: destCity.country, lat: destCity.lat, lon: destCity.lon, private: false },
    );
    // 按 400km/h（检测阈值 900 的一半以下）反推飞行时间并加 2h 缓冲，夹在 3~6 小时。
    const gapH = Math.min(6, Math.max(3, Math.ceil(distance / 400) + 2));
    // 出差含“去程 + 返程”两段飞行，静默窗口必须覆盖到返程落地之后：
    // t1 出发，t1+gapH 到达目的地，工作停留 4h 后再飞 gapH 返程。
    // 窗口内不生成家乡 IP 的背景登录，否则“目的地登录 -> 家乡登录”会被误判为不可能旅行。
    const stayH = 4;
    travelPlans.push({ persona: p, t1, cityB, gapH, stayH });
    quietWindows.set(p.userId, {
      from: t1 - 20 * MINUTE,
      to: t1 + (2 * gapH + stayH) * HOUR + 30 * MINUTE,
    });
  }

  let produced = 0;
  let guard = 0;
  while (produced < target && guard++ < target * 4) {
    const p = rng.pick(personas);
    // 工作时段（UTC 1~10 点）事件更密集。
    const hour = rng.chance(0.7) ? rng.int(1, 10) : rng.int(11, 23);
    const ts = dayStart + hour * HOUR + rng.int(0, 59) * MINUTE + rng.int(0, 59_999);
    const quiet = quietWindows.get(p.userId);
    if (quiet && ts >= quiet.from && ts <= quiet.to) continue;
    const service: AuthService = p.vpnUser && rng.chance(0.6) ? 'vpn' : 'sso';
    const useOffice = service === 'vpn' && hour >= 1 && hour <= 10 && rng.chance(0.75);
    const ip = useOffice
      ? `${rng.pick(OFFICE_NETS)}${rng.int(2, 250)}`
      : rng.pick(p.homeIps);

    // 良性失败：偶发输错，typoProne 的人会连续错 2~4 次后成功。
    if (rng.chance(0.08)) {
      const typoBurst = p.typoProne ? rng.int(2, 4) : 1;
      for (let j = 0; j < typoBurst && produced < target; j++) {
        events.push(makeEvent(ts + j * 4_000, service, p.userId, ip, 'failure', 'bad_password'));
        produced++;
      }
      events.push(makeEvent(ts + typoBurst * 4_000 + 2_000, service, p.userId, ip, 'success'));
      produced++;
      continue;
    }
    events.push(makeEvent(ts, service, p.userId, ip, 'success'));
    produced++;
  }

  // ---- 良性混淆场景：专门考验检测器的区分能力 ----
  // (a) 合法出差：城市对、时间、静默窗口在背景流量之前已统一规划。
  travelPlans.forEach((plan, i) => {
    const p = plan.persona;
    const t1 = plan.t1;
    const ipA = p.homeIps[0]!;
    // 排除该 persona 自己的住宅 IP：否则出差城市与家乡同哈希池时可能挑中其 homeIp，
    // 造成“出差 IP 在家乡被复用”的假证据。
    const ipB = uniqueIp(plan.cityB, 30_000 + i, new Set(p.homeIps));
    const distance = haversineKm(lookupIp(ipA), lookupIp(ipB));
    if (lookupIp(ipB).city === lookupIp(ipA).city) {
      throw new Error(`出差 IP 与家乡同城: ${p.userId}`);
    }
    events.push(makeEvent(t1, 'sso', p.userId, ipA, 'success', undefined, 'benign_travel'));
    const arriveTs = t1 + plan.gapH * HOUR;
    events.push(makeEvent(arriveTs, 'sso', p.userId, ipB, 'success', undefined, 'benign_travel'));
    // 停留期间在目的地正常办公登录（同城市、同 IP 段，不会触发距离阈值）。
    events.push(makeEvent(arriveTs + 2 * HOUR, 'sso', p.userId, ipB, 'success', undefined, 'benign_travel'));
    // 显式返程：再飞 gapH 小时后在家乡 IP 登录。由于静默窗口覆盖全程，
    // 检测器看到的相邻公网成功对是“目的地 -> 家乡”，但时间间隔 = gapH，速度合理。
    const returnTs = arriveTs + plan.stayH * HOUR + plan.gapH * HOUR;
    events.push(makeEvent(returnTs, 'sso', p.userId, ipA, 'success', undefined, 'benign_travel'));
    confusers.push({
      id: `conf-travel-${i}`,
      description: `合法出差往返：${lookupIp(ipA).city}->${lookupIp(ipB).city}->${lookupIp(ipA).city}，单段飞行 ${plan.gapH}h（约 ${Math.round(distance / plan.gapH)}km/h）`,
      users: [p.userId],
    });
  });

  // (b) NAT 出口：企业统一出口是私网地址（真实 VPN 汇聚场景），25 名员工一小时内经它登录；
  //     私网地址不参与地理检测，全部成功且每账号 1 次也不满足喷洒条件。
  const natIp = '10.30.1.1';
  const natUsers = rng.sample(personas, 25);
  const natBase = dayStart + 3 * HOUR;
  natUsers.forEach((p, i) => {
    events.push(makeEvent(natBase + i * 90_000, 'vpn', p.userId, natIp, 'success', undefined, 'benign_nat'));
  });
  confusers.push({
    id: 'conf-nat-0',
    description: '企业 NAT 私网出口：25 人共用 10.30.1.1，全部成功',
    users: natUsers.map((p) => p.userId),
  });

  // (c) 良性重试：单个账号在自己常用 IP 上连续失败 12 次（键盘故障/改密后缓存）。
  const retryPerson = personas[0]!;
  const retryBase = dayStart + 5 * HOUR;
  for (let i = 0; i < 12; i++) {
    events.push(
      makeEvent(retryBase + i * 45_000, 'vpn', retryPerson.userId, retryPerson.homeIps[0]!, 'failure', 'bad_password', 'benign_retry'),
    );
  }
  events.push(makeEvent(retryBase + 12 * 45_000, 'vpn', retryPerson.userId, retryPerson.homeIps[0]!, 'success', undefined, 'benign_retry'));
  confusers.push({
    id: 'conf-retry-0',
    description: '单账号同 IP 连续失败 12 次后成功：来源单一，不应触发多IP暴力破解',
    users: [retryPerson.userId],
  });

  // (d) 同城漂移：同一城市两个不同 IP（移动网络切基站），不应触发不可能旅行。
  const driftPerson = personas[1]!;
  const driftIp = uniqueIp(driftPerson.homeCity, 42_4242);
  const driftT = dayStart + 7 * HOUR;
  events.push(makeEvent(driftT, 'sso', driftPerson.userId, driftPerson.homeIps[0]!, 'success', undefined, 'benign_drift'));
  events.push(makeEvent(driftT + 20 * MINUTE, 'sso', driftPerson.userId, driftIp, 'success', undefined, 'benign_drift'));
  confusers.push({
    id: 'conf-drift-0',
    description: '同城移动网络漂移：20 分钟内同城市换 IP，距离低于最小阈值',
    users: [driftPerson.userId],
  });
}

// ---------------------------------------------------------------------------
// 攻击场景
// ---------------------------------------------------------------------------

/** 口令喷洒：1 个攻击 IP，1 小时内对 25~40 个账号各试 1~2 次，绝大多数失败。 */
function injectSpray(
  rng: Rng,
  personas: { userId: string }[],
  events: AuthEvent[],
  truth: ScenarioTruth[],
  dayStart: number,
  idx: number,
  variant: number,
  uniqueIp: IpAllocator,
): void {
  const id = `spray-${idx}`;
  const attackCity = rng.int(0, listCities().length - 1);
  const attackIp = uniqueIp(attackCity, 500_000 + variant * 131);
  const targetCount = rng.int(25, 40);
  const targets = rng.sample(personas, targetCount).map((p) => p.userId);
  const start = dayStart + (12 + idx * 2) * HOUR + rng.int(0, 30) * MINUTE;
  let cursor = start;
  for (const userId of targets) {
    const attempts = rng.chance(0.3) ? 2 : 1;
    for (let j = 0; j < attempts; j++) {
      cursor += rng.int(20_000, 90_000); // 低频铺开：间隔 20~90 秒
      events.push(makeEvent(cursor, 'sso', userId, attackIp, 'failure', 'bad_password', id));
    }
  }
  truth.push({
    scenarioId: id,
    attackType: 'password_spray',
    startTs: start,
    endTs: cursor,
    users: targets,
    ips: [attackIp],
    description: `攻击 IP ${attackIp}(${lookupIp(attackIp).city}) 对 ${targets.length} 个账号低频喷洒`,
  });
}

/** 暴力破解：8~15 个攻击 IP 轮换，打同一个账号，1 小时内 30~60 次失败，全部失败。 */
function injectBruteForce(
  rng: Rng,
  victimPool: { userId: string }[],
  events: AuthEvent[],
  truth: ScenarioTruth[],
  dayStart: number,
  idx: number,
  variant: number,
  uniqueIp: IpAllocator,
): void {
  const id = `brute-${idx}`;
  const victim = rng.pick(victimPool).userId;
  const ipCount = rng.int(8, 15);
  const attackIps = Array.from({ length: ipCount }, (_, i) =>
    uniqueIp(rng.int(0, listCities().length - 1), 600_000 + variant * 977 + i),
  );
  const failures = rng.int(30, 60);
  const start = dayStart + (14 + (idx % 3)) * HOUR + rng.int(0, 20) * MINUTE;
  let cursor = start;
  for (let i = 0; i < failures; i++) {
    cursor += rng.int(20_000, 70_000);
    events.push(makeEvent(cursor, 'vpn', victim, rng.pick(attackIps), 'failure', 'bad_password', id));
  }
  truth.push({
    scenarioId: id,
    attackType: 'brute_force',
    startTs: start,
    endTs: cursor,
    users: [victim],
    ips: attackIps,
    description: `${ipCount} 个代理 IP 对账号 ${victim} 轮换暴力破解，${failures} 次失败`,
  });
}

/** 撞库：攻击 IP 池对 10~16 个账号先大量失败，其中 2~3 个最终成功（凭证命中）。 */
function injectCredentialStuffing(
  rng: Rng,
  victimPool: { userId: string }[],
  events: AuthEvent[],
  truth: ScenarioTruth[],
  dayStart: number,
  idx: number,
  variant: number,
  uniqueIp: IpAllocator,
): void {
  const id = `stuff-${idx}`;
  const targets = rng.sample(victimPool, rng.int(10, 16));
  const attackIps = Array.from({ length: 4 }, (_, i) =>
    uniqueIp(rng.int(0, listCities().length - 1), 700_000 + variant * 523 + i),
  );
  const start = dayStart + (16 + (idx % 2)) * HOUR + rng.int(0, 20) * MINUTE;
  let cursor = start;
  const compromised = rng.sample(targets, rng.int(2, 3));
  const compromisedIds = new Set(compromised.map((p) => p.userId));

  for (const victim of targets) {
    const failCount = compromisedIds.has(victim.userId) ? rng.int(9, 16) : rng.int(4, 10);
    for (let j = 0; j < failCount; j++) {
      cursor += rng.int(15_000, 60_000);
      events.push(makeEvent(cursor, 'sso', victim.userId, rng.pick(attackIps), 'failure', 'bad_password', id));
    }
    if (compromisedIds.has(victim.userId)) {
      cursor += rng.int(15_000, 40_000);
      events.push(makeEvent(cursor, 'sso', victim.userId, rng.pick(attackIps), 'success', undefined, id));
    }
  }
  truth.push({
    scenarioId: id,
    attackType: 'credential_stuffing',
    startTs: start,
    endTs: cursor,
    users: targets.map((p) => p.userId),
    ips: attackIps,
    description: `撞库 IP 池对 ${targets.length} 个账号枚举，${compromised.length} 个账号被攻破成功登录`,
  });
}

/** 不可能旅行：同一账号 30~90 分钟内在两个相距 >=3000km 的城市各成功登录一次。 */
function injectImpossibleTravel(
  rng: Rng,
  victimPool: { userId: string }[],
  events: AuthEvent[],
  truth: ScenarioTruth[],
  dayStart: number,
  idx: number,
  variant: number,
  uniqueIp: IpAllocator,
): void {
  const id = `travel-${idx}`;
  const victim = rng.pick(victimPool).userId;
  const cityA = rng.int(0, listCities().length - 1);
  // 挑一个足够远的城市 B，保证距离阈值不会把攻击场景过滤掉。
  let cityB = rng.int(0, listCities().length - 1);
  let guard = 0;
  while (guard++ < 40) {
    const dist = haversineKm(lookupIp(ipForCity(cityA, 1)), lookupIp(ipForCity(cityB, 1)));
    if (cityB !== cityA && dist >= 3000) break;
    cityB = (cityB + 1) % listCities().length;
  }
  const ipA = uniqueIp(cityA, 800_000 + variant * 17);
  const ipB = uniqueIp(cityB, 810_000 + variant * 17);
  const t1 = dayStart + (18 + (idx % 4)) * HOUR + rng.int(0, 40) * MINUTE;
  const gapMin = rng.int(30, 90);
  events.push(makeEvent(t1, 'vpn', victim, ipA, 'success', undefined, id));
  events.push(makeEvent(t1 + gapMin * MINUTE, 'vpn', victim, ipB, 'success', undefined, id));
  truth.push({
    scenarioId: id,
    attackType: 'impossible_travel',
    startTs: t1,
    endTs: t1 + gapMin * MINUTE,
    users: [victim],
    ips: [ipA, ipB],
    description: `${victim} ${gapMin} 分钟内从 ${lookupIp(ipA).city} 跳到 ${lookupIp(ipB).city}`,
  });
}

function makeEvent(
  ts: number,
  service: AuthService,
  userId: string,
  ip: string,
  outcome: AuthOutcome,
  reason?: string,
  scenario?: string,
): AuthEvent {
  const e: AuthEvent = {
    ts,
    service,
    userId,
    ip,
    outcome,
    userAgent: service === 'vpn' ? 'CorpVPN/4.2' : 'Mozilla/5.0 SSO-Client',
  };
  if (reason) e.reason = reason;
  if (scenario) e._scenario = scenario;
  return e;
}
