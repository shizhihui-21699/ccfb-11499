import { detectionConfig } from './config.js';
import { correlateAlerts } from './correlate.js';
import { BruteForceDetector } from './detectors/bruteForce.js';
import { CredentialStuffingDetector } from './detectors/credentialStuffing.js';
import { ImpossibleTravelDetector } from './detectors/impossibleTravel.js';
import { PasswordSprayDetector } from './detectors/passwordSpray.js';
import { isPrivateIp } from './geo.js';
import { isCsvHeader, parseLine } from './normalize.js';
import { Sessionizer } from './sessionize.js';
import type {
  Alert,
  AuthEvent,
  DetectorType,
  SecurityIncident,
  Session,
  TimelineEntry,
} from './types.js';

export interface AnalysisStats {
  totalEvents: number;
  successCount: number;
  failureCount: number;
  uniqueUsers: number;
  uniqueIps: number;
  privateIpEvents: number;
  sessionCount: number;
  alertCount: number;
  incidentCount: number;
  alertsByType: Record<DetectorType, number>;
  alertsBySeverity: Record<Alert['severity'], number>;
  timeRange: { startTs: number; endTs: number } | null;
}

export interface AnalysisReport {
  generatedAt: string;
  config: typeof detectionConfig;
  stats: AnalysisStats;
  alerts: Alert[];
  incidents: SecurityIncident[];
  sessions: Session[];
}

export interface EngineOptions {
  /** 输入是否已按时间排序；默认 false，引擎会缓冲后全量排序（百万级约数百 MB 内存）。 */
  presorted?: boolean;
  /** 附带全部会话到报告中；UI 默认只看聚合数据，大文件可关闭以减小报告体积。 */
  includeSessions?: boolean;
}

/**
 * 分析引擎主入口。
 * 流程：读取文本行 -> 归一化 -> 排序编号 -> 会话化 + 四路检测 -> 告警合并 -> 报告。
 */
export function runEngine(lines: Iterable<string>, options: EngineOptions = {}): AnalysisReport {
  const events = ingest(lines);
  sortAndSequence(events);
  return analyzeEvents(events, options);
}

/** 已拿到内存事件数组时的入口（CLI 与 UI 的文件上传都复用它）。 */
export function analyzeEvents(
  input: AuthEvent[],
  options: EngineOptions = {},
): AnalysisReport {
  const events = input as (AuthEvent & { seq: number })[];
  if (events.some((e) => e.seq === undefined)) sortAndSequence(events);

  const alerts: Alert[] = [];
  const emit = (alert: Omit<Alert, 'id'>) => {
    alerts.push({ ...alert, id: `alert-${alerts.length + 1}` });
  };

  const sessionizer = new Sessionizer();
  const detectors = [
    new ImpossibleTravelDetector(),
    new PasswordSprayDetector(),
    new BruteForceDetector(),
    new CredentialStuffingDetector(),
  ];

  for (const event of events) {
    sessionizer.process(event);
    for (const d of detectors) d.process(event, emit);
  }

  const sessions = sessionizer.flush();
  const incidents = correlateAlerts(alerts).map((inc) => enrichTimeline(inc, events));

  return {
    generatedAt: new Date().toISOString(),
    config: detectionConfig,
    stats: buildStats(events, alerts, incidents, sessions),
    alerts,
    incidents,
    sessions: options.includeSessions === false ? [] : sessions,
  };
}

function ingest(lines: Iterable<string>): AuthEvent[] {
  const events: AuthEvent[] = [];
  let csvHeader: string[] | undefined;
  for (const line of lines) {
    if (!line.trim()) continue;
    if (csvHeader === undefined && isCsvHeader(line)) {
      csvHeader = line.split(',').map((s) => s.trim());
      continue;
    }
    const event = parseLine(line, csvHeader);
    if (event) events.push(event);
  }
  return events;
}

function sortAndSequence(events: AuthEvent[]): void {
  events.sort((a, b) => a.ts - b.ts || a.userId.localeCompare(b.userId));
  events.forEach((e, i) => {
    e.seq = i + 1;
  });
}

/** 把事件涉及的成功/失败原始事件补进事件时间线，让时间线能看到攻击全过程。 */
function enrichTimeline(
  incident: SecurityIncident,
  events: (AuthEvent & { seq: number })[],
): SecurityIncident {
  const relevantSeqs = new Set<number>();
  // incident 已带告警 id，反查告警的 eventSeqs 需要通过 alerts 关联；
  // 这里直接用用户/IP + 时间范围圈定相关事件，避免再传告警映射。
  const userSet = new Set(incident.users);
  const ipSet = new Set(incident.ips);
  const entries: TimelineEntry[] = [...incident.timeline];

  for (const e of events) {
    if (e.ts < incident.startTs || e.ts > incident.endTs) continue;
    const related = userSet.has(e.userId) || ipSet.has(e.ip);
    if (!related) continue;
    relevantSeqs.add(e.seq);
    if (e.outcome === 'success') {
      entries.push({
        ts: e.ts,
        kind: 'success',
        detail: `成功登录 ${e.userId}`,
        ip: e.ip,
        userId: e.userId,
      });
    }
  }

  entries.sort((a, b) => a.ts - b.ts);
  return {
    ...incident,
    timeline: entries,
    eventCount: Math.max(incident.eventCount, relevantSeqs.size),
  };
}

function buildStats(
  events: (AuthEvent & { seq: number })[],
  alerts: Alert[],
  incidents: SecurityIncident[],
  sessions: Session[],
): AnalysisStats {
  const emptyByType = {
    impossible_travel: 0,
    password_spray: 0,
    brute_force: 0,
    credential_stuffing: 0,
  } as Record<DetectorType, number>;
  const emptyBySeverity = { low: 0, medium: 0, high: 0, critical: 0 } as Record<
    Alert['severity'],
    number
  >;

  for (const a of alerts) {
    emptyByType[a.type]++;
    emptyBySeverity[a.severity]++;
  }

  return {
    totalEvents: events.length,
    successCount: events.filter((e) => e.outcome === 'success').length,
    failureCount: events.filter((e) => e.outcome === 'failure').length,
    uniqueUsers: new Set(events.map((e) => e.userId)).size,
    uniqueIps: new Set(events.map((e) => e.ip)).size,
    privateIpEvents: events.filter((e) => isPrivateIp(e.ip)).length,
    sessionCount: sessions.length,
    alertCount: alerts.length,
    incidentCount: incidents.length,
    alertsByType: emptyByType,
    alertsBySeverity: emptyBySeverity,
    timeRange: events.length
      ? { startTs: events[0]!.ts, endTs: events[events.length - 1]!.ts }
      : null,
  };
}
