import type { AuthEvent, AuthOutcome, AuthService } from './types.js';

/**
 * 日志归一化：真实环境里 VPN 网关与 SSO（IdP）导出的字段名各不相同，
 * 这里用别名表把它们收敛到 AuthEvent。支持 JSON 对象、JSONL 文本行与 CSV 行。
 */

const FIELD_ALIASES: Record<string, keyof AuthEvent> = {
  timestamp: 'ts',
  time: 'ts',
  ts: 'ts',
  '@timestamp': 'ts',
  eventtime: 'ts',
  date: 'ts',
  service: 'service',
  event_source: 'service',
  source: 'service',
  product: 'service',
  app: 'service',
  userid: 'userId',
  username: 'userId',
  user: 'userId',
  account: 'userId',
  account_name: 'userId',
  login: 'userId',
  subject: 'userId',
  ip: 'ip',
  src_ip: 'ip',
  sourceip: 'ip',
  source_ip: 'ip',
  clientip: 'ip',
  client_ip: 'ip',
  remote_ip: 'ip',
  outcome: 'outcome',
  result: 'outcome',
  status: 'outcome',
  event_type: 'outcome',
  success: 'outcome',
  reason: 'reason',
  failure_reason: 'reason',
  failreason: 'reason',
  error: 'reason',
  useragent: 'userAgent',
  ua: 'userAgent',
  user_agent: 'userAgent',
};

const SUCCESS_TOKENS = new Set(['success', 'succeeded', 'ok', 'allowed', 'accept', 'accepted', 'login_success', '0', 'true']);
const FAILURE_TOKENS = new Set(['failure', 'failed', 'fail', 'deny', 'denied', 'reject', 'rejected', 'login_failure', '1', 'false']);

/** 解析时间戳：epoch 秒/毫秒、ISO 字符串均可。 */
export function parseTimestamp(raw: unknown): number {
  if (typeof raw === 'number') {
    // 10 位视为秒，13 位视为毫秒。
    return raw < 1e12 ? raw * 1000 : raw;
  }
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (/^\d+$/.test(trimmed)) return parseTimestamp(Number(trimmed));
    const parsed = Date.parse(trimmed);
    if (!Number.isNaN(parsed)) return parsed;
  }
  throw new Error(`无法解析时间戳: ${String(raw)}`);
}

function normalizeUser(raw: unknown): string {
  const s = String(raw).trim();
  // DOMAIN\user 或 DOMAIN/user 的 Windows 风格前缀去掉；邮箱保留域名（跨租户可能重名）。
  const slash = s.lastIndexOf('\\');
  const base = slash >= 0 ? s.slice(slash + 1) : s;
  return base.toLowerCase();
}

function normalizeOutcome(raw: unknown): AuthOutcome {
  const token = String(raw).trim().toLowerCase();
  if (SUCCESS_TOKENS.has(token)) return 'success';
  if (FAILURE_TOKENS.has(token)) return 'failure';
  throw new Error(`无法解析认证结果: ${String(raw)}`);
}

function normalizeService(raw: unknown): AuthService {
  const token = String(raw).trim().toLowerCase();
  if (token.includes('vpn') || token.includes('gateway') || token.includes('防火墙')) return 'vpn';
  return 'sso';
}

/** 把一条原始记录（字段名任意）映射成 AuthEvent。 */
export function normalizeRecord(record: Record<string, unknown>): AuthEvent {
  const mapped: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    const canonical = FIELD_ALIASES[key.toLowerCase().replace(/\s+/g, '_')];
    if (canonical && mapped[canonical] === undefined) mapped[canonical] = value;
  }

  if (mapped.ts === undefined || mapped.userId === undefined || mapped.ip === undefined || mapped.outcome === undefined) {
    throw new Error(`记录缺少必需字段(ts/userId/ip/outcome): ${JSON.stringify(record).slice(0, 200)}`);
  }

  const event: AuthEvent = {
    ts: parseTimestamp(mapped.ts),
    service: mapped.service === undefined ? 'sso' : normalizeService(mapped.service),
    userId: normalizeUser(mapped.userId),
    rawUser: String(mapped.userId),
    ip: String(mapped.ip).trim(),
    outcome: normalizeOutcome(mapped.outcome),
  };
  if (mapped.reason !== undefined) event.reason = String(mapped.reason);
  if (mapped.userAgent !== undefined) event.userAgent = String(mapped.userAgent);
  if (typeof record._scenario === 'string') event._scenario = record._scenario;
  return event;
}

/** 解析单行输入：JSONL 或 CSV（首行表头）。返回 null 表示空行/注释行。 */
export function parseLine(line: string, csvHeader?: string[]): AuthEvent | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;

  if (trimmed.startsWith('{')) {
    return normalizeRecord(JSON.parse(trimmed) as Record<string, unknown>);
  }

  if (csvHeader) {
    const fields = splitCsv(trimmed);
    const record: Record<string, unknown> = {};
    csvHeader.forEach((h, i) => {
      record[h] = fields[i];
    });
    return normalizeRecord(record);
  }
  throw new Error(`无法识别的日志行（既不是 JSON 也未提供 CSV 表头）: ${trimmed.slice(0, 120)}`);
}

/** 极简 CSV 解析，支持双引号包裹与转义引号。 */
export function splitCsv(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cur += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      out.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

export function isCsvHeader(line: string): boolean {
  const t = line.trim().toLowerCase();
  return !t.startsWith('{') && t.includes(',') && /(user|account|ip|time|ts)/.test(t);
}
