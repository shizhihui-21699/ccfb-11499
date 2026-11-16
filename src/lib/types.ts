/**
 * 核心数据模型：一条归一化后的认证日志事件，以及检测器产出的告警 / 事件。
 * 输入日志经过 normalize() 后统一成本结构，引擎只依赖它，不感知原始字段名。
 */

/** 归一化认证结果。 */
export type AuthOutcome = 'success' | 'failure';

/** 认证来源产品类型（VPN / SSO 字段可能不同，归一化时区分）。 */
export type AuthService = 'vpn' | 'sso';

/** 一条认证日志。所有时间戳为 epoch 毫秒。 */
export interface AuthEvent {
  /** 引擎按时间排序后赋予的单调序号，undefined 表示尚未排序。 */
  seq?: number;
  ts: number;
  service: AuthService;
  userId: string;
  /** 原始用户名（大小写/域名归一化前），便于追溯。 */
  rawUser?: string;
  ip: string;
  outcome: AuthOutcome;
  /** 失败原因码，如 bad_password / locked / mfa_failed。 */
  reason?: string;
  userAgent?: string;
  /** 数据生成器注入的标注，真实日志里不存在；引擎不得读取该字段做判断。 */
  _scenario?: string;
}

/** 检测器类型标识。 */
export type DetectorType =
  | 'impossible_travel'
  | 'password_spray'
  | 'brute_force'
  | 'credential_stuffing';

/** 单条告警：一个检测器在某个窗口内对某个主体（IP / 用户）的一次判定。 */
export interface Alert {
  id: string;
  type: DetectorType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** 告警主体 key，例如 ip:1.2.3.4 / user:alice。 */
  subject: string;
  startTs: number;
  endTs: number;
  /** 参与判定的事件序号。 */
  eventSeqs: number[];
  /** 命中的用户 / IP，供事件合并与界面展示。 */
  users: string[];
  ips: string[];
  /** 人类可读证据。 */
  evidence: Record<string, string | number>;
}

/** 事件：由多条相关告警合并而来（并查集），带时间线。 */
export interface SecurityIncident {
  id: string;
  types: DetectorType[];
  severity: Alert['severity'];
  startTs: number;
  endTs: number;
  alertIds: string[];
  users: string[];
  ips: string[];
  /** 时间线条目：既包含告警，也包含关键原始事件（成功登录等）。 */
  timeline: TimelineEntry[];
  eventCount: number;
  alertCount: number;
}

export interface TimelineEntry {
  ts: number;
  kind: 'alert' | 'success' | 'failure';
  detail: string;
  alertId?: string;
  ip?: string;
  userId?: string;
}

/** 一个用户的会话（30 分钟无活动即断开，成功/失败都计入）。 */
export interface Session {
  id: string;
  userId: string;
  startTs: number;
  endTs: number;
  ip: string;
  city?: string;
  country?: string;
  failureCount: number;
  successCount: number;
  eventSeqs: number[];
}

/** 地理信息。 */
export interface GeoInfo {
  ip: string;
  city: string;
  country: string;
  lat: number;
  lon: number;
  /** 私有 / 保留地址，地理判定跳过。 */
  private: boolean;
}
