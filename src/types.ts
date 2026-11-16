export type Service = 'vpn' | 'sso';
export type Result = 'success' | 'failure';

export interface LogEvent {
  ts: number; // epoch ms
  user: string;
  ip: string;
  service: Service;
  result: Result;
  reason?: string;
}

export interface Session {
  id: string;
  user: string;
  ips: string[];
  start: number;
  end: number;
  count: number;
  successes: number;
  failures: number;
}

export type AlertType =
  | 'impossible_travel'
  | 'password_spraying'
  | 'brute_force'
  | 'credential_stuffing';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export const ALERT_TYPE_LABEL: Record<AlertType, string> = {
  impossible_travel: '不可能旅行',
  password_spraying: '口令喷洒',
  brute_force: '暴力破解',
  credential_stuffing: '撞库',
};

export interface Alert {
  id: string;
  type: AlertType;
  start: number;
  end: number;
  users: string[];
  ips: string[];
  score: number; // 0-100
  severity: Severity;
  summary: string;
  details: Record<string, unknown>;
}

export interface Incident {
  id: string;
  title: string;
  types: AlertType[];
  start: number;
  end: number;
  users: string[];
  ips: string[];
  score: number;
  severity: Severity;
  alerts: Alert[];
}

export interface AnalysisOutput {
  generatedAt: number;
  stats: {
    events: number;
    users: number;
    ips: number;
    sessions: number;
    alerts: number;
    incidents: number;
    byType: Record<AlertType, number>;
  };
  incidents: Incident[];
}
