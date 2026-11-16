import type { Alert, AuthEvent, DetectorType } from '../types.js';

/** 带时间戳的滑动窗口，自动淘汰过期事件。 */
export class SlidingWindow<T extends { ts: number }> {
  private items: T[] = [];

  add(item: T): void {
    this.items.push(item);
  }

  /** 淘汰窗口外元素，返回当前窗口内的快照。 */
  evict(nowTs: number, windowMs: number): T[] {
    const cutoff = nowTs - windowMs;
    let drop = 0;
    while (drop < this.items.length && this.items[drop]!.ts < cutoff) drop++;
    if (drop > 0) this.items.splice(0, drop);
    return this.items;
  }

  get size(): number {
    return this.items.length;
  }
}

export type EmitFn = (alert: Omit<Alert, 'id'>) => void;

/**
 * 告警工厂：统一编号、按 (type, subject) 冷却去重。
 * 同一主体在冷却期内只产出一条告警（endTs 滚动延展），
 * 避免一次持续攻击在每个事件上都报一条。
 */
export class AlertFactory {
  private seq = 0;
  private lastEmit = new Map<string, number>();

  constructor(private readonly cooldownMs: number) {}

  emit(
    type: DetectorType,
    subject: string,
    nowTs: number,
    payload: Omit<Alert, 'id' | 'type' | 'subject'>,
    emit: EmitFn,
  ): Alert {
    const key = `${type}:${subject}`;
    const last = this.lastEmit.get(key);
    if (last !== undefined && nowTs - last < this.cooldownMs) {
      // 冷却期内：返回标记 id='' 表示被抑制，检测器可据此跳过后续处理。
      return suppressedAlert(type, subject);
    }
    this.lastEmit.set(key, nowTs);
    const alert: Alert = {
      id: `alert-${++this.seq}`,
      type,
      subject,
      ...payload,
    };
    emit(alert);
    return alert;
  }
}

function suppressedAlert(type: DetectorType, subject: string): Alert {
  return {
    id: '',
    type,
    subject,
    severity: 'low',
    startTs: 0,
    endTs: 0,
    eventSeqs: [],
    users: [],
    ips: [],
    evidence: {},
  };
}

export function isSuppressed(alert: Alert): boolean {
  return alert.id === '';
}

/** 统计窗口内去重值数量。 */
export function distinctCount(values: Iterable<string>): number {
  return new Set(values).size;
}

export type SequencedEvent = AuthEvent & { seq: number };
