import { detectionConfig, HOUR } from '../config.js';
import type { AuthEvent } from '../types.js';
import { AlertFactory, SlidingWindow, isSuppressed, type EmitFn, type SequencedEvent } from './common.js';

interface IpState {
  window: SlidingWindow<SequencedEvent>;
  /** 已对该 IP 报过的用户，避免事件计数重复。 */
}

/**
 * 口令喷洒：同一 IP 在 1 小时滑动窗内对大量不同账号做低频尝试。
 * 与暴力破解的区分点：账号面广（>=15）、每账号尝试少（<=3）、失败率高。
 * 天然覆盖“低频”——窗口按时间滑动而非按次数，慢速铺开的喷洒一样会被累计到。
 */
export class PasswordSprayDetector {
  private states = new Map<string, IpState>();
  private factory = new AlertFactory(HOUR);

  process(event: SequencedEvent, emit: EmitFn): void {
    let state = this.states.get(event.ip);
    if (!state) {
      state = { window: new SlidingWindow() };
      this.states.set(event.ip, state);
    }
    state.window.add(event);

    const events = state.window.evict(event.ts, detectionConfig.passwordSpray.windowMs);
    const perUser = new Map<string, number>();
    let failures = 0;
    for (const e of events) {
      perUser.set(e.userId, (perUser.get(e.userId) ?? 0) + 1);
      if (e.outcome === 'failure') failures++;
    }

    const distinctUsers = perUser.size;
    const totalAttempts = events.length;
    const avgPerUser = totalAttempts / distinctUsers;
    const failureRate = failures / totalAttempts;
    const cfg = detectionConfig.passwordSpray;

    if (
      distinctUsers >= cfg.minDistinctUsers &&
      avgPerUser <= cfg.maxAttemptsPerUser &&
      failureRate >= cfg.minFailureRate
    ) {
      const alert = this.factory.emit(
        'password_spray',
        `ip:${event.ip}`,
        event.ts,
        {
          severity: distinctUsers >= cfg.minDistinctUsers * 2 ? 'critical' : 'high',
          startTs: events[0]!.ts,
          endTs: event.ts,
          eventSeqs: events.map((e: AuthEvent & { seq: number }) => e.seq),
          users: [...perUser.keys()],
          ips: [event.ip],
          evidence: {
            distinctUsers,
            totalAttempts,
            avgAttemptsPerUser: Number(avgPerUser.toFixed(2)),
            failureRate: Number(failureRate.toFixed(3)),
            windowHours: cfg.windowMs / HOUR,
          },
        },
        emit,
      );
      if (isSuppressed(alert)) return;
    }
  }
}
