import { detectionConfig, HOUR } from '../config.js';
import { isPrivateIp } from '../geo.js';
import { AlertFactory, SlidingWindow, isSuppressed, type EmitFn, type SequencedEvent } from './common.js';

/**
 * 暴力破解：多个公网 IP 针对同一账号，在 1 小时窗内累计大量失败。
 * 与喷洒互为镜像（喷洒是 1 IP × N 账号；暴力是 N IP × 1 账号）。
 * 分布式代理池会摊薄单 IP 次数，所以判定主体是“账号”而非 IP。
 * 私网/办公网地址不计入：企业内网 NAT 出口每次可能是不同 10.x 地址，
 * 但那不是“多来源攻击”，只是内网汇聚。
 */
export class BruteForceDetector {
  private windows = new Map<string, SlidingWindow<SequencedEvent>>();
  private factory = new AlertFactory(HOUR);

  process(event: SequencedEvent, emit: EmitFn): void {
    let window = this.windows.get(event.userId);
    if (!window) {
      window = new SlidingWindow();
      this.windows.set(event.userId, window);
    }
    window.add(event);

    const events = window.evict(event.ts, detectionConfig.bruteForce.windowMs);
    const failures = events.filter((e) => e.outcome === 'failure' && !isPrivateIp(e.ip));
    const distinctIps = new Set(failures.map((e) => e.ip)).size;
    // 只有“在发起失败的同一批攻击 IP 上出现成功”才算凭证被攻破，交给撞库规则 A 接管。
    // 用户在自己住宅 IP 上的正常成功不抑制：攻击者仍在外部代理池上继续打他的账号。
    const failureIpSet = new Set(failures.map((e) => e.ip));
    const succeededOnAttackIp = events.some(
      (e) => e.outcome === 'success' && !isPrivateIp(e.ip) && failureIpSet.has(e.ip),
    );
    const cfg = detectionConfig.bruteForce;

    if (!succeededOnAttackIp && failures.length >= cfg.minFailures && distinctIps >= cfg.minDistinctIps) {
      const alert = this.factory.emit(
        'brute_force',
        `user:${event.userId}`,
        event.ts,
        {
          severity: failures.length >= cfg.minFailures * 3 ? 'critical' : 'high',
          startTs: failures[0]!.ts,
          endTs: event.ts,
          eventSeqs: failures.map((e) => e.seq),
          users: [event.userId],
          ips: [...new Set(failures.map((e) => e.ip))],
          evidence: {
            failureCount: failures.length,
            distinctSourceIps: distinctIps,
            windowHours: cfg.windowMs / HOUR,
          },
        },
        emit,
      );
      if (isSuppressed(alert)) return;
    }
  }
}
