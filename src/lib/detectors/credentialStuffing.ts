import { detectionConfig, HOUR } from '../config.js';
import { isPrivateIp } from '../geo.js';
import { AlertFactory, SlidingWindow, isSuppressed, type EmitFn, type SequencedEvent } from './common.js';

/**
 * 撞库检测，两条互补规则：
 *
 * A. 纵向（以账号为主体）：一次成功登录之前的 6 小时窗内，
 *    同账号失败 >= 8 次——“成功前大量失败”，是凭证被猜中/填充成功的最强信号。
 *
 * B. 横向（以 IP 为主体）：同一 IP 在 6 小时窗内对 >=10 个账号
 *    产生 >=30 次失败——批量凭证枚举，即使没有成功也要报。
 *
 * 失败窗口同时包含成功事件用于时间轴，但统计只计 failure。
 */
export class CredentialStuffingDetector {
  private perUser = new Map<string, SlidingWindow<SequencedEvent>>();
  private perIp = new Map<string, SlidingWindow<SequencedEvent>>();
  private factory = new AlertFactory(3 * HOUR);

  process(event: SequencedEvent, emit: EmitFn): void {
    // ---- 规则 B：IP 横向枚举（成功/失败都入窗，按失败计数）----
    let ipWindow = this.perIp.get(event.ip);
    if (!ipWindow) {
      ipWindow = new SlidingWindow();
      this.perIp.set(event.ip, ipWindow);
    }
    ipWindow.add(event);
    const ipEvents = ipWindow.evict(event.ts, detectionConfig.credentialStuffing.windowMs);
    const ipFailures = ipEvents.filter((e) => e.outcome === 'failure' && !isPrivateIp(e.ip));
    const ipUsers = new Set(ipFailures.map((e) => e.userId));
    const cfg = detectionConfig.credentialStuffing;

    if (ipFailures.length >= cfg.ipMinFailures && ipUsers.size >= cfg.ipMinDistinctUsers) {
      const alert = this.factory.emit(
        'credential_stuffing',
        `ip:${event.ip}`,
        event.ts,
        {
          severity: ipFailures.length >= cfg.ipMinFailures * 3 ? 'critical' : 'high',
          startTs: ipFailures[0]!.ts,
          endTs: event.ts,
          eventSeqs: ipFailures.map((e) => e.seq),
          users: [...ipUsers],
          ips: [event.ip],
          evidence: {
            rule: 'B-ip-sweep',
            failureCount: ipFailures.length,
            distinctUsers: ipUsers.size,
            windowHours: cfg.windowMs / HOUR,
          },
        },
        emit,
      );
      if (!isSuppressed(alert)) {
        // 继续走规则 A：同一事件可能同时是某账号“失败后成功”的时刻。
      }
    }

    // ---- 规则 A：账号纵向，成功前大量失败 ----
    let userWindow = this.perUser.get(event.userId);
    if (!userWindow) {
      userWindow = new SlidingWindow();
      this.perUser.set(event.userId, userWindow);
    }

    if (event.outcome === 'success') {
      const prior = userWindow
        .evict(event.ts, cfg.windowMs)
        .filter((e) => e.outcome === 'failure' && e.ts < event.ts && !isPrivateIp(e.ip));
      const distinctIps = new Set(prior.map((e) => e.ip)).size;
      // 要求多来源公网 IP：单一 IP（哪怕是住宅地址）的连续失败更像本人记错密码，
      // 撞库/填充的典型特征是凭证在多台主机上被尝试。
      if (prior.length >= cfg.minFailuresBeforeSuccess && distinctIps >= cfg.minDistinctPublicIps) {
        const alert = this.factory.emit(
          'credential_stuffing',
          `user:${event.userId}`,
          event.ts,
          {
            severity: prior.length >= cfg.minFailuresBeforeSuccess * 3 ? 'critical' : 'high',
            startTs: prior[0]!.ts,
            endTs: event.ts,
            eventSeqs: [...prior.map((e) => e.seq), event.seq],
            users: [event.userId],
            ips: [...new Set([...prior.map((e) => e.ip), event.ip])],
            evidence: {
              rule: 'A-failures-before-success',
              failuresBeforeSuccess: prior.length,
              distinctSourceIps: distinctIps,
              successIp: event.ip,
              windowHours: cfg.windowMs / HOUR,
            },
          },
          emit,
        );
        if (isSuppressed(alert)) return;
      }
    }
    userWindow.add(event);
  }
}
