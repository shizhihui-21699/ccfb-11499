import { detectionConfig } from '../config.js';
import { haversineKm, lookupIp } from '../geo.js';
import type { Alert } from '../types.js';
import { AlertFactory, isSuppressed, type EmitFn, type SequencedEvent } from './common.js';

interface SuccessPoint {
  ts: number;
  ip: string;
  seq: number;
}

/**
 * 不可能旅行：同一用户【时间相邻】的两次成功登录，若地理距离 / 时间差推导出的
 * 平均速度超过民航速度上限，且两城足够远，则告警。
 *
 * 只比较相邻成功登录是关键：用户“家乡 -> 出差地 -> 家乡”的三段式行程里，
 * 非相邻的（出差地, 家乡第二次）可能间隔很短，但中间已有家乡登录作为锚点，
 * 相邻配对的速度始终合理。私网 IP 与窗口之外的历史不参与。
 */
export class ImpossibleTravelDetector {
  /** 每个用户最近的成功登录序列（只需保留窗口内的尾部若干条）。 */
  private history = new Map<string, SuccessPoint[]>();
  /**
   * 冷却取 1 小时而非检测窗口的倍数：同一用户可能在一天内被多次攻击（撞库得手后
   * 又发生异地登录），冷却过长会把后续真实攻击吞掉造成漏报；滑动窗口本身已能
   * 防止同一对登录被重复计数。
   */
  private factory = new AlertFactory(60 * 60_000);

  process(event: SequencedEvent, emit: EmitFn): void {
    if (event.outcome !== 'success') return;
    const geo = lookupIp(event.ip);
    const cfg = detectionConfig.impossibleTravel;

    if (geo.private) {
      // 内网登录仍作为锚点更新，打断地理链，但自身不参与距离比较。
      this.pushAnchor(event.userId, { ts: event.ts, ip: event.ip, seq: event.seq });
      return;
    }

    const list = this.history.get(event.userId) ?? [];
    // 淘汰窗口外历史，找最近一条公网成功（私网锚点已把链断开，不会跳过）。
    const cutoff = event.ts - cfg.windowMs;
    while (list.length > 0 && list[0]!.ts < cutoff) list.shift();

    const prev = [...list].reverse().find((p) => !lookupIp(p.ip).private);
    if (prev) {
      const elapsedH = (event.ts - prev.ts) / 3_600_000;
      if (elapsedH > 0) {
        const prevGeo = lookupIp(prev.ip);
        const distance = haversineKm(prevGeo, geo);
        const speed = distance / elapsedH;
        if (distance >= cfg.minDistanceKm && speed > cfg.maxSpeedKmh) {
          const alert = this.factory.emit(
            'impossible_travel',
            `user:${event.userId}`,
            event.ts,
            {
              severity: speed > cfg.maxSpeedKmh * 2 ? 'critical' : 'high',
              startTs: prev.ts,
              endTs: event.ts,
              eventSeqs: [prev.seq, event.seq],
              users: [event.userId],
              ips: [prev.ip, event.ip],
              evidence: {
                distanceKm: Math.round(distance),
                speedKmh: Math.round(speed),
                from: `${prevGeo.city}(${prev.ip})`,
                to: `${geo.city}(${event.ip})`,
                elapsedHours: Number(elapsedH.toFixed(2)),
              },
            },
            emit,
          );
          if (isSuppressed(alert)) return;
        }
      }
    }
    this.pushAnchor(event.userId, { ts: event.ts, ip: event.ip, seq: event.seq });
  }

  private pushAnchor(userId: string, point: SuccessPoint): void {
    const list = this.history.get(userId) ?? [];
    list.push(point);
    // 只保留窗口内尾部，控制内存：每条成功都入列，窗口 4h 内单用户事件有限。
    const cutoff = point.ts - detectionConfig.impossibleTravel.windowMs;
    while (list.length > 0 && list[0]!.ts < cutoff) list.shift();
    this.history.set(userId, list);
  }
}
