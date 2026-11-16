import { detectionConfig } from './config.js';
import { lookupIp } from './geo.js';
import type { AuthEvent, Session } from './types.js';

/**
 * 流式会话化：为每个用户维护“当前会话”，
 * 距上一事件超过 idleTimeoutMs 即关闭旧会话、开新会话。
 * 会话结果用于报告统计与界面展示；检测器各自维护专用窗口状态，不依赖会话。
 */
export class Sessionizer {
  private active = new Map<string, Session>();
  private closed: Session[] = [];
  private counter = 0;

  process(event: AuthEvent & { seq: number }): Session | null {
    const existing = this.active.get(event.userId);
    const geo = lookupIp(event.ip);

    if (existing && event.ts - existing.endTs <= detectionConfig.session.idleTimeoutMs) {
      existing.endTs = event.ts;
      existing.eventSeqs.push(event.seq);
      if (event.outcome === 'success') existing.successCount++;
      else existing.failureCount++;
      // 会话内换 IP：保留首个 IP 作为会话锚点，事件层仍保留真实 IP。
      return null;
    }

    if (existing) {
      this.closed.push(existing);
      this.active.delete(event.userId);
    }

    const session: Session = {
      id: `s${++this.counter}`,
      userId: event.userId,
      startTs: event.ts,
      endTs: event.ts,
      ip: event.ip,
      city: geo.private ? undefined : geo.city,
      country: geo.private ? undefined : geo.country,
      failureCount: event.outcome === 'failure' ? 1 : 0,
      successCount: event.outcome === 'success' ? 1 : 0,
      eventSeqs: [event.seq],
    };
    this.active.set(event.userId, session);
    return session;
  }

  /** 流结束后取出全部会话（含仍活跃的）。 */
  flush(): Session[] {
    for (const s of this.active.values()) this.closed.push(s);
    this.active.clear();
    return this.closed.sort((a, b) => a.startTs - b.startTs);
  }

  get activeCount(): number {
    return this.active.size;
  }
}
