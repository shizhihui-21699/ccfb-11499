/**
 * 可复现随机数：数据生成器所有随机性都来自这里，
 * 固定 seed 即可逐字节复现整份数据集，评估结果可回归对比。
 */
export class Rng {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0;
  }

  /** mulberry32，返回 [0,1)。 */
  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  /** [min, max] 闭区间整数。 */
  int(min: number, max: number): number {
    return min + Math.floor(this.next() * (max - min + 1));
  }

  pick<T>(items: readonly T[]): T {
    return items[Math.floor(this.next() * items.length)]!;
  }

  /** 以概率 p 返回 true。 */
  chance(p: number): boolean {
    return this.next() < p;
  }

  /** 指数分布间隔（毫秒），用于模拟登录事件的泊松到达。 */
  exponential(meanMs: number): number {
    const u = Math.max(this.next(), 1e-9);
    return Math.round(-Math.log(u) * meanMs);
  }

  /** 从数组中无放回抽取 n 个。 */
  sample<T>(items: readonly T[], n: number): T[] {
    const pool = [...items];
    const out: T[] = [];
    while (out.length < n && pool.length > 0) {
      const idx = Math.floor(this.next() * pool.length);
      out.push(pool.splice(idx, 1)[0]!);
    }
    return out;
  }
}
