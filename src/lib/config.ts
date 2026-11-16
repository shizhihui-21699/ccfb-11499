import type { DetectorType } from './types.js';

/**
 * 检测窗口与阈值的唯一来源。
 * 初值依据常见攻击节奏设定，最终用 evaluate 的标注结果回调（见 README 调参记录）。
 * 所有时长单位为毫秒。
 */
export const HOUR = 3_600_000;
export const MINUTE = 60_000;

export const detectionConfig = {
  session: {
    /** 会话不活动超时：30 分钟无事件则关闭。 */
    idleTimeoutMs: 30 * MINUTE,
  },

  impossibleTravel: {
    /**
     * 两次成功登录之间低于该时长才评估。取 4 小时：
     * 真实不可能旅行几乎都在 2 小时内完成跳转；窗口过长会把“到达目的地 -> 回到家乡”
     * 两段本不相关的登录强行配对，制造误报。
     */
    windowMs: 4 * HOUR,
    /** 平均移动速度超过该值（km/h）判定不可能旅行；商用产品常用 800~1200。 */
    maxSpeedKmh: 900,
    /** 两城直线距离低于该值（km）不判，避免同城 ISP 漂移误报。 */
    minDistanceKm: 100,
  },

  passwordSpray: {
    /** 统计窗口：低频喷洒常按小时铺开，取 1 小时滑动窗。 */
    windowMs: HOUR,
    /** 单 IP 在窗口内尝试的不同账号数下限。 */
    minDistinctUsers: 15,
    /** 每账号平均尝试次数上限（喷洒的特征是“广撒网、每账号少试”）。 */
    maxAttemptsPerUser: 3,
    /** 窗口内失败率下限。 */
    minFailureRate: 0.8,
  },

  bruteForce: {
    /** 针对单账号的统计窗口。 */
    windowMs: HOUR,
    /** 单账号在窗口内失败次数下限。 */
    minFailures: 10,
    /** 命中要求的不同公网来源 IP 数下限（良性用户最多 2 个住宅 IP，攻击代理池 >=8）。 */
    minDistinctIps: 4,
  },

  credentialStuffing: {
    /** “成功前大量失败”的回看窗口。 */
    windowMs: 6 * HOUR,
    /** 成功登录前，同账号累计失败次数下限。 */
    minFailuresBeforeSuccess: 8,
    /** 规则 A 要求的不同公网来源 IP 下限（住宅 IP 最多 2 个，攻击池 >=3 即可分离）。 */
    minDistinctPublicIps: 3,
    /** 同 IP 横向撞库：窗口内涉及的不同账号数下限。 */
    ipMinDistinctUsers: 10,
    /** 同 IP 横向撞库：窗口内失败总量下限。 */
    ipMinFailures: 30,
  },
} as const;

/** 严重度排序，事件合并取最高。 */
export const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'] as const;

export const DETECTOR_LABELS: Record<DetectorType, string> = {
  impossible_travel: '不可能旅行',
  password_spray: '口令喷洒',
  brute_force: '暴力破解（多IP打单账号）',
  credential_stuffing: '撞库（成功前大量失败）',
};
