import type { Alert, DetectorType } from './types.js';
import type { ScenarioTruth } from '../generator/generate.js';

/**
 * 评估器：把引擎告警与生成器的 ground truth 场景做匹配，
 * 计算每类检测器的 precision / recall / F1 与误报率。
 *
 * 两层匹配口径（同时满足时间窗交集 + 实体重叠）：
 *  - 精确匹配：告警类型 == 场景类型。用于衡量每个检测器对“本职攻击”的识别能力。
 *  - 关联匹配：告警命中任意类型的攻击场景。跨类型关联（例如撞库成功同时触发
 *    不可能旅行）是并查集事件合并的正确行为，这类告警不是误报，单独计为关联 TP。
 *
 * 指标口径：
 *  - precision 用“精确 TP”，回答“这个检测器报的警有多少是它该管的攻击”；
 *  - 关联命中的告警不计 FP，但在 correlatedTruePositives 中单独披露；
 *  - 一条告警最多匹配一条场景（取实体重叠最多者）。
 */

export interface DetectorMetrics {
  detector: DetectorType;
  /** 类型精确匹配的 TP。 */
  truePositives: number;
  /** 命中了其他类型攻击场景的告警数（关联告警，非误报）。 */
  correlatedTruePositives: number;
  /** 未命中任何攻击场景的告警数（真正的误报）。 */
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  /** 每万条良性事件产生的误报告警数。 */
  falseAlertsPer10kBenign: number;
  matchedScenarioIds: string[];
  unmatchedAlerts: { alertId: string; subject: string; evidence: Alert['evidence'] }[];
}

export interface EvaluationReport {
  totalScenarios: number;
  totalAlerts: number;
  detectedScenarios: number;
  scenarioRecall: number;
  perDetector: Record<DetectorType, DetectorMetrics>;
  micro: { precision: number; recall: number; f1: number };
  /** 未被任何告警覆盖的场景（漏报明细）。 */
  missedScenarios: ScenarioTruth[];
}

const DETECTORS: DetectorType[] = [
  'impossible_travel',
  'password_spray',
  'brute_force',
  'credential_stuffing',
];

function overlapsTime(alert: Alert, truth: ScenarioTruth): boolean {
  return !(alert.endTs < truth.startTs || alert.startTs > truth.endTs);
}

function overlapsEntity(alert: Alert, truth: ScenarioTruth): boolean {
  const truthUsers = new Set(truth.users);
  const truthIps = new Set(truth.ips);
  return alert.users.some((u) => truthUsers.has(u)) || alert.ips.some((ip) => truthIps.has(ip));
}

function overlapScore(alert: Alert, truth: ScenarioTruth): number {
  const truthUsers = new Set(truth.users);
  const truthIps = new Set(truth.ips);
  let score = 0;
  for (const u of alert.users) if (truthUsers.has(u)) score++;
  for (const ip of alert.ips) if (truthIps.has(ip)) score++;
  return score;
}

/** 在一组场景里找与告警时间/实体重叠且得分最高者。 */
function bestMatch(alert: Alert, truths: ScenarioTruth[]): ScenarioTruth | null {
  let best: ScenarioTruth | null = null;
  let bestScore = 0;
  for (const truth of truths) {
    if (!overlapsTime(alert, truth) || !overlapsEntity(alert, truth)) continue;
    const score = overlapScore(alert, truth);
    if (score > bestScore) {
      best = truth;
      bestScore = score;
    }
  }
  return best;
}

export function evaluate(
  alerts: Alert[],
  groundTruth: ScenarioTruth[],
  benignEventCount: number,
): EvaluationReport {
  // 每条告警的归类结果。
  const exactMatch = new Map<string, ScenarioTruth>();
  const correlatedMatch = new Map<string, ScenarioTruth>();
  const detectedScenarioIds = new Set<string>();

  for (const alert of alerts) {
    // 先在同类型场景里找精确匹配。
    const sameType = groundTruth.filter((t) => t.attackType === alert.type);
    const exact = bestMatch(alert, sameType);
    if (exact) {
      exactMatch.set(alert.id, exact);
      detectedScenarioIds.add(exact.scenarioId);
      continue;
    }
    // 再在全部场景里找关联匹配（跨类型，但确实是攻击活动）。
    const related = bestMatch(alert, groundTruth);
    if (related) {
      correlatedMatch.set(alert.id, related);
      detectedScenarioIds.add(related.scenarioId);
    }
  }

  const perDetector = {} as Record<DetectorType, DetectorMetrics>;
  let tpAll = 0;
  let fpAll = 0;
  let fnAll = 0;

  for (const detector of DETECTORS) {
    const truths = groundTruth.filter((t) => t.attackType === detector);
    const detectorAlerts = alerts.filter((a) => a.type === detector);

    const tp = detectorAlerts.filter((a) => exactMatch.has(a.id)).length;
    const correlated = detectorAlerts.filter((a) => correlatedMatch.has(a.id)).length;
    const fp = detectorAlerts.length - tp - correlated;
    const fn = truths.filter((t) => !detectedScenarioIds.has(t.scenarioId)).length;
    const matchedIds = truths
      .filter((t) => detectedScenarioIds.has(t.scenarioId))
      .map((t) => t.scenarioId);

    // precision 只把精确 TP 计入分子；关联告警视为“合理的跨检测器信号”，不惩罚。
    const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
    const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
    const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

    perDetector[detector] = {
      detector,
      truePositives: tp,
      correlatedTruePositives: correlated,
      falsePositives: fp,
      falseNegatives: fn,
      precision: round4(precision),
      recall: round4(recall),
      f1: round4(f1),
      falseAlertsPer10kBenign: benignEventCount === 0 ? 0 : round4((fp / benignEventCount) * 10_000),
      matchedScenarioIds: matchedIds,
      unmatchedAlerts: detectorAlerts
        .filter((a) => !exactMatch.has(a.id) && !correlatedMatch.has(a.id))
        .map((a) => ({ alertId: a.id, subject: a.subject, evidence: a.evidence })),
    };
    tpAll += tp;
    fpAll += fp;
    fnAll += fn;
  }

  const microPrecision = tpAll + fpAll === 0 ? 1 : tpAll / (tpAll + fpAll);
  const microRecall = tpAll + fnAll === 0 ? 1 : tpAll / (tpAll + fnAll);
  const microF1 =
    microPrecision + microRecall === 0 ? 0 : (2 * microPrecision * microRecall) / (microPrecision + microRecall);

  return {
    totalScenarios: groundTruth.length,
    totalAlerts: alerts.length,
    detectedScenarios: detectedScenarioIds.size,
    scenarioRecall: round4(detectedScenarioIds.size / Math.max(1, groundTruth.length)),
    perDetector,
    micro: {
      precision: round4(microPrecision),
      recall: round4(microRecall),
      f1: round4(microF1),
    },
    missedScenarios: groundTruth.filter((t) => !detectedScenarioIds.has(t.scenarioId)),
  };
}

function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}
