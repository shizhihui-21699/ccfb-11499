import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { DETECTOR_LABELS } from '../lib/config.js';
import { evaluate, type EvaluationReport } from '../lib/evaluate.js';
import type { AnalysisReport } from '../lib/engine.js';
import type { ScenarioTruth } from '../generator/generate.js';

/**
 * 用法: tsx src/cli/evaluate.ts [报告路径] [标注路径] [评估输出路径]
 * 对照 ground truth 计算每类检测器的 precision/recall/F1 与误报率。
 */
const reportPath = resolve(process.argv[2] ?? 'data/report.json');
const truthPath = resolve(process.argv[3] ?? 'data/ground-truth.json');
const evalPath = resolve(process.argv[4] ?? 'data/evaluation.json');

const report = JSON.parse(readFileSync(reportPath, 'utf8')) as AnalysisReport;
const truthDoc = JSON.parse(readFileSync(truthPath, 'utf8')) as {
  preset: { benignEvents: number };
  scenarios: ScenarioTruth[];
};

// 良性事件数：日志总量减去带攻击标注的事件。报告不含原始标注，
// 因此用 ground truth 场景覆盖的事件量做差（近似：攻击事件数从生成侧统计更精确，
// 这里直接采用 preset.benignEvents，生成器保证良性部分按该目标产出）。
const benignEventCount = truthDoc.preset.benignEvents;

const result: EvaluationReport = evaluate(report.alerts, truthDoc.scenarios, benignEventCount);
writeFileSync(evalPath, JSON.stringify(result, null, 2));

console.log('=== 检测评估（标注数据集）===');
console.log(
  `场景召回: ${result.detectedScenarios}/${result.totalScenarios} = ${(result.scenarioRecall * 100).toFixed(1)}%`,
);
console.log(`微平均 P/R/F1: ${pct(result.micro.precision)} / ${pct(result.micro.recall)} / ${pct(result.micro.f1)}`);
console.log('');
for (const [detector, m] of Object.entries(result.perDetector)) {
  console.log(
    `${DETECTOR_LABELS[detector as keyof typeof DETECTOR_LABELS].padEnd(28)} ` +
      `P=${pct(m.precision).padStart(7)} R=${pct(m.recall).padStart(7)} F1=${pct(m.f1).padStart(7)} ` +
      `精确TP=${m.truePositives} 关联TP=${m.correlatedTruePositives} FP=${m.falsePositives} FN=${m.falseNegatives} ` +
      `误报/万条良性=${m.falseAlertsPer10kBenign}`,
  );
}
if (result.missedScenarios.length > 0) {
  console.log('\n漏报场景:');
  for (const t of result.missedScenarios) console.log(`  - [${t.attackType}] ${t.scenarioId}: ${t.description}`);
}
for (const m of Object.values(result.perDetector)) {
  if (m.unmatchedAlerts.length > 0) {
    console.log(`\n[${m.detector}] 误报告警明细:`);
    for (const fp of m.unmatchedAlerts) console.log(`  - ${fp.alertId} ${fp.subject} ${JSON.stringify(fp.evidence)}`);
  }
}
console.log(`\n评估结果: ${evalPath}`);

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}
