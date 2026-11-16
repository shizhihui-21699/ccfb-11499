import { createReadStream, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { runEngine, type AnalysisReport } from '../lib/engine.js';

/**
 * 用法: tsx src/cli/analyze.ts <日志文件 jsonl/csv> [报告输出路径]
 * 流式逐行读取，避免一次性 readFile 大文件；引擎内部仍会排序（如需外部预排序可改 presorted）。
 */
const inputPath = resolve(process.argv[2] ?? 'data/auth-events.jsonl');
const reportPath = resolve(process.argv[3] ?? 'data/report.json');

async function main(): Promise<void> {
  const rl = createInterface({
    input: createReadStream(inputPath, { encoding: 'utf8' }),
    crlfDelay: Infinity,
  });

  const lines: string[] = [];
  for await (const line of rl) lines.push(line);

  console.time('analyze');
  const report: AnalysisReport = runEngine(lines, { includeSessions: false });
  console.timeEnd('analyze');

  mkdirSync(resolve(dirnameOf(reportPath)), { recursive: true });
  writeFileSync(reportPath, JSON.stringify(report));

  const s = report.stats;
  console.log('--- 统计 ---');
  console.log(`事件 ${s.totalEvents} | 成功 ${s.successCount} | 失败 ${s.failureCount} | 用户 ${s.uniqueUsers} | IP ${s.uniqueIps}`);
  console.log(`会话 ${s.sessionCount} | 告警 ${s.alertCount} | 事件(incident) ${s.incidentCount}`);
  console.log('按类型:', JSON.stringify(s.alertsByType));
  console.log(`报告: ${reportPath}`);
}

function dirnameOf(p: string): string {
  return p.slice(0, p.lastIndexOf('/')) || '.';
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
