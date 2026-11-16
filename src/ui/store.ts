import { createSignal } from 'solid-js';
import { analyzeEvents, type AnalysisReport } from '../lib/engine.js';
import { isCsvHeader, parseLine } from '../lib/normalize.js';
import type { AuthEvent } from '../lib/types.js';

/**
 * UI 全局状态：支持两种数据来源
 *  1. 直接上传原始日志（jsonl/csv），在浏览器线程内跑同一套引擎；
 *  2. 上传 CLI 产出的 report.json，跳过分析直接渲染（适合超大文件离线分析后查看）。
 * 大文件分析用 setTimeout 分片，避免阻塞首屏；这里先给出同步实现 + 状态反馈。
 */

export type LoadState = 'idle' | 'parsing' | 'analyzing' | 'done' | 'error';

const [report, setReport] = createSignal<AnalysisReport | null>(null);
const [loadState, setLoadState] = createSignal<LoadState>('idle');
const [errorMsg, setErrorMsg] = createSignal<string>('');
const [sourceName, setSourceName] = createSignal<string>('');

export function useReportStore() {
  return { report, loadState, errorMsg, sourceName };
}

/** 载入 CLI 生成的报告 JSON。 */
export async function loadReportFile(file: File): Promise<void> {
  setLoadState('parsing');
  setErrorMsg('');
  setSourceName(file.name);
  try {
    const text = await file.text();
    const parsed = JSON.parse(text) as AnalysisReport;
    if (!parsed.stats || !Array.isArray(parsed.alerts)) {
      throw new Error('文件缺少 stats/alerts 字段，不是有效的分析报告');
    }
    setReport(parsed);
    setLoadState('done');
  } catch (err) {
    setLoadState('error');
    setErrorMsg(err instanceof Error ? err.message : String(err));
  }
}

/** 载入原始日志并在浏览器内运行引擎。 */
export async function loadLogFile(file: File): Promise<void> {
  setLoadState('parsing');
  setErrorMsg('');
  setSourceName(file.name);
  try {
    const text = await file.text();
    const lines = text.split(/\r?\n/);
    const events: AuthEvent[] = [];
    let csvHeader: string[] | undefined;

    for (const line of lines) {
      if (!line.trim()) continue;
      if (csvHeader === undefined && isCsvHeader(line)) {
        csvHeader = line.split(',').map((s) => s.trim());
        continue;
      }
      const event = parseLine(line, csvHeader);
      if (event) events.push(event);
    }

    setLoadState('analyzing');
    // 让出一帧，让状态提示先渲染，再执行同步 CPU 密集分析。
    await new Promise((resolve) => setTimeout(resolve, 30));
    const result = analyzeEvents(events, { includeSessions: false });
    setReport(result);
    setLoadState('done');
  } catch (err) {
    setLoadState('error');
    setErrorMsg(err instanceof Error ? err.message : String(err));
  }
}

export function resetStore(): void {
  setReport(null);
  setLoadState('idle');
  setErrorMsg('');
  setSourceName('');
}
