import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { PRESETS, generateDataset, type GeneratorPreset } from '../generator/generate.js';

/**
 * 用法: tsx src/cli/generate.ts [preset] [输出目录]
 * preset: small(默认) | medium | large，或 JSON: '{"users":100,"benignEvents":5000,"attacksPerType":1,"seed":1}'
 */
const presetArg = process.argv[2] ?? 'small';
const outDir = resolve(process.argv[3] ?? 'data');

let preset: GeneratorPreset;
if (presetArg.startsWith('{')) {
  const overrides = JSON.parse(presetArg) as Partial<GeneratorPreset>;
  preset = { ...PRESETS.small, ...overrides } as GeneratorPreset;
} else {
  const found = PRESETS[presetArg];
  if (!found) throw new Error(`未知 preset: ${presetArg}，可选 ${Object.keys(PRESETS).join(' | ')}`);
  preset = found;
}

mkdirSync(outDir, { recursive: true });
console.time('generate');
const { events, groundTruth, benignConfusers } = generateDataset(preset);
console.timeEnd('generate');

// 日志写成 JSONL；_scenario 标注字段保留在日志里，引擎代码不读取它。
const logPath = `${outDir}/auth-events.jsonl`;
const lines = events.map((e) => JSON.stringify(e));
writeFileSync(logPath, lines.join('\n') + '\n');

writeFileSync(`${outDir}/ground-truth.json`, JSON.stringify({ preset, scenarios: groundTruth, benignConfusers }, null, 2));

const attackEvents = events.filter((e) => e._scenario !== undefined).length;
console.log(`用户数: ${preset.users}`);
console.log(`事件总数: ${events.length}（其中攻击事件 ${attackEvents}，良性 ${events.length - attackEvents}）`);
console.log(`攻击场景: ${groundTruth.length}，良性混淆: ${benignConfusers.length}`);
console.log(`输出: ${logPath}`);
console.log(`标注: ${dirname(logPath)}/ground-truth.json`);
