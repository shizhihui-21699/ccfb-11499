#!/usr/bin/env tsx
// 用法: npx tsx src/evaluate.ts <incidents.json> <groundtruth.json>
// 评估口径：
//   - 告警是否 TP：与任意标注攻击（不限类型）实体(账号或IP)重叠且时间重叠 → 一次攻击触发多类告警不算误报
//   - 分类型召回：该类型攻击被同类型告警覆盖的比例
//   - 误报率 = 未匹配任何攻击的告警 / 全部告警
import { readFileSync } from 'node:fs';
import type { Alert, AlertType, AnalysisOutput } from './types.js';

interface AttackLabel {
  id: string;
  type: AlertType;
  start: number;
  end: number;
  users: string[];
  ips: string[];
  note?: string;
}

const [outPath, gtPath] = process.argv.slice(2);
if (!outPath || !gtPath) {
  console.error('usage: tsx src/evaluate.ts <incidents.json> <groundtruth.json>');
  process.exit(1);
}
const output = JSON.parse(readFileSync(outPath, 'utf8')) as AnalysisOutput;
const gt = JSON.parse(readFileSync(gtPath, 'utf8')) as { attacks: AttackLabel[] };

const TOLERANCE_MS = 30 * 60 * 1000;
const TYPES: AlertType[] = ['impossible_travel', 'password_spraying', 'brute_force', 'credential_stuffing'];
const alerts: Alert[] = output.incidents.flatMap((inc) => inc.alerts);

function overlaps(a: { start: number; end: number }, b: { start: number; end: number }) {
  return a.start <= b.end + TOLERANCE_MS && a.end >= b.start - TOLERANCE_MS;
}
function entityHit(a: Alert, atk: AttackLabel) {
  return a.users.some((u) => atk.users.includes(u)) || a.ips.some((ip) => atk.ips.includes(ip));
}
const matchesAny = (a: Alert) => gt.attacks.find((atk) => overlaps(a, atk) && entityHit(a, atk));
const matchesSame = (a: Alert, type: AlertType) =>
  gt.attacks.find((atk) => atk.type === type && overlaps(a, atk) && entityHit(a, atk));

// 告警级：TP/FP
let tp = 0;
const fpAlerts: Alert[] = [];
for (const a of alerts) {
  if (matchesAny(a)) tp++;
  else fpAlerts.push(a);
}
const precision = alerts.length ? tp / alerts.length : 1;
const fpr = alerts.length ? fpAlerts.length / alerts.length : 0;

// 攻击级：分类型召回 + 总体检出
console.log('\n攻击类型               攻击数  同类型检出  任意告警检出  召回率(同类型)');
let totalAttacks = 0;
let totalDetected = 0;
for (const type of TYPES) {
  const attacks = gt.attacks.filter((a) => a.type === type);
  const sameType = attacks.filter((atk) =>
    alerts.some((a) => a.type === type && overlaps(a, atk) && entityHit(a, atk)),
  ).length;
  const anyType = attacks.filter((atk) => alerts.some((a) => overlaps(a, atk) && entityHit(a, atk))).length;
  totalAttacks += attacks.length;
  totalDetected += anyType;
  console.log(
    `${type.padEnd(22)} ${String(attacks.length).padStart(4)} ${String(sameType).padStart(9)} ${String(anyType).padStart(11)}   ${((sameType / (attacks.length || 1)) * 100).toFixed(1)}%`,
  );
}

console.log(`\n告警总数: ${alerts.length}  TP: ${tp}  FP: ${fpAlerts.length}`);
console.log(`精确率: ${(precision * 100).toFixed(1)}%`);
console.log(`误报率: ${(fpr * 100).toFixed(1)}%（每天误报告警 ${fpAlerts.length} 条）`);
console.log(`攻击检出率(任意类型告警): ${totalDetected}/${totalAttacks} = ${((totalDetected / totalAttacks) * 100).toFixed(1)}%`);

const missed = gt.attacks.filter((atk) => !alerts.some((a) => overlaps(a, atk) && entityHit(a, atk)));
if (missed.length) {
  console.log('\n漏报攻击:');
  for (const m of missed) console.log(`  ${m.id} ${m.type} ${m.note ?? ''}`);
}
if (fpAlerts.length) {
  console.log('\n误报告警（前10）:');
  for (const a of fpAlerts.slice(0, 10)) console.log(`  ${a.id} ${a.type} ${a.summary}`);
}
