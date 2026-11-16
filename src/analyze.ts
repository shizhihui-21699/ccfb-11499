#!/usr/bin/env tsx
// 用法: npx tsx src/analyze.ts <logs.jsonl> [--out public/incidents.json]
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { correlate } from './correlate.js';
import { runAllDetectors } from './detectors.js';
import { loadEvents } from './parser.js';
import { sessionize } from './sessionize.js';
import type { AlertType, AnalysisOutput } from './types.js';

const args = process.argv.slice(2);
const logPath = args[0];
if (!logPath) {
  console.error('usage: tsx src/analyze.ts <logs.jsonl> [--out incidents.json]');
  process.exit(1);
}
const outIdx = args.indexOf('--out');
const outPath = outIdx >= 0 ? args[outIdx + 1] : 'public/incidents.json';

const t0 = Date.now();
const events = await loadEvents(logPath);
const { sessions, byUser } = sessionize(events);
const alerts = runAllDetectors(events, byUser);
const incidents = correlate(alerts);

const byType = Object.fromEntries(
  (['impossible_travel', 'password_spraying', 'brute_force', 'credential_stuffing'] as AlertType[]).map((t) => [
    t,
    alerts.filter((a) => a.type === t).length,
  ]),
) as Record<AlertType, number>;

const output: AnalysisOutput = {
  generatedAt: Date.now(),
  stats: {
    events: events.length,
    users: byUser.size,
    ips: new Set(events.map((e) => e.ip)).size,
    sessions: sessions.length,
    alerts: alerts.length,
    incidents: incidents.length,
    byType,
  },
  incidents,
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(output));
console.log(
  `events=${events.length} users=${output.stats.users} sessions=${sessions.length} ` +
    `alerts=${alerts.length} incidents=${incidents.length} (${Date.now() - t0}ms)`,
);
console.log('byType:', byType);
console.log(`written: ${outPath}`);
