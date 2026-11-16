/**
 * 轻量单元测试：不依赖测试框架，node --import tsx 直接运行。
 * 覆盖关键纯函数的确定性契约，任何断言失败进程以非零码退出。
 */
import assert from 'node:assert/strict';
import { haversineKm, isPrivateIp, lookupIp } from '../src/lib/geo.js';
import { normalizeRecord, parseTimestamp, splitCsv } from '../src/lib/normalize.js';
import { correlateAlerts } from '../src/lib/correlate.js';
import { Rng } from '../src/lib/rng.js';
import type { Alert } from '../src/lib/types.js';

let passed = 0;
function test(name: string, fn: () => void): void {
  fn();
  passed++;
  console.log(`  ✓ ${name}`);
}

console.log('geo:');
test('私网地址识别', () => {
  assert.equal(isPrivateIp('10.0.0.1'), true);
  assert.equal(isPrivateIp('192.168.1.1'), true);
  assert.equal(isPrivateIp('172.16.5.5'), true);
  assert.equal(isPrivateIp('127.0.0.1'), true);
  assert.equal(isPrivateIp('8.8.8.8'), false);
  assert.equal(lookupIp('10.0.0.1').private, true);
});

test('同一 IP 地理查询确定性', () => {
  const a = lookupIp('8.8.8.8');
  const b = lookupIp('8.8.8.8');
  assert.deepEqual(a, b);
  assert.equal(a.private, false);
});

test('同城距离为 0，跨城距离为正', () => {
  const g = lookupIp('8.8.8.8');
  assert.equal(haversineKm(g, g), 0);
  const other = lookupIp('1.1.1.1');
  if (other.city !== g.city) assert.ok(haversineKm(g, other) > 100);
});

console.log('normalize:');
test('时间戳秒/毫秒/ISO 三种格式', () => {
  assert.equal(parseTimestamp(1_700_000_000), 1_700_000_000_000);
  assert.equal(parseTimestamp(1_700_000_000_000), 1_700_000_000_000);
  assert.equal(parseTimestamp('2026-11-16T00:00:00Z'), Date.parse('2026-11-16T00:00:00Z'));
});

test('字段别名与用户名归一化', () => {
  const e = normalizeRecord({
    src_ip: '8.8.8.8',
    Username: 'DOMAIN\\Alice',
    result: 'Failed',
    time: '2026-11-16T00:00:00Z',
  });
  assert.equal(e.ip, '8.8.8.8');
  assert.equal(e.userId, 'alice');
  assert.equal(e.outcome, 'failure');
});

test('CSV 引号解析', () => {
  assert.deepEqual(splitCsv('a,"b,c",d'), ['a', 'b,c', 'd']);
  assert.deepEqual(splitCsv('"x""y",z'), ['x"y', 'z']);
});

console.log('rng:');
test('同种子序列可复现', () => {
  const a = new Rng(123);
  const b = new Rng(123);
  for (let i = 0; i < 100; i++) assert.equal(a.next(), b.next());
});

console.log('correlate:');
test('共享 IP 的两条告警合并为一个事件', () => {
  const base: Alert = {
    id: '',
    type: 'password_spray',
    severity: 'high',
    subject: '',
    startTs: 1_000,
    endTs: 2_000,
    eventSeqs: [1],
    users: [],
    ips: [],
    evidence: {},
  };
  const a: Alert = { ...base, id: 'a', ips: ['1.1.1.1'], users: ['u1'] };
  const b: Alert = {
    ...base,
    id: 'b',
    type: 'credential_stuffing',
    ips: ['1.1.1.1'],
    users: ['u2'],
    startTs: 1_500,
  };
  const c: Alert = { ...base, id: 'c', ips: ['9.9.9.9'], users: ['u9'], startTs: 5_000, endTs: 6_000 };
  const incidents = correlateAlerts([a, b, c]);
  // a,b 共享 IP 合并；c 独立。
  assert.equal(incidents.length, 2);
  const merged = incidents.find((i) => i.alertIds.length === 2);
  assert.ok(merged);
  assert.deepEqual(merged!.types.sort(), ['credential_stuffing', 'password_spray']);
});

test('时间相隔过远的告警不合并', () => {
  const base: Alert = {
    id: '',
    type: 'brute_force',
    severity: 'high',
    subject: '',
    startTs: 0,
    endTs: 0,
    eventSeqs: [],
    users: ['u1'],
    ips: [],
    evidence: {},
  };
  const a: Alert = { ...base, id: 'a', startTs: 0, endTs: 1_000 };
  const b: Alert = { ...base, id: 'b', startTs: 100_000_000, endTs: 100_001_000 };
  assert.equal(correlateAlerts([a, b]).length, 2);
});

console.log(`\n全部通过：${passed} 个测试`);
