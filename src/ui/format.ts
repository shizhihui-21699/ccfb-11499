/** 时间戳与数字的展示格式化，纯函数，UI 各处复用。 */

export function fmtTime(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function fmtDateTime(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function fmtDuration(ms: number): string {
  const min = Math.round(ms / 60000);
  if (min < 60) return `${min} 分钟`;
  const h = Math.floor(min / 60);
  return `${h} 小时 ${min % 60} 分`;
}

export function fmtNum(n: number): string {
  return n.toLocaleString('zh-CN');
}

export function fmtPct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}
