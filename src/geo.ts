// 离线 GeoIP 模拟：真实场景会替换为 MaxMind GeoLite2 本地库查询。
// 这里用确定性的 IP 哈希映射到内置城市表，保证同一 IP 永远解析到同一位置。

export interface GeoInfo {
  city: string;
  country: string;
  lat: number;
  lon: number;
  internal: boolean;
}

interface City {
  city: string;
  country: string;
  lat: number;
  lon: number;
  weight: number; // 人口/流量权重，影响随机分布
}

export const CITIES: City[] = [
  { city: 'Beijing', country: 'CN', lat: 39.9042, lon: 116.4074, weight: 22 },
  { city: 'Shanghai', country: 'CN', lat: 31.2304, lon: 121.4737, weight: 20 },
  { city: 'Shenzhen', country: 'CN', lat: 22.5431, lon: 114.0579, weight: 14 },
  { city: 'Guangzhou', country: 'CN', lat: 23.1291, lon: 113.2644, weight: 12 },
  { city: 'Hangzhou', country: 'CN', lat: 30.2741, lon: 120.1551, weight: 10 },
  { city: 'Chengdu', country: 'CN', lat: 30.5728, lon: 104.0668, weight: 8 },
  { city: 'Hong Kong', country: 'HK', lat: 22.3193, lon: 114.1694, weight: 4 },
  { city: 'Tokyo', country: 'JP', lat: 35.6762, lon: 139.6503, weight: 3 },
  { city: 'Singapore', country: 'SG', lat: 1.3521, lon: 103.8198, weight: 3 },
  { city: 'Frankfurt', country: 'DE', lat: 50.1109, lon: 8.6821, weight: 1.5 },
  { city: 'Amsterdam', country: 'NL', lat: 52.3676, lon: 4.9041, weight: 1 },
  { city: 'San Jose', country: 'US', lat: 37.3382, lon: -121.8863, weight: 1.5 },
  { city: 'New York', country: 'US', lat: 40.7128, lon: -74.006, weight: 1 },
  { city: 'London', country: 'UK', lat: 51.5074, lon: -0.1278, weight: 1 },
  { city: 'Moscow', country: 'RU', lat: 55.7558, lon: 37.6173, weight: 0.5 },
  { city: 'Lagos', country: 'NG', lat: 6.5244, lon: 3.3792, weight: 0.3 },
];

const INTERNAL: GeoInfo = { city: 'Internal', country: 'LAN', lat: 0, lon: 0, internal: true };

function fnv1a(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

const TOTAL_WEIGHT = CITIES.reduce((a, c) => a + c.weight, 0);
const cache = new Map<string, GeoInfo>();

export function isPrivateIp(ip: string): boolean {
  return (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('169.254.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === '127.0.0.1'
  );
}

export function geoLookup(ip: string): GeoInfo {
  const hit = cache.get(ip);
  if (hit) return hit;
  let info: GeoInfo;
  if (isPrivateIp(ip)) {
    info = INTERNAL;
  } else {
    // 用哈希在城市表上按权重取点，确定性
    const r = (fnv1a(ip) % 10000) / 10000;
    let acc = 0;
    let c = CITIES[0];
    for (const city of CITIES) {
      acc += city.weight / TOTAL_WEIGHT;
      if (r <= acc) { c = city; break; }
    }
    // 同城内加微小抖动，模拟同城市不同接入点
    const j = ((fnv1a(ip + '#j') % 1000) / 1000 - 0.5) * 0.5;
    info = { city: c.city, country: c.country, lat: c.lat + j * 0.1, lon: c.lon + j * 0.1, internal: false };
  }
  cache.set(ip, info);
  return info;
}

/** Haversine 距离，单位 km */
export function distanceKm(a: GeoInfo, b: GeoInfo): number {
  const R = 6371;
  const dLat = ((b.lat - a.lat) * Math.PI) / 180;
  const dLon = ((b.lon - a.lon) * Math.PI) / 180;
  const s =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((a.lat * Math.PI) / 180) * Math.cos((b.lat * Math.PI) / 180) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(s));
}
