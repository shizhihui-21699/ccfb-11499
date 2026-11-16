import type { GeoInfo } from './types.js';

/**
 * 离线 IP 地理库（模拟版）。
 * 真实部署可替换为 MaxMind/IPIP 的 mmdb 读取实现，只要保持 lookupIp() 签名不变。
 *
 * 设计要点：
 * - 内置一张全球城市坐标表，公网 IP 用确定性哈希映射到城市，
 *   同一 IP 在引擎与数据生成器中永远得到同一位置，结果可复现。
 * - 私网 / 保留地址标记 private=true，不可能旅行等地理检测直接跳过。
 * - 提供 ipForCity() 反查，供生成器构造“来自指定城市”的攻击流量。
 */

interface CityRecord {
  id: number;
  city: string;
  country: string;
  lat: number;
  lon: number;
}

const CITIES: CityRecord[] = [
  { id: 0, city: '北京', country: 'CN', lat: 39.9042, lon: 116.4074 },
  { id: 1, city: '上海', country: 'CN', lat: 31.2304, lon: 121.4737 },
  { id: 2, city: '深圳', country: 'CN', lat: 22.5431, lon: 114.0579 },
  { id: 3, city: '香港', country: 'HK', lat: 22.3193, lon: 114.1694 },
  { id: 4, city: '东京', country: 'JP', lat: 35.6762, lon: 139.6503 },
  { id: 5, city: '新加坡', country: 'SG', lat: 1.3521, lon: 103.8198 },
  { id: 6, city: '首尔', country: 'KR', lat: 37.5665, lon: 126.978 },
  { id: 7, city: '孟买', country: 'IN', lat: 19.076, lon: 72.8777 },
  { id: 8, city: '迪拜', country: 'AE', lat: 25.2048, lon: 55.2708 },
  { id: 9, city: '莫斯科', country: 'RU', lat: 55.7558, lon: 37.6173 },
  { id: 10, city: '伊斯坦布尔', country: 'TR', lat: 41.0082, lon: 28.9784 },
  { id: 11, city: '法兰克福', country: 'DE', lat: 50.1109, lon: 8.6821 },
  { id: 12, city: '伦敦', country: 'UK', lat: 51.5074, lon: -0.1278 },
  { id: 13, city: '巴黎', country: 'FR', lat: 48.8566, lon: 2.3522 },
  { id: 14, city: '阿姆斯特丹', country: 'NL', lat: 52.3676, lon: 4.9041 },
  { id: 15, city: '斯德哥尔摩', country: 'SE', lat: 59.3293, lon: 18.0686 },
  { id: 16, city: '开罗', country: 'EG', lat: 30.0444, lon: 31.2357 },
  { id: 17, city: '约翰内斯堡', country: 'ZA', lat: -26.2041, lon: 28.0473 },
  { id: 18, city: '拉各斯', country: 'NG', lat: 6.5244, lon: 3.3792 },
  { id: 19, city: '内罗毕', country: 'KE', lat: -1.2921, lon: 36.8219 },
  { id: 20, city: '圣保罗', country: 'BR', lat: -23.5505, lon: -46.6333 },
  { id: 21, city: '墨西哥城', country: 'MX', lat: 19.4326, lon: -99.1332 },
  { id: 22, city: '纽约', country: 'US', lat: 40.7128, lon: -74.006 },
  { id: 23, city: '多伦多', country: 'CA', lat: 43.6532, lon: -79.3832 },
  { id: 24, city: '旧金山', country: 'US', lat: 37.7749, lon: -122.4194 },
  { id: 25, city: '洛杉矶', country: 'US', lat: 34.0522, lon: -118.2437 },
  { id: 26, city: '悉尼', country: 'AU', lat: -33.8688, lon: 151.2093 },
  { id: 27, city: '奥克兰', country: 'NZ', lat: -36.8485, lon: 174.7633 },
];

/** FNV-1a 32 位哈希，确定性且无外部依赖。 */
function fnv1a(input: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    // 32 位 FNV prime，用 Math.imul 保持整数语义。
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function ipToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const p of parts) {
    const octet = Number(p);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    value = value * 256 + octet;
  }
  return value >>> 0;
}

/** RFC1918 + 环回 + 链路本地 + 保留段识别。 */
export function isPrivateIp(ip: string): boolean {
  const int = ipToInt(ip);
  if (int === null) return true;
  const a = (int >>> 24) & 0xff;
  const b = (int >>> 16) & 0xff;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

function cityForIp(ip: string): CityRecord {
  return CITIES[fnv1a(ip) % CITIES.length]!;
}

/** 查询 IP 地理信息；私网地址返回 private 标记且坐标为 0。 */
export function lookupIp(ip: string): GeoInfo {
  if (isPrivateIp(ip)) {
    return { ip, city: '内网', country: '-', lat: 0, lon: 0, private: true };
  }
  const c = cityForIp(ip);
  return { ip, city: c.city, country: c.country, lat: c.lat, lon: c.lon, private: false };
}

export function listCities(): readonly CityRecord[] {
  return CITIES;
}

/**
 * 反查：生成一个确定性公网 IP，使其哈希落在指定城市。
 * salt 区分同一城市的不同主机（例如攻击机池 / 良性住宅 IP 池）。
 */
export function ipForCity(cityIndex: number, salt: number): string {
  const target = ((cityIndex % CITIES.length) + CITIES.length) % CITIES.length;
  // 在 20.0.0.0 ~ 199.x 的公网外观空间里探测，跳过 10/127/172.16-31/192.168 段。
  let probe = (salt * 7919 + 17) % 500_000;
  for (let i = 0; i < 2_000_000; i++) {
    probe = (probe + 1) % 0xffffffff;
    const ip = intToIp(probe);
    if (isPrivateIp(ip)) continue;
    if (fnv1a(ip) % CITIES.length === target) return ip;
  }
  // 理论不可达：城市数远小于探测空间。
  throw new Error(`ipForCity: no IP found for city ${cityIndex}`);
}

function intToIp(int: number): string {
  return [
    (int >>> 24) & 0xff,
    (int >>> 16) & 0xff,
    (int >>> 8) & 0xff,
    int & 0xff,
  ].join('.');
}

/** Haversine 大圆距离，单位 km。 */
export function haversineKm(a: GeoInfo, b: GeoInfo): number {
  const R = 6371;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const lat1 = toRad(a.lat);
  const lat2 = toRad(b.lat);
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}

function toRad(deg: number): number {
  return (deg * Math.PI) / 180;
}
