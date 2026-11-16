# 登录异常检测分析器（VPN/SSO）

TypeScript 分析核心 + SolidJS 可视化界面。面向日均百万级 VPN/SSO 登录日志，检测四类账号攻击并关联成安全事件。

## 快速开始

```bash
npm install
npm run generate          # 生成带标注数据集 data/logs.jsonl + data/groundtruth.json（默认 10 万事件）
npm run analyze           # 分析日志 → public/incidents.json
npm run evaluate          # 对比标注，输出精确率/召回率/误报率
npm run dev               # 打开 SolidJS 界面 http://localhost:5173
```

生成百万级数据集：`npm run generate -- --events 1000000 --out data-1m`（分析耗时约 2.5 秒）。

## 管线

```
logs.jsonl → parser → sessionize(30min 不活动切分) → 4 个检测器 → mergeAlerts → correlate(并查集) → incidents.json
```

- `src/geo.ts` — 离线 GeoIP 模拟：IP 哈希确定性映射到内置城市表（真实环境替换为 MaxMind GeoLite2 本地库，接口不变），Haversine 算距
- `src/detectors.ts` — 四类检测器，阈值集中在 `THRESHOLDS`
- `src/correlate.ts` — 告警按共享账号/IP + 2 小时时间邻近合并为事件
- `src/generate.ts` — 数据集生成器：正常流量（工作时间分布、手抖打错密码、公司 NAT 出口、正常出差）+ 26 个注入攻击 + 标注
- `src/evaluate.ts` — 评估：告警与任意类型攻击实体+时间重叠即 TP（一次攻击触发多类告警不算误报）

## 检测阈值（经验初值，可用标注数据回调）

| 检测 | 窗口 | 阈值 |
|---|---|---|
| 不可能旅行 | 相邻两次成功登录 | 等效速度 > 800 km/h 且距离 > 300 km |
| 口令喷洒 | 单 IP 滑动 1h | ≥15 个账号、≥30 次尝试、单账号 ≤3 次、失败率 ≥70% |
| 分布式暴破 | 单账号滑动 1h | ≥20 次失败且来自 ≥5 个 IP |
| 撞库 | 同账号同 IP 10min / 账号 1h / IP 1h | ①≥8 次失败后 30min 内成功 ②成功前 1h ≥10 次失败来自 ≥3 个 IP ③IP 对 ≥5 账号失败且失败率 ≥30% 后出现的成功 |

## 当前指标（10 万事件、26 个注入攻击）

- 攻击检出率 26/26 = 100%（分类型召回均 100%）
- 精确率 100%，误报率 0%（0 条误报告警/天）
- 673 条告警关联为 26 个事件（SOC 实际处置单元）

## 界面

左侧事件列表（按评分排序，严重度色条），右侧事件详情：涉及账号/IP、SVG 告警时间线（按类型着色）、告警明细表。支持按类型/严重度过滤。
