# 认证日志安全分析器（VPN / SSO）

面向日百万级认证日志的撞库 / 口令喷洒 / 暴力破解 / 不可能旅行检测系统。
TypeScript 流式分析引擎 + 可复现的带标注数据集 + SolidJS 可视化界面。

## 快速开始

```bash
npm install

# 1. 生成带标注的合成数据集（small / medium / large，或自定义 JSON 参数）
npm run gen -- small data

# 2. 跑分析引擎，产出 report.json
npm run analyze -- data/auth-events.jsonl data/report.json

# 3. 对照 ground truth 算精确率/召回率/误报率
npm run evaluate -- data/report.json data/ground-truth.json data/evaluation.json

# 一键跑完三步
npm run all

# 单元测试
npm test

# 启动 SolidJS 界面（可上传日志或 report.json）
npm run dev
```

生产构建：`npm run build`，产物在 `dist/`。

## 架构

```
原始日志(JSONL/CSV)
   │  normalize.ts   字段别名归一化（VPN/SSO 两套命名）、时间戳/用户名/结果归一
   ▼
AuthEvent[]（排序、编号）
   ├── Sessionizer        30 分钟空闲超时的会话化
   ├── ImpossibleTravel   相邻成功登录的地理速度判定
   ├── PasswordSpray      1 IP × N 账号的低频滑动窗口
   ├── BruteForce         N IP × 1 账号的多来源失败
   └── CredentialStuffing 成功前大量失败 + 单 IP 横向枚举
   ▼
Alert[] ── correlate.ts（并查集：共享账号/IP + 时间邻近连边）──▶ SecurityIncident
   ▼
report.json ── SolidJS UI（KPI、事件卡片、时间线抽屉、证据明细）
```

### 关键模块

| 文件 | 职责 |
| --- | --- |
| `src/lib/geo.ts` | 离线 IP 地理库（确定性哈希映射，28 城市坐标 + Haversine 距离），可替换为 mmdb 实现 |
| `src/lib/normalize.ts` | 多厂商字段别名、JSONL/CSV、秒/毫秒/ISO 时间戳 |
| `src/lib/sessionize.ts` | 每用户 30 分钟空闲会话 |
| `src/lib/detectors/*.ts` | 四类检测器，各自维护滑动窗口，阈值集中在 `config.ts` |
| `src/lib/correlate.ts` | 并查集告警合并，关联成带时间线的安全事件 |
| `src/lib/evaluate.ts` | 两层匹配的评估（精确 TP / 关联 TP / 误报） |
| `src/generator/generate.ts` | 带标注数据生成器，含 4 类良性混淆场景 |

## 检测窗口与阈值（`src/lib/config.ts`）

| 检测器 | 窗口 | 主阈值 | 设定理由 |
| --- | --- | --- | --- |
| 不可能旅行 | 4 h | 速度 > 900 km/h，距离 > 100 km | 真实异常跳转多在 2h 内；窗口过长会把返程登录错配。只比较**时间相邻**的成功登录，避免 A→B→A 行程被非相邻配对误判 |
| 口令喷洒 | 1 h 滑动 | ≥15 个不同账号，每账号 ≤3 次，失败率 ≥80% | 时间窗而非计数窗，慢速铺开的低频喷洒一样累计；高账号面 + 低单账号次数与暴力破解区分 |
| 暴力破解 | 1 h 滑动 | ≥10 次失败，≥4 个不同公网 IP，攻击 IP 上无成功 | 主体是账号而非 IP，适配代理池；私网/NAT 地址不计入；仅当攻击 IP 自身出现成功才移交撞库检测器 |
| 撞库 | 6 h | 成功前 ≥8 次失败且 ≥3 个公网 IP；或单 IP ≥30 失败/≥10 账号 | 规则 A 抓“失败后得手”，规则 B 抓无成功的横向枚举；多公网 IP 条件排除本人记错密码 |

所有检测器对同一主体有 1 小时告警冷却，防止持续攻击刷屏，但不会因冷却吞掉后续独立攻击。

## 数据集与评估口径

生成器输出两部分：

- **良性背景流量**：通勤、VPN 办公、记错密码，外加 4 类刻意设计的混淆场景——
  合法出差往返、企业 NAT 私网出口、单账号同 IP 连续失败、同城移动网络漂移。
- **注入攻击**：四类各若干个带 ID 的场景，攻击事件带 `_scenario` 标注（引擎代码不读取该字段）。

评估采用两层匹配（时间窗交集 + 账号/IP 实体重叠）：

- **精确 TP**：告警类型与场景类型一致；
- **关联 TP**：告警命中了其他类型的攻击（如撞库得手同时触发不可能旅行）——属并查集的正确关联，不计误报；
- **FP**：未命中任何攻击场景，即真正的误报。

### 实测结果

| 数据集 | 事件量 | 场景召回 | 微平均 P/R/F1 | 误报（每万条良性） |
| --- | --- | --- | --- | --- |
| small（400 用户，种子 20261116） | 1.2 万 | 100% | 100% | 0 |
| medium（2000 用户） | 12 万 | 100% | 100% | 0 |
| large（1 万用户） | 80 万 | 100% | 100% | 0 |
| 异种子（种子 987654321） | 4 万 | 100% | 100% | 0 |

large 数据集分析耗时约 5.4 秒（Node 同步引擎，M 系列 Mac），报告 545 KB。

> 说明：合成数据集的零误报是在“良性行为符合生成器画像”的前提下成立。接入真实日志后，
> 应先用 `evaluate` 对人工标注时段回归，再按实际误报样本调 `config.ts` 阈值——
> 所有阈值集中在一处，改动不需要碰检测逻辑。

## 接入真实日志

引擎只依赖归一化后的 `AuthEvent`，接入新日志源只需在 `normalize.ts` 的 `FIELD_ALIASES`
补充字段别名。离线地理库可替换为 MaxMind/IPIP 的 mmdb 读取，保持 `lookupIp()` 签名即可。
UI 支持两种载入方式：直接上传原始日志在浏览器内分析，或上传 CLI 离线产出的 `report.json`。
