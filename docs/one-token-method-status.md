# One Token 方法审计与改造状态

更新日期：2026-08-21

## 结论

项目原有 `one-token/v1` 只实现了论文的数学骨架，不能称为严格复现。它与论文在提示词集合、语言、采样计划、推理模型排除、split-half 划分、阈值校准和证据留存上都有实质差异。

因此当前系统把结果拆成两层：

- 原始 JSD 和 legacy band 只用于探索、漂移观察与校准数据分析。
- operational verdict 只有在参考真值、协议、质量门和独立留出校准策略全部匹配时才允许输出；否则统一为 `unverifiable`。

仓库目前没有启用任何 `validated` threshold policy，所以所有 One Token operational verdict 都应保持 `unverifiable`。

## 论文、旧协议与新协议

| 项目 | 论文 Study A | legacy `one-token/v1` | Web 默认 V2 论文 profile |
|---|---|---|---|
| tasks × languages | 10 × 4 = 40 cells | 8 × 2 = 16 cells；业务默认只取前 4 个 | 精确 10 × 4 = 40 cells |
| 语言 | en / ru / zh / ar | en / zh | en / ru / zh / ar |
| user prompt | 每个 cell 固定一个作者 prompt | 每次从项目自定义 paraphrase 池随机取样 | 固定作者 prompt，禁止混入 paraphrase |
| system prompt | 每种语言一个固定作者 prompt | 项目自定义 prompt | 固定作者 prompt |
| T=1 样本 | 通常每 cell 30；昂贵模型 15 | 默认 25；本项目 quick 为 15 | 由 V2 collection plan 显式记录；论文基准计划为 30 |
| 请求体 | `temperature=1`、`max_tokens=16`、`reasoning.enabled=false`、`usage.include=true`；不发送 seed/top_p | 会尝试多种 reasoning adapter，并可回退到 1024 tokens | 请求体严格固定；无 1024 fallback，不发送 seed/top_p |
| 推理污染 | mandatory reasoning 模型排除；可见 reasoning trace 的响应排除 | post-reasoning 仍可进入比较；reasoning token 只统计 | trace 或正 reasoning token 都剔除并把 directness 标为 violated；缺失 reasoning usage 则标为 unknown，不能进入强判定 |
| 调度 | run-id seeded shuffle | `Math.random()` | clean-room 复现作者 string hash + Mulberry32 + Fisher-Yates |
| split-half | 每个 cell 按 repetition index 奇偶划分 | 按全局 arrival index 奇偶划分 | 每个 cell 按 repetition index 奇偶划分 |
| 比较 | 每侧每 cell 至少 10 个有效样本；逐 cell base-2 JSD 后等权平均 | 这部分数学实现基本一致 | 保留同一数学定义，并增加 V2 manifest/plan/quality 校验 |
| 阈值 | 在论文数据上扫描阈值绘制 ROC/EER；没有发布可迁移的生产阈值 | 固定 0.25/0.35 | 不内置生产阈值；只能由精确 scope 的 validated policy 提供 |
| 原始证据 | 作者软件保存逐响应元数据 | 默认只保存聚合分布 | canonical JSONL sidecar + SHA-256，记录 rep、时间、provider、reported model、finish reason、usage 等 |

## 已完成的安全改造

1. 父项目增加 fail-closed decision gate。CLI 原始 verdict 保存在 `legacyVerdict`，对外结论保存在 `decision.operationalVerdict`。
2. 旧版固定 0.25/0.35 被明确标为 `legacy-exploratory`，`decisionEligible=false`；旧 CLI 字段和退出码仅为兼容保留。
3. 协议不一致、post-reasoning、正 reasoning token、不合格参考来源、无策略或策略 scope 不匹配都会得到 `unverifiable`。
4. V2 artifact 携带严格 manifest、collection plan、quality 和 raw evidence hash；V1 永远不能静默升级为 V2。
5. 新增作者 40-cell 固定 prompt profile、作者兼容 normalizer、deterministic scheduler、repetition-parity split 和推理污染筛查。
6. 新增严格 `ThresholdPolicy` 格式、canonical hash、训练/holdout 不重用校验及 inert calibration evidence 存储。策略不会被路由自动发现或启用。
7. 历史 V1/OpenTech 快照保持只读；它们被标记为非官方 relay snapshot、不可用于 operational identity decision。
8. Web 参考采集与待测批次已接入同一 V2 profile：参考端固定采集 40×30、保存 canonical JSONL，待测端按参考证据自动选择协议；V1/V2 混合批次会被拒绝。长任务在本机后台执行，支持刷新恢复、暂停、取消和 partial 证据。

## 仍未完成，不能对外宣称的事项

- Web 默认的 V2 collector 复现的是论文的 T=1 Study-A 指纹采集通道，不等于复现论文的整套实验。T=0 determinism、165 模型主实验、ROC/EER 和全部消融尚未在本仓库重跑。
- 尚未采集同协议的官方第一方 enrollment reference。
- 尚未完成“官方自对照、已知替换、独立留出”的真实校准，也没有真实 FAR/FRR 及置信区间。
- 尚未把任何校准策略接入生产路由；这是有意的安全默认，而不是遗漏一个阈值常量。
- 论文的 7.3% / 10.6% EER 不能外推到当前项目、任意 relay 或 quick 4×15 采样。

## 启用 operational decision 的最小条件

1. 用户明确授权后，使用同一个 V2 profile 分别采集官方 reference、官方独立复测和已知替换控制；API key 不落盘。
2. 每份 artifact 通过 manifest、40-cell coverage、directness、reasoning、有效样本和 raw sidecar hash 质量门。
3. calibration training 与 holdout artifact 完全分离，生成包含 FAR、FRR、置信区间和证据 ID 的策略。
4. 策略必须精确匹配 profile hash、provider scope、model、protocol、cell selection、reference/audit k/n 和质量门。
5. 经过代码审查后再把该策略 ID/hash 显式绑定到 baseline；不存在“自动取最近策略”或全局通用阈值。
6. 策略 retired 后，无需回滚代码即可停止强判定。

## 第一方来源与固定摘要

- 论文：[arXiv:2607.10252v1](https://arxiv.org/html/2607.10252v1)
- 作者软件：[Zenodo 10.5281/zenodo.21278793](https://zenodo.org/records/21278793)
- 作者数据：[Zenodo 10.5281/zenodo.21278557](https://zenodo.org/records/21278557)
- 软件归档 SHA-256：`8a9c8db47609fd0682a44398e55a4e0b322cf3ae479c3189f0874aae928044ef`
- 作者 `config/prompts.json` SHA-256：`32f4fc3ab5077438f362bb4d0c06d1ebbe2bb5d2e0809474045dcd60a6b592c1`
- Study-A canonical payload SHA-256：`9ef56c982a503b4dba94710b63866aaff47db1e37cc34538e225acb9f5fe1341`
- 作者 normalizer 源文件 SHA-256：`8f755ca604e4814126c253f44135199b1636ddfedcb070fa4ece3368fb858fa8`
- 作者 scheduler 源文件 SHA-256：`0ed556db47fa318416e777f63a80ea97b0397f7806488ca8d5db09121f972746`

精确 prompt 属于作者 MIT 软件归档；归属与许可证全文见子模块 `THIRD_PARTY_NOTICES.md`。
