# OpenTech API 双 Key 模型指纹对比报告

- 测试日期：2026-08-20（Asia/Shanghai）
- Endpoint：`https://api.opentech.top/v1`
- 工具：`llm-fingerprint-detector` 0.1.0
- 采样档位：`quick`（每模型 4 个 cell × 15 样本）
- Key 标记：`key-a`、`key-b`（报告不保存密钥）
- 判定阈值：match ≤ 0.25；uncertain 0.25–0.35；mismatch > 0.35

## 同名模型跨 Key 比较

| 模型 | Mean JSD | 判定 | 备注 |
|---|---:|---|---|
| `gpt-5.5` | 0.175 | MATCH | 4/4 cells 可比较 |
| `gpt-5.4` | 0.167 | MATCH | 4/4 cells 可比较 |
| `gpt-5.4-mini` | 0.078 | MATCH | 本轮最接近 |
| `codex-auto-review` | 0.134 | MATCH | 4/4 cells 可比较 |
| `gpt-5.6-sol` | 0.173 | MATCH | key-a 自身 split-half JSD 0.278，稳定性告警 |
| `gpt-5.6-terra` | 0.089 | MATCH | key-a 有 2/60 请求失败 |
| `gpt-5.6-luna` | 0.195 | MATCH | key-b 有 1/60 请求失败；中文随机数 cell JSD 0.456 |

结论：7 个共有文本模型在两把 Key 之间全部匹配，没有发现按 Key 分配明显不同模型后端的证据。

## 权限与接口差异

- 两把 Key 共有：`gpt-5.5`、`gpt-5.4`、`gpt-5.4-mini`、`codex-auto-review`、`gpt-5.6-sol`、`gpt-5.6-terra`、`gpt-5.6-luna`、`gpt-image-2`。
- `key-b` 额外拥有：`gpt-5.3-codex-spark`。
- `gpt-image-2` 在两边均返回 HTTP 400：不支持 Chat Completions，因此不适用于本指纹检测器。
- `gpt-5.3-codex-spark` 仅能在 key-b 访问，无法跨 Key 比较；其自身 split-half JSD 为 0.276，有稳定性告警。

## 跨模型异常

- `codex-auto-review` 与 `gpt-5.6-luna` 在 key-a 内的 JSD 为 0.166，在 key-b 内为 0.142，均被 quick 阈值判为 MATCH。
- key-a 的 `gpt-5.6-luna` 与 key-b 的 `codex-auto-review` 距离为 0.099，比同名 `gpt-5.6-luna` 的跨 Key 距离 0.195 更近。
- 这可能表示两个模型名使用相同或非常接近的后端/系统包装，也可能是 quick 档样本较少造成的假阳性。需要 `standard` 或 `strict` 重测才能加强结论。

## 网关行为

最小的“只回复 OK”请求中：

- `gpt-5.5`、`gpt-5.4`、`gpt-5.4-mini` 和三个 `gpt-5.6-*` 路由均报告 4,391 个输入 token。
- `codex-auto-review` 报告 1,450 个输入 token。
- `gpt-5.3-codex-spark` 报告 1,605 个输入 token。

如此简单的用户请求出现大量输入 token，说明服务端很可能注入了较长的隐藏上下文或代理提示词。它不能单独证明模型替换，但意味着这些接口不是无附加上下文的原始 Chat Completions 路由。

## 结论边界

本次结果只能说明两把 Key 下的同名模型行为相符，不能证明这些名称对应官方 OpenAI 模型。项目没有这些模型的官方可信参考指纹；若要验证真实性，需要从可信官方端点采集同一模型、同一协议的参考指纹后再比较。
