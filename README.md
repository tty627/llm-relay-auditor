# Relay Model Auditor

批量比较同一个模型在参考 API 与多个中转站上的 One Token 行为指纹。

你提供：

- 一个参考 API 的 URL、API Key 和实际模型 ID；
- 1–20 个待测中转站的 URL、API Key 和可选模型别名。

系统会采集三轮参考指纹，再批量测试各中转站，最后输出网页结果、JSON 和 CSV。

> **重要限制：**结果表示“目标与这组三轮参考快照是否相似”，不能单独证明目标一定是官方模型，也不能据此直接判定供应商真假。当前所有报告固定为 `decisionEligible=false`、`operationalVerdict=unverifiable`。

## 快速启动

需要 Python 3.12+ 和 Node.js 22+：

```bash
git clone --recurse-submodules https://github.com/tty627/llm-relay-auditor.git
cd llm-relay-auditor

python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

(cd llm-fingerprint-detector && npm ci && npm run build)
uvicorn relay_auditor.main:app --reload
```

然后打开 <http://127.0.0.1:8000/>。

## 使用流程

### 1. 创建参考指纹

在页面的“建立三成员参考集”区域填写：

- **来源声明**：官方 API 或可信中转站。这只是你的来源说明，系统不会自动把中转站认定为官方真值。
- **协议**：`Anthropic Messages` 或 `OpenAI Chat`。
- **实际模型 ID**：上游 API 真正接受的模型名，例如 `claude-opus-5`。
- **Base URL**：例如 `https://api.example.com/v1`。
- **API Key**：只在当前任务运行期间保存在服务内存。

点击“采集三轮参考指纹”。系统依次采集 3 个独立成员：

```text
每轮：40 cells × 30 samples = 1,200 个逻辑请求
三轮：3 × 1,200 = 3,600 个逻辑请求
```

只有三轮都完整、协议和采样 manifest 一致、证据哈希有效时，这个 ReferenceSet 才能用于批量比较。

### 2. 导入待测中转站

参考集完成后，在“批量目标站”区域粘贴 TSV。每行一个中转站：

```text
站点名称<TAB>Base URL<TAB>API Key<TAB>可选模型别名
```

例如：

```text
Relay A	https://a.example.com/v1	sk-your-key-a	claude-opus-5
Relay B	https://b.example.com/v1	sk-your-key-b	opus-5-alias
```

最多 20 行。没有填写模型别名时，使用页面上的全局默认模型 ID。

### 3. 开始批量测试

默认调度参数：

- 最多同时测试 4 个站；
- 每站最多 3 个并发请求；
- 全局最多 12 个并发请求；
- 同一个 origin 同时只运行一个站点任务。

每个站先做严格 preflight。鉴权失败不重试；429、部分 5xx、超时和网络错误最多重试两次，并遵守有上限的 `Retry-After`。

页面刷新不会停止任务。服务进程重启后，由于内存中的 Key 已消失，未完成任务会标记为 `interrupted`，不会自动重新发送请求。

### 4. 下载结果

完成后可下载：

- `report.json`：规范结果和证据哈希的完整来源；
- `report.csv`：由验证过的 JSON 派生，每个中转站一行，适合筛选和汇总。

## 怎么看结果

先看质量，再看相对距离。主要状态如下：

| 状态 | 含义 |
| --- | --- |
| `exploratory_reference_like` | 目标与三轮参考的区间都落在参考内部波动范围内 |
| `exploratory_reference_deviation` | 目标与三轮参考的区间都明显超出参考内部波动范围 |
| `inconclusive` | 区间重叠，当前样本不能明确区分 |
| `insufficient_quality` | 至少一个 cell 的有效样本少于 24/30 |
| `unsupported_protocol` | 请求格式、响应结构或协议不兼容 |
| `request_failed` | 鉴权、网络或上游错误导致任务无法完成 |

报告还会显示：

- 与三个参考成员分别计算的 JSD、median、MAD 和 bootstrap 95% 区间；
- 40-cell coverage、split-half、有效/无效/错误样本数；
- directness、上游返回的模型名、延迟 p50/p95 和重试次数。

JSD 是分布距离，不是“模型为真的概率”。数值越小只表示与当前参考快照更接近。

## 请求量

One Token 指要求模型回答一个短词或数字，不是把 `max_tokens` 设置为 1。系统使用 `max_tokens=16`，避免多语言 tokenizer 把一个短答案切成多个 token。

基础请求量：

```text
总请求 = 参考 3,600 + 中转站数量 × 1,200
```

示例：

- 1 个中转站：4,800 个基础请求；
- 5 个中转站：9,600 个基础请求；
- 20 个中转站：27,600 个基础请求。

每站还有最多 240 次额外重试的硬预算。首次真实运行建议先测试 1 个站，确认模型 ID、协议、限流和费用后再扩展。

## 协议要求

参考与目标必须使用相同协议、transport profile、battery hash 和采样数，不能跨协议强行比较。

- `openai-chat-onetoken-v1`：`POST /v1/chat/completions`。
- `anthropic-messages-opus5-onetoken-v1`：`POST /v1/messages`。

采样请求体固定，不会静默切换参数、改用另一种协议或增加长输出 fallback。Anthropic 的 thinking/tool/XML 内容不会混入答案分布。

## API Key 安全

- 服务默认只应绑定 `127.0.0.1`；不要直接部署到公网。
- 页面提交成功后立即清空明文 Key 和 TSV 输入。
- Key 不写入 URL、命令行参数、SQLite、浏览器持久存储、日志、证据或报告。
- 上游重定向会被拒绝，避免 Key 被转发到其他主机。
- 公网模式下拒绝 HTTP、userinfo、query/fragment、私网、loopback、link-local、云 metadata 和 DNS rebinding。
- 如果上游回显凭据，任务会立即停止并删除受污染的临时证据。

服务端环境变量凭据、Docker Compose、旧版工作台和发布验收流程见[高级运维与开发者说明](./docs/advanced-operations.md)。

## 开发验证

```bash
pytest
ruff check .
(cd llm-fingerprint-detector && npm test)
node --test tests/web_status.test.js tests/web_profiles.test.js
```

内置 Mock 可验证采集、比较、暂停、恢复、报告和安全降级链路，但 Mock 通过不代表真实模型识别准确率或供应商质量。

## 进一步阅读

- [高级运维、Docker、旧版兼容与发布验收](./docs/advanced-operations.md)
- [One Token 方法审计与改造状态](./docs/one-token-method-status.md)
- [真实中转端测试与自动化边界](./docs/relay-live-test-findings-2026-08-21.md)
- [中转站模型验真与质量防注水方案](./中转站模型验真与质量防注水方案.md)
