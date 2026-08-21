# Relay Model Auditor

面向大模型中转站、聚合网关和 API 采购团队的黑盒模型验真 MVP。当前 v0.2 实现：

> 当前验证状态：仓库已保存 2026-08-20 的 OpenTech 中转端指纹快照，但它们来自中转服务，不是官方模型端点的真值；项目尚未完成官方端对照，也没有可用于当前采样协议的 `validated` threshold policy。因此，PR0 的 One Token 安全门会把当前结果的 operational verdict 统一收敛为 `unverifiable`（不可验证）。原始 JSD 和旧版 verdict 仍会保留，但只用于诊断、漂移观察和候选探索，不能作为模型身份结论。Mock 输出也只用于工程验收，不代表模型识别准确率、真实阈值或供应商质量结论。

- OpenAI Chat Completions 兼容端点烟测。
- 原始证据 JSON、SHA-256 和 SQLite/PostgreSQL 审计记录。
- 集成基于 [One Token Is Enough](https://arxiv.org/abs/2607.10252) 思路的开源行为指纹检测器，并在服务边界增加 fail-closed 的 operational decision gate。
- 内置 `reference-model` / `substitute-model` Mock，可在没有 API Key 时跑完整闭环。
- 六类 Tokenizer 斜率采集、`R²`、重复计数稳定性和参考对比。
- 端点与 14 天有效期基线登记。
- `mixed-10` / `mixed-20` / `mixed-50` 概率性混合路由 Mock。
- 本地 Web 控制台：保存参考模型指纹库，自动发现端点模型，并批量映射、对比多个中转站。
- FastAPI/OpenAPI 接口、Docker Compose 和 GitHub Actions。

完整设计见[《中转站模型验真与质量防注水方案》](./中转站模型验真与质量防注水方案.md)。

One Token 论文对照、legacy 偏差、V2 改造状态与上线门槛见
[《One Token 方法审计与改造状态》](./docs/one-token-method-status.md)。

2026-08-21 真实中转端测试观察、自动拉取阻塞点与后续修复边界见
[《真实中转端测试与自动化边界》](./docs/relay-live-test-findings-2026-08-21.md)。

## 本地启动

```bash
git submodule update --init --recursive

python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

cd llm-fingerprint-detector
npm ci
npm run build
cd ..

uvicorn relay_auditor.main:app --reload
```

访问：

- Web 控制台：<http://127.0.0.1:8000/>
- 健康检查：<http://127.0.0.1:8000/health>
- OpenAPI：<http://127.0.0.1:8000/docs>
- Mock 模型：<http://127.0.0.1:8000/mock/v1/models>

## Web 控制台

控制台当前只运行 One Token 行为指纹：

1. 填写可信参考端的 Base URL 和 Key，通过 `GET /models` 读取模型列表；也可以手动添加模型 ID。
2. 勾选一个或多个参考模型并采集指纹。参考端名称、URL、模型 ID、指纹元数据、证据路径和 SHA-256 会保存到本地 SQLite；Key 不保存。
3. 添加一个或多个待测中转站并读取它们的全部模型，为每个待测模型选择一个已保存的参考指纹。模型 ID 相同时会自动建议映射，也允许人工选择不同 ID 的参考模型。
4. 选择快速、标准或严格采样规格，为每条映射设置高、普通或低优先级，再批量对比所有启用的映射。运行期间可把排队项提升为下一项，也可取消单个模型或整个批次；已经完成的结果不会随取消操作删除。
5. 每次参考采集和待测验证都会写入独立 JSON 证据与 SQLite 审计记录，页面可以下载原始证据；旧记录不会因参考指纹更新而删除。
6. 页面会在开始前显示采样耗时区间，运行时显示已用时间与预计剩余时间；完成首个模型后会按本机实际速度动态修正。
7. 已保存参考模型可通过“删除 → 确认删除”两步移出参考库。删除只修改基线状态，历史 JSON、Audit Run 与 SHA-256 证据继续保留。
8. 页面会把名称、URL、模型映射和采样规格自动保存到浏览器工作区；刷新后自动恢复，但 API Key 始终排除在浏览器持久存储之外。
9. `/history` 对比记录页按批次展示等待、执行、暂停、取消、完成、失败和服务重启中断的模型验证，支持按中转站、模型、结论筛选、下载证据，以及把一条历史记录重新载入工作台。
10. 对比并发可选固定模式或自动模式。自动模式按规范化的中转站 URL 与目标模型读取本机历史，首次从保守并发开始，积累稳定样本后逐档试探，并在结果与历史中保存实际采用的并发及选择原因。
11. 当旧版原始 verdict 为 `uncertain` 或 `mismatch` 时，页面会把已经采集的目标指纹与本机其他有效参考指纹离线比较，按模型聚合并列出最相似候选。该步骤不会再次请求中转站，也不会把 operational verdict 从 `unverifiable` 提升为身份结论；候选距离只供探索。

默认表单已填入本地 Mock，可在不使用真实 Key 的情况下验证完整交互。模型发现要求端点兼容 `GET /models`，采样要求兼容 `POST /chat/completions`；任一接口不兼容时仍可手动填写模型 ID。不同供应商的原生 Responses/Messages 协议尚未接入此页面。

浏览器输入的 Key 只发送给本机 `/api/v1/console/*` 接口，并通过该任务独立的子进程环境传给采样器；不会进入命令行参数、数据库、证据文件或浏览器持久存储。页面不要通过公网地址访问，服务应继续绑定 `127.0.0.1`。关闭页面前可以点击“清空全部 Key”。

刷新页面会保留工作区配置、完整批次队列、实时进度、优先顺序、已完成结果和历史记录；正在执行的批次由本机服务继续处理，刷新页面不会终止任务。任务支持暂停、继续、取消和排队项置顶；暂停当前模型时会安全停止采样，继续后从该模型重新采集。为了坚持 Key 不落盘，只有本机服务进程重启才会清除运行中批次的临时 Key，并把未完成条目标记为“已中断”，此时需要重新提交这些模型。

## 跑本地验真闭环

保持服务运行，在另一个终端执行：

```bash
source .venv/bin/activate
python scripts/demo_local.py
```

演示依次执行：

1. 健康检查和烟测。
2. 采集 `reference-model` 的 4×15 One Token 参考指纹。
3. 验证同一个模型，旧版原始 verdict 预期为 `match`。
4. 验证 `substitute-model`，旧版原始 verdict 预期为 `mismatch`。

以上 One Token 演示在没有 `validated` threshold policy 和合格参考真值时，operational verdict 都应为 `unverifiable`。演示的作用是验证采集、比较、证据保存和安全降级链路，不是证明旧版阈值有效。

继续运行 Tokenizer 与混合路由演示：

```bash
python scripts/demo_tokenizer.py
```

预期结果：Mock 中同 Tokenizer 为 `match`，替换模型为 `mismatch`，`mixed-20` 因重复计数变化或斜率偏移被识别为 `unstable/mismatch`。这些确定性场景只验证检测链路是否按设计工作，不构成真实模型准确率或阈值的测量。

按实施计划运行 10 组同模型和 5 组已知替换校准：

```bash
python scripts/calibrate_mock.py
```

实验结果写入被 Git 忽略的 `reports/mock_one_token_calibration.json`，同时报告 `median + 3×MAD` 的 robust 候选值、覆盖观测尾部的小样本候选值，以及 Mock 内的误报数和已知替换检出数。该脚本不会生成或启用生产可用的 `validated` threshold policy；真实上线前仍需在协议一致的官方真值数据上校准，并用独立留出集验证。

证据默认写入 `data/evidence/`，数据库默认位于 `data/relay_auditor.db`；两者均被 Git 忽略。它们是本机审计材料，不会因页面刷新消失，但仍应定期做只读备份并妥善保护测试机。

## Docker Compose

```bash
git submodule update --init --recursive
docker compose up --build
```

Compose 使用 PostgreSQL 保存审计记录；这组凭据只供本地开发，生产部署必须替换并通过密钥管理系统注入。

## 接入真实端点

用于脚本和自动化的常规 API 不接受请求体中的明文 Key，只接收环境变量名。例如先在服务进程中配置：

```bash
export AUDITOR_ALLOWED_API_KEY_ENVS='RELAY_AUDIT_KEY'
export AUDITOR_API_KEY_BASE_URL_BINDINGS='{"RELAY_AUDIT_KEY":["https://relay.example.com/v1"]}'
export AUDITOR_MANAGEMENT_TOKEN="$(openssl rand -hex 32)"
export RELAY_AUDIT_KEY='...'

admin_curl() {
  printf 'header = "X-Relay-Auditor-Token: %s"\n' "$AUDITOR_MANAGEMENT_TOKEN" \
    | curl --config - "$@"
}
```

`AUDITOR_ALLOWED_API_KEY_ENVS` 是逗号分隔的显式白名单。服务只会解析白名单中的
变量；`AUDITOR_API_KEY_BASE_URL_BINDINGS` 还必须把每个变量绑定到允许接收该 Key 的
Base URL。创建登记和实际执行都会检查这个运维侧映射，API 调用方不能靠自行登记其他
地址绕过。所有使用托管 Key 的登记、发现和审计还必须提供至少 24 字符的本地管理令牌；
示例函数通过标准输入把令牌交给 curl，避免把令牌展开到进程参数。采样子进程只获得
当前任务对应的随机临时变量，不继承服务进程里的其他供应商 Key。
托管 Key 只允许发送到 HTTPS Base URL；只有显式的 `localhost`、`127.0.0.1` 或 `::1`
回环地址可使用 HTTP。

首次使用时，先把环境变量名与固定的 Base URL、模型登记绑定：

```bash
endpoint_id="$(admin_curl -sS http://127.0.0.1:8000/api/v1/endpoints \
    -H 'content-type: application/json' \
    -d '{
      "name": "approved-relay-model",
      "provider": "relay",
      "base_url": "https://relay.example.com/v1",
      "model": "claimed-model",
      "api_key_env": "RELAY_AUDIT_KEY"
    }' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
```

之后可以在不传明文 Key 的情况下拉取该端点模型列表；裸域地址会与采样路径一样规范化
到 `/v1`，429/502/503/504 会进行有界重试：

```bash
admin_curl -sS -X POST \
  "http://127.0.0.1:8000/api/v1/endpoints/${endpoint_id}/models"
```

再提交：

```bash
admin_curl -sS http://127.0.0.1:8000/api/v1/audits/smoke \
  -H 'content-type: application/json' \
  -d '{
    "target": {
      "base_url": "https://relay.example.com/v1",
      "model": "claimed-model",
      "api_key_env": "RELAY_AUDIT_KEY"
    }
  }'
```

携带 `api_key_env` 的常规审计请求必须通过管理令牌认证，并与一条已启用登记记录的
`base_url + model + api_key_env` 一致；其中运维配置的 Base URL 绑定是防止 Key 外送的
安全边界，登记的模型字段用于一致性检查，并不替代请求预算或模型 allowlist。
服务环境中的 Key 可供脚本在服务重启后重新发起任务，但现有浏览器临时 Key 批次仍不会
跨服务重启自动续跑。

Compose 示例只显式转发 `RELAY_AUDIT_KEY`；若批准更多 Key 名称，必须在自己的 Compose
覆盖文件或 Secret 管理器中逐项注入，不能只改 allowlist。默认端口仅绑定
`127.0.0.1`，远程或多用户部署仍需外层身份认证、预算控制和 KMS/Vault。

`.env`、`.env.local`、证据和数据库都不会进入 Git。不要把真实密钥写入命令行参数、请求体或报告。

本地 Web 控制台是唯一例外：专用 `/api/v1/console/*` 接口会临时接收页面中的 Key；批次运行或暂停期间只保存在本机服务内存，采样时再通过子进程环境传入，批次结束或服务重启即清除。若需要部署给多人使用，应先替换为 KMS/Vault 与登录鉴权，不能直接沿用本地临时 Key 模式。

## 当前边界

这是方案 v1.1 的第 1～2 周 MVP。PR0 明确区分两层结果：

- `legacyVerdict` 与 `rawMeanJsd` 是开源检测器的原始输出，只能用于诊断、漂移观察、候选探索和后续校准数据分析。
- `operationalVerdict` 是系统可以对外消费的安全结论。只有参考真值合格、基线有效、协议与推理通道兼容，并且同一方法与采样条件下的 threshold policy 已经独立验证为 `validated` 时，才允许输出 `match`、`uncertain` 或 `mismatch`；否则 fail closed 为 `unverifiable`。

当前 OpenTech 快照的参考元数据标记为 `relay_snapshot_not_official` 且 `decision_eligible=false`。它们可以用于同一中转服务的复测、两组权限行为对照和漂移检测，但不能证明中转模型等同于官方模型。项目当前也没有已经启用的 `validated` One Token threshold policy，所以现阶段所有 One Token operational verdict 都应为 `unverifiable`。

旧版检测器中的固定 `0.25/0.35` 分界不再作为本项目的 operational threshold。论文报告的 EER 或任何论文实验阈值也不能直接迁移到本项目：模型集合、供应商实现、请求协议、推理通道、采样规格和数据划分均需匹配，并且必须在独立留出数据上重新验证。项目不宣称已经复现论文 EER，也不以 Mock 或 OpenTech 快照推导真实世界准确率。

当前 Tokenizer 阈值仍标记为 `engineering_default_pending_official_calibration`。KBF、上下文二分、私有质量集、调度告警和供应商工单仍在后续迭代范围内。即使未来通过校准门槛，单次 `mismatch` 也只是统计证据，不是对供应商欺诈的直接证明。
