# 高级运维与开发者说明

本文保存不适合放在首页 README 的运维、兼容和发布细节。第一次使用单模型批量审计器时，只需要阅读 [README](../README.md)。

## Docker Compose

```bash
git submodule update --init --recursive
export AUDITOR_GIT_SHA="$(git rev-parse --verify 'HEAD^{commit}')"
export AUDITOR_ACCESS_TOKEN="$(openssl rand -hex 32)"
export AUDITOR_MANAGEMENT_TOKEN="$AUDITOR_ACCESS_TOKEN"
docker compose up --build
```

Compose 使用 PostgreSQL，并只把端口发布到 `127.0.0.1`。浏览器通过 HTTP Basic 登录，用户名为 `auditor`，密码为 `AUDITOR_ACCESS_TOKEN`。

容器中没有 `.git`，所以必须显式注入 `AUDITOR_GIT_SHA`。无法得到合法 commit SHA 时，服务会 fail closed，避免报告记录虚假的构建来源。

## 服务端环境变量凭据

自动化调用不接受请求体中的明文 Key，只接受启动前批准的环境变量名。最小配置：

```bash
export AUDITOR_ALLOWED_API_KEY_ENVS='RELAY_AUDIT_KEY'
export AUDITOR_API_KEY_BASE_URL_BINDINGS='{"RELAY_AUDIT_KEY":["https://relay.example.com/v1"]}'
export AUDITOR_ACCESS_TOKEN="$(openssl rand -hex 32)"
export AUDITOR_MANAGEMENT_TOKEN="$AUDITOR_ACCESS_TOKEN"
export RELAY_AUDIT_KEY='...'
```

安全约束：

- 环境变量名必须在显式 allowlist 中；
- 每个变量必须绑定允许接收该 Key 的规范化 Base URL；
- 托管凭据操作必须通过管理令牌认证；
- HTTPS 是默认要求，只有显式 loopback 地址可在本地测试时使用 HTTP；
- 采样子进程只获得当前任务的一把临时凭据，不继承其他供应商 Key；
- `.env`、`.env.local`、数据库和证据目录均被 Git 忽略，但仍应使用系统 Secret 管理器保护。

端点登记后，审计请求中的 `base_url + model + api_key_env` 必须与启用的登记记录完全一致。调用方不能通过修改请求地址把 Key 发送到其他主机。

## 控制台 API

正式单模型批量入口：

```text
POST /api/v1/console/reference-sets
GET  /api/v1/console/reference-sets
GET  /api/v1/console/reference-sets/{id}
POST /api/v1/console/reference-sets/{id}/pause|resume|cancel

POST /api/v1/console/one-model-batches
GET  /api/v1/console/one-model-batches/{id}
POST /api/v1/console/one-model-batches/{id}/pause|resume|cancel
GET  /api/v1/console/one-model-batches/{id}/report.json
GET  /api/v1/console/one-model-batches/{id}/report.csv
```

浏览器页面可以临时提交明文 Key；这是仅供本机 loopback 控制台使用的例外。远程或多用户部署必须增加外层身份认证、预算控制以及 KMS/Vault，不能直接暴露该接口。

## 旧版多模型工作台

旧版入口保留用于历史记录和兼容测试，支持：

- 通过 `GET /models` 发现多个模型或手动填写模型 ID；
- legacy V1 与论文 V2 canonical40 采集；
- 多模型到多个参考指纹的人工映射；
- 历史任务、暂停、恢复、取消和候选参考离线比较。

限制：旧单成员 baseline 不会自动升级为三成员 ReferenceSet；legacy verdict 和候选距离只用于诊断，不能覆盖正式接口的 `operationalVerdict=unverifiable`。

本地 Mock 演示：

```bash
source .venv/bin/activate
python scripts/demo_local.py
python scripts/demo_tokenizer.py
python scripts/calibrate_mock.py
```

这些脚本验证工程链路，不生成生产可用的 `validated` threshold policy。

## 真实 Key 启用前的发布验收

发布结论必须绑定到具体父仓库 commit 和递归检出的子模块版本。至少从全新目录执行：

```bash
git clone --recurse-submodules https://github.com/tty627/llm-relay-auditor.git
cd llm-relay-auditor

python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

(cd llm-fingerprint-detector && npm ci && npm test)
pytest
ruff check .
node --test tests/web_status.test.js tests/web_profiles.test.js

export AUDITOR_GIT_SHA="$(git rev-parse --verify 'HEAD^{commit}')"
export AUDITOR_ACCESS_TOKEN="$(openssl rand -hex 32)"
export AUDITOR_MANAGEMENT_TOKEN="$AUDITOR_ACCESS_TOKEN"
docker compose config -q

git diff --exit-code
git status --short
git submodule status --recursive
```

最终安全验收还必须使用至少两把虚构 canary Key，并独立扫描 HTTP 输出、进程日志、JUnit、SQLite、JSON、JSONL、CSV 和浏览器刷新后的可见状态。扫描应覆盖 exact、NFC、casefold、去分隔符和 Unicode 转义变体。

网络测试应覆盖 SSRF、DNS rebinding、重定向拒绝、429 隔离与重试预算、取消冷却以及服务重启。任一凭据泄漏、越权发送、未验证重定向或失败后自动重放，都必须使 `REAL KEY BATCH READY = NO`。

即使上述工程验收通过，也不代表模型身份、FAR/FRR 或供应商质量已经校准。正式结论必须继续区分：

```text
工程与凭据安全是否可运行
≠
模型身份是否被统计学验证
```
