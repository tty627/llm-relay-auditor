# Relay Model Auditor

面向大模型中转站、聚合网关和 API 采购团队的黑盒模型验真 MVP。当前版本实现：

- OpenAI Chat Completions 兼容端点烟测。
- 原始证据 JSON、SHA-256 和 SQLite/PostgreSQL 审计记录。
- 集成 [One Token Is Enough](https://arxiv.org/abs/2607.10252) 的行为指纹采集与验证。
- 内置 `reference-model` / `substitute-model` Mock，可在没有 API Key 时跑完整闭环。
- FastAPI/OpenAPI 接口、Docker Compose 和 GitHub Actions。

完整设计见[《中转站模型验真与质量防注水方案》](./中转站模型验真与质量防注水方案.md)。

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

- 健康检查：<http://127.0.0.1:8000/health>
- OpenAPI：<http://127.0.0.1:8000/docs>
- Mock 模型：<http://127.0.0.1:8000/mock/v1/models>

## 跑本地验真闭环

保持服务运行，在另一个终端执行：

```bash
source .venv/bin/activate
python scripts/demo_local.py
```

演示依次执行：

1. 健康检查和烟测。
2. 采集 `reference-model` 的 4×15 One Token 参考指纹。
3. 验证同一个模型，预期 `match`。
4. 验证 `substitute-model`，预期 `mismatch`。

证据默认写入 `data/evidence/`，数据库默认位于 `data/relay_auditor.db`；两者均被 Git 忽略。

## Docker Compose

```bash
git submodule update --init --recursive
docker compose up --build
```

Compose 使用 PostgreSQL 保存审计记录；这组凭据只供本地开发，生产部署必须替换并通过密钥管理系统注入。

## 接入真实端点

服务不接受请求体中的明文 Key，只接收环境变量名。例如先在服务进程中配置：

```bash
export RELAY_AUDIT_KEY='...'
```

再提交：

```bash
curl -sS http://127.0.0.1:8000/api/v1/audits/smoke \
  -H 'content-type: application/json' \
  -d '{
    "target": {
      "base_url": "https://relay.example.com/v1",
      "model": "claimed-model",
      "api_key_env": "RELAY_AUDIT_KEY"
    }
  }'
```

`.env`、`.env.local`、证据和数据库都不会进入 Git。不要把真实密钥写入命令行参数、请求体或报告。

## 当前边界

这是方案 v1.1 的第 1～2 周 MVP 骨架。Tokenizer 斜率、KBF、上下文二分、私有质量集、调度告警和供应商工单仍在后续迭代范围内。任何 `mismatch` 都是统计证据，不是对供应商欺诈的单次证明。
