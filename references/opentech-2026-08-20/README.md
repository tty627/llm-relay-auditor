# OpenTech 参考指纹快照（2026-08-20）

本目录保存两组 OpenTech 中转端行为指纹，共 15 份：`key-a` 7 份、`key-b` 8 份。
文件中不包含 API Key，可由 `scripts/import_reference_fingerprints.py` 导入本机 Relay
Auditor 的证据库和参考目录。

```bash
source .venv/bin/activate
python scripts/import_reference_fingerprints.py
```

这些指纹来自同一个中转服务，不是官方模型端点的真值。它们适合用作后续漂移检测、
同供应商复测和两组权限之间的行为对照，不应单独用于证明模型名称对应官方模型。
完整采样结论见 [REPORT.md](./REPORT.md)。
