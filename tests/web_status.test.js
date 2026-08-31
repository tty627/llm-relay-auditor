const test = require("node:test");
const assert = require("node:assert/strict");

const status = require("../src/relay_auditor/web/status.js");
const profiles = require("../src/relay_auditor/web/profiles.js");

test("论文 V2 固定使用 canonical40 与每 cell 30 样本", () => {
  const selected = profiles.settingsForProfile(
    profiles.PAPER_PROFILE_ID,
    { cells: 4, samples: 15, concurrency: 2 },
  );

  assert.equal(selected.methodProfileId, profiles.PAPER_PROFILE_ID);
  assert.equal(selected.cells, 40);
  assert.equal(selected.samples, 30);
  assert.equal(selected.concurrency, 2);
  assert.equal(profiles.requestCount(profiles.PAPER_PROFILE_ID, 2, selected), 2400);
});

test("参考后台批次请求发送模型列表、自动并发和两个超时", () => {
  const payload = profiles.referenceCollectionRequest({
    referenceName: " Official ",
    endpoint: { base_url: "https://official.example/v1", api_key: "temporary" },
    models: ["model-a", "model-a", " model-b "],
    profileId: profiles.PAPER_PROFILE_ID,
    settings: {
      cells: 4,
      samples: 15,
      concurrency: 8,
      concurrencyMode: "auto",
      requestTimeoutSeconds: 21,
      modelTimeoutSeconds: 420,
    },
    validDays: 30,
  });

  assert.deepEqual(payload, {
    reference_name: "Official",
    provider: "user_reference",
    endpoint: { base_url: "https://official.example/v1", api_key: "temporary" },
    models: ["model-a", "model-b"],
    method_profile_id: profiles.PAPER_PROFILE_ID,
    cells: 40,
    samples: 30,
    concurrency: 8,
    concurrency_mode: "auto",
    request_timeout_seconds: 21,
    model_timeout_seconds: 420,
    valid_days: 30,
  });
  assert.equal(Object.hasOwn(payload.endpoint, "model"), false);
});

test("409 结构化 detail 和纯文本都能恢复既有批次 ID", () => {
  const batchId = "12345678-1234-1234-1234-123456789abc";
  assert.equal(status.conflictBatchId({ detail: { message: "active", batch_id: batchId } }), batchId);
  assert.equal(status.conflictBatchId(`已有批次 ${batchId}`), batchId);
  assert.equal(status.conflictBatchId({ detail: { message: "missing id" } }), "");
});

test("参考采集摘要独立统计成功失败部分证据和当前模型", () => {
  const summary = status.referenceCollectionSummary([
    { model: "done", status: "completed" },
    { model: "failed", status: "failed", partial_evidence: true, artifact_id: "partial" },
    { model: "current", status: "running", progress: { stage: "sampling", done: 3, total: 30 } },
    { model: "later", status: "queued" },
  ]);

  assert.equal(summary.success, 1);
  assert.equal(summary.failed, 1);
  assert.equal(summary.partial, 1);
  assert.equal(summary.running, 1);
  assert.equal(summary.queued, 1);
  assert.equal(summary.currentModel, "current");
});

test("历史 raw JSONL 仅在 availability 或 SHA 存在时提供", () => {
  const byFlag = status.rawSampleEvidenceInfo({
    artifact_id: "artifact-a",
    samples_evidence_available: true,
  });
  const bySha = status.rawSampleEvidenceInfo({
    artifact_id: "artifact-b",
    partial_evidence: true,
    raw_evidence_sha256: "a".repeat(64),
  });
  const unavailable = status.rawSampleEvidenceInfo({ artifact_id: "artifact-c" });

  assert.deepEqual(byFlag, { available: true, artifactId: "artifact-a", sha256: "" });
  assert.equal(bySha.available, true);
  assert.equal(bySha.artifactId, "artifact-b");
  assert.equal(bySha.sha256, "a".repeat(64));
  assert.equal(unavailable.available, false);
});

test("批次拒绝混合 V1 和 V2 参考且兼容缺少 profile 的旧记录", () => {
  const legacy = { reference: { artifactId: "legacy" } };
  const paper = {
    reference: {
      artifactId: "paper",
      methodProfileId: profiles.PAPER_PROFILE_ID,
    },
  };

  assert.equal(
    profiles.mappingProfileSummary([legacy]).profileId,
    profiles.LEGACY_PROFILE_ID,
  );
  const mixed = profiles.mappingProfileSummary([legacy, paper]);
  assert.equal(mixed.compatible, false);
  assert.match(mixed.message, /不能混合/);
});

test("历史指定参考缺失时保持未选择且不按同名模型回退", () => {
  const references = [
    { artifactId: "current-artifact", model: "gpt-test" },
    { artifactId: "other-artifact", model: "other-model" },
  ];

  assert.deepEqual(
    status.referenceSelection(references, "gpt-test", "deleted-history-artifact"),
    { artifactId: "", preferredUnavailable: true },
  );
  assert.deepEqual(
    status.referenceSelection(references, "gpt-test", ""),
    { artifactId: "current-artifact", preferredUnavailable: false },
  );
});

test("模型刷新合并发现结果并保留映射优先级启用状态和手工模型", () => {
  const merged = status.mergeTargetModelMappings([
    {
      model: "still-listed",
      referenceArtifactId: "artifact-1",
      enabled: false,
      priority: 80,
      source: "discovered",
    },
    {
      model: "manual-only",
      referenceArtifactId: "artifact-2",
      enabled: true,
      priority: 20,
      source: "manual",
    },
    {
      model: "no-longer-listed",
      referenceArtifactId: "artifact-3",
      enabled: true,
      priority: 50,
      source: "discovered",
    },
  ], [{ id: "new-model" }, { id: "still-listed" }]);

  assert.deepEqual(merged, [
    {
      model: "new-model",
      source: "discovered",
      missingFromDiscovery: false,
    },
    {
      model: "still-listed",
      referenceArtifactId: "artifact-1",
      enabled: false,
      priority: 80,
      source: "discovered",
      missingFromDiscovery: false,
    },
    {
      model: "manual-only",
      referenceArtifactId: "artifact-2",
      enabled: true,
      priority: 20,
      source: "manual",
      missingFromDiscovery: true,
    },
    {
      model: "no-longer-listed",
      referenceArtifactId: "artifact-3",
      enabled: true,
      priority: 50,
      source: "discovered",
      missingFromDiscovery: true,
    },
  ]);
});

test("历史指定参考缺失时保持未选择且不按同名模型回退", () => {
  const references = [
    { artifactId: "current-artifact", model: "gpt-test" },
    { artifactId: "other-artifact", model: "other-model" },
  ];

  assert.deepEqual(
    status.referenceSelection(references, "gpt-test", "deleted-history-artifact"),
    { artifactId: "", preferredUnavailable: true },
  );
  assert.deepEqual(
    status.referenceSelection(references, "gpt-test", ""),
    { artifactId: "current-artifact", preferredUnavailable: false },
  );
});

test("参考暂不可用时自动停用但保留用户启用意图并在恢复后还原", () => {
  assert.deepEqual(status.mappingEnabledState(true, true), {
    enabledIntent: true,
    checked: false,
    autoDisabled: true,
    userDisabled: false,
  });
  assert.deepEqual(status.mappingEnabledState(true, false), {
    enabledIntent: true,
    checked: true,
    autoDisabled: false,
    userDisabled: false,
  });
  assert.deepEqual(status.mappingEnabledState(false, false), {
    enabledIntent: false,
    checked: false,
    autoDisabled: false,
    userDisabled: true,
  });
});

test("模型刷新合并发现结果并保留映射优先级启用状态和手工模型", () => {
  const merged = status.mergeTargetModelMappings([
    {
      model: "still-listed",
      referenceArtifactId: "artifact-1",
      enabled: false,
      priority: 80,
      source: "discovered",
    },
    {
      model: "manual-only",
      referenceArtifactId: "artifact-2",
      enabled: true,
      priority: 20,
      source: "manual",
    },
    {
      model: "no-longer-listed",
      referenceArtifactId: "artifact-3",
      enabled: true,
      priority: 50,
      source: "discovered",
    },
  ], [{ id: "new-model" }, { id: "still-listed" }]);

  assert.deepEqual(merged, [
    {
      model: "new-model",
      source: "discovered",
      missingFromDiscovery: false,
    },
    {
      model: "still-listed",
      referenceArtifactId: "artifact-1",
      enabled: false,
      priority: 80,
      source: "discovered",
      missingFromDiscovery: false,
    },
    {
      model: "manual-only",
      referenceArtifactId: "artifact-2",
      enabled: true,
      priority: 20,
      source: "manual",
      missingFromDiscovery: true,
    },
    {
      model: "no-longer-listed",
      referenceArtifactId: "artifact-3",
      enabled: true,
      priority: 50,
      source: "discovered",
      missingFromDiscovery: true,
    },
  ]);
});

test("批次状态分别统计成功失败等待重试计划阻断取消排队运行和暂停", () => {
  const counts = status.batchStateCounts([
    { status: "completed" },
    { status: "failed" },
    { status: "interrupted" },
    { status: "canceled" },
    { status: "queued" },
    { status: "running" },
    { status: "canceling" },
    { status: "paused" },
    {
      status: "queued",
      progress: { stage: "waiting_retry", last_http_status: 429 },
    },
    {
      status: "failed",
      failure_phase: "plan_budget_limit",
    },
  ]);

  assert.deepEqual(counts, {
    success: 1,
    failed: 2,
    canceled: 1,
    queued: 1,
    waiting: 1,
    blocked: 1,
    running: 2,
    paused: 1,
    total: 10,
  });
  assert.equal(status.batchStatusLabel("completed", counts), "批次处理结束 · 有计划需调整");
});

test("限流等待显示自动重试次数与倒计时且不计失败", () => {
  const now = Date.parse("2026-08-21T08:00:00Z");
  const item = {
    status: "failed",
    retryable: true,
    progress: {
      stage: "cooldown",
      last_http_status: 429,
      retry_count: 2,
      max_retries: 8,
      next_retry_at: "2026-08-21T08:00:12Z",
    },
  };

  assert.equal(status.itemOperationalState(item), "waiting");
  assert.equal(status.itemStatusLabel(item), "等待限流恢复");
  assert.equal(
    status.retryWaitingText(item, now),
    "中转站限流，正在等待后自动重试 · 已重试 2/8 次 · 12 秒后重试",
  );
});

test("兼容后端 waiting_retry 的 detail 冷却时间与 errors 尝试次数", () => {
  const now = Date.parse("2026-08-21T08:00:05Z");
  const item = {
    status: "queued",
    progress: {
      stage: "waiting_retry",
      errors: 3,
      updated_at: "2026-08-21T08:00:00Z",
      detail: "预检第 3 次遇到可恢复错误 HTTP 503，冷却 20 秒后自动重试",
    },
  };

  assert.equal(status.itemOperationalState(item), "waiting");
  assert.equal(
    status.retryWaitingText(item, now),
    "中转站或上游暂时不可用，正在等待后自动重试 · 预检已尝试 3 次 · 15 秒后重试",
  );
});

test("计划预算提醒归为需调整而不是执行失败", () => {
  const item = {
    status: "failed",
    failure_phase: "plan_budget_limit",
    error_message: "预估采样较慢",
  };

  assert.equal(status.itemOperationalState(item), "blocked");
  assert.equal(status.itemStatusLabel(item), "计划需调整");
  assert.doesNotMatch(status.planBudgetText(item), /执行失败/);
  assert.match(status.planBudgetText(item), /连续无进度上限不限制总执行时长/);
});

test("识别 CLI 顶层 partial 部分采样字段", () => {
  const info = status.partialEvidenceInfo({
    status: "failed",
    evidence_available: true,
    artifact_id: "artifact-1",
    response: {
      artifact_id: "artifact-1",
      result: {
        partial: true,
        completedSamples: 17,
        expectedSamples: 400,
      },
    },
  });

  assert.deepEqual(info, {
    isPartial: true,
    isTargetFingerprint: false,
    evidenceState: "",
    available: true,
    artifactId: "artifact-1",
    sampleCount: 17,
    expectedSamples: 400,
  });
  assert.match(status.partialSampleText(info), /17\/400/);
  assert.match(status.partialSampleText(info), /不可判定模型/);
});

test("完整目标指纹不会误标成部分采样", () => {
  const info = status.partialEvidenceInfo({
    status: "failed",
    evidence_state: "target_fingerprint",
    evidence_available: true,
    artifact_id: "artifact-2",
    partial_sample_count: 400,
    partial_expected_samples: 400,
  });

  assert.equal(info.isPartial, false);
  assert.equal(info.isTargetFingerprint, true);
  assert.match(status.incompleteEvidenceText(info), /比较未完成/);
  assert.match(status.incompleteEvidenceText(info), /不可判定模型/);
});

test("兼容预检 HTTP 延迟超时和重试详情", () => {
  const item = {
    progress: {
      last_http_status: 503,
      last_latency_ms: 812,
      timeout_count: 1,
      retry_attempt: 2,
      retry_max: 3,
    },
  };

  assert.deepEqual(status.progressDiagnostics(item), [
    "最近 HTTP 503",
    "耗时 812 ms",
    "超时 1 次",
    "重试 2/3",
  ]);
});

test("最终证据中的预检结果可以恢复展示", () => {
  const text = status.preflightText({
    response: {
      result: {
        execution: {
          preflight: { statusCode: 200, latencyMs: 321, attempts: 2, retries: 0 },
        },
      },
    },
  });

  assert.equal(text, "最近 HTTP 200 · 耗时 321 ms · 兼容尝试 2 次 · 零网络重试");
});

test("安全判定优先展示 operational verdict 并保留原始结论与原因", () => {
  const decision = status.recordDecision({
    status: "completed",
    verdict: "unverifiable",
    decision: {
      operationalVerdict: "unverifiable",
      status: "uncalibrated",
      reasons: ["validated_threshold_policy_missing"],
      legacyVerdict: "match",
      rawMeanJsd: 0.012,
      decisionEligible: false,
    },
  });

  assert.equal(decision.operationalVerdict, "unverifiable");
  assert.equal(decision.legacyVerdict, "match");
  assert.equal(decision.status, "uncalibrated");
  assert.equal(decision.rawMeanJsd, 0.012);
  assert.equal(status.statusLabels.unverifiable, "不可验证");
  assert.match(status.decisionSummary(decision), /未校准/);
  assert.match(status.decisionSummary(decision), /缺少已验证阈值策略/);
});

test("旧 One Token 记录只读降级为不可验证", () => {
  const decision = status.recordDecision({
    detector: "one_token_verify",
    status: "completed",
    verdict: "match",
    mean_jsd: 0.01,
  });

  assert.deepEqual(decision, {
    hasDecision: true,
    operationalVerdict: "unverifiable",
    legacyVerdict: "match",
    status: "legacy_unmigrated",
    reasons: ["legacy_result_without_safe_decision"],
    decisionEligible: false,
    rawMeanJsd: 0.01,
    semantics: "legacy-unmigrated",
  });
  assert.match(status.decisionSummary(decision), /旧记录未迁移/);
  assert.match(status.decisionSummary(decision), /不能用于身份结论/);
});
