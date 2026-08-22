const test = require("node:test");
const assert = require("node:assert/strict");

const status = require("../src/relay_auditor/web/status.js");

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
