(function exposeRelayStatus(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.RelayStatus = api;
})(typeof globalThis !== "undefined" ? globalThis : this, () => {
  const statusLabels = Object.freeze({
    match: "较一致",
    uncertain: "不确定",
    mismatch: "明显不一致",
    insufficient: "证据不足",
    unverifiable: "不可验证",
    error: "执行失败",
    completed: "执行成功",
    failed: "执行失败",
    running: "执行中",
    queued: "排队 / 未执行",
    paused: "已暂停",
    pausing: "暂停中",
    canceling: "取消中",
    canceled: "已取消",
    interrupted: "服务重启中断",
    waiting: "等待自动重试",
    waiting_retry: "等待自动重试",
    cooldown: "限流冷却中",
    blocked: "计划需调整",
    plan_warning: "计划需调整",
  });

  const decisionStatusLabels = Object.freeze({
    calibrated: "已校准",
    uncalibrated: "未校准",
    incompatible: "方法不兼容",
    insufficient: "证据不足",
    legacy_unmigrated: "旧记录未迁移",
  });

  const decisionReasonLabels = Object.freeze({
    legacy_result_without_safe_decision: "旧记录不含安全判定，不能用于身份结论",
    validated_threshold_policy_missing: "缺少已验证阈值策略",
    threshold_policy_not_validated: "阈值策略尚未验证",
    mean_jsd_missing: "缺少平均 JSD",
    legacy_verdict_insufficient: "原始比较证据不足",
    protocol_mismatch: "参考端与目标端协议不一致",
    target_post_reasoning: "目标指纹在推理后采样",
    reference_post_reasoning: "参考指纹在推理后采样",
    target_reasoning_tokens_positive: "目标采样混入推理 token",
    reference_reasoning_tokens_positive: "参考采样混入推理 token",
    reference_ground_truth_missing: "参考端缺少真实来源声明",
    reference_ground_truth_not_eligible: "参考端来源不具备判定资格",
    reference_decision_ineligible: "参考端被标记为不可判定",
    reference_baseline_not_active: "参考基线不是有效状态",
  });

  function firstValue(...values) {
    return values.find((value) => value !== undefined && value !== null && value !== "");
  }

  function finiteNumber(...values) {
    const value = firstValue(...values);
    if (value === undefined) return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  function normalizeReasons(value) {
    const reasons = Array.isArray(value)
      ? value
      : value === undefined || value === null || value === ""
        ? []
        : [value];
    return [...new Set(reasons.map((reason) => String(reason).trim()).filter(Boolean))];
  }

  function normalizedText(...values) {
    const value = firstValue(...values);
    return value === undefined ? "" : String(value).trim().toLowerCase();
  }

  function referenceSelection(references = [], targetModel = "", preferredArtifactId = "") {
    const preferred = String(preferredArtifactId || "").trim();
    if (preferred) {
      const selected = references.find((item) => item?.artifactId === preferred);
      return {
        artifactId: selected?.artifactId || "",
        preferredUnavailable: !selected,
      };
    }
    const exact = references.find((item) => item?.model === targetModel);
    return {
      artifactId: exact?.artifactId || "",
      preferredUnavailable: false,
    };
  }

  function mappingEnabledState(enabledIntent = false, preferredUnavailable = false) {
    const intended = enabledIntent === true;
    const unavailable = preferredUnavailable === true;
    return {
      enabledIntent: intended,
      checked: intended && !unavailable,
      autoDisabled: intended && unavailable,
      userDisabled: !intended,
    };
  }

  function mergeTargetModelMappings(existingMappings = [], discoveredModels = []) {
    const existingByModel = new Map();
    existingMappings.forEach((item) => {
      const model = String(item?.model || "").trim();
      if (model && !existingByModel.has(model)) existingByModel.set(model, { ...item, model });
    });

    const merged = [];
    const seen = new Set();
    discoveredModels.forEach((item) => {
      const model = String(typeof item === "string" ? item : item?.id || item?.model || "").trim();
      if (!model || seen.has(model)) return;
      seen.add(model);
      const existing = existingByModel.get(model);
      merged.push({
        ...(existing || {}),
        model,
        source: existing?.source || "discovered",
        missingFromDiscovery: false,
      });
    });

    existingByModel.forEach((item, model) => {
      if (seen.has(model)) return;
      merged.push({
        ...item,
        model,
        source: item.source || "retained",
        missingFromDiscovery: true,
      });
    });
    return merged;
  }

  function timestampMs(value) {
    if (value === undefined || value === null || value === "") return null;
    if (typeof value === "number" || /^\d+(?:\.\d+)?$/.test(String(value).trim())) {
      const number = Number(value);
      if (!Number.isFinite(number)) return null;
      return number < 1e12 ? number * 1000 : number;
    }
    const parsed = Date.parse(String(value));
    return Number.isFinite(parsed) ? parsed : null;
  }

  function retryInfo(item = {}, nowMs = Date.now()) {
    const progress = item.progress || {};
    const diagnostics = progress.diagnostics || item.diagnostics || {};
    const stage = normalizedText(progress.stage, item.stage);
    const status = normalizedText(item.status, "queued");
    const rawDetail = String(firstValue(
      progress.detail,
      progress.last_error,
      item.error_message,
      diagnostics.last_error,
      "",
    ));
    const detailAttemptMatch = rawDetail.match(/(?:预检)?第\s*(\d+)\s*次/);
    const detailCooldownMatch = rawDetail.match(/(?:冷却|等待)\s*(\d+(?:\.\d+)?)\s*秒/);
    const retryableValue = firstValue(
      progress.retryable,
      item.retryable,
      diagnostics.retryable,
      item.response?.retryable,
      item.response?.result?.retryable,
    );
    const retryable = retryableValue === true
      || ["true", "1", "yes"].includes(normalizedText(retryableValue));
    const retryCount = finiteNumber(
      progress.retry_count,
      progress.retryCount,
      progress.retry_attempt,
      progress.retryAttempt,
      item.retry_count,
      item.retryCount,
      diagnostics.retry_count,
      item.response?.retry_count,
      item.response?.result?.retry_count,
    );
    const attemptCount = finiteNumber(
      progress.attempt,
      progress.attempt_count,
      progress.preflight_attempt,
      item.attempt_count,
      detailAttemptMatch?.[1],
      ["waiting_retry", "preflight_wait"].includes(stage) ? progress.errors : undefined,
    );
    const maxRetries = finiteNumber(
      progress.max_retries,
      progress.maxRetries,
      progress.retry_max,
      progress.retryMax,
      item.max_retries,
      item.maxRetries,
      diagnostics.max_retries,
      item.response?.max_retries,
      item.response?.result?.max_retries,
    );
    const retryAtRaw = firstValue(
      progress.next_retry_at,
      progress.nextRetryAt,
      progress.retry_at,
      progress.retryAt,
      item.next_retry_at,
      item.nextRetryAt,
      item.retry_at,
      item.retryAt,
      item.response?.next_retry_at,
      item.response?.retry_at,
    );
    const explicitRetryAtMs = timestampMs(retryAtRaw);
    const cooldownStartedAtMs = timestampMs(progress.updated_at || item.updated_at);
    const derivedRetryAtMs = cooldownStartedAtMs !== null && detailCooldownMatch
      ? cooldownStartedAtMs + Number(detailCooldownMatch[1]) * 1000
      : null;
    const retryAtMs = explicitRetryAtMs ?? derivedRetryAtMs;
    const remainingMs = retryAtMs === null ? null : Math.max(0, retryAtMs - Number(nowMs));
    const explicitWaiting = [
      "waiting_retry",
      "preflight_wait",
      "cooldown",
      "rate_limit_cooldown",
      "retry_wait",
      "waiting_for_retry",
    ].includes(stage) || ["waiting_retry", "cooldown"].includes(status);
    const scheduled = retryAtMs !== null && retryAtMs > Number(nowMs) - 1000;
    const retriesRemain = maxRetries === null || retryCount === null || retryCount < maxRetries;
    const waiting = explicitWaiting
      || scheduled
      || (retryable && retriesRemain && ["running", "queued", "failed", "interrupted"].includes(status));
    const detailStatusMatch = rawDetail.match(/HTTP\s*(\d{3})/i);
    const statusCode = finiteNumber(
      progress.last_http_status,
      progress.lastHttpStatus,
      progress.last_status_code,
      item.last_http_status,
      diagnostics.last_http_status,
      diagnostics.status_code,
      detailStatusMatch?.[1],
    );
    const errorKind = normalizedText(
      progress.last_error_kind,
      progress.lastErrorKind,
      diagnostics.last_error_kind,
      item.last_error_kind,
    );
    let reason = "中转站暂时没有响应";
    let kind = "temporary";
    if (statusCode === 429 || stage.includes("rate_limit") || /限流|rate\s*limit/i.test(rawDetail)) {
      reason = "中转站限流";
      kind = "rate_limit";
    } else if ([502, 503, 504].includes(statusCode) || /暂时?不可用|temporar(?:y|ily) unavailable/i.test(rawDetail)) {
      reason = "中转站或上游暂时不可用";
      kind = "unavailable";
    } else if (errorKind.includes("timeout") || stage.includes("timeout") || /超时|timeout/i.test(rawDetail)) {
      reason = "中转站响应较慢或超时";
      kind = "timeout";
    }
    return {
      waiting,
      stage,
      retryable,
      retryCount,
      attemptCount,
      maxRetries,
      retryAtMs,
      remainingMs,
      statusCode,
      kind,
      reason,
    };
  }

  function formatRetryDelay(milliseconds) {
    if (milliseconds === null || milliseconds === undefined) return "";
    const seconds = Math.max(0, Math.ceil(Number(milliseconds) / 1000));
    if (seconds <= 0) return "即将重试";
    if (seconds < 60) return `${seconds} 秒后重试`;
    const minutes = Math.floor(seconds / 60);
    const rest = seconds % 60;
    return rest ? `${minutes} 分 ${rest} 秒后重试` : `${minutes} 分钟后重试`;
  }

  function retryWaitingText(item = {}, nowMs = Date.now()) {
    const info = retryInfo(item, nowMs);
    if (!info.waiting) return "";
    const parts = [`${info.reason}，正在等待后自动重试`];
    if (info.attemptCount !== null) {
      parts.push(`预检已尝试 ${info.attemptCount} 次`);
    } else if (info.retryCount !== null) {
      parts.push(`已重试 ${info.retryCount}${info.maxRetries !== null ? `/${info.maxRetries}` : ""} 次`);
    }
    const countdown = formatRetryDelay(info.remainingMs);
    if (countdown) parts.push(countdown);
    return parts.join(" · ");
  }

  function isPlanBudgetWarning(item = {}) {
    const progress = item.progress || {};
    const failurePhase = normalizedText(
      item.failure_phase,
      item.failurePhase,
      progress.failure_phase,
      progress.failurePhase,
      item.response?.failure_phase,
      item.response?.result?.failure_phase,
    );
    const stage = normalizedText(progress.stage, item.stage);
    if (["plan", "planning", "budget", "plan_budget", "budget_estimate"].includes(failurePhase)
      || /(?:plan|planning|estimate).*(?:budget|limit|timeout)|(?:budget|limit).*(?:plan|estimate)/.test(failurePhase)) {
      return true;
    }
    if ([
      "plan_budget",
      "plan_warning",
      "budget_warning",
      "budget_check",
      "plan_validation",
      "plan_rejected",
    ].includes(stage)) return true;
    const detail = String(firstValue(item.error_message, progress.detail, ""));
    return /(?:预计|估计|理论).*(?:超过|超出).*(?:上限|时限)|(?:计划|采样).*(?:超过|超出).*(?:预算|时限)|改用快速模式|提高单模型上限/.test(detail);
  }

  function planBudgetText(item = {}) {
    if (!isPlanBudgetWarning(item)) return "";
    const detail = String(firstValue(item.progress?.detail, item.error_message, "")).trim();
    const estimate = detail.match(/预计(?:至少)?需要约?\s*\d+(?:\.\d+)?\s*秒/)?.[0];
    const parts = ["采样耗时预估提醒"];
    if (estimate) parts.push(estimate);
    parts.push("该记录尚未开始正式采样；连续无进度上限不限制总执行时长");
    return parts.join(" · ");
  }

  function itemOperationalState(item = {}) {
    if (retryInfo(item).waiting) return "waiting";
    if (isPlanBudgetWarning(item)) return "blocked";
    const status = normalizedText(item.status, "queued");
    if (status === "completed") return "success";
    if (["failed", "interrupted"].includes(status)) return "failed";
    if (status === "canceled") return "canceled";
    if (["running", "canceling"].includes(status)) return "running";
    if (["paused", "pausing"].includes(status)) return "paused";
    return "queued";
  }

  function itemStatusLabel(item = {}) {
    const operationalState = itemOperationalState(item);
    if (operationalState === "waiting") {
      const info = retryInfo(item);
      if (info.kind === "rate_limit") return "等待限流恢复";
      if (info.kind === "unavailable") return "等待上游恢复";
      if (info.kind === "timeout") return "等待慢速中转站";
      return "等待自动重试";
    }
    if (operationalState === "blocked") return "计划需调整";
    return statusLabels[item.status] || item.status || "排队 / 未执行";
  }

  function recordDecision(item = {}) {
    const response = item.response || {};
    const result = response.result || item.result || {};
    const embeddedDecision = [item.decision, response.decision, result.decision].find(
      (value) => value && typeof value === "object" && !Array.isArray(value),
    ) || null;
    const rawLegacy = firstValue(
      item.legacy_verdict,
      response.legacy_verdict,
      embeddedDecision?.legacyVerdict,
      result.legacyVerdict,
      result.comparison?.verdict,
      ["match", "uncertain", "mismatch", "insufficient"].includes(item.verdict)
        ? item.verdict
        : undefined,
    );
    const explicitStatus = firstValue(
      item.decision_status,
      response.decision_status,
      embeddedDecision?.status,
    );
    const semantics = firstValue(
      item.verdict_semantics,
      response.verdict_semantics,
      result.verdictSemantics,
    );
    const isLegacyOneToken = item.status === "completed"
      && (!item.detector || item.detector === "one_token_verify")
      && !embeddedDecision
      && !explicitStatus
      && Boolean(rawLegacy);
    const status = isLegacyOneToken ? "legacy_unmigrated" : explicitStatus || null;
    const reasons = isLegacyOneToken
      ? ["legacy_result_without_safe_decision"]
      : normalizeReasons(firstValue(
        item.reasons,
        item.decision_reasons,
        response.reasons,
        embeddedDecision?.reasons,
      ));
    const operationalVerdict = isLegacyOneToken
      ? "unverifiable"
      : firstValue(
        item.operational_verdict,
        response.operational_verdict,
        embeddedDecision?.operationalVerdict,
        item.verdict,
        item.status,
      );
    const decisionEligible = typeof embeddedDecision?.decisionEligible === "boolean"
      ? embeddedDecision.decisionEligible
      : status === "legacy_unmigrated"
        ? false
        : null;
    return {
      hasDecision: Boolean(embeddedDecision || explicitStatus || semantics || isLegacyOneToken),
      operationalVerdict,
      legacyVerdict: rawLegacy || null,
      status,
      reasons,
      decisionEligible,
      rawMeanJsd: finiteNumber(
        embeddedDecision?.rawMeanJsd,
        item.mean_jsd,
        result.comparison?.meanJsd,
        result.meanJsd,
      ),
      semantics: isLegacyOneToken ? "legacy-unmigrated" : semantics || null,
    };
  }

  function decisionSummary(decision) {
    if (!decision?.hasDecision) return "";
    const parts = [];
    if (decision.status) {
      parts.push(`判定状态：${decisionStatusLabels[decision.status] || decision.status}`);
    }
    if (decision.legacyVerdict) {
      parts.push(`原始结论：${statusLabels[decision.legacyVerdict] || decision.legacyVerdict}`);
    }
    if (decision.reasons?.length) {
      parts.push(`原因：${decision.reasons.map(
        (reason) => decisionReasonLabels[reason] || reason,
      ).join("；")}`);
    }
    return parts.join(" · ");
  }

  function batchStateCounts(items = []) {
    const counts = {
      success: 0,
      failed: 0,
      canceled: 0,
      queued: 0,
      waiting: 0,
      blocked: 0,
      running: 0,
      paused: 0,
      total: items.length,
    };
    items.forEach((item) => {
      const state = itemOperationalState(item);
      if (Object.hasOwn(counts, state)) counts[state] += 1;
      else counts.queued += 1;
    });
    return counts;
  }

  function batchSummaryParts(counts) {
    return [
      ["success", "成功"],
      ["failed", "失败"],
      ["waiting", "等待重试"],
      ["blocked", "计划需调整"],
      ["canceled", "取消"],
      ["queued", "排队 / 未执行"],
      ["running", "运行"],
      ["paused", "暂停"],
    ].map(([key, label]) => ({ key, label, count: Number(counts?.[key]) || 0 }));
  }

  function batchStatusLabel(status, counts) {
    if (status === "running") {
      if (counts?.waiting > 0 && !counts?.running) return "正在等待中转站恢复";
      if (counts?.waiting > 0) return "后端正在执行 · 部分任务等待重试";
      return "后端正在执行";
    }
    if (status === "pausing") return "正在暂停当前请求";
    if (status === "paused") return "批次已暂停";
    if (status === "canceling") return "正在取消剩余任务";
    if (status === "canceled") return "批次已取消";
    if (status === "interrupted") return "批次因服务重启中断";
    if (status === "completed") {
      if (counts?.blocked > 0) return "批次处理结束 · 有计划需调整";
      return counts?.total > 0 && counts.success === counts.total
        ? "批次执行成功"
        : "批次处理结束";
    }
    return statusLabels[status] || status || "历史批次";
  }

  function partialEvidenceInfo(item = {}) {
    const response = item.response || {};
    const result = response.result || item.result || {};
    const partialNode = result.partial && typeof result.partial === "object"
      ? result.partial
      : {};
    const artifactId = firstValue(
      item.partial_artifact_id,
      item.partialArtifactId,
      response.artifact_id,
      item.artifact_id,
    );
    const evidenceAvailable = Boolean(
      item.evidence_available
      || item.partial_evidence_available
      || item.partialEvidenceAvailable
      || artifactId,
    );
    const evidenceState = String(firstValue(
      item.evidence_state,
      item.evidenceState,
      response.evidence_state,
      result.evidence_state,
      result.evidenceState,
      "",
    ) || "");
    const explicitPartial = Boolean(
      item.partial_evidence
      || item.partialEvidence
      || item.partial_evidence_available
      || item.partialEvidenceAvailable
      || result.partial
      || response.partial,
    );
    const isPartial = evidenceState === "partial" || explicitPartial;
    const isTargetFingerprint = evidenceState === "target_fingerprint"
      || (!evidenceState && evidenceAvailable && !isPartial && item.status && item.status !== "completed");
    const sampleCount = finiteNumber(
      item.partial_sample_count,
      item.partialSampleCount,
      result.partial_sample_count,
      result.partialSampleCount,
      result.completedSamples,
      result.completed_samples,
      partialNode.sample_count,
      partialNode.sampleCount,
      partialNode.done,
      item.progress?.done,
    );
    const expectedSamples = finiteNumber(
      item.partial_expected_samples,
      item.partialExpectedSamples,
      result.partial_expected_samples,
      result.partialExpectedSamples,
      result.expectedSamples,
      result.expected_samples,
      partialNode.expected_samples,
      partialNode.expectedSamples,
      partialNode.total,
      item.progress?.total,
    );
    return {
      isPartial,
      isTargetFingerprint,
      evidenceState,
      available: evidenceAvailable && Boolean(artifactId),
      artifactId,
      sampleCount,
      expectedSamples,
    };
  }

  function partialSampleText(info) {
    if (!info?.isPartial) return "";
    const samples = info.sampleCount !== null
      ? `已保存 ${info.sampleCount}${info.expectedSamples !== null ? `/${info.expectedSamples}` : ""} 个采样`
      : "已保存中断前采样";
    return `部分采样 · ${samples}，可下载 / 查看但不可判定模型`;
  }

  function incompleteEvidenceText(info) {
    if (info?.isPartial) return partialSampleText(info);
    if (!info?.isTargetFingerprint) return "";
    const samples = info.sampleCount !== null
      ? `已保存 ${info.sampleCount}${info.expectedSamples !== null ? `/${info.expectedSamples}` : ""} 个采样`
      : "目标指纹证据已保存";
    return `${samples}，但比较未完成；可下载 / 查看但不可判定模型`;
  }

  function progressDiagnostics(item = {}) {
    const progress = item.progress || {};
    const diagnostics = progress.diagnostics || item.diagnostics || {};
    const lastRequest = progress.last_request || diagnostics.last_request || {};
    const preflight = firstValue(
      item.preflight,
      item.response?.result?.execution?.preflight,
      item.result?.execution?.preflight,
    ) || {};
    const parts = [];
    const statusCode = finiteNumber(
      progress.last_http_status,
      progress.lastHttpStatus,
      progress.last_status_code,
      diagnostics.last_http_status,
      diagnostics.lastHttpStatus,
      diagnostics.status_code,
      lastRequest.http_status,
      lastRequest.status_code,
      lastRequest.statusCode,
      preflight.statusCode,
      preflight.status_code,
    );
    if (statusCode !== null) parts.push(`最近 HTTP ${statusCode}`);

    const latencyMs = finiteNumber(
      progress.last_latency_ms,
      progress.lastLatencyMs,
      diagnostics.last_latency_ms,
      diagnostics.lastLatencyMs,
      lastRequest.latency_ms,
      preflight.latencyMs,
      preflight.latency_ms,
      preflight.totalLatencyMs,
      preflight.total_latency_ms,
    );
    if (latencyMs !== null) parts.push(`耗时 ${Math.round(latencyMs)} ms`);

    const timeoutCount = finiteNumber(
      progress.timeout_count,
      progress.timeoutCount,
      progress.timeouts,
      diagnostics.timeout_count,
      lastRequest.timeout_count,
    );
    const timedOut = Boolean(firstValue(
      progress.timed_out,
      progress.last_timeout,
      progress.lastTimeout,
      diagnostics.timed_out,
      lastRequest.timed_out,
      progress.lastErrorKind === "timeout" ? true : undefined,
      progress.last_error_kind === "timeout" ? true : undefined,
    ));
    if (timeoutCount !== null && timeoutCount > 0) parts.push(`超时 ${timeoutCount} 次`);
    else if (timedOut) parts.push("最近一次请求超时");

    const retryAttempt = finiteNumber(
      progress.retry_attempt,
      progress.retryAttempt,
      progress.retry_count,
      progress.retries,
      diagnostics.retry_attempt,
      lastRequest.retry_attempt,
    );
    const retryMax = finiteNumber(
      progress.retry_max,
      progress.retryMax,
      progress.max_retries,
      diagnostics.retry_max,
      lastRequest.retry_max,
    );
    if (retryAttempt !== null && retryAttempt > 0) {
      parts.push(`重试 ${retryAttempt}${retryMax !== null ? `/${retryMax}` : " 次"}`);
    } else if (progress.retrying === true) {
      parts.push("正在重试");
    }

    const preflightAttempts = finiteNumber(preflight.attempts);
    if (preflightAttempts !== null) parts.push(`兼容尝试 ${preflightAttempts} 次`);
    const preflightRetries = finiteNumber(preflight.retries);
    if (preflightRetries !== null) {
      parts.push(preflightRetries === 0 ? "零网络重试" : `网络重试 ${preflightRetries} 次`);
    }

    const rawDetail = firstValue(
      progress.last_error,
      progress.lastError,
      diagnostics.last_error,
      lastRequest.error,
      item.last_error,
      item.lastError,
    );
    const detail = rawDetail === undefined ? "" : String(rawDetail).trim();
    if (detail) parts.push(detail.slice(0, 180));
    else if (typeof progress.detail === "string" && /(HTTP\s*\d{3}|超时|重试|Retry)/i.test(progress.detail)) {
      parts.push(progress.detail.slice(0, 180));
    }
    return [...new Set(parts)];
  }

  function preflightText(item = {}) {
    const progress = item.progress || {};
    if (["preflight", "preflight_retry", "healthcheck", "connection_check"].includes(progress.stage)) {
      return progress.detail || "正在检查接口兼容性与中转站状态";
    }
    const parts = progressDiagnostics(item);
    return parts.length ? parts.join(" · ") : "";
  }

  return Object.freeze({
    statusLabels,
    decisionStatusLabels,
    decisionReasonLabels,
    recordDecision,
    decisionSummary,
    batchStateCounts,
    batchSummaryParts,
    batchStatusLabel,
    partialEvidenceInfo,
    partialSampleText,
    incompleteEvidenceText,
    progressDiagnostics,
    preflightText,
    retryInfo,
    retryWaitingText,
    isPlanBudgetWarning,
    planBudgetText,
    itemOperationalState,
    itemStatusLabel,
    referenceSelection,
    mappingEnabledState,
    mergeTargetModelMappings,
  });
});
