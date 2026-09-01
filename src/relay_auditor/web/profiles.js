(function exposeRelayProfiles(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.RelayProfiles = api;
})(typeof globalThis !== "undefined" ? globalThis : this, () => {
  const LEGACY_PROFILE_ID = "legacy-one-token/v1";
  const PAPER_PROFILE_ID = "bruckner-2026-canonical40/v1";
  const ONE_MODEL_REFERENCE_REQUESTS = 3 * 40 * 30;
  const ONE_MODEL_TARGET_REQUESTS = 40 * 30;
  const protocolProfiles = Object.freeze({
    openai_chat: "openai-chat-onetoken-v1",
    anthropic_messages: "anthropic-messages-opus5-onetoken-v1",
  });

  const profiles = Object.freeze({
    [LEGACY_PROFILE_ID]: Object.freeze({
      id: LEGACY_PROFILE_ID,
      label: "旧版探索模式",
      shortLabel: "Legacy V1",
      description: "自定义探针，仅用于快速诊断、漂移观察和历史兼容。",
      fixedCells: null,
      defaultSamples: null,
      evidenceLabel: "聚合指纹 JSON",
      paperFaithful: false,
    }),
    [PAPER_PROFILE_ID]: Object.freeze({
      id: PAPER_PROFILE_ID,
      label: "论文 V2 高保真",
      shortLabel: "Paper V2",
      description: "作者固定 10×4 探针、直接采样、逐请求 JSONL 证据；结果仍需本地校准。",
      fixedCells: 40,
      defaultSamples: 30,
      evidenceLabel: "V2 指纹 JSON + 原始 JSONL",
      paperFaithful: true,
    }),
  });

  function normalizeProfileId(value) {
    return value === PAPER_PROFILE_ID ? PAPER_PROFILE_ID : LEGACY_PROFILE_ID;
  }

  function profile(value) {
    return profiles[normalizeProfileId(value)];
  }

  function referenceProfileId(reference = {}) {
    return normalizeProfileId(
      reference.methodProfileId
      ?? reference.method_profile_id
      ?? reference.metadata?.method_profile_id,
    );
  }

  function settingsForProfile(profileId, legacySettings) {
    const selected = profile(profileId);
    if (!selected.paperFaithful) return { ...legacySettings, methodProfileId: selected.id };
    return {
      ...legacySettings,
      methodProfileId: selected.id,
      cells: selected.fixedCells,
      samples: selected.defaultSamples,
    };
  }

  function mappingProfileSummary(mappings = []) {
    const ids = [...new Set(
      mappings
        .map((mapping) => referenceProfileId(mapping?.reference || mapping))
        .filter(Boolean),
    )];
    if (ids.length === 0) {
      return { compatible: true, profileId: null, profileIds: [], message: "" };
    }
    if (ids.length === 1) {
      return {
        compatible: true,
        profileId: ids[0],
        profileIds: ids,
        message: `${profile(ids[0]).label} · 同批次协议一致`,
      };
    }
    return {
      compatible: false,
      profileId: null,
      profileIds: ids,
      message: "同一批次不能混合论文 V2 与旧版 V1 参考，请分成两个批次执行。",
    };
  }

  function requestCount(profileId, modelCount, legacySettings) {
    const count = Math.max(0, Number(modelCount) || 0);
    const selected = settingsForProfile(profileId, legacySettings);
    return count * selected.cells * selected.samples;
  }

  function referenceCollectionRequest({
    referenceName,
    provider = "user_reference",
    endpoint,
    models = [],
    profileId,
    settings,
    validDays = 14,
  }) {
    const selected = settingsForProfile(profileId, settings);
    const normalizedModels = [...new Set(
      models.map((model) => String(model || "").trim()).filter(Boolean),
    )];
    return {
      reference_name: String(referenceName || "").trim(),
      provider: String(provider || "user_reference").trim(),
      endpoint: { ...(endpoint || {}) },
      models: normalizedModels,
      method_profile_id: selected.methodProfileId,
      cells: selected.cells,
      samples: selected.samples,
      concurrency: Number(selected.concurrency),
      concurrency_mode: selected.concurrencyMode === "fixed" ? "fixed" : "auto",
      request_timeout_seconds: Number(selected.requestTimeoutSeconds),
      model_timeout_seconds: Number(selected.modelTimeoutSeconds),
      valid_days: Number(validDays),
    };
  }

  function transportProfileForProtocol(protocol) {
    return protocolProfiles[protocol] || protocolProfiles.anthropic_messages;
  }

  function normalizeOneModelBaseUrl(value) {
    const raw = String(value || "").trim();
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      return { valid: false, value: "", error: "URL 格式无效" };
    }
    if (parsed.protocol !== "https:") {
      return { valid: false, value: "", error: "必须使用 HTTPS" };
    }
    if (parsed.username || parsed.password) {
      return { valid: false, value: "", error: "URL 不得包含用户信息" };
    }
    if (parsed.search || parsed.hash) {
      return { valid: false, value: "", error: "URL 不得包含查询参数或片段" };
    }
    const pathname = parsed.pathname.replace(/\/+$/, "");
    return {
      valid: true,
      value: `${parsed.origin}${pathname}`,
      error: "",
    };
  }

  function credentialSpec(value) {
    const clean = String(value || "").trim();
    if (!clean) return { valid: false, value: null, error: "凭据不能为空" };
    if (clean.toLowerCase().startsWith("env:")) {
      const name = clean.slice(4).trim();
      if (!/^[A-Z_][A-Z0-9_]{0,99}$/.test(name)) {
        return { valid: false, value: null, error: "env 名称格式无效" };
      }
      return { valid: true, value: { mode: "env_ref", name }, error: "" };
    }
    return {
      valid: true,
      value: { mode: "ephemeral", api_key: clean },
      error: "",
    };
  }

  function parseOneModelTsv(text) {
    const sourceLines = String(text || "").split(/\r?\n/);
    const rows = [];
    const errors = [];
    sourceLines.forEach((line, sourceIndex) => {
      if (!line.trim()) return;
      const columns = line.split("\t");
      const header = columns.map((column) => column.trim().toLowerCase());
      if (
        rows.length === 0
        && header[0] === "station_name"
        && ["url", "base_url"].includes(header[1])
      ) return;
      if (columns.length < 3 || columns.length > 4) {
        errors.push({ row: sourceIndex + 1, message: "需要 3 或 4 个 TSV 列" });
        return;
      }
      rows.push({
        sourceRow: sourceIndex + 1,
        stationName: columns[0].trim(),
        baseUrl: columns[1].trim(),
        credentialText: columns[2].trim(),
        modelId: (columns[3] || "").trim(),
      });
    });
    if (rows.length > 20) errors.push({ row: 0, message: "单批最多 20 个中转站" });
    return { rows: rows.slice(0, 20), errors };
  }

  function validateOneModelTargets(rows, defaultModelId) {
    const fallbackModel = String(defaultModelId || "").trim();
    const errors = [];
    const seen = new Set();
    const targets = [];
    if (!fallbackModel) errors.push({ row: 0, message: "默认模型 ID 不能为空" });
    if (!Array.isArray(rows) || rows.length < 1 || rows.length > 20) {
      errors.push({ row: 0, message: "目标数量必须为 1–20" });
      return { valid: false, targets, errors };
    }
    rows.forEach((row, index) => {
      const rowNumber = Number(row?.sourceRow) || index + 1;
      const stationName = String(row?.stationName || "").trim();
      const modelId = String(row?.modelId || "").trim();
      if (!stationName || stationName.length > 80) {
        errors.push({ row: rowNumber, message: "站点名需要 1–80 个字符" });
      }
      if (modelId.length > 255) {
        errors.push({ row: rowNumber, message: "模型别名不能超过 255 个字符" });
      }
      const normalizedUrl = normalizeOneModelBaseUrl(row?.baseUrl);
      if (!normalizedUrl.valid) {
        errors.push({ row: rowNumber, message: normalizedUrl.error });
      }
      const credential = credentialSpec(row?.credentialText);
      if (!credential.valid) {
        errors.push({ row: rowNumber, message: credential.error });
      }
      const effectiveModel = modelId || fallbackModel;
      const identity = `${normalizedUrl.value.toLowerCase()}\u0000${effectiveModel}`;
      if (normalizedUrl.valid && effectiveModel && seen.has(identity)) {
        errors.push({ row: rowNumber, message: "URL 与实际模型组合重复" });
      }
      if (normalizedUrl.valid && effectiveModel) seen.add(identity);
      targets.push({
        row_id: `row-${String(index + 1).padStart(2, "0")}`,
        station_name: stationName,
        base_url: normalizedUrl.value,
        credential: credential.value,
        model_id: modelId || null,
      });
    });
    return { valid: errors.length === 0, targets, errors };
  }

  function oneModelRequestEstimate(targetCount) {
    const count = Math.max(0, Math.min(20, Number(targetCount) || 0));
    return {
      referenceRequests: ONE_MODEL_REFERENCE_REQUESTS,
      targetRequests: count * ONE_MODEL_TARGET_REQUESTS,
      totalRequests: ONE_MODEL_REFERENCE_REQUESTS + count * ONE_MODEL_TARGET_REQUESTS,
    };
  }

  return Object.freeze({
    LEGACY_PROFILE_ID,
    PAPER_PROFILE_ID,
    profiles,
    normalizeProfileId,
    profile,
    referenceProfileId,
    settingsForProfile,
    mappingProfileSummary,
    requestCount,
    referenceCollectionRequest,
    protocolProfiles,
    ONE_MODEL_REFERENCE_REQUESTS,
    ONE_MODEL_TARGET_REQUESTS,
    transportProfileForProtocol,
    normalizeOneModelBaseUrl,
    credentialSpec,
    parseOneModelTsv,
    validateOneModelTargets,
    oneModelRequestEstimate,
  });
});
