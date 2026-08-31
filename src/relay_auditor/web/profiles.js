(function exposeRelayProfiles(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.RelayProfiles = api;
})(typeof globalThis !== "undefined" ? globalThis : this, () => {
  const LEGACY_PROFILE_ID = "legacy-one-token/v1";
  const PAPER_PROFILE_ID = "bruckner-2026-canonical40/v1";

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
  });
});
