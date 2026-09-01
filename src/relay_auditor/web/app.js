const presets = {
  quick: { cells: 4, samples: 15, label: "快速" },
  standard: { cells: 8, samples: 25, label: "标准" },
  strict: { cells: 16, samples: 25, label: "严格" },
};

const relayStatus = window.RelayStatus;
const relayProfiles = window.RelayProfiles;
const verdictLabels = {
  match: "较一致",
  uncertain: "不确定",
  mismatch: "明显不一致",
  insufficient: "证据不足",
  error: "执行失败",
  running: "执行中",
  queued: "等待执行",
  paused: "已暂停",
  pausing: "暂停中",
  canceling: "取消中",
  canceled: "已取消",
  interrupted: "服务重启中断",
  ...(relayStatus?.statusLabels || {}),
  unverifiable: "不可验证",
};

// Legacy compatibility marker: relay-auditor.workspace.v1. Browser persistence is disabled.
let restoringWorkspace = false;

const state = {
  references: [],
  referenceModels: new Map(),
  observedRuns: [],
  running: true,
  ready: false,
  busySources: {
    initialization: true,
    transient: false,
    reference: false,
    comparison: false,
  },
  targetSequence: 0,
  activeReferenceCollectionId: null,
  activeReferenceCollectionStatus: null,
  referenceCollectionPollTimer: null,
  referenceRecoveryBlocked: false,
  activeBatchId: null,
  activeBatchStatus: null,
  batchPollTimer: null,
  comparisonRecoveryError: "",
  comparisonRecoveryBlocked: false,
  referenceSets: [],
  activeReferenceSetId: null,
  activeReferenceSetStatus: null,
  referenceSetPollTimer: null,
  oneModelTargetSequence: 0,
  oneModelBatchId: null,
  oneModelBatchStatus: null,
  oneModelBatchItems: [],
  oneModelBatchPollTimer: null,
};

const elements = {
  referenceForm: document.querySelector("#reference-form"),
  referenceName: document.querySelector("#reference-name"),
  referenceUrl: document.querySelector("#reference-url"),
  referenceKey: document.querySelector("#reference-key"),
  referenceManualModel: document.querySelector("#reference-manual-model"),
  methodProfile: document.querySelector("#method-profile"),
  methodProfileNote: document.querySelector("#method-profile-note"),
  referenceBadge: document.querySelector("#reference-badge"),
  referenceModelList: document.querySelector("#reference-model-list"),
  referenceModelCount: document.querySelector("#reference-model-count"),
  referenceProgress: document.querySelector("#reference-progress"),
  activeReferencePanel: document.querySelector("#active-reference-panel"),
  activeReferenceStatus: document.querySelector("#active-reference-status"),
  activeReferenceCounts: document.querySelector("#active-reference-counts"),
  activeReferenceCurrent: document.querySelector("#active-reference-current"),
  activeReferenceList: document.querySelector("#active-reference-list"),
  pauseReference: document.querySelector("#pause-reference"),
  cancelReference: document.querySelector("#cancel-reference"),
  retryReferenceRecovery: document.querySelector("#retry-reference-recovery"),
  referenceLibrary: document.querySelector("#reference-library"),
  referenceLibraryEmpty: document.querySelector("#reference-library-empty"),
  fetchReferenceModels: document.querySelector("#fetch-reference-models"),
  addReferenceModel: document.querySelector("#add-reference-model"),
  selectAllReferenceModels: document.querySelector("#select-all-reference-models"),
  clearReferenceModels: document.querySelector("#clear-reference-models"),
  refreshReferences: document.querySelector("#refresh-references"),
  preset: document.querySelector("#preset"),
  concurrencyMode: document.querySelector("#concurrency-mode"),
  concurrency: document.querySelector("#concurrency"),
  concurrencyNote: document.querySelector("#concurrency-note"),
  requestTimeout: document.querySelector("#request-timeout"),
  modelTimeout: document.querySelector("#model-timeout"),
  requestEstimate: document.querySelector("#request-estimate"),
  timeEstimate: document.querySelector("#time-estimate"),
  timeEstimateNote: document.querySelector("#time-estimate-note"),
  targetList: document.querySelector("#target-list"),
  targetTemplate: document.querySelector("#target-template"),
  mappingTemplate: document.querySelector("#mapping-template"),
  addTarget: document.querySelector("#add-target"),
  runAll: document.querySelector("#run-all"),
  retryComparisonRecovery: document.querySelector("#retry-comparison-recovery"),
  pauseBatch: document.querySelector("#pause-batch"),
  cancelBatch: document.querySelector("#cancel-batch"),
  activeBatchPanel: document.querySelector("#active-batch-panel"),
  activeBatchStatus: document.querySelector("#active-batch-status"),
  activeBatchCounts: document.querySelector("#active-batch-counts"),
  activeBatchList: document.querySelector("#active-batch-list"),
  mappingSummary: document.querySelector("#mapping-summary"),
  mappingTimeEstimate: document.querySelector("#mapping-time-estimate"),
  clearKeys: document.querySelector("#clear-keys"),
  emptyResults: document.querySelector("#empty-results"),
  results: document.querySelector("#results"),
  appHealth: document.querySelector("#app-health"),
  workspaceStatus: document.querySelector("#workspace-status"),
  resetWorkspace: document.querySelector("#reset-workspace"),
  resultsTitle: document.querySelector("#results-title"),
  oneModelApiStatus: document.querySelector("#one-model-api-status"),
  referenceSetForm: document.querySelector("#reference-set-form"),
  referenceSetName: document.querySelector("#reference-set-name"),
  referenceSourceType: document.querySelector("#reference-source-type"),
  referenceProtocol: document.querySelector("#reference-protocol"),
  referenceTransportProfile: document.querySelector("#reference-transport-profile"),
  referenceLogicalModel: document.querySelector("#reference-logical-model"),
  referenceActualModel: document.querySelector("#reference-actual-model"),
  referenceSetUrl: document.querySelector("#reference-set-url"),
  referenceCredentialMode: document.querySelector("#reference-credential-mode"),
  referenceEphemeralWrap: document.querySelector("#reference-ephemeral-wrap"),
  referenceSetKey: document.querySelector("#reference-set-key"),
  referenceEnvWrap: document.querySelector("#reference-env-wrap"),
  referenceSetEnv: document.querySelector("#reference-set-env"),
  anthropicWorkspaceWrap: document.querySelector("#anthropic-workspace-wrap"),
  anthropicWorkspaceId: document.querySelector("#anthropic-workspace-id"),
  referenceSetFormMessage: document.querySelector("#reference-set-form-message"),
  referenceSetProgress: document.querySelector("#reference-set-progress"),
  referenceSetProgressTitle: document.querySelector("#reference-set-progress-title"),
  referenceSetProgressMeta: document.querySelector("#reference-set-progress-meta"),
  referenceSetPause: document.querySelector("#reference-set-pause"),
  referenceSetCancel: document.querySelector("#reference-set-cancel"),
  referenceSetMembers: document.querySelector("#reference-set-members"),
  referenceSetDistances: document.querySelector("#reference-set-distances"),
  refreshReferenceSets: document.querySelector("#refresh-reference-sets"),
  readyReferenceSets: document.querySelector("#ready-reference-sets"),
  oneModelReferenceSelect: document.querySelector("#one-model-reference-select"),
  oneModelDefaultModel: document.querySelector("#one-model-default-model"),
  oneModelMaxStations: document.querySelector("#one-model-max-stations"),
  oneModelPerStation: document.querySelector("#one-model-per-station"),
  oneModelGlobalConcurrency: document.querySelector("#one-model-global-concurrency"),
  oneModelTsv: document.querySelector("#one-model-tsv"),
  importOneModelTsv: document.querySelector("#import-one-model-tsv"),
  addOneModelTarget: document.querySelector("#add-one-model-target"),
  clearOneModelTargets: document.querySelector("#clear-one-model-targets"),
  oneModelImportMessage: document.querySelector("#one-model-import-message"),
  oneModelTargetRows: document.querySelector("#one-model-target-rows"),
  oneModelTargetCount: document.querySelector("#one-model-target-count"),
  oneModelTargetEstimate: document.querySelector("#one-model-target-estimate"),
  oneModelTotalEstimate: document.querySelector("#one-model-total-estimate"),
  runOneModelBatch: document.querySelector("#run-one-model-batch"),
  oneModelResultFilter: document.querySelector("#one-model-result-filter"),
  oneModelResultSort: document.querySelector("#one-model-result-sort"),
  oneModelJsonDownload: document.querySelector("#one-model-json-download"),
  oneModelCsvDownload: document.querySelector("#one-model-csv-download"),
  oneModelBatchStatus: document.querySelector("#one-model-batch-status"),
  oneModelBatchMeta: document.querySelector("#one-model-batch-meta"),
  oneModelPause: document.querySelector("#one-model-pause"),
  oneModelCancel: document.querySelector("#one-model-cancel"),
  oneModelResultRows: document.querySelector("#one-model-result-rows"),
};

function setWorkspaceStatus(message) {
  if (elements.workspaceStatus) elements.workspaceStatus.textContent = message;
}

function saveWorkspaceNow() {
  if (restoringWorkspace) return;
  setWorkspaceStatus("配置仅保留在当前页面 · Key 不写浏览器存储");
}

function scheduleWorkspaceSave() {
  if (restoringWorkspace) return;
  saveWorkspaceNow();
}

function restoreWorkspace() {
  // Deliberately fail closed: form values, URLs, model mappings and credentials
  // are not reconstructed from any browser persistence API.
  return false;
}

function seedDefaultWorkspace() {
  elements.referenceName.value = "Local Mock";
  elements.referenceUrl.value = "http://127.0.0.1:8000/mock/v1";
  elements.referenceManualModel.value = "reference-model";
  elements.methodProfile.value = relayProfiles.PAPER_PROFILE_ID;
  elements.preset.value = "standard";
  elements.concurrencyMode.value = "auto";
  elements.concurrency.value = "4";
  elements.requestTimeout.value = "15";
  elements.modelTimeout.value = "300";
  state.referenceModels.clear();
  state.referenceModels.set("reference-model", true);
  elements.targetList.replaceChildren();
  state.targetSequence = 0;
  addTarget({ name: "Local Mock 中转站", baseUrl: "http://127.0.0.1:8000/mock/v1" });
  renderReferenceModelPicker();
}

function settings(profileId = elements.methodProfile.value) {
  const preset = presets[elements.preset.value] || presets.standard;
  const legacySettings = {
    cells: preset.cells,
    samples: preset.samples,
    concurrencyMode: elements.concurrencyMode.value === "fixed" ? "fixed" : "auto",
    concurrency: Number(elements.concurrency.value) || 4,
    requestTimeoutSeconds: Number(elements.requestTimeout.value) || 15,
    modelTimeoutSeconds: Number(elements.modelTimeout.value) || 300,
  };
  return relayProfiles.settingsForProfile(profileId, legacySettings);
}

function targetCards() {
  return [...elements.targetList.querySelectorAll(".station-card")];
}

function selectedReferenceModels() {
  return [...state.referenceModels.entries()]
    .filter(([, selected]) => selected)
    .map(([model]) => model);
}

function connectionPayload(urlInput, keyInput) {
  const endpoint = { base_url: urlInput.value.trim() };
  const apiKey = keyInput.value.trim();
  if (apiKey) endpoint.api_key = apiKey;
  return endpoint;
}

function endpointPayload(urlInput, model, keyInput) {
  return { ...connectionPayload(urlInput, keyInput), model };
}

async function requestJson(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
  });
  let body;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    const rawDetail = body?.detail;
    const detail = Array.isArray(rawDetail)
      ? rawDetail.map((item) => item.msg || JSON.stringify(item)).join("；")
      : rawDetail && typeof rawDetail === "object"
        ? rawDetail.message || JSON.stringify(rawDetail)
        : rawDetail || `HTTP ${response.status}`;
    const error = new Error(detail);
    error.status = response.status;
    error.detail = rawDetail;
    error.body = body;
    throw error;
  }
  return body;
}

function postJson(path, payload) {
  return requestJson(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
}

function deleteJson(path) {
  return requestJson(path, { method: "DELETE" });
}

function formatNumber(value, digits = 3) {
  return typeof value === "number" && Number.isFinite(value) ? value.toFixed(digits) : "—";
}

function formatDuration(value) {
  if (typeof value !== "number") return "—";
  if (value < 1000) return `${Math.round(value)} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

function formatClockDuration(value) {
  const milliseconds = Math.max(0, Number(value) || 0);
  if (milliseconds < 1000) return "<1 秒";
  const seconds = Math.ceil(milliseconds / 1000);
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  if (minutes < 60) return rest ? `${minutes} 分 ${rest} 秒` : `${minutes} 分钟`;
  const hours = Math.floor(minutes / 60);
  const restMinutes = minutes % 60;
  return restMinutes ? `${hours} 小时 ${restMinutes} 分` : `${hours} 小时`;
}

function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function scaledDuration(run, current) {
  if (!run || !run.durationMs || !run.cells || !run.samples || !run.concurrency) return null;
  const previousWaves = (run.cells * run.samples) / run.concurrency;
  const estimateConcurrency = current.concurrencyMode === "auto" ? 1 : current.concurrency;
  const currentWaves = (current.cells * current.samples) / estimateConcurrency;
  return previousWaves > 0 ? run.durationMs * (currentWaves / previousWaves) : null;
}

function estimateDuration(modelCount, current = settings()) {
  if (!modelCount) return { lowMs: 0, highMs: 0, perModelMs: 0, historical: false };
  const historical = [...state.observedRuns, ...state.references]
    .map((run) => scaledDuration(run, current))
    .filter((value) => typeof value === "number" && Number.isFinite(value) && value > 0);
  const historicalMedian = median(historical);
  if (historicalMedian !== null) {
    return {
      lowMs: historicalMedian * 0.75 * modelCount,
      highMs: historicalMedian * 1.5 * modelCount,
      perModelMs: historicalMedian,
      historical: true,
    };
  }
  const estimateConcurrency = current.concurrencyMode === "auto" ? 1 : current.concurrency;
  const waves = Math.ceil((current.cells * current.samples) / estimateConcurrency);
  return {
    lowMs: (waves * 1200 + 5000) * modelCount,
    highMs: (waves * 4000 + 15000) * modelCount,
    perModelMs: waves * 2500 + 10000,
    historical: false,
  };
}

function durationRangeText(estimate) {
  if (!estimate.lowMs && !estimate.highMs) return "—";
  const low = formatClockDuration(estimate.lowMs);
  const high = formatClockDuration(estimate.highMs);
  return low === high ? `约 ${low}` : `约 ${low}–${high}`;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString("zh-CN", { hour12: false });
}

function adapterText(adapter) {
  if (!adapter) return "—";
  if (adapter.postReasoning) return "推理后置通道";
  return adapter.strategy || "none";
}

function setBusy(busy, source = "transient") {
  state.busySources[source] = Boolean(busy);
  const anyBusy = Object.values(state.busySources).some(Boolean);
  state.running = anyBusy;
  document.body.classList.toggle("is-busy", anyBusy);
  document.querySelectorAll("button, input, select").forEach((node) => {
    node.disabled = anyBusy && node.dataset.allowBusy !== "true";
  });
  if (!anyBusy) {
    updateControls();
    updateOneModelTargetValidation();
  }
}

function normalizeReference(item) {
  const baseline = item.baseline || {};
  const endpoint = item.endpoint || {};
  const metadata = baseline.metadata || {};
  return {
    baselineId: baseline.id,
    artifactId: baseline.artifact_id,
    name: metadata.reference_name || endpoint.name || "参考端",
    model: endpoint.model || "",
    baseUrl: endpoint.base_url || "",
    provider: endpoint.provider || "",
    status: baseline.status || "unknown",
    validFrom: baseline.valid_from,
    expiresAt: baseline.expires_at,
    sha256: item.artifact_sha256 || "",
    evidenceAvailable: Boolean(item.evidence_available),
    durationMs: Number(item.duration_ms) || null,
    cells: Number(metadata.cells) || null,
    samples: Number(metadata.samples) || null,
    concurrency: Number(metadata.concurrency) || null,
    methodProfileId: relayProfiles.normalizeProfileId(
      item.method_profile_id || metadata.method_profile_id,
    ),
    protocol: item.protocol || metadata.protocol || "one-token/v1",
    samplesEvidenceAvailable: Boolean(
      item.samples_evidence_available || metadata.samples_evidence_available,
    ),
    rawEvidenceSha256: item.raw_evidence_sha256 || metadata.raw_evidence_sha256 || "",
  };
}

async function loadReferences() {
  try {
    const body = await requestJson("/api/v1/console/references");
    state.references = (body.items || []).map(normalizeReference);
    renderReferenceLibrary();
    refreshAllMappingOptions();
  } catch (error) {
    elements.referenceLibraryEmpty.classList.remove("hidden");
    elements.referenceLibraryEmpty.querySelector("strong").textContent = "参考模型库读取失败";
    elements.referenceLibraryEmpty.querySelector("p").textContent = error instanceof Error ? error.message : String(error);
  }
}

function showDeleteConfirmation(card, reference, deleteButton) {
  card.querySelector(".delete-confirmation")?.remove();
  deleteButton.disabled = true;
  const confirmation = document.createElement("div");
  confirmation.className = "delete-confirmation";
  confirmation.setAttribute("role", "alert");

  const message = document.createElement("div");
  const title = document.createElement("strong");
  const detail = document.createElement("small");
  title.textContent = `确认移除 ${reference.model}？`;
  detail.textContent = "将从参考模型库移除，但历史 JSON、运行记录与 SHA-256 证据会保留。";
  message.append(title, detail);

  const buttons = document.createElement("div");
  buttons.className = "delete-confirmation-actions";
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "button button-ghost";
  cancel.textContent = "取消";
  const confirm = document.createElement("button");
  confirm.type = "button";
  confirm.className = "button button-danger";
  confirm.textContent = "确认删除";
  buttons.append(cancel, confirm);
  confirmation.append(message, buttons);
  card.append(confirmation);

  cancel.addEventListener("click", () => {
    confirmation.remove();
    deleteButton.disabled = false;
  });
  confirm.addEventListener("click", async () => {
    confirm.disabled = true;
    cancel.disabled = true;
    confirm.textContent = "删除中…";
    try {
      await deleteJson(`/api/v1/console/references/${reference.baselineId}`);
      await loadReferences();
    } catch (error) {
      confirm.disabled = false;
      cancel.disabled = false;
      confirm.textContent = "重试删除";
      detail.className = "error-text";
      detail.textContent = error instanceof Error ? error.message : String(error);
    }
  });
}

function renderReferenceLibrary() {
  elements.referenceLibrary.replaceChildren();
  elements.referenceLibraryEmpty.classList.toggle("hidden", state.references.length > 0);
  state.references.forEach((reference) => {
    const card = document.createElement("article");
    card.className = "reference-item";

    const heading = document.createElement("div");
    heading.className = "reference-item-heading";
    const title = document.createElement("div");
    const name = document.createElement("strong");
    const model = document.createElement("code");
    name.textContent = reference.name;
    model.textContent = reference.model;
    title.append(name, model);
    const status = document.createElement("span");
    status.className = reference.methodProfileId === relayProfiles.PAPER_PROFILE_ID
      ? "badge badge-running"
      : "badge badge-muted";
    status.textContent = relayProfiles.profile(reference.methodProfileId).shortLabel;
    heading.append(title, status);

    const endpoint = document.createElement("p");
    endpoint.className = "reference-url";
    endpoint.textContent = reference.baseUrl;

    const meta = document.createElement("dl");
    [
      ["采集时间", formatDate(reference.validFrom)],
      ["采样耗时", reference.durationMs === null ? "—" : formatClockDuration(reference.durationMs)],
      ["指纹协议", relayProfiles.profile(reference.methodProfileId).label],
      ["有效期至", formatDate(reference.expiresAt)],
      ["SHA-256", reference.sha256 ? reference.sha256.slice(0, 16) : "—"],
      ["原始证据", reference.rawEvidenceSha256 ? reference.rawEvidenceSha256.slice(0, 16) : "—"],
    ].forEach(([key, value]) => {
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = key;
      dd.textContent = value;
      meta.append(dt, dd);
    });

    const actions = document.createElement("div");
    actions.className = "reference-actions";
    const artifact = document.createElement("span");
    artifact.textContent = `Artifact ${reference.artifactId.slice(0, 8)}`;
    actions.append(artifact);
    const actionButtons = document.createElement("div");
    actionButtons.className = "reference-action-buttons";
    if (reference.evidenceAvailable) {
      const download = document.createElement("a");
      download.className = "evidence-link";
      download.href = `/api/v1/console/evidence/${reference.artifactId}`;
      download.textContent = "下载指纹 JSON";
      actionButtons.append(download);
    }
    if (reference.samplesEvidenceAvailable) {
      const samplesDownload = document.createElement("a");
      samplesDownload.className = "evidence-link";
      samplesDownload.href = `/api/v1/console/evidence/${reference.artifactId}/samples`;
      samplesDownload.textContent = "下载原始 JSONL";
      actionButtons.append(samplesDownload);
    }
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "reference-delete";
    remove.textContent = "删除";
    remove.setAttribute("aria-label", `删除参考模型 ${reference.model}`);
    remove.addEventListener("click", () => showDeleteConfirmation(card, reference, remove));
    actionButtons.append(remove);
    actions.append(actionButtons);
    card.append(heading, endpoint, meta, actions);
    elements.referenceLibrary.append(card);
  });
}

function renderReferenceModelPicker() {
  elements.referenceModelList.replaceChildren();
  [...state.referenceModels.keys()]
    .sort((a, b) => a.localeCompare(b))
    .forEach((model) => {
      const label = document.createElement("label");
      label.className = "model-option";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = Boolean(state.referenceModels.get(model));
      checkbox.addEventListener("change", () => {
        state.referenceModels.set(model, checkbox.checked);
        updateControls();
      });
      const text = document.createElement("code");
      text.textContent = model;
      label.append(checkbox, text);
      elements.referenceModelList.append(label);
    });
  updateControls();
}

function addReferenceModel(model, selected = true) {
  const clean = model.trim();
  if (!clean) return;
  const current = state.referenceModels.get(clean);
  state.referenceModels.set(clean, current === undefined ? selected : current || selected);
  renderReferenceModelPicker();
  scheduleWorkspaceSave();
}

async function fetchReferenceModels() {
  if (!elements.referenceUrl.reportValidity()) return;
  setBusy(true);
  elements.referenceBadge.className = "badge badge-running";
  elements.referenceBadge.textContent = "读取中";
  try {
    const body = await postJson("/api/v1/console/models", {
      endpoint: connectionPayload(elements.referenceUrl, elements.referenceKey),
    });
    (body.models || []).forEach((item) => {
      if (!state.referenceModels.has(item.id)) state.referenceModels.set(item.id, false);
    });
    renderReferenceModelPicker();
    elements.referenceBadge.className = "badge badge-match";
    elements.referenceBadge.textContent = `发现 ${body.count} 个模型`;
  } catch (error) {
    elements.referenceBadge.className = "badge badge-error";
    elements.referenceBadge.textContent = "读取失败";
    showReferenceProgress(error instanceof Error ? error.message : String(error), "error");
  } finally {
    setBusy(false);
  }
}

function showReferenceProgress(message, level = "normal") {
  elements.referenceProgress.classList.remove("hidden");
  elements.referenceProgress.classList.toggle("error-text", level === "error");
  elements.referenceProgress.textContent = message;
}

function referenceCollectionIsTerminal(status) {
  return ["completed", "failed", "canceled", "interrupted"].includes(String(status || ""));
}

function referenceItemProgressText(item) {
  const progress = item.progress || {};
  const partial = relayStatus.partialEvidenceInfo(item);
  const retry = relayStatus.retryWaitingText(item);
  if (retry) return retry;
  if (item.status === "completed") return progress.detail || "参考指纹与证据已保存";
  if (item.status === "failed" || item.status === "interrupted") {
    const message = item.error_message || progress.detail || "参考采集未完成";
    const partialText = relayStatus.incompleteEvidenceText(partial);
    return partialText ? `${message} · ${partialText}` : message;
  }
  if (item.status === "canceled") {
    const partialText = relayStatus.incompleteEvidenceText(partial);
    return partialText ? `已取消 · ${partialText}` : "已取消，尚未产生可用参考指纹";
  }
  if (item.status === "paused") return progress.detail || "采集已暂停，可继续或取消";
  if (item.status === "canceling") return progress.detail || "正在停止当前采样请求";
  if (progress.stage === "sampling") {
    return `已收到 ${Number(progress.done) || 0}/${Number(progress.total) || 0} 个采样响应${progress.errors ? ` · ${progress.errors} 个错误` : ""}`;
  }
  return progress.detail || (item.status === "queued" ? "排队等待采集" : "正在准备参考采集");
}

function referenceItemStatus(item) {
  const operational = relayStatus.itemOperationalState(item);
  if (operational === "success") return { className: "match", label: "已保存" };
  if (operational === "failed") return { className: "error", label: "失败" };
  if (operational === "waiting") return { className: "waiting", label: relayStatus.itemStatusLabel(item) };
  if (operational === "canceled") return { className: "muted", label: "已取消" };
  if (operational === "paused") return { className: "uncertain", label: "已暂停" };
  if (operational === "running") return { className: "running", label: "采集中" };
  return { className: "muted", label: "排队 / 未执行" };
}

function renderReferenceCollectionItem(item) {
  const progress = item.progress || {};
  const partial = relayStatus.partialEvidenceInfo(item);
  const raw = relayStatus.rawSampleEvidenceInfo(item);
  const done = Number(progress.done) || 0;
  const total = Number(progress.total) || 0;
  const percent = total > 0 ? Math.min(100, (done / total) * 100) : 0;
  const statusInfo = referenceItemStatus(item);
  const task = document.createElement("article");
  task.className = `active-task${relayStatus.itemOperationalState(item) === "waiting" ? " is-waiting-retry" : ""}`;

  const name = document.createElement("div");
  name.className = "active-task-name";
  const label = document.createElement("strong");
  const model = document.createElement("code");
  label.textContent = "参考模型";
  model.textContent = item.model || "未知模型";
  name.append(label, model);

  const progressBox = document.createElement("div");
  progressBox.className = "active-task-progress";
  const description = document.createElement("p");
  description.textContent = referenceItemProgressText(item);
  const diagnostics = document.createElement("small");
  diagnostics.className = "task-network-diagnostics";
  diagnostics.textContent = relayStatus.progressDiagnostics(item).join(" · ");
  diagnostics.classList.toggle("hidden", !diagnostics.textContent);
  const track = document.createElement("div");
  track.className = "task-progress-track";
  const fill = document.createElement("i");
  fill.style.width = `${percent}%`;
  track.append(fill);
  progressBox.append(description, diagnostics, track);

  const meta = document.createElement("div");
  meta.className = "active-task-meta";
  const status = document.createElement("strong");
  status.className = `badge badge-${statusInfo.className}`;
  status.textContent = statusInfo.label;
  const updated = document.createElement("span");
  updated.textContent = progress.updated_at ? `更新于 ${formatDate(progress.updated_at)}` : "等待首次更新";
  const concurrency = document.createElement("span");
  const effective = Number(item.effective_concurrency);
  concurrency.textContent = Number.isFinite(effective) && effective > 0
    ? `实际并发 ${effective}${item.concurrency_reason ? ` · ${item.concurrency_reason}` : ""}`
    : item.concurrency_reason || "等待选择并发";
  const retries = document.createElement("span");
  const retryCount = Number(item.retry_count);
  retries.textContent = Number.isFinite(retryCount) && retryCount > 0
    ? `已重试 ${retryCount} 次`
    : "尚无重试";
  meta.append(status, updated, concurrency, retries);
  task.append(name, progressBox, meta);

  const actions = document.createElement("div");
  actions.className = "active-task-actions";
  if (item.artifact_id) {
    const evidence = document.createElement("a");
    evidence.className = `button button-ghost${partial.isPartial ? " partial-evidence-link" : ""}`;
    evidence.href = `/api/v1/console/evidence/${item.artifact_id}`;
    evidence.textContent = partial.isPartial ? "下载部分指纹 JSON" : "下载指纹 JSON";
    if (partial.isPartial) evidence.title = relayStatus.incompleteEvidenceText(partial);
    actions.append(evidence);
  }
  if (raw.available) {
    const samples = document.createElement("a");
    samples.className = "button button-ghost partial-evidence-link";
    samples.href = `/api/v1/console/evidence/${raw.artifactId}/samples`;
    samples.textContent = partial.isPartial ? "下载部分原始 JSONL" : "下载原始 JSONL";
    if (raw.sha256) samples.title = `SHA-256 ${raw.sha256}`;
    actions.append(samples);
  }
  if (actions.childElementCount) task.append(actions);
  return task;
}

function renderReferenceCollection(body, { recovered = false } = {}) {
  const batch = body?.batch;
  if (!batch) {
    state.referenceRecoveryBlocked = false;
    elements.retryReferenceRecovery.classList.add("hidden");
    elements.retryReferenceRecovery.disabled = false;
    state.activeReferenceCollectionId = null;
    state.activeReferenceCollectionStatus = null;
    elements.activeReferencePanel.classList.add("hidden");
    window.clearTimeout(state.referenceCollectionPollTimer);
    state.referenceCollectionPollTimer = null;
    setBusy(false, "reference");
    return;
  }

  const previousStatus = state.activeReferenceCollectionStatus;
  const items = Array.isArray(body.items) ? body.items : [];
  const summary = relayStatus.referenceCollectionSummary(items);
  state.activeReferenceCollectionId = batch.id;
  state.activeReferenceCollectionStatus = batch.status;
  state.referenceRecoveryBlocked = false;
  elements.retryReferenceRecovery.classList.add("hidden");
  elements.retryReferenceRecovery.disabled = false;
  const terminal = referenceCollectionIsTerminal(batch.status);
  const active = !terminal;
  elements.activeReferencePanel.classList.remove(
    "hidden", "is-paused", "is-complete", "is-canceled", "is-mixed",
  );
  elements.activeReferencePanel.classList.toggle("is-paused", batch.status === "paused");
  elements.activeReferencePanel.classList.toggle("is-complete", batch.status === "completed");
  elements.activeReferencePanel.classList.toggle("is-canceled", batch.status === "canceled");
  elements.activeReferencePanel.classList.toggle(
    "is-mixed",
    summary.failed > 0 || summary.canceled > 0 || summary.partial > 0,
  );
  const statusText = relayStatus.batchStatusLabel(batch.status, summary);
  elements.activeReferenceStatus.textContent = `${recovered ? "已恢复 · " : ""}${statusText}`;
  elements.activeReferenceCounts.replaceChildren();
  [
    ["success", "成功", summary.success],
    ["failed", "失败", summary.failed],
    ["partial", "部分证据", summary.partial],
    ["canceled", "取消", summary.canceled],
    ["queued", "排队", summary.queued],
    ["running", "运行", summary.running],
    ["paused", "暂停", summary.paused],
  ].forEach(([key, label, count]) => {
    const node = document.createElement("span");
    node.className = `batch-state-count is-${key}`;
    node.textContent = `${label} ${count}`;
    elements.activeReferenceCounts.append(node);
  });
  elements.activeReferenceCurrent.textContent = summary.currentModel
    ? `当前模型：${summary.currentModel} · 已完成 ${Number(batch.completed_items) || summary.success}/${Number(batch.total_items) || items.length}`
    : `已完成 ${Number(batch.completed_items) || summary.success}/${Number(batch.total_items) || items.length}`;
  elements.activeReferenceList.replaceChildren();
  items.forEach((item) => elements.activeReferenceList.append(renderReferenceCollectionItem(item)));

  elements.referenceBadge.className = terminal
    ? summary.failed || summary.partial ? "badge badge-uncertain" : "badge badge-match"
    : batch.status === "paused" ? "badge badge-uncertain" : "badge badge-running";
  elements.referenceBadge.textContent = terminal
    ? `${summary.success} 成功 / ${summary.failed} 失败`
    : summary.currentModel ? `正在采集 ${summary.currentModel}` : statusText;
  showReferenceProgress(
    `${statusText} · 成功 ${summary.success}、失败 ${summary.failed}、部分证据 ${summary.partial}、排队 ${summary.queued}。刷新页面会自动恢复此任务。`,
    batch.status === "failed" ? "error" : "normal",
  );

  setBusy(active, "reference");
  const pauseable = ["running", "pausing", "paused"].includes(batch.status);
  const cancelable = ["running", "pausing", "paused", "canceling"].includes(batch.status);
  elements.pauseReference.classList.toggle("hidden", !pauseable);
  elements.cancelReference.classList.toggle("hidden", !cancelable);
  elements.pauseReference.disabled = !pauseable || batch.status === "pausing";
  elements.cancelReference.disabled = !cancelable || batch.status === "canceling";
  elements.pauseReference.textContent = batch.status === "paused" ? "继续采集" : "暂停采集";

  if (terminal) {
    window.clearTimeout(state.referenceCollectionPollTimer);
    state.referenceCollectionPollTimer = null;
    if (previousStatus && !referenceCollectionIsTerminal(previousStatus)) loadReferences();
  }
}

function scheduleReferenceCollectionPoll(delay = 1000) {
  window.clearTimeout(state.referenceCollectionPollTimer);
  if (!state.activeReferenceCollectionId
    || referenceCollectionIsTerminal(state.activeReferenceCollectionStatus)) return;
  state.referenceCollectionPollTimer = window.setTimeout(pollReferenceCollection, delay);
}

async function pollReferenceCollection() {
  if (!state.activeReferenceCollectionId) return;
  try {
    const body = await requestJson(
      `/api/v1/console/reference-collections/${state.activeReferenceCollectionId}`,
    );
    renderReferenceCollection(body);
    scheduleReferenceCollectionPoll();
  } catch (error) {
    elements.activeReferencePanel.classList.remove("hidden");
    elements.activeReferenceStatus.textContent = `参考采集状态读取失败：${error instanceof Error ? error.message : String(error)}`;
    showReferenceProgress(elements.activeReferenceStatus.textContent, "error");
    scheduleReferenceCollectionPoll(3000);
  }
}

async function recoverReferenceCollection(collectionId, message = "已恢复正在执行的参考采集") {
  const body = await requestJson(`/api/v1/console/reference-collections/${collectionId}`);
  state.referenceRecoveryBlocked = false;
  renderReferenceCollection(body, { recovered: true });
  showReferenceProgress(`${message} · 批次 ${String(collectionId).slice(0, 8)}`);
  scheduleReferenceCollectionPoll();
  return true;
}

async function loadActiveReferenceCollection() {
  state.referenceRecoveryBlocked = true;
  elements.retryReferenceRecovery.disabled = true;
  updateControls();
  try {
    const body = await requestJson("/api/v1/console/reference-collections/active");
    if (!body?.batch) {
      renderReferenceCollection({ batch: null, items: [] });
      return false;
    }
    renderReferenceCollection(body, { recovered: true });
    scheduleReferenceCollectionPoll();
    return true;
  } catch (error) {
    state.referenceRecoveryBlocked = true;
    setBusy(false, "reference");
    elements.activeReferencePanel.classList.remove("hidden");
    elements.retryReferenceRecovery.classList.remove("hidden");
    elements.retryReferenceRecovery.disabled = false;
    elements.pauseReference.classList.add("hidden");
    elements.cancelReference.classList.add("hidden");
    elements.activeReferenceStatus.textContent = `参考采集恢复失败：${error instanceof Error ? error.message : String(error)}`;
    elements.activeReferenceCurrent.textContent = "无法确认是否已有任务；请先检查本地服务并点击“重试恢复”，确认完成前不会允许创建新批次。";
    showReferenceProgress(elements.activeReferenceStatus.textContent, "error");
    return false;
  }
}

async function collectReferences(event) {
  event.preventDefault();
  if (!state.ready || state.running || state.referenceRecoveryBlocked
    || !elements.referenceForm.reportValidity()) return;
  const models = selectedReferenceModels();
  if (!models.length) {
    showReferenceProgress("请至少选择一个待采集模型。", "error");
    return;
  }
  const current = settings();
  const payload = relayProfiles.referenceCollectionRequest({
    referenceName: elements.referenceName.value,
    endpoint: connectionPayload(elements.referenceUrl, elements.referenceKey),
    models,
    profileId: current.methodProfileId,
    settings: current,
    validDays: 14,
  });
  setBusy(true, "reference");
  elements.referenceBadge.className = "badge badge-running";
  elements.referenceBadge.textContent = "正在创建后台批次";
  showReferenceProgress(`正在提交 ${models.length} 个参考模型；创建后刷新页面也会继续执行。`);
  try {
    const body = await postJson("/api/v1/console/reference-collections", payload);
    renderReferenceCollection(body);
    scheduleReferenceCollectionPoll();
  } catch (error) {
    const existingId = error?.status === 409 ? relayStatus.conflictBatchId(error) : "";
    if (existingId) {
      try {
        await recoverReferenceCollection(existingId, "检测到已有参考采集，已重新关联");
        return;
      } catch (recoveryError) {
        state.referenceRecoveryBlocked = true;
        elements.activeReferencePanel.classList.remove("hidden");
        elements.retryReferenceRecovery.classList.remove("hidden");
        elements.retryReferenceRecovery.disabled = false;
        elements.pauseReference.classList.add("hidden");
        elements.cancelReference.classList.add("hidden");
        elements.activeReferenceStatus.textContent = `已有参考采集 ${existingId}，但恢复失败`;
        elements.activeReferenceCurrent.textContent = "请检查本地服务并点击“重试恢复”；确认完成前不会允许创建新批次。";
        showReferenceProgress(
          `已有参考采集 ${existingId}，但恢复失败：${recoveryError instanceof Error ? recoveryError.message : String(recoveryError)}`,
          "error",
        );
      }
    } else if (error?.status === 409) {
      state.referenceRecoveryBlocked = true;
      elements.activeReferencePanel.classList.remove("hidden");
      elements.retryReferenceRecovery.classList.remove("hidden");
      elements.retryReferenceRecovery.disabled = false;
      elements.pauseReference.classList.add("hidden");
      elements.cancelReference.classList.add("hidden");
      elements.activeReferenceStatus.textContent = "后端报告已有参考采集，但未返回批次 ID";
      elements.activeReferenceCurrent.textContent = "请点击“重试恢复”从活动任务接口重新关联；确认完成前不会允许创建新批次。";
      showReferenceProgress(
        `参考采集任务冲突：${error instanceof Error ? error.message : String(error)}`,
        "error",
      );
    } else {
      showReferenceProgress(
        `参考采集任务创建失败：${error instanceof Error ? error.message : String(error)}`,
        "error",
      );
    }
    setBusy(false, "reference");
    elements.referenceBadge.className = "badge badge-error";
    elements.referenceBadge.textContent = "创建失败";
  }
}

async function pauseOrResumeReferenceCollection() {
  if (!state.activeReferenceCollectionId) return;
  elements.pauseReference.disabled = true;
  const action = state.activeReferenceCollectionStatus === "paused" ? "resume" : "pause";
  try {
    const body = await postJson(
      `/api/v1/console/reference-collections/${state.activeReferenceCollectionId}/${action}`,
      {},
    );
    renderReferenceCollection(body);
    scheduleReferenceCollectionPoll();
  } catch (error) {
    elements.activeReferenceStatus.textContent = `参考采集操作失败：${error instanceof Error ? error.message : String(error)}`;
    elements.pauseReference.disabled = false;
  }
}

async function cancelReferenceCollection() {
  if (!state.activeReferenceCollectionId) return;
  const confirmed = window.confirm("取消参考采集？已完成与部分采样证据会保留，尚未执行的模型将停止。");
  if (!confirmed) return;
  elements.cancelReference.disabled = true;
  try {
    const body = await postJson(
      `/api/v1/console/reference-collections/${state.activeReferenceCollectionId}/cancel`,
      {},
    );
    renderReferenceCollection(body);
    scheduleReferenceCollectionPoll();
  } catch (error) {
    elements.activeReferenceStatus.textContent = `取消参考采集失败：${error instanceof Error ? error.message : String(error)}`;
    elements.cancelReference.disabled = false;
  }
}

async function retryReferenceRecovery() {
  elements.retryReferenceRecovery.disabled = true;
  showReferenceProgress("正在重新检查后台参考采集…");
  await loadActiveReferenceCollection();
}

function populateReferenceSelect(select, targetModel, preferredArtifactId = "") {
  select.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = state.references.length ? "选择参考模型" : "参考模型库为空";
  select.append(placeholder);

  const sorted = [...state.references].sort((a, b) => {
    const exactA = a.model === targetModel ? 0 : 1;
    const exactB = b.model === targetModel ? 0 : 1;
    return exactA - exactB || a.model.localeCompare(b.model);
  });
  sorted.forEach((reference) => {
    const option = document.createElement("option");
    option.value = reference.artifactId;
    option.textContent = `[${relayProfiles.profile(reference.methodProfileId).shortLabel}] ${reference.name} · ${reference.model}`;
    select.append(option);
  });
  const selection = relayStatus.referenceSelection(
    state.references,
    targetModel,
    preferredArtifactId,
  );
  select.value = selection.artifactId;
  select.dataset.preferredArtifactId = preferredArtifactId || selection.artifactId;
  select.dataset.preferredUnavailable = selection.preferredUnavailable ? "true" : "";
  if (selection.preferredUnavailable) {
    placeholder.textContent = "指定的历史参考已不可用，请重新选择";
  }
  select.disabled = state.running || state.references.length === 0;
  return selection;
}

function updateMappingStatus(row) {
  const select = row.querySelector(".mapping-reference");
  const enabled = row.querySelector(".mapping-enabled");
  const status = row.querySelector(".mapping-state");
  const reference = state.references.find((item) => item.artifactId === select.value);
  if (select.dataset.preferredUnavailable === "true") {
    status.className = "mapping-state badge badge-uncertain";
    status.textContent = "历史参考不可用";
    status.title = "历史记录指定的参考指纹已不存在，请手动重新选择；系统不会改用同名模型。";
    return;
  }
  if (!reference) {
    status.className = "mapping-state badge badge-muted";
    status.textContent = row.dataset.missingFromDiscovery === "true" ? "未发现 · 已保留" : "未映射";
    status.title = row.dataset.missingFromDiscovery === "true"
      ? "最新模型列表未返回此模型，已保留其原有配置。"
      : "";
    return;
  }
  status.className = enabled.checked
    ? "mapping-state badge badge-match"
    : "mapping-state badge badge-muted";
  const mappedText = enabled.checked ? "已启用" : "已映射";
  const profileText = relayProfiles.profile(reference.methodProfileId).shortLabel;
  status.textContent = row.dataset.missingFromDiscovery === "true"
    ? `${mappedText} · ${profileText} · 未发现`
    : `${mappedText} · ${profileText}`;
  status.title = row.dataset.missingFromDiscovery === "true"
    ? "最新模型列表未返回此模型，已保留其原有映射。"
    : "";
}

function applyMappingEnabledState(row, enabledIntent) {
  const select = row.querySelector(".mapping-reference");
  const enabled = row.querySelector(".mapping-enabled");
  const mappingState = relayStatus.mappingEnabledState(
    enabledIntent,
    select.dataset.preferredUnavailable === "true",
  );
  row.dataset.enabledIntent = mappingState.enabledIntent ? "true" : "false";
  row.dataset.referenceAutoDisabled = mappingState.autoDisabled ? "true" : "";
  enabled.checked = mappingState.checked;
  return mappingState;
}

function addTargetModel(card, model, values = {}) {
  const clean = model.trim();
  if (!clean) return null;
  const existing = [...card.querySelectorAll(".mapping-row")].find(
    (row) => row.dataset.model === clean,
  );
  if (existing) return existing;

  const fragment = elements.mappingTemplate.content.cloneNode(true);
  const row = fragment.querySelector(".mapping-row");
  row.dataset.model = clean;
  row.dataset.modelSource = values.source || "retained";
  row.dataset.missingFromDiscovery = values.missingFromDiscovery ? "true" : "";
  row.querySelector(".mapping-model").textContent = clean;
  const select = row.querySelector(".mapping-reference");
  populateReferenceSelect(select, clean, values.referenceArtifactId || "");
  const priority = row.querySelector(".mapping-priority");
  const savedPriority = Number(values.priority);
  priority.value = [80, 50, 20].includes(savedPriority) ? String(savedPriority) : "50";
  const enabled = row.querySelector(".mapping-enabled");
  const enabledIntent = values.enabled === undefined
    ? Boolean(select.value)
    : Boolean(values.enabled);
  applyMappingEnabledState(row, enabledIntent);
  enabled.addEventListener("change", () => {
    row.dataset.enabledIntent = enabled.checked ? "true" : "false";
    row.dataset.referenceAutoDisabled = "";
    updateMappingStatus(row);
    updateControls();
  });
  select.addEventListener("change", () => {
    select.dataset.preferredArtifactId = select.value;
    select.dataset.preferredUnavailable = "";
    applyMappingEnabledState(row, Boolean(select.value));
    updateMappingStatus(row);
    updateControls();
  });
  card.querySelector(".mapping-list").append(row);
  card.querySelector(".mapping-block").classList.remove("hidden");
  updateMappingStatus(row);
  updateControls();
  scheduleWorkspaceSave();
  return row;
}

function refreshAllMappingOptions() {
  targetCards().forEach((card) => {
    card.querySelectorAll(".mapping-row").forEach((row) => {
      const select = row.querySelector(".mapping-reference");
      const previous = select.dataset.preferredArtifactId || select.value;
      populateReferenceSelect(select, row.dataset.model, previous);
      applyMappingEnabledState(row, row.dataset.enabledIntent === "true");
      updateMappingStatus(row);
    });
  });
  updateControls();
}

async function fetchTargetModels(card) {
  const url = card.querySelector(".target-url");
  const key = card.querySelector(".target-key");
  if (!url.reportValidity()) return;
  setBusy(true);
  setTargetState(card, "running", "读取中", "正在请求 GET /models…");
  try {
    const body = await postJson("/api/v1/console/models", {
      endpoint: connectionPayload(url, key),
    });
    const list = card.querySelector(".mapping-list");
    const existing = [...card.querySelectorAll(".mapping-row")].map((row) => {
      const select = row.querySelector(".mapping-reference");
      return {
        model: row.dataset.model,
        referenceArtifactId: select.dataset.preferredArtifactId || select.value,
        enabled: row.dataset.enabledIntent === "true",
        priority: Number(row.querySelector(".mapping-priority").value) || 50,
        source: row.dataset.modelSource || "retained",
      };
    });
    const merged = relayStatus.mergeTargetModelMappings(existing, body.models || []);
    list.replaceChildren();
    merged.forEach((item) => addTargetModel(card, item.model, item));
    const retainedCount = merged.filter((item) => item.missingFromDiscovery).length;
    const retainedText = retainedCount
      ? ` 已保留 ${retainedCount} 个最新列表未返回的手工或既有模型及其映射。`
      : "";
    setTargetState(
      card,
      "match",
      `${body.count} 个模型`,
      `已按模型 ID 自动匹配可用参考指纹；原有映射、优先级和启用状态均已保留。${retainedText}`,
    );
  } catch (error) {
    setTargetState(card, "error", "读取失败", error instanceof Error ? error.message : String(error));
  } finally {
    setBusy(false);
  }
}

function addTarget(values = {}) {
  const fragment = elements.targetTemplate.content.cloneNode(true);
  const card = fragment.querySelector(".station-card");
  state.targetSequence += 1;
  card.dataset.targetId = String(state.targetSequence);
  card.querySelector(".target-name").value = values.name || `中转站 ${state.targetSequence}`;
  card.querySelector(".target-url").value = values.baseUrl || "";
  card.querySelector(".target-key").value = values.apiKey || "";
  card.querySelector(".remove-target").addEventListener("click", () => {
    card.remove();
    updateControls();
    scheduleWorkspaceSave();
  });
  card.querySelector(".fetch-target-models").addEventListener("click", () => fetchTargetModels(card));
  card.querySelector(".add-target-model").addEventListener("click", () => {
    const input = card.querySelector(".target-manual-model");
    addTargetModel(card, input.value, { source: "manual" });
    input.value = "";
  });
  elements.targetList.append(card);
  updateControls();
  scheduleWorkspaceSave();
  return card;
}

function setTargetState(card, level, message, detail = "") {
  const badge = card.querySelector(".target-state");
  const status = card.querySelector(".target-message");
  badge.className = `target-state badge badge-${level}`;
  badge.textContent = message;
  status.textContent = detail;
}

function selectedMappings() {
  const mappings = [];
  targetCards().forEach((card) => {
    card.querySelectorAll(".mapping-row").forEach((row) => {
      const enabled = row.querySelector(".mapping-enabled").checked;
      const artifactId = row.querySelector(".mapping-reference").value;
      const reference = state.references.find((item) => item.artifactId === artifactId);
      if (enabled && reference) {
        mappings.push({
          card,
          row,
          reference,
          model: row.dataset.model,
          priority: Number(row.querySelector(".mapping-priority").value) || 50,
        });
      }
    });
  });
  return mappings;
}

function updateControls() {
  const referenceSelected = selectedReferenceModels().length;
  const mappings = selectedMappings();
  const referenceSettings = settings();
  const mappingProfiles = relayProfiles.mappingProfileSummary(mappings);
  const mappingSettings = settings(
    mappingProfiles.profileId || relayProfiles.LEGACY_PROFILE_ID,
  );
  const referenceRequests = relayProfiles.requestCount(
    referenceSettings.methodProfileId,
    referenceSelected,
    referenceSettings,
  );
  const mappingRequests = mappingProfiles.compatible
    ? relayProfiles.requestCount(
      mappingSettings.methodProfileId,
      mappings.length,
      mappingSettings,
    )
    : 0;
  const total = referenceRequests + mappingRequests;
  const referenceEstimate = estimateDuration(referenceSelected, referenceSettings);
  const mappingEstimate = estimateDuration(mappings.length, mappingSettings);
  elements.referenceModelCount.textContent = `${referenceSelected} 个已选 / ${state.referenceModels.size} 个候选`;
  const autoConcurrency = referenceSettings.concurrencyMode === "auto";
  const selectedProfile = relayProfiles.profile(referenceSettings.methodProfileId);
  elements.preset.disabled = state.running || selectedProfile.paperFaithful;
  elements.methodProfileNote.textContent = selectedProfile.description
    + (selectedProfile.paperFaithful
      ? " 固定 40×30；没有本地 validated policy 时只输出统计距离。"
      : " 采样规模由下方规格控制，不能作为论文复现或身份定案。");
  elements.concurrency.disabled = state.running;
  elements.concurrencyNote.textContent = autoConcurrency
    ? "参考采集首个模型从不高于 2 的保守并发开始，后续按本批前一模型的错误与重试升降；中转站对比则按同端点与模型的历史稳定性选择。连续无进度上限不限制任务总时长。"
    : `所有任务固定使用并发 ${referenceSettings.concurrency}；连续无进度上限只在长期没有新响应时中断，不限制任务总时长。`;
  elements.requestEstimate.textContent = `${total.toLocaleString("zh-CN")} 次（参考 ${referenceRequests.toLocaleString("zh-CN")} + 对比 ${mappingRequests.toLocaleString("zh-CN")}${autoConcurrency ? "；自动并发不增加采样量" : ""}）`;
  elements.timeEstimate.textContent = durationRangeText(referenceEstimate);
  elements.timeEstimateNote.textContent = autoConcurrency
    ? "参考首项按不高于 2 的并发保守估算并在本批后续模型自适应；对比任务优先采用同端点与模型的历史并发。"
    : referenceEstimate.historical
      ? "根据本机已完成采样的实际速度估算；网络拥堵、限流与重试会造成波动。"
      : "首次按单请求 1.2–4 秒粗估；完成模型后会用实际速度更新剩余时间。";
  elements.mappingSummary.textContent = state.comparisonRecoveryError || (!mappingProfiles.compatible
    ? mappingProfiles.message
    : mappings.length
      ? `已选择 ${mappings.length} 组模型映射 · ${mappingProfiles.message} · 预计产生 ${mappings.length} 份独立比较证据。`
      : "读取模型后，系统会优先按相同模型 ID 自动匹配参考指纹。");
  elements.mappingTimeEstimate.textContent = mappings.length
    ? `${durationRangeText(mappingEstimate)}${autoConcurrency ? "（按中转站历史；无历史从并发 ≤2 开始）" : mappingEstimate.historical ? "（按本机历史速度）" : "（首次网络粗估）"}`
    : "预计耗时将在选择模型后显示。";
  elements.mappingSummary.classList.toggle(
    "error-text",
    Boolean(state.comparisonRecoveryError) || !mappingProfiles.compatible,
  );
  elements.runAll.disabled = !state.ready || state.running || state.comparisonRecoveryBlocked
    || mappings.length === 0 || !mappingProfiles.compatible;
  elements.referenceForm.querySelector("button[type='submit']").disabled = !state.ready
    || state.running || state.referenceRecoveryBlocked || referenceSelected === 0;
  document.querySelectorAll(".mapping-reference").forEach((select) => {
    select.disabled = state.running || state.references.length === 0;
  });
}

function resultMetric(label, value) {
  const box = document.createElement("div");
  box.className = "metric";
  const name = document.createElement("span");
  const data = document.createElement("strong");
  name.textContent = label;
  data.textContent = value;
  box.append(name, data);
  return box;
}

function normalizeDecision(result) {
  const decision = result?.decision;
  if (!decision || typeof decision !== "object" || Array.isArray(decision)) return null;
  const reasons = Array.isArray(decision.reasons)
    ? decision.reasons
    : decision.reasons === null || decision.reasons === undefined
      ? []
      : [decision.reasons];
  return {
    operationalVerdict: decision.operationalVerdict || null,
    status: decision.status ?? null,
    reasons: reasons.map((reason) => String(reason).trim()).filter(Boolean),
    legacyVerdict: decision.legacyVerdict || null,
    rawMeanJsd: decision.rawMeanJsd,
    decisionEligible: typeof decision.decisionEligible === "boolean"
      ? decision.decisionEligible
      : null,
  };
}

function resolveResultDecision(response, result, comparison, fallbackVerdict = null) {
  const decision = normalizeDecision(result);
  const historicalVerdict = fallbackVerdict
    || response?.verdict
    || comparison?.verdict
    || "insufficient";
  if (!decision) {
    return {
      hasDecision: false,
      verdict: historicalVerdict,
      legacyVerdict: historicalVerdict,
      rawMeanJsd: comparison?.meanJsd ?? result?.meanJsd,
      status: null,
      reasons: [],
      decisionEligible: null,
    };
  }
  const legacyVerdict = decision.legacyVerdict || historicalVerdict;
  return {
    ...decision,
    hasDecision: true,
    verdict: decision.operationalVerdict
      || (decision.decisionEligible === false ? "unverifiable" : legacyVerdict),
    legacyVerdict,
    rawMeanJsd: decision.rawMeanJsd ?? comparison?.meanJsd ?? result?.meanJsd,
  };
}

function verdictDetailText(verdict) {
  if (!verdict) return "—";
  const label = verdictLabels[verdict];
  return label ? `${label} (${verdict})` : verdict;
}

function renderDecisionDetails(decision) {
  const section = document.createElement("section");
  section.className = "decision-details";
  const heading = document.createElement("strong");
  heading.className = "decision-details-heading";
  heading.textContent = "判定详情";

  const grid = document.createElement("div");
  grid.className = "decision-details-grid";
  grid.append(
    resultMetric("决策状态", decision.status === null ? "—" : String(decision.status)),
    resultMetric(
      "可作判定",
      decision.decisionEligible === true ? "是" : decision.decisionEligible === false ? "否" : "—",
    ),
    resultMetric("旧版结论", verdictDetailText(decision.legacyVerdict)),
    resultMetric("原始平均 JSD", formatNumber(decision.rawMeanJsd)),
  );

  const reasons = document.createElement("div");
  reasons.className = "decision-reasons";
  const reasonsLabel = document.createElement("span");
  reasonsLabel.textContent = "判定原因";
  reasons.append(reasonsLabel);
  if (decision.reasons.length) {
    const list = document.createElement("ul");
    decision.reasons.forEach((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      list.append(item);
    });
    reasons.append(list);
  } else {
    const empty = document.createElement("p");
    empty.textContent = "—";
    reasons.append(empty);
  }
  section.append(heading, grid, reasons);
  return section;
}

function liveResultContext(mapping, batchId) {
  return {
    batchId,
    stationName: mapping.card.querySelector(".target-name").value.trim() || "未命名中转站",
    targetUrl: mapping.card.querySelector(".target-url").value.trim(),
    targetModel: mapping.model,
    referenceName: mapping.reference.name,
    referenceModel: mapping.reference.model,
    referenceArtifactId: mapping.reference.artifactId,
    methodProfileId: mapping.reference.methodProfileId,
  };
}

function resultEffectiveConcurrency(response, result, target) {
  const value = target.effectiveConcurrency
    ?? target.actualConcurrency
    ?? result.effectiveConcurrency
    ?? result.actualConcurrency
    ?? result.execution?.concurrency?.selected
    ?? response.effective_concurrency
    ?? response.actual_concurrency;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function identificationCandidates(response, result) {
  const identification = result.identification || response.identification || {};
  const candidates = Array.isArray(identification.candidates)
    ? identification.candidates
    : Array.isArray(response.candidates)
      ? response.candidates
      : [];
  return { identification, candidates };
}

function renderIdentification(context, response, result, verdict, legacyVerdict = null) {
  const { identification, candidates } = identificationCandidates(response, result);
  const triggerVerdict = identification.triggerVerdict || legacyVerdict || verdict;
  const attempted = identification.attempted === true
    || identification.decisionBasis === "legacy_exploratory"
    || candidates.length > 0;
  if (!attempted && !["uncertain", "mismatch"].includes(triggerVerdict)) return null;
  const section = document.createElement("section");
  section.className = "candidate-ranking";
  const heading = document.createElement("div");
  heading.className = "candidate-ranking-heading";
  const title = document.createElement("strong");
  const count = document.createElement("span");
  title.textContent = identification.decisionBasis === "legacy_exploratory"
    ? "探索性相似候选"
    : "可能模型";
  count.textContent = candidates.length ? `按指纹距离列出前 ${Math.min(candidates.length, 3)} 名` : "暂无可靠候选";
  heading.append(title, count);
  section.append(heading);

  if (candidates.length) {
    const list = document.createElement("div");
    list.className = "candidate-list";
    candidates.slice(0, 3).forEach((candidate, index) => {
      const row = document.createElement("div");
      row.className = "candidate-row";
      const rank = document.createElement("span");
      rank.className = "candidate-rank";
      rank.textContent = `#${candidate.rank || index + 1}`;
      const identity = document.createElement("div");
      const model = document.createElement("code");
      const source = document.createElement("small");
      const candidateModel = candidate.referenceModel || candidate.reference_model || candidate.model || "未知模型";
      const candidateName = candidate.referenceName || candidate.reference_name || "本地参考库";
      model.textContent = candidateModel;
      source.textContent = candidateName;
      identity.append(model, source);
      const distance = document.createElement("div");
      distance.className = "candidate-distance";
      const meanJsd = candidate.medianMeanJsd
        ?? candidate.median_mean_jsd
        ?? candidate.meanJsd
        ?? candidate.mean_jsd;
      const comparable = candidate.comparableCellCount ?? candidate.comparable_cell_count;
      const score = document.createElement("strong");
      const cells = document.createElement("small");
      score.textContent = `JSD ${formatNumber(Number(meanJsd))}`;
      const support = candidate.supportCount ?? candidate.support_count;
      cells.textContent = support
        ? `${support} 份参考 · ${comparable ?? "—"} 个可比较探针`
        : `${comparable ?? "—"} 个可比较探针`;
      distance.append(score, cells);
      const artifactId = candidate.referenceArtifactId || candidate.reference_artifact_id;
      const original = candidate.isOriginalReference
        || candidate.is_original_reference
        || (artifactId && artifactId === context.referenceArtifactId);
      if (original) {
        const badge = document.createElement("span");
        badge.className = "badge badge-muted candidate-original";
        badge.textContent = "原对比参考";
        row.append(rank, identity, distance, badge);
      } else {
        row.append(rank, identity, distance);
      }
      list.append(row);
    });
    section.append(list);
  } else {
    const empty = document.createElement("p");
    empty.className = "candidate-empty";
    empty.textContent = identification.reason
      || identification.error
      || "参考样本不足，或本地参考库中没有可可靠排序的其他模型。";
    section.append(empty);
  }

  const disclaimer = document.createElement("p");
  disclaimer.className = "candidate-disclaimer";
  disclaimer.textContent = identification.notice
    || "候选排名表示与本地参考指纹的距离，不等同于模型身份确认。";
  section.append(disclaimer);
  return section;
}

function renderResult(context, response) {
  elements.emptyResults.classList.add("hidden");
  const result = response.result || {};
  const comparison = result.comparison || {};
  const target = result.target || {};
  const targetFingerprint = target.fingerprint || target;
  const targetCollection = target.collection || result.collection || {};
  const protocol = targetFingerprint.protocol
    || result.protocol
    || result.method_profile_id
    || context.methodProfileId
    || "one-token/v1";
  const methodProfileId = protocol === relayProfiles.PAPER_PROFILE_ID
    ? relayProfiles.PAPER_PROFILE_ID
    : relayProfiles.normalizeProfileId(result.method_profile_id || context.methodProfileId);
  const partial = relayStatus.partialEvidenceInfo({
    ...context,
    status: response.status || context.status,
    evidence_available: Boolean(response.artifact_id),
    artifact_id: response.artifact_id,
    response,
  });
  const incompleteEvidence = partial.isPartial || partial.isTargetFingerprint;
  const decision = resolveResultDecision(response, result, comparison);
  const verdict = incompleteEvidence
    ? "insufficient"
    : decision.verdict;
  const meanJsd = decision.rawMeanJsd;
  const stationName = context.stationName || "未命名中转站";
  const targetUrl = context.targetUrl || "";
  const resultKey = context.auditId || `${context.batchId}:${stationName}:${context.targetModel}`;
  const effectiveConcurrency = resultEffectiveConcurrency(response, result, target);

  const article = document.createElement("article");
  article.className = `result-card${incompleteEvidence ? " is-partial" : ""}`;
  article.dataset.resultKey = resultKey;

  const overview = document.createElement("div");
  const heading = document.createElement("div");
  heading.className = "result-heading";
  const titleGroup = document.createElement("div");
  const title = document.createElement("h3");
  const endpoint = document.createElement("p");
  title.textContent = `${stationName} · ${context.targetModel}`;
  endpoint.className = "result-endpoint";
  endpoint.textContent = `${targetUrl} → ${context.referenceName} / ${context.referenceModel}`;
  titleGroup.append(title, endpoint);
  const verdictBadge = document.createElement("span");
  verdictBadge.className = `badge badge-${verdict}`;
  verdictBadge.textContent = partial.isPartial
    ? "部分采样"
    : partial.isTargetFingerprint
      ? "目标指纹"
      : verdictLabels[verdict] || verdict;
  heading.append(titleGroup, verdictBadge);

  const large = document.createElement("div");
  large.className = "metric-large";
  const largeLabel = document.createElement("span");
  const largeValue = document.createElement("strong");
  const largeUnit = document.createElement("small");
  largeLabel.textContent = incompleteEvidence
    ? partial.isPartial ? "已保存采样" : "目标指纹采样"
    : decision.hasDecision ? "原始平均 JSD" : "平均 JSD";
  largeValue.textContent = incompleteEvidence
    ? `${partial.sampleCount ?? "—"}${partial.expectedSamples !== null ? `/${partial.expectedSamples}` : ""}`
    : formatNumber(meanJsd);
  largeUnit.textContent = incompleteEvidence
    ? partial.isPartial
      ? "采样未完成，仅供排障与续跑，不生成模型判定"
      : "目标指纹已保存，但比较未完成，不生成模型判定"
    : decision.hasDecision
      ? "原始统计距离 0–1；不直接作为操作判定阈值"
      : "历史记录未包含 decision；范围 0–1，越小越接近参考分布";
  large.append(largeLabel, largeValue, largeUnit);
  overview.append(heading, large);

  const details = document.createElement("div");
  const metrics = document.createElement("div");
  metrics.className = "result-metrics";
  metrics.append(
    resultMetric("指纹方法", relayProfiles.profile(methodProfileId).shortLabel),
    resultMetric("可比较探针", String(comparison.comparableCellCount ?? "—")),
    resultMetric(
      "内部 JSD",
      formatNumber(target.splitHalfJsd ?? targetCollection.splitHalfMeanJsd),
    ),
    resultMetric(
      "错误请求",
      String(target.errorCount ?? targetCollection.errorSamples ?? targetFingerprint.errorCount ?? "—"),
    ),
    resultMetric("任务耗时", formatDuration(target.durationMs ?? result.durationMs)),
    resultMetric(
      "直接采样",
      targetCollection.directness || targetFingerprint.quality?.directness || adapterText(target.adapter),
    ),
    resultMetric("实际并发", effectiveConcurrency === null ? "—" : String(effectiveConcurrency)),
    resultMetric("证据 SHA", (response.artifact_sha256 || "—").slice(0, 10)),
  );
  const preflight = relayStatus.preflightText({ response, result });
  if (preflight) metrics.append(resultMetric("请求预检", preflight));

  const track = document.createElement("div");
  track.className = "distance-track distance-track-raw";
  const marker = document.createElement("i");
  marker.className = "distance-marker";
  marker.style.left = `${Math.max(0, Math.min(100, (Number(meanJsd) || 0) * 100))}%`;
  track.append(marker);
  const labels = document.createElement("div");
  labels.className = "track-labels";
  ["0", "原始 JSD（仅作统计量）", "1"].forEach((label) => {
    const span = document.createElement("span");
    span.textContent = label;
    labels.append(span);
  });
  details.append(metrics);
  if (decision.hasDecision) details.append(renderDecisionDetails(decision));
  if (
    !incompleteEvidence
    && meanJsd !== null
    && meanJsd !== undefined
    && Number.isFinite(Number(meanJsd))
  ) {
    details.append(track, labels);
  }

  const cells = Array.isArray(comparison.cells) ? comparison.cells : [];
  if (cells.length) {
    const disclosure = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = `查看 ${cells.length} 个探针距离`;
    const table = document.createElement("table");
    table.className = "cell-table";
    const header = document.createElement("thead");
    const headerRow = document.createElement("tr");
    ["探针", "参考样本", "待测样本", "JSD"].forEach((label) => {
      const th = document.createElement("th");
      th.textContent = label;
      headerRow.append(th);
    });
    header.append(headerRow);
    const body = document.createElement("tbody");
    cells.forEach((cell) => {
      const row = document.createElement("tr");
      [cell.cellId, cell.validA, cell.validB, formatNumber(cell.jsd)].forEach((value) => {
        const td = document.createElement("td");
        td.textContent = String(value ?? "—");
        row.append(td);
      });
      body.append(row);
    });
    table.append(header, body);
    disclosure.append(summary, table);
    details.append(disclosure);
  }

  const identification = incompleteEvidence
    ? null
    : renderIdentification(context, response, result, verdict, decision.legacyVerdict);
  if (identification) details.append(identification);

  const evidenceBar = document.createElement("div");
  evidenceBar.className = "result-evidence";
  const artifact = document.createElement("span");
  artifact.textContent = `${partial.isPartial ? "部分采样" : partial.isTargetFingerprint ? "目标指纹" : "Artifact"} ${response.artifact_id}`;
  const download = document.createElement("a");
  download.className = "evidence-link";
  download.href = `/api/v1/console/evidence/${response.artifact_id}`;
  download.textContent = partial.isPartial
    ? "下载部分采样 JSON"
    : partial.isTargetFingerprint
      ? "下载目标指纹 JSON"
      : "下载比较证据 JSON";
  evidenceBar.append(artifact, download);
  const rawEvidenceSha = targetFingerprint.quality?.rawEvidenceSha256
    || targetCollection.rawEvidenceSha256
    || result.rawEvidenceSha256;
  if (rawEvidenceSha && response.artifact_id) {
    const rawDownload = document.createElement("a");
    rawDownload.className = "evidence-link";
    rawDownload.href = `/api/v1/console/evidence/${response.artifact_id}/samples`;
    rawDownload.textContent = "下载原始 JSONL";
    evidenceBar.append(rawDownload);
  }
  details.append(evidenceBar);

  const warnings = [...new Set([
    ...(incompleteEvidence ? [`${relayStatus.incompleteEvidenceText(partial)}。`] : []),
    ...(result.warnings || []),
    ...(target.warnings || []),
  ])];
  if (warnings.length) {
    const warning = document.createElement("p");
    warning.className = "result-warning";
    warning.textContent = warnings.join("；");
    details.append(warning);
  }

  article.append(overview, details);
  const existing = [...elements.results.querySelectorAll(".result-card")].find(
    (item) => item.dataset.resultKey === resultKey,
  );
  if (existing) existing.replaceWith(article);
  else elements.results.prepend(article);
}

async function loadLatestResults() {
  try {
    const body = await requestJson("/api/v1/console/comparisons/latest");
    elements.emptyResults.classList.remove("error-text");
    let rendered = 0;
    (body.items || []).forEach((item) => {
      if (!item.response) return;
      renderResult(
        {
          auditId: item.audit_id,
          batchId: item.batch_id,
          stationName: item.station_name,
          targetUrl: item.target_base_url,
          targetModel: item.target_model,
          referenceName: item.reference_name,
          referenceModel: item.reference_model || "未知参考模型",
          referenceArtifactId: item.reference_artifact_id,
          methodProfileId: item.method_profile_id,
          status: item.status,
          partial_evidence: item.partial_evidence,
          partial_sample_count: item.partial_sample_count,
          partial_expected_samples: item.partial_expected_samples,
          evidence_state: item.evidence_state,
        },
        item.response,
      );
      rendered += 1;
    });
    if (rendered && elements.resultsTitle) elements.resultsTitle.textContent = "最近一次对比结果";
    return true;
  } catch (error) {
    elements.emptyResults.classList.remove("hidden");
    elements.emptyResults.classList.add("error-text");
    const title = elements.emptyResults.querySelector("strong");
    const detail = elements.emptyResults.querySelector("p");
    if (title) title.textContent = "最近结果恢复失败";
    if (detail) detail.textContent = error instanceof Error ? error.message : String(error);
    return false;
  }
}

function taskResultVerdict(item) {
  const response = item.response || {};
  const result = response.result || {};
  return resolveResultDecision(
    response,
    result,
    result.comparison || {},
    item.verdict || "match",
  ).verdict;
}

function taskDisplayStatus(item) {
  if (item.status === "completed") return taskResultVerdict(item);
  const operationalState = relayStatus.itemOperationalState(item);
  return ["waiting", "blocked"].includes(operationalState)
    ? operationalState
    : item.verdict || item.status;
}

function taskStatusClass(item) {
  if (item.status === "completed") return taskResultVerdict(item);
  if (relayStatus.itemOperationalState(item) === "waiting") return "waiting";
  if (relayStatus.itemOperationalState(item) === "blocked") return "blocked";
  if (item.status === "failed" || item.status === "interrupted") return "error";
  if (["paused", "canceling"].includes(item.status)) return "uncertain";
  if (item.status === "canceled") return "muted";
  if (item.status === "running") return "running";
  return "muted";
}

function taskProgressText(item) {
  const progress = item.progress || {};
  const partial = relayStatus.partialEvidenceInfo(item);
  const retryText = relayStatus.retryWaitingText(item);
  if (retryText) return retryText;
  const planText = relayStatus.planBudgetText(item);
  if (planText) return planText;
  if (item.status === "completed") return "执行成功，对比证据已保存";
  if (item.status === "failed" || item.status === "interrupted") {
    const failure = item.error_message || progress.detail || "任务未完成";
    const evidence = relayStatus.incompleteEvidenceText(partial);
    return evidence ? `${failure} · ${evidence}` : failure;
  }
  if (item.status === "canceling") return progress.detail || "正在取消，等待当前请求终止";
  if (item.status === "canceled") {
    const canceled = progress.detail || "已由用户取消";
    const evidence = relayStatus.incompleteEvidenceText(partial);
    return evidence ? `${canceled} · ${evidence}` : canceled;
  }
  if (item.status === "paused") return progress.detail || "已暂停";
  if (item.status === "queued") {
    const position = Number(item.queue_position);
    return Number.isFinite(position) && position > 0
      ? `队列第 ${position} 位，等待前一模型完成`
      : "已进入后端队列，等待前一模型完成";
  }
  if (["preflight", "preflight_retry", "healthcheck", "connection_check"].includes(progress.stage)) {
    return relayStatus.preflightText(item) || "正在检查接口兼容性与中转站状态";
  }
  if (["concurrency", "concurrency_probe", "calibrating"].includes(progress.stage)) {
    return progress.detail || "正在选择适合该中转站的稳定并发数量";
  }
  if (progress.stage === "adapter") return progress.detail || "正在探测兼容请求参数";
  if (progress.stage === "sampling") {
    return `已收到 ${progress.done || 0}/${progress.total || 0} 个采样响应${progress.errors ? ` · ${progress.errors} 个错误` : ""}`;
  }
  return progress.detail || "正在启动采样器，准备发起请求";
}

function matchingMappingRow(item) {
  const normalizedUrl = String(item.target_base_url || "").replace(/\/$/, "");
  for (const card of targetCards()) {
    const cardUrl = card.querySelector(".target-url").value.trim().replace(/\/$/, "");
    if (cardUrl !== normalizedUrl) continue;
    const row = [...card.querySelectorAll(".mapping-row")].find(
      (candidate) => candidate.dataset.model === item.target_model,
    );
    if (row) return row;
  }
  return null;
}

function renderActiveTask(item) {
  const progress = item.progress || {};
  const partial = relayStatus.partialEvidenceInfo(item);
  const done = Number(progress.done) || 0;
  const total = Number(progress.total) || 0;
  const percent = total > 0 ? Math.min(100, (done / total) * 100) : 0;
  const updatedAt = progress.updated_at ? new Date(progress.updated_at).getTime() : Date.now();
  const staleSeconds = Math.max(0, Math.floor((Date.now() - updatedAt) / 1000));
  const operationalState = relayStatus.itemOperationalState(item);
  const stale = item.status === "running"
    && operationalState !== "waiting"
    && progress.stage !== "identifying"
    && staleSeconds > 20;

  const task = document.createElement("article");
  task.className = `active-task${stale ? " is-stale" : ""}${operationalState === "waiting" ? " is-waiting-retry" : ""}${operationalState === "blocked" ? " is-plan-blocked" : ""}`;
  task.dataset.auditId = item.audit_id;
  const name = document.createElement("div");
  name.className = "active-task-name";
  const station = document.createElement("strong");
  const model = document.createElement("code");
  station.textContent = item.station_name;
  model.textContent = item.target_model;
  name.append(station, model);

  const progressBox = document.createElement("div");
  progressBox.className = "active-task-progress";
  const description = document.createElement("p");
  description.textContent = stale
    ? `${taskProgressText(item)} · 已 ${staleSeconds} 秒没有收到新进度，请检查中转站请求日志`
    : taskProgressText(item);
  const diagnostics = relayStatus.progressDiagnostics(item).filter(
    (part) => !description.textContent.includes(part),
  );
  const diagnosticLine = document.createElement("small");
  diagnosticLine.className = "task-network-diagnostics";
  diagnosticLine.textContent = diagnostics.join(" · ");
  diagnosticLine.classList.toggle("hidden", diagnostics.length === 0);
  const track = document.createElement("div");
  track.className = "task-progress-track";
  const fill = document.createElement("i");
  fill.style.width = `${percent}%`;
  track.append(fill);
  progressBox.append(description, diagnosticLine, track);

  const meta = document.createElement("div");
  meta.className = "active-task-meta";
  const status = document.createElement("strong");
  const displayStatus = taskDisplayStatus(item);
  status.textContent = ["waiting", "blocked"].includes(operationalState)
    ? relayStatus.itemStatusLabel(item)
    : verdictLabels[displayStatus] || displayStatus;
  const updated = document.createElement("span");
  updated.textContent = progress.updated_at ? `更新于 ${formatDate(progress.updated_at)}` : "等待首次更新";
  const queue = document.createElement("span");
  const priority = Number(item.priority) || 50;
  const priorityLabel = priority >= 80 ? "高优先级" : priority <= 20 ? "低优先级" : "普通优先级";
  const effectiveConcurrency = Number(
    item.effective_concurrency
      ?? item.actual_concurrency
      ?? item.task_options?.effective_concurrency
      ?? progress.effective_concurrency
      ?? progress.actual_concurrency,
  );
  const metaParts = [priorityLabel];
  if (Number.isFinite(Number(item.queue_position)) && Number(item.queue_position) > 0) {
    metaParts.push(`队列 #${item.queue_position}`);
  }
  if (Number.isFinite(effectiveConcurrency) && effectiveConcurrency > 0) {
    metaParts.push(`实际并发 ${effectiveConcurrency}`);
  }
  queue.textContent = metaParts.join(" · ");
  meta.append(status, updated, queue);

  const actions = document.createElement("div");
  actions.className = "active-task-actions";
  if (item.status === "queued" && operationalState === "queued") {
    const prioritize = document.createElement("button");
    prioritize.type = "button";
    prioritize.className = "button button-ghost";
    prioritize.dataset.allowBusy = "true";
    prioritize.textContent = "下一项执行";
    prioritize.addEventListener("click", () => prioritizeComparisonTask(item.audit_id, prioritize));
    actions.append(prioritize);
  }
  if (["queued", "running", "paused", "waiting_retry", "cooldown"].includes(item.status)
    || operationalState === "waiting") {
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "button button-danger";
    cancel.dataset.allowBusy = "true";
    cancel.textContent = "取消此项";
    cancel.addEventListener("click", () => cancelComparisonTask(item.audit_id, cancel));
    actions.append(cancel);
  }
  if ((partial.isPartial || partial.isTargetFingerprint) && partial.available) {
    const evidence = document.createElement("a");
    evidence.className = "button button-ghost partial-evidence-link";
    evidence.href = `/api/v1/console/evidence/${partial.artifactId}`;
    evidence.textContent = partial.isPartial ? "下载部分采样" : "下载目标指纹";
    evidence.title = partial.isPartial
      ? "部分采样仅供查看与排障，不可用于模型判定"
      : "目标指纹已保存，但比较未完成，不可用于模型判定";
    actions.append(evidence);
  }
  task.append(name, progressBox, meta, actions);
  return task;
}

function renderActiveBatch(body) {
  const batch = body.batch;
  if (!batch) {
    state.activeBatchId = null;
    state.activeBatchStatus = null;
    elements.activeBatchPanel.classList.add("hidden");
    return;
  }
  state.activeBatchId = batch.id;
  state.activeBatchStatus = batch.status;
  state.comparisonRecoveryError = "";
  state.comparisonRecoveryBlocked = false;
  elements.retryComparisonRecovery.classList.add("hidden");
  elements.retryComparisonRecovery.disabled = false;
  elements.mappingSummary.classList.remove("error-text");
  const items = body.items || [];
  const counts = relayStatus.batchStateCounts(items);
  elements.activeBatchPanel.classList.remove("hidden", "is-paused", "is-complete", "is-canceled", "is-mixed");
  elements.activeBatchPanel.classList.toggle("is-paused", batch.status === "paused");
  elements.activeBatchPanel.classList.toggle("is-complete", batch.status === "completed");
  elements.activeBatchPanel.classList.toggle("is-canceled", batch.status === "canceled");
  elements.activeBatchPanel.classList.toggle(
    "is-mixed",
    counts.failed > 0 || counts.canceled > 0 || counts.blocked > 0,
  );
  elements.activeBatchList.replaceChildren();

  items.forEach((item) => {
    elements.activeBatchList.append(renderActiveTask(item));
    const row = matchingMappingRow(item);
    if (row) {
      const badge = row.querySelector(".mapping-state");
      badge.className = `mapping-state badge badge-${taskStatusClass(item)}`;
      const displayStatus = taskDisplayStatus(item);
      badge.textContent = verdictLabels[displayStatus] || displayStatus;
    }
    if (item.response) {
      renderResult(
        {
          auditId: item.audit_id,
          batchId: item.batch_id,
          stationName: item.station_name,
          targetUrl: item.target_base_url,
          targetModel: item.target_model,
          referenceName: item.reference_name,
          referenceModel: item.reference_model || "未知参考模型",
          referenceArtifactId: item.reference_artifact_id,
          methodProfileId: item.method_profile_id,
          status: item.status,
          partial_evidence: item.partial_evidence,
          partial_sample_count: item.partial_sample_count,
          partial_expected_samples: item.partial_expected_samples,
          evidence_state: item.evidence_state,
        },
        item.response,
      );
    }
  });

  const statusText = relayStatus.batchStatusLabel(batch.status, counts);
  elements.activeBatchStatus.textContent = statusText;
  elements.activeBatchCounts.replaceChildren();
  relayStatus.batchSummaryParts(counts).forEach((part) => {
    const summary = document.createElement("span");
    summary.className = `batch-state-count is-${part.key}`;
    summary.textContent = `${part.label} ${part.count}`;
    elements.activeBatchCounts.append(summary);
  });
  elements.mappingSummary.textContent = `${statusText}；成功 ${counts.success}、失败 ${counts.failed}、等待重试 ${counts.waiting}、计划需调整 ${counts.blocked}、取消 ${counts.canceled}、排队 / 未执行 ${counts.queued}、运行 ${counts.running}、暂停 ${counts.paused}。刷新或切换到历史页不会清除任务。`;
  elements.mappingTimeEstimate.textContent = "限流、暂不可用或响应慢会等待并自动重试，不计为失败；连续无进度超时、最近 HTTP 和尝试次数会分别显示。";

  const polling = ["running", "pausing", "paused", "canceling"].includes(batch.status)
    || counts.waiting > 0;
  const pauseable = ["running", "pausing", "paused"].includes(batch.status);
  const cancelable = ["running", "pausing", "paused"].includes(batch.status);
  setBusy(polling, "comparison");
  elements.pauseBatch.classList.toggle("hidden", !pauseable);
  elements.cancelBatch.classList.toggle("hidden", !cancelable);
  elements.cancelBatch.disabled = !cancelable;
  if (pauseable) {
    elements.pauseBatch.disabled = batch.status === "pausing";
    elements.pauseBatch.textContent = batch.status === "paused" ? "继续任务" : "暂停任务";
  }
  if (!polling) {
    window.clearTimeout(state.batchPollTimer);
    state.batchPollTimer = null;
  }
}

function scheduleBatchPoll(delay = 1000) {
  window.clearTimeout(state.batchPollTimer);
  if (!state.activeBatchId) return;
  state.batchPollTimer = window.setTimeout(pollActiveBatch, delay);
}

async function pollActiveBatch() {
  if (!state.activeBatchId) return;
  try {
    const body = await requestJson(`/api/v1/console/comparison-batches/${state.activeBatchId}`);
    renderActiveBatch(body);
    const counts = relayStatus.batchStateCounts(body.items || []);
    if (["running", "pausing", "paused", "canceling"].includes(body.batch.status)
      || counts.waiting > 0) scheduleBatchPoll();
  } catch (error) {
    elements.activeBatchStatus.textContent = `任务状态读取失败：${error instanceof Error ? error.message : String(error)}`;
    scheduleBatchPoll(3000);
  }
}

async function loadActiveBatch() {
  state.comparisonRecoveryBlocked = true;
  elements.retryComparisonRecovery.disabled = true;
  updateControls();
  try {
    const body = await requestJson("/api/v1/console/comparison-batches/active");
    if (body.batch) {
      renderActiveBatch(body);
      scheduleBatchPoll();
      return true;
    }
    state.comparisonRecoveryBlocked = false;
    state.comparisonRecoveryError = "";
    elements.retryComparisonRecovery.classList.add("hidden");
    elements.retryComparisonRecovery.disabled = false;
    elements.activeBatchPanel.classList.add("hidden");
    setBusy(false, "comparison");
    return false;
  } catch (error) {
    state.comparisonRecoveryBlocked = true;
    setBusy(false, "comparison");
    state.comparisonRecoveryError = `无法确认是否已有对比任务：${error instanceof Error ? error.message : String(error)}`;
    elements.activeBatchPanel.classList.remove("hidden");
    elements.activeBatchStatus.textContent = `对比任务恢复失败：${error instanceof Error ? error.message : String(error)}`;
    elements.activeBatchCounts.replaceChildren();
    elements.retryComparisonRecovery.classList.remove("hidden");
    elements.retryComparisonRecovery.disabled = false;
    elements.pauseBatch.classList.add("hidden");
    elements.cancelBatch.classList.add("hidden");
    elements.mappingSummary.classList.add("error-text");
    elements.mappingSummary.textContent = `${state.comparisonRecoveryError}。请检查本地服务状态后再创建新批次。`;
    return false;
  }
}

async function recoverComparisonBatch(batchId, message = "已恢复正在执行的对比批次") {
  const body = await requestJson(`/api/v1/console/comparison-batches/${batchId}`);
  state.comparisonRecoveryBlocked = false;
  renderActiveBatch(body);
  state.comparisonRecoveryError = "";
  elements.mappingSummary.classList.remove("error-text");
  elements.mappingSummary.textContent = `${message} · 批次 ${String(batchId).slice(0, 8)}。`;
  scheduleBatchPoll();
  return true;
}

async function retryComparisonRecovery() {
  elements.retryComparisonRecovery.disabled = true;
  state.comparisonRecoveryError = "正在重新检查后台对比任务…";
  updateControls();
  await loadActiveBatch();
}

async function runAllMappings() {
  if (!state.ready || state.running || state.comparisonRecoveryBlocked) return;
  state.comparisonRecoveryError = "";
  const mappings = selectedMappings();
  if (!mappings.length) return;
  const mappingProfiles = relayProfiles.mappingProfileSummary(mappings);
  if (!mappingProfiles.compatible) {
    elements.mappingSummary.classList.add("error-text");
    elements.mappingSummary.textContent = mappingProfiles.message;
    return;
  }
  setBusy(true, "comparison");
  elements.results.replaceChildren();
  elements.emptyResults.classList.remove("hidden");
  elements.emptyResults.classList.remove("error-text");
  const emptyTitle = elements.emptyResults.querySelector("strong");
  const emptyDetail = elements.emptyResults.querySelector("p");
  if (emptyTitle) emptyTitle.textContent = "等待本批次首个结果";
  if (emptyDetail) emptyDetail.textContent = "任务由本地服务执行；刷新页面后仍会恢复进度和已完成证据。";
  if (elements.resultsTitle) elements.resultsTitle.textContent = "本次对比结果";
  const current = settings(mappingProfiles.profileId || relayProfiles.LEGACY_PROFILE_ID);
  try {
    const body = await postJson("/api/v1/console/comparison-batches", {
      items: mappings.map((mapping) => ({
        endpoint: endpointPayload(
          mapping.card.querySelector(".target-url"),
          mapping.model,
          mapping.card.querySelector(".target-key"),
        ),
        reference_artifact_id: mapping.reference.artifactId,
        station_name: mapping.card.querySelector(".target-name").value.trim() || "未命名中转站",
        reference_name: mapping.reference.name,
        reference_model: mapping.reference.model,
        priority: mapping.priority,
      })),
      cells: current.cells,
      samples: current.samples,
      concurrency_mode: current.concurrencyMode,
      concurrency: current.concurrency,
      request_timeout_seconds: current.requestTimeoutSeconds,
      model_timeout_seconds: current.modelTimeoutSeconds,
    });
    renderActiveBatch(body);
    scheduleBatchPoll();
  } catch (error) {
    const existingId = error?.status === 409 ? relayStatus.conflictBatchId(error) : "";
    if (existingId) {
      try {
        await recoverComparisonBatch(existingId, "检测到已有对比批次，已重新关联");
        return;
      } catch (recoveryError) {
        state.comparisonRecoveryBlocked = true;
        elements.activeBatchPanel.classList.remove("hidden");
        elements.retryComparisonRecovery.classList.remove("hidden");
        elements.retryComparisonRecovery.disabled = false;
        elements.pauseBatch.classList.add("hidden");
        elements.cancelBatch.classList.add("hidden");
        elements.activeBatchStatus.textContent = `已有对比批次 ${existingId}，但恢复失败`;
        elements.activeBatchCounts.replaceChildren();
        elements.mappingSummary.textContent = `已有对比批次 ${existingId}，但恢复失败：${recoveryError instanceof Error ? recoveryError.message : String(recoveryError)}`;
      }
    } else if (error?.status === 409) {
      state.comparisonRecoveryBlocked = true;
      elements.activeBatchPanel.classList.remove("hidden");
      elements.retryComparisonRecovery.classList.remove("hidden");
      elements.retryComparisonRecovery.disabled = false;
      elements.pauseBatch.classList.add("hidden");
      elements.cancelBatch.classList.add("hidden");
      elements.activeBatchStatus.textContent = "后端报告已有对比批次，但未返回批次 ID";
      elements.activeBatchCounts.replaceChildren();
      elements.mappingSummary.textContent = `对比批次冲突：${error instanceof Error ? error.message : String(error)}。请点击“重试恢复”从活动任务接口重新关联。`;
    } else {
      elements.mappingSummary.textContent = `任务创建失败：${error instanceof Error ? error.message : String(error)}`;
    }
    elements.mappingSummary.classList.add("error-text");
    state.comparisonRecoveryError = elements.mappingSummary.textContent;
    setBusy(false, "comparison");
  }
}

async function pauseOrResumeActiveBatch() {
  if (!state.activeBatchId) return;
  elements.pauseBatch.disabled = true;
  const action = state.activeBatchStatus === "paused" ? "resume" : "pause";
  try {
    const body = await postJson(
      `/api/v1/console/comparison-batches/${state.activeBatchId}/${action}`,
      {},
    );
    renderActiveBatch(body);
    scheduleBatchPoll();
  } catch (error) {
    elements.activeBatchStatus.textContent = `操作失败：${error instanceof Error ? error.message : String(error)}`;
    elements.pauseBatch.disabled = false;
  }
}

async function cancelActiveBatch() {
  if (!state.activeBatchId) return;
  const confirmed = window.confirm("取消整个批次？已完成的结果和证据会保留，当前及排队任务将停止。");
  if (!confirmed) return;
  elements.cancelBatch.disabled = true;
  try {
    const body = await postJson(
      `/api/v1/console/comparison-batches/${state.activeBatchId}/cancel`,
      {},
    );
    renderActiveBatch(body);
    scheduleBatchPoll();
  } catch (error) {
    elements.activeBatchStatus.textContent = `取消失败：${error instanceof Error ? error.message : String(error)}`;
    elements.cancelBatch.disabled = false;
  }
}

async function cancelComparisonTask(auditId, button) {
  if (!state.activeBatchId || !auditId) return;
  const confirmed = window.confirm("取消此模型任务？如果它正在运行，当前采样会终止，队列随后继续。");
  if (!confirmed) return;
  button.disabled = true;
  try {
    const body = await postJson(
      `/api/v1/console/comparison-batches/${state.activeBatchId}/items/${encodeURIComponent(auditId)}/cancel`,
      {},
    );
    renderActiveBatch(body);
    scheduleBatchPoll();
  } catch (error) {
    elements.activeBatchStatus.textContent = `取消任务失败：${error instanceof Error ? error.message : String(error)}`;
    button.disabled = false;
  }
}

async function prioritizeComparisonTask(auditId, button) {
  if (!state.activeBatchId || !auditId) return;
  button.disabled = true;
  try {
    const body = await postJson(
      `/api/v1/console/comparison-batches/${state.activeBatchId}/items/${encodeURIComponent(auditId)}/prioritize`,
      {},
    );
    renderActiveBatch(body);
    scheduleBatchPoll();
  } catch (error) {
    elements.activeBatchStatus.textContent = `调整顺序失败：${error instanceof Error ? error.message : String(error)}`;
    button.disabled = false;
  }
}

const oneModelTerminalStatuses = new Set([
  "completed",
  "failed",
  "canceled",
  "interrupted",
]);
const referenceSetTerminalStatuses = new Set([
  "ready",
  "failed",
  "canceled",
  "interrupted",
]);
const exploratoryLabels = Object.freeze({
  exploratory_reference_like: "相对参考相似",
  exploratory_reference_deviation: "偏离参考",
  inconclusive: "区间重叠",
  insufficient_quality: "质量不足",
  unsupported_protocol: "协议不兼容",
  request_failed: "请求失败",
});
const safeResultReasonCodes = new Set([
  "all_target_lower_bounds_above_reference_envelope",
  "all_target_upper_bounds_within_reference_envelope",
  "authentication_failed",
  "batch_canceled",
  "batch_scheduler_failed",
  "batch_wall_clock_timeout",
  "cell_answer_counts_invalid",
  "cell_coverage_mismatch",
  "cell_total_count_mismatch",
  "cell_valid_count_mismatch",
  "credential_echo_detected",
  "credential_lost_after_restart",
  "fingerprint_incomplete",
  "minimum_valid_samples_per_cell_not_met",
  "missing_credential",
  "network",
  "partial_fingerprint",
  "reasoning_contamination",
  "redirect_forbidden",
  "request_failed",
  "scheduler_incomplete",
  "service_shutdown",
  "station_wall_clock_timeout",
  "target_fingerprint_missing",
  "target_intervals_overlap_reference_envelope",
  "timeout",
  "unsupported_protocol",
  "upstream_unavailable",
]);
const safeProgressStages = new Set([
  "queued",
  "preflight",
  "sampling",
  "comparing",
  "paused",
  "canceling",
  "completed",
  "failed",
  "canceled",
  "interrupted",
]);

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== "");
}

function finiteNumber(...values) {
  const value = firstDefined(...values);
  const number = Number(value);
  return value === undefined || !Number.isFinite(number) ? null : number;
}

function directnessLabel(...values) {
  const value = firstDefined(...values);
  if (value === undefined) return null;
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric.toFixed(2);
  const text = String(value).trim();
  return text ? text.slice(0, 32) : null;
}

function safeApiError(error, fallback) {
  const status = Number(error?.status);
  if (Number.isInteger(status)) return `${fallback}（HTTP ${status}）`;
  return fallback;
}

function setInlineMessage(element, message, kind = "") {
  if (!element) return;
  element.textContent = message;
  element.className = `inline-message${kind ? ` is-${kind}` : ""}`;
}

function setOneModelQuery(name, value) {
  const url = new URL(window.location.href);
  if (value) url.searchParams.set(name, value);
  else url.searchParams.delete(name);
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

function queryUuid(name) {
  const value = new URL(window.location.href).searchParams.get(name) || "";
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
    ? value
    : "";
}

function clearReferenceSetSecrets() {
  if (elements.referenceSetKey) elements.referenceSetKey.value = "";
}

function clearOneModelSecrets() {
  elements.oneModelTargetRows?.querySelectorAll(".one-model-target-credential").forEach((input) => {
    input.value = "";
  });
  if (elements.oneModelTsv) elements.oneModelTsv.value = "";
}

function syncReferenceSetForm() {
  const protocol = elements.referenceProtocol.value;
  const ephemeral = elements.referenceCredentialMode.value === "ephemeral";
  elements.referenceTransportProfile.value = relayProfiles.transportProfileForProtocol(protocol);
  elements.referenceEphemeralWrap.classList.toggle("hidden", !ephemeral);
  elements.referenceEnvWrap.classList.toggle("hidden", ephemeral);
  elements.referenceSetKey.required = ephemeral;
  elements.referenceSetEnv.required = !ephemeral;
  elements.anthropicWorkspaceWrap.classList.toggle("hidden", protocol !== "anthropic_messages");
  if (protocol !== "anthropic_messages") elements.anthropicWorkspaceId.value = "";
}

function referenceSetCredential() {
  if (elements.referenceCredentialMode.value === "ephemeral") {
    const apiKey = elements.referenceSetKey.value.trim();
    if (!apiKey) throw new Error("请输入临时 API Key");
    return { mode: "ephemeral", api_key: apiKey };
  }
  const name = elements.referenceSetEnv.value.trim();
  if (!/^[A-Z_][A-Z0-9_]{0,99}$/.test(name)) {
    throw new Error("环境变量名必须是白名单中的大写名称");
  }
  return { mode: "env_ref", name };
}

function normalizeReferenceSet(value) {
  const wrapper = value?.reference_set || value?.referenceSet || value?.item || value || {};
  const members = value?.members || wrapper.members || [];
  const statistics = wrapper.pairwise_statistics
    || wrapper.pairwiseStatistics
    || value?.pairwise_statistics
    || value?.pairwiseStatistics
    || null;
  return {
    id: String(firstDefined(wrapper.id, wrapper.reference_set_id, value?.reference_set_id) || ""),
    status: String(firstDefined(wrapper.status, "unknown")),
    selectable: firstDefined(wrapper.selectable, value?.selectable) === true,
    evidenceIntegrity: String(firstDefined(
      wrapper.evidence_integrity,
      wrapper.evidenceIntegrity,
      value?.evidence_integrity,
      value?.evidenceIntegrity,
      "unknown",
    )),
    name: String(firstDefined(wrapper.reference_name, wrapper.referenceName, "未命名参考集")),
    sourceType: String(firstDefined(wrapper.source_type, wrapper.sourceType, "trusted_relay")),
    protocol: String(firstDefined(wrapper.protocol, "")),
    profile: String(firstDefined(wrapper.transport_profile_id, wrapper.transportProfileId, "")),
    logicalModel: String(firstDefined(wrapper.logical_model, wrapper.logicalModel, "")),
    actualModel: String(firstDefined(wrapper.actual_model, wrapper.actualModel, "")),
    baseUrl: String(firstDefined(wrapper.normalized_base_url, wrapper.normalizedBaseUrl, "")),
    manifestSha256: String(firstDefined(
      wrapper.immutable_manifest_sha256,
      wrapper.immutableManifestSha256,
      "",
    )),
    referenceEnvelope: finiteNumber(
      wrapper.reference_envelope,
      wrapper.referenceEnvelope,
      statistics?.referenceEnvelope,
      statistics?.reference_envelope,
    ),
    statistics,
    members: Array.isArray(members) ? members : [],
    createdAt: firstDefined(wrapper.created_at, wrapper.createdAt),
    completedAt: firstDefined(wrapper.completed_at, wrapper.completedAt),
  };
}

function referenceMemberProgress(member) {
  const done = finiteNumber(member?.progress_done, member?.progressDone, member?.done) || 0;
  const total = finiteNumber(member?.progress_total, member?.progressTotal, member?.total) || 1200;
  return { done: Math.max(0, done), total: Math.max(1, total) };
}

function renderReferenceSetMembers(referenceSet) {
  elements.referenceSetMembers.replaceChildren();
  const membersByOrdinal = new Map(
    referenceSet.members.map((member, index) => [Number(member.ordinal) || index + 1, member]),
  );
  for (let ordinal = 1; ordinal <= 3; ordinal += 1) {
    const member = membersByOrdinal.get(ordinal) || { ordinal, status: "queued" };
    const progress = referenceMemberProgress(member);
    const article = document.createElement("article");
    article.className = "reference-member";

    const heading = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `成员 ${ordinal}`;
    const status = document.createElement("span");
    status.className = `badge badge-${String(member.status || "queued")}`;
    status.textContent = verdictLabels[member.status] || member.status || "等待采集";
    heading.append(title, status);

    const track = document.createElement("div");
    track.className = "reference-member-track";
    const bar = document.createElement("i");
    bar.style.width = `${Math.min(100, (progress.done / progress.total) * 100)}%`;
    track.append(bar);

    const counts = document.createElement("small");
    const retries = finiteNumber(member.retry_count, member.retryCount) || 0;
    const errors = finiteNumber(member.error_count, member.errorCount) || 0;
    const quality = member.quality || {};
    const valid = finiteNumber(quality.validSamples, quality.valid_samples);
    const directness = directnessLabel(quality.directness);
    counts.textContent = [
      `${progress.done.toLocaleString()} / ${progress.total.toLocaleString()}`,
      valid === null ? "" : `${valid.toLocaleString()} valid`,
      directness === null ? "" : `direct ${directness}`,
      `重试 ${retries}`,
      `错误 ${errors}`,
    ].filter(Boolean).join(" · ");
    article.append(heading, track, counts);

    [
      ["Fingerprint SHA-256", firstDefined(member.artifact_sha256, member.artifactSha256)],
      ["Raw JSONL SHA-256", firstDefined(member.raw_evidence_sha256, member.rawEvidenceSha256)],
    ].forEach(([label, hash]) => {
      if (!hash) return;
      const line = document.createElement("p");
      const labelNode = document.createElement("span");
      const code = document.createElement("code");
      labelNode.textContent = label;
      code.textContent = String(hash);
      line.append(labelNode, code);
      article.append(line);
    });
    elements.referenceSetMembers.append(article);
  }
}

function pairwiseComparisons(referenceSet) {
  const statistics = referenceSet.statistics || {};
  const comparisons = statistics.pairwiseComparisons || statistics.pairwise_comparisons || [];
  return Array.isArray(comparisons) ? comparisons : [];
}

function renderReferenceSetDistances(referenceSet) {
  elements.referenceSetDistances.replaceChildren();
  const comparisons = pairwiseComparisons(referenceSet);
  if (!comparisons.length) {
    const pending = document.createElement("p");
    pending.textContent = "三轮完成后计算成员间 JSD 与 95% bootstrap 区间。";
    elements.referenceSetDistances.append(pending);
    return;
  }
  const title = document.createElement("strong");
  title.textContent = "参考内部距离";
  elements.referenceSetDistances.append(title);
  comparisons.forEach((comparison) => {
    const row = document.createElement("div");
    const left = firstDefined(comparison.leftMemberOrdinal, comparison.left_member_ordinal, "?");
    const right = firstDefined(comparison.rightMemberOrdinal, comparison.right_member_ordinal, "?");
    const mean = finiteNumber(comparison.meanJsdBase2, comparison.mean_jsd_base2);
    const interval = comparison.confidenceInterval95 || comparison.confidence_interval_95 || {};
    const lower = finiteNumber(interval.lower);
    const upper = finiteNumber(interval.upper);
    row.textContent = `成员 ${left} ↔ ${right}: JSD ${formatNumber(mean, 6)} · 95% CI ${formatNumber(lower, 6)}–${formatNumber(upper, 6)}`;
    elements.referenceSetDistances.append(row);
  });
  const envelope = document.createElement("p");
  envelope.className = "reference-envelope";
  envelope.textContent = `探索性 reference envelope：${formatNumber(referenceSet.referenceEnvelope, 6)}`;
  elements.referenceSetDistances.append(envelope);
}

function renderActiveReferenceSet(referenceSet) {
  if (!referenceSet?.id) return;
  state.activeReferenceSetId = referenceSet.id;
  state.activeReferenceSetStatus = referenceSet.status;
  elements.referenceSetProgress.classList.remove("hidden");
  elements.referenceSetProgressTitle.textContent = `${referenceSet.name} · ${verdictLabels[referenceSet.status] || referenceSet.status}`;
  elements.referenceSetProgressMeta.textContent = [
    `${referenceSet.protocol || "未知协议"}`,
    `${referenceSet.actualModel || "未知模型"}`,
    `创建 ${formatDate(referenceSet.createdAt)}`,
  ].join(" · ");
  renderReferenceSetMembers(referenceSet);
  renderReferenceSetDistances(referenceSet);
  const terminal = referenceSetTerminalStatuses.has(referenceSet.status);
  elements.referenceSetPause.classList.toggle("hidden", terminal);
  elements.referenceSetCancel.classList.toggle("hidden", terminal);
  elements.referenceSetPause.disabled = false;
  elements.referenceSetCancel.disabled = false;
  elements.referenceSetPause.textContent = referenceSet.status === "paused" ? "恢复" : "暂停";
  if (referenceSet.manifestSha256) {
    const suffix = document.createElement("p");
    suffix.className = "reference-manifest-hash";
    const label = document.createElement("span");
    const code = document.createElement("code");
    label.textContent = "冻结 manifest SHA-256";
    code.textContent = referenceSet.manifestSha256;
    suffix.append(label, code);
    elements.referenceSetDistances.append(suffix);
  }
  if (terminal) {
    window.clearTimeout(state.referenceSetPollTimer);
    state.referenceSetPollTimer = null;
    loadReferenceSets({ quiet: true });
  }
}

function referenceSetCard(referenceSet) {
  const article = document.createElement("article");
  article.className = `ready-reference-card${referenceSet.selectable ? " is-ready" : ""}`;
  const heading = document.createElement("div");
  const title = document.createElement("strong");
  title.textContent = referenceSet.name;
  const status = document.createElement("span");
  status.className = `badge badge-${referenceSet.status}`;
  status.textContent = referenceSet.selectable
    ? "READY"
    : referenceSet.status === "ready"
      ? "证据不可选"
      : (verdictLabels[referenceSet.status] || referenceSet.status);
  heading.append(title, status);
  const meta = document.createElement("p");
  meta.textContent = `${referenceSet.sourceType === "official_api" ? "用户声明：官方 API" : "用户声明：可信中转"} · ${referenceSet.protocol} · ${referenceSet.actualModel}`;
  const time = document.createElement("small");
  time.textContent = `${formatDate(referenceSet.createdAt)} · evidence ${referenceSet.evidenceIntegrity} · envelope ${formatNumber(referenceSet.referenceEnvelope, 6)}`;
  const hash = document.createElement("code");
  hash.textContent = referenceSet.manifestSha256 || "manifest hash 待生成";
  article.append(heading, meta, time, hash);
  if (referenceSet.selectable) {
    const choose = document.createElement("button");
    choose.type = "button";
    choose.className = "button button-ghost";
    choose.textContent = elements.oneModelReferenceSelect.value === referenceSet.id ? "已选择" : "用于下一批";
    choose.addEventListener("click", () => {
      elements.oneModelReferenceSelect.value = referenceSet.id;
      setOneModelQuery("reference_set_id", referenceSet.id);
      renderReferenceSetLibrary();
      updateOneModelTargetValidation();
    });
    article.append(choose);
  }
  return article;
}

function renderReferenceSetLibrary() {
  elements.readyReferenceSets.replaceChildren();
  if (!state.referenceSets.length) {
    const empty = document.createElement("div");
    empty.className = "compact-empty";
    const title = document.createElement("strong");
    const copy = document.createElement("p");
    title.textContent = "暂无 ReferenceSet";
    copy.textContent = "完成三轮采集并通过完整性验证后才能用于比较。";
    empty.append(title, copy);
    elements.readyReferenceSets.append(empty);
  } else {
    state.referenceSets.forEach((item) => elements.readyReferenceSets.append(referenceSetCard(item)));
  }

  const selected = elements.oneModelReferenceSelect.value || queryUuid("reference_set_id");
  const ready = state.referenceSets.filter((item) => item.selectable);
  elements.oneModelReferenceSelect.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = ready.length ? "选择三成员 ReferenceSet" : "暂无 ready ReferenceSet";
  elements.oneModelReferenceSelect.append(placeholder);
  ready.forEach((item) => {
    const option = document.createElement("option");
    option.value = item.id;
    option.textContent = `${item.name} · ${item.protocol} · ${item.actualModel}`;
    elements.oneModelReferenceSelect.append(option);
  });
  if (ready.some((item) => item.id === selected)) elements.oneModelReferenceSelect.value = selected;
  updateOneModelTargetValidation();
}

async function loadReferenceSets({ quiet = false } = {}) {
  try {
    const body = await requestJson("/api/v1/console/reference-sets");
    const items = Array.isArray(body?.items) ? body.items : Array.isArray(body) ? body : [];
    state.referenceSets = items.map(normalizeReferenceSet).filter((item) => item.id);
    elements.oneModelApiStatus.textContent = "新批次 API 已连接";
    elements.oneModelApiStatus.className = "badge badge-running";
    renderReferenceSetLibrary();
    return true;
  } catch (error) {
    state.referenceSets = [];
    renderReferenceSetLibrary();
    elements.oneModelApiStatus.textContent = error?.status === 404 ? "新批次 API 尚未启用" : "新批次 API 连接失败";
    elements.oneModelApiStatus.className = "badge badge-muted";
    if (!quiet) {
      setInlineMessage(
        elements.referenceSetFormMessage,
        safeApiError(error, "无法读取 ReferenceSet"),
        "error",
      );
    }
    return false;
  }
}

function scheduleReferenceSetPoll(delay = 1200) {
  window.clearTimeout(state.referenceSetPollTimer);
  if (!state.activeReferenceSetId || referenceSetTerminalStatuses.has(state.activeReferenceSetStatus)) return;
  state.referenceSetPollTimer = window.setTimeout(pollReferenceSet, delay);
}

async function pollReferenceSet() {
  if (!state.activeReferenceSetId) return;
  try {
    const body = await requestJson(`/api/v1/console/reference-sets/${state.activeReferenceSetId}`);
    const referenceSet = normalizeReferenceSet(body);
    renderActiveReferenceSet(referenceSet);
    if (!referenceSetTerminalStatuses.has(referenceSet.status)) scheduleReferenceSetPoll();
  } catch (error) {
    elements.referenceSetProgressTitle.textContent = safeApiError(error, "参考集状态暂时不可读取");
    scheduleReferenceSetPoll(3500);
  }
}

async function createReferenceSet(event) {
  event.preventDefault();
  setInlineMessage(elements.referenceSetFormMessage, "");
  let credential;
  let normalizedUrl;
  try {
    credential = referenceSetCredential();
    normalizedUrl = relayProfiles.normalizeOneModelBaseUrl(elements.referenceSetUrl.value);
    if (!normalizedUrl.valid) throw new Error(normalizedUrl.error);
  } catch (error) {
    setInlineMessage(elements.referenceSetFormMessage, error.message, "error");
    return;
  }
  const protocol = elements.referenceProtocol.value;
  const payload = {
    reference_name: elements.referenceSetName.value.trim(),
    source_type: elements.referenceSourceType.value,
    protocol,
    transport_profile_id: relayProfiles.transportProfileForProtocol(protocol),
    logical_model: elements.referenceLogicalModel.value.trim(),
    actual_model: elements.referenceActualModel.value.trim(),
    base_url: normalizedUrl.value,
    credential,
    anthropic_workspace_id: protocol === "anthropic_messages"
      ? elements.anthropicWorkspaceId.value.trim() || null
      : null,
    cell_count: 40,
    samples_per_cell: 30,
    member_count: 3,
    concurrency: 3,
    request_timeout_seconds: 30,
    member_timeout_seconds: 7200,
  };
  elements.referenceSetUrl.value = normalizedUrl.value;
  elements.referenceSetForm.querySelector("button[type='submit']").disabled = true;
  setInlineMessage(elements.referenceSetFormMessage, "正在提交；临时 Key 已从页面清空…", "info");
  const pending = postJson("/api/v1/console/reference-sets", payload);
  clearReferenceSetSecrets();
  credential = null;
  payload.credential = null;
  try {
    const body = await pending;
    const referenceSet = normalizeReferenceSet(body);
    if (!referenceSet.id) throw new Error("missing_reference_set_id");
    setOneModelQuery("reference_set_id", referenceSet.id);
    setInlineMessage(elements.referenceSetFormMessage, "ReferenceSet 已创建；三轮将依次采集。", "success");
    renderActiveReferenceSet(referenceSet);
    await loadReferenceSets({ quiet: true });
    scheduleReferenceSetPoll();
  } catch (error) {
    setInlineMessage(elements.referenceSetFormMessage, safeApiError(error, "ReferenceSet 创建失败"), "error");
  } finally {
    elements.referenceSetForm.querySelector("button[type='submit']").disabled = false;
  }
}

async function pauseOrResumeReferenceSet() {
  if (!state.activeReferenceSetId) return;
  const action = state.activeReferenceSetStatus === "paused" ? "resume" : "pause";
  elements.referenceSetPause.disabled = true;
  try {
    const body = await postJson(
      `/api/v1/console/reference-sets/${state.activeReferenceSetId}/${action}`,
      {},
    );
    renderActiveReferenceSet(normalizeReferenceSet(body));
    scheduleReferenceSetPoll();
  } catch (error) {
    elements.referenceSetProgressTitle.textContent = safeApiError(error, "参考集操作失败");
    elements.referenceSetPause.disabled = false;
  }
}

async function cancelReferenceSet() {
  if (!state.activeReferenceSetId || !window.confirm("取消三轮参考采集？已完成证据会保留，但该组不能用于后续批次。")) return;
  elements.referenceSetCancel.disabled = true;
  try {
    const body = await postJson(
      `/api/v1/console/reference-sets/${state.activeReferenceSetId}/cancel`,
      {},
    );
    renderActiveReferenceSet(normalizeReferenceSet(body));
  } catch (error) {
    elements.referenceSetProgressTitle.textContent = safeApiError(error, "取消参考集失败");
    elements.referenceSetCancel.disabled = false;
  }
}

function oneModelRowsFromDom() {
  return [...elements.oneModelTargetRows.querySelectorAll("tr[data-one-model-row]")].map(
    (row, index) => ({
      sourceRow: index + 1,
      stationName: row.querySelector(".one-model-target-name").value,
      baseUrl: row.querySelector(".one-model-target-url").value,
      credentialText: row.querySelector(".one-model-target-credential").value,
      modelId: row.querySelector(".one-model-target-model").value,
      element: row,
    }),
  );
}

function oneModelConcurrencySettings() {
  const maxStations = Number(elements.oneModelMaxStations.value);
  const perStation = Number(elements.oneModelPerStation.value);
  const global = Number(elements.oneModelGlobalConcurrency.value);
  if (!Number.isInteger(maxStations) || maxStations < 1 || maxStations > 8) {
    return { valid: false, error: "并行站点必须为 1–8" };
  }
  if (!Number.isInteger(perStation) || perStation < 1 || perStation > 4) {
    return { valid: false, error: "每站并发必须为 1–4" };
  }
  if (!Number.isInteger(global) || global < 1 || global > 16) {
    return { valid: false, error: "全局并发必须为 1–16" };
  }
  if (global > maxStations * perStation) {
    return { valid: false, error: "全局并发不能超过“并行站点 × 每站并发”" };
  }
  return {
    valid: true,
    value: {
      max_parallel_stations: maxStations,
      per_station_concurrency: perStation,
      global_request_concurrency: global,
    },
  };
}

function addOneModelTargetRow(values = {}) {
  const currentCount = elements.oneModelTargetRows.querySelectorAll("tr[data-one-model-row]").length;
  if (currentCount >= 20) {
    setInlineMessage(elements.oneModelImportMessage, "单批最多 20 个中转站。", "error");
    return null;
  }
  state.oneModelTargetSequence += 1;
  const row = document.createElement("tr");
  row.dataset.oneModelRow = String(state.oneModelTargetSequence);

  const numberCell = document.createElement("td");
  numberCell.className = "one-model-row-number";

  const inputDefinitions = [
    ["stationName", "one-model-target-name", "站点名称", "text"],
    ["baseUrl", "one-model-target-url", "https://relay.example/v1", "url"],
    ["credentialText", "one-model-target-credential api-key", "API Key 或 env:NAME", "password"],
    ["modelId", "one-model-target-model", "留空使用默认模型", "text"],
  ];
  inputDefinitions.forEach(([key, className, placeholder, type]) => {
    const cell = document.createElement("td");
    const input = document.createElement("input");
    input.type = type;
    input.className = className;
    input.placeholder = placeholder;
    input.autocomplete = type === "password" ? "new-password" : "off";
    input.spellcheck = false;
    input.value = String(values[key] || "");
    if (key === "stationName") input.maxLength = 80;
    if (key === "modelId") input.maxLength = 255;
    input.addEventListener("input", updateOneModelTargetValidation);
    if (key === "baseUrl") {
      input.addEventListener("blur", () => updateOneModelTargetValidation({ normalizeUrls: true }));
    }
    cell.append(input);
    row.append(cell);
  });

  const statusCell = document.createElement("td");
  statusCell.className = "one-model-row-validation";
  statusCell.textContent = "待校验";
  const actionCell = document.createElement("td");
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "icon-button one-model-remove-target";
  remove.setAttribute("aria-label", "移除目标站");
  remove.textContent = "×";
  remove.addEventListener("click", () => {
    row.querySelector(".one-model-target-credential").value = "";
    row.remove();
    updateOneModelTargetValidation();
  });
  actionCell.append(remove);
  row.prepend(numberCell);
  row.append(statusCell, actionCell);
  elements.oneModelTargetRows.append(row);
  updateOneModelTargetValidation();
  return row;
}

function updateOneModelTargetValidation(options = {}) {
  if (!elements.oneModelTargetRows) return { valid: false, targets: [], errors: [] };
  const rows = oneModelRowsFromDom();
  rows.forEach((row, index) => {
    row.element.querySelector(".one-model-row-number").textContent = String(index + 1);
    if (options.normalizeUrls) {
      const normalized = relayProfiles.normalizeOneModelBaseUrl(row.baseUrl);
      if (normalized.valid) {
        row.element.querySelector(".one-model-target-url").value = normalized.value;
        row.baseUrl = normalized.value;
      }
    }
  });
  const validation = relayProfiles.validateOneModelTargets(rows, elements.oneModelDefaultModel.value);
  const errorsByRow = new Map();
  validation.errors.forEach((error) => {
    if (!error.row) return;
    if (!errorsByRow.has(error.row)) errorsByRow.set(error.row, []);
    errorsByRow.get(error.row).push(error.message);
  });
  rows.forEach((row, index) => {
    const status = row.element.querySelector(".one-model-row-validation");
    const errors = errorsByRow.get(index + 1) || [];
    row.element.classList.toggle("is-invalid", errors.length > 0);
    row.element.classList.toggle("is-valid", !errors.length);
    status.textContent = errors.length ? errors.join("；") : "可提交";
  });
  const concurrency = oneModelConcurrencySettings();
  const globalError = validation.errors.find((error) => !error.row)?.message || concurrency.error || "";
  const rowErrorCount = validation.errors.filter((error) => error.row).length;
  if (!rows.length && concurrency.valid) {
    setInlineMessage(elements.oneModelImportMessage, "粘贴 TSV 或添加空行；凭据只保留在当前输入框。", "");
  } else if (globalError) {
    setInlineMessage(elements.oneModelImportMessage, globalError, "error");
  } else if (rowErrorCount) {
    setInlineMessage(elements.oneModelImportMessage, `有 ${rowErrorCount} 项逐行校验错误，请按红色提示修正。`, "error");
  } else if (rows.length) {
    setInlineMessage(elements.oneModelImportMessage, `已校验 ${rows.length} 行；凭据不会写入浏览器存储。`, "success");
  } else {
    setInlineMessage(elements.oneModelImportMessage, "");
  }
  const estimate = relayProfiles.oneModelRequestEstimate(rows.length);
  elements.oneModelTargetCount.textContent = `${rows.length} / 20`;
  elements.oneModelTargetEstimate.textContent = estimate.targetRequests.toLocaleString();
  elements.oneModelTotalEstimate.textContent = estimate.totalRequests.toLocaleString();
  elements.runOneModelBatch.disabled = !(
    validation.valid
    && concurrency.valid
    && elements.oneModelReferenceSelect.value
  );
  // Routine validation never retains a second copy of any plaintext credential.
  if (!options.keepTargets) {
    validation.targets.forEach((target) => { target.credential = null; });
    validation.targets.length = 0;
  }
  return validation;
}

function importOneModelTsv() {
  const parsed = relayProfiles.parseOneModelTsv(elements.oneModelTsv.value);
  if (parsed.errors.length) {
    const message = parsed.errors.map((error) => (
      `${error.row ? `第 ${error.row} 行：` : ""}${error.message}`
    )).join("；");
    setInlineMessage(elements.oneModelImportMessage, message, "error");
    return;
  }
  clearOneModelSecrets();
  elements.oneModelTargetRows.replaceChildren();
  state.oneModelTargetSequence = 0;
  parsed.rows.forEach((row) => addOneModelTargetRow(row));
  parsed.rows.forEach((row) => { row.credentialText = ""; });
  elements.oneModelTsv.value = "";
  updateOneModelTargetValidation({ normalizeUrls: true });
}

function clearOneModelTargets() {
  clearOneModelSecrets();
  elements.oneModelTargetRows.replaceChildren();
  state.oneModelTargetSequence = 0;
  updateOneModelTargetValidation();
}

function safeReasonCodes(...sources) {
  const values = sources.flatMap((source) => (
    Array.isArray(source) ? source : source === undefined || source === null ? [] : [source]
  ));
  return [...new Set(values
    .map((value) => String(value).trim())
    .filter((value) => safeResultReasonCodes.has(value)))]
    .slice(0, 8);
}

function normalizeOneModelItem(item, index) {
  const result = item?.result || item?.comparison || item || {};
  const quality = item?.quality || result?.metrics || result?.quality || {};
  const distances = result?.distances || item?.distances || {};
  const distanceMembers = Array.isArray(distances)
    ? distances
    : Array.isArray(distances?.members) ? distances.members : [];
  const means = distanceMembers.length
    ? distanceMembers.map((distance) => finiteNumber(
      distance.meanJsdBase2,
      distance.mean_jsd_base2,
      distance.mean_jsd,
    )).filter((value) => value !== null)
    : [];
  const status = String(firstDefined(item?.status, result?.execution_status, "queued"));
  const exploratoryStatus = String(firstDefined(
    item?.exploratory_status,
    item?.exploratoryStatus,
    result?.status,
    result?.exploratory_status,
    "",
  ));
  const reasonCodes = safeReasonCodes(
    item?.safe_error_code,
    item?.safeErrorCode,
    result?.reasonCodes,
    result?.reason_codes,
    result?.error?.code,
    quality?.reasonCodes,
    quality?.reason_codes,
  );
  return {
    sequence: finiteNumber(item?.sequence) ?? index,
    rowId: String(firstDefined(item?.row_id, item?.rowId, `row-${index + 1}`)),
    stationName: String(firstDefined(item?.station_name, item?.stationName, "未命名中转站")),
    model: String(firstDefined(item?.model, item?.model_id, item?.modelId, "")),
    reportedModel: String(firstDefined(
      item?.reported_model,
      item?.reportedModel,
      result?.reported_model,
      result?.reportedModel,
      "",
    )),
    status,
    stage: safeProgressStages.has(String(item?.stage || "")) ? String(item.stage) : "",
    progressDone: finiteNumber(item?.progress_done, item?.progressDone) || 0,
    progressTotal: finiteNumber(item?.progress_total, item?.progressTotal) || 1200,
    exploratoryStatus,
    medianJsd: finiteNumber(
      result?.medianMeanJsdBase2,
      result?.median_mean_jsd_base2,
      distances?.median_mean_jsd,
      item?.median_mean_jsd_base2,
      means.length ? median(means) : undefined,
    ),
    coverage: finiteNumber(quality?.cellCoverage, quality?.cell_coverage),
    sufficientCells: finiteNumber(
      quality?.sufficientCellCount,
      quality?.sufficient_cell_count,
      quality?.coverage_cells,
    ),
    cellCount: finiteNumber(quality?.cellCount, quality?.cell_count, quality?.total_cells) || 40,
    validSamples: finiteNumber(quality?.validSamples, quality?.valid_samples),
    invalidSamples: finiteNumber(quality?.invalidSamples, quality?.invalid_samples),
    errorSamples: finiteNumber(quality?.errorSamples, quality?.error_samples),
    directness: directnessLabel(quality?.directness),
    splitHalf: finiteNumber(
      quality?.splitHalf,
      quality?.split_half,
      quality?.split_half_mean_jsd,
    ),
    latencyP50: finiteNumber(
      item?.latency_p50_ms,
      item?.latencyP50Ms,
      result?.latencyP50Ms,
      result?.latency?.p50_ms,
    ),
    latencyP95: finiteNumber(
      item?.latency_p95_ms,
      item?.latencyP95Ms,
      result?.latencyP95Ms,
      result?.latency?.p95_ms,
    ),
    retries: finiteNumber(item?.retry_count, item?.retryCount, result?.requests?.retries) || 0,
    errorCount: finiteNumber(item?.error_count, item?.errorCount) || 0,
    httpStatus: finiteNumber(
      item?.error_http_status,
      item?.errorHttpStatus,
      result?.error?.http_status,
      result?.preflight?.http_status,
    ),
    reasonCodes,
  };
}

function normalizeOneModelBatch(value) {
  const wrapper = value?.batch || value?.one_model_batch || value?.oneModelBatch || value || {};
  const rawItems = value?.items || wrapper.items || value?.targets || [];
  return {
    id: String(firstDefined(wrapper.id, wrapper.batch_id, value?.batch_id) || ""),
    referenceSetId: String(firstDefined(wrapper.reference_set_id, wrapper.referenceSetId, "")),
    status: String(firstDefined(wrapper.status, "running")),
    totalItems: finiteNumber(wrapper.total_items, wrapper.totalItems) || (Array.isArray(rawItems) ? rawItems.length : 0),
    completedItems: finiteNumber(wrapper.completed_items, wrapper.completedItems) || 0,
    failedItems: finiteNumber(wrapper.failed_items, wrapper.failedItems) || 0,
    progressDone: finiteNumber(wrapper.progress_done, wrapper.progressDone) || 0,
    progressTotal: finiteNumber(wrapper.progress_total, wrapper.progressTotal) || 0,
    protocol: String(firstDefined(wrapper.protocol, "")),
    profile: String(firstDefined(wrapper.transport_profile_id, wrapper.transportProfileId, "")),
    createdAt: firstDefined(wrapper.created_at, wrapper.createdAt),
    updatedAt: firstDefined(wrapper.updated_at, wrapper.updatedAt),
    reportSha256: String(firstDefined(wrapper.report_sha256, wrapper.reportSha256, "")),
    items: Array.isArray(rawItems) ? rawItems.map(normalizeOneModelItem) : [],
  };
}

function oneModelStatusLabel(item) {
  return exploratoryLabels[item.exploratoryStatus]
    || verdictLabels[item.status]
    || item.status
    || "等待执行";
}

function oneModelQualityLabel(item) {
  const parts = [];
  if (item.validSamples !== null) parts.push(`${item.validSamples.toLocaleString()} valid`);
  if (item.coverage !== null) parts.push(`${(item.coverage * 100).toFixed(0)}% cells`);
  else if (item.sufficientCells !== null) parts.push(`${item.sufficientCells}/${item.cellCount} cells`);
  if (item.directness !== null) parts.push(`direct ${item.directness}`);
  if (item.splitHalf !== null) parts.push(`split ${item.splitHalf.toFixed(2)}`);
  return parts.join(" · ") || "—";
}

function oneModelQualityScore(item) {
  if (item.coverage !== null) return item.coverage;
  if (item.sufficientCells !== null && item.cellCount) return item.sufficientCells / item.cellCount;
  if (item.validSamples !== null) return item.validSamples / 1200;
  return -1;
}

function oneModelErrorScore(item) {
  return item.errorCount + (item.errorSamples || 0) + (item.status === "failed" ? 1200 : 0);
}

function renderOneModelResults() {
  let items = [...state.oneModelBatchItems];
  const filter = elements.oneModelResultFilter.value;
  if (filter === "active") {
    items = items.filter((item) => !oneModelTerminalStatuses.has(item.status));
  } else if (filter === "has_error") {
    items = items.filter((item) => oneModelErrorScore(item) > 0 || [
      "request_failed",
      "unsupported_protocol",
    ].includes(item.exploratoryStatus));
  } else if (filter) {
    items = items.filter((item) => item.exploratoryStatus === filter || item.status === filter);
  }
  const sort = elements.oneModelResultSort.value;
  if (sort === "jsd_asc") {
    items.sort((left, right) => (left.medianJsd ?? Infinity) - (right.medianJsd ?? Infinity));
  } else if (sort === "quality_desc") {
    items.sort((left, right) => oneModelQualityScore(right) - oneModelQualityScore(left));
  } else if (sort === "errors_desc") {
    items.sort((left, right) => oneModelErrorScore(right) - oneModelErrorScore(left));
  } else if (sort === "latency_asc") {
    items.sort((left, right) => (left.latencyP95 ?? Infinity) - (right.latencyP95 ?? Infinity));
  } else if (sort === "status") {
    items.sort((left, right) => oneModelStatusLabel(left).localeCompare(oneModelStatusLabel(right), "zh-CN"));
  } else {
    items.sort((left, right) => left.sequence - right.sequence);
  }

  elements.oneModelResultRows.replaceChildren();
  if (!items.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 7;
    cell.className = "table-empty";
    cell.textContent = state.oneModelBatchItems.length ? "当前筛选条件下无结果" : "等待批次结果";
    row.append(cell);
    elements.oneModelResultRows.append(row);
    return;
  }

  items.forEach((item) => {
    const row = document.createElement("tr");
    row.className = `one-model-result-row status-${item.exploratoryStatus || item.status}`;
    const station = document.createElement("td");
    const stationName = document.createElement("strong");
    const model = document.createElement("code");
    const reportedModel = document.createElement("small");
    const progress = document.createElement("small");
    stationName.textContent = item.stationName;
    model.textContent = item.model;
    reportedModel.textContent = item.reportedModel ? `reported: ${item.reportedModel}` : "reported: —";
    progress.textContent = `${item.progressDone.toLocaleString()} / ${item.progressTotal.toLocaleString()}`;
    station.append(stationName, model, reportedModel, progress);

    const status = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge badge-${item.exploratoryStatus || item.status}`;
    badge.textContent = oneModelStatusLabel(item);
    status.append(badge);

    const quality = document.createElement("td");
    quality.textContent = oneModelQualityLabel(item);
    const jsd = document.createElement("td");
    jsd.className = "numeric-cell";
    jsd.textContent = formatNumber(item.medianJsd, 6);
    const latency = document.createElement("td");
    latency.className = "numeric-cell";
    latency.textContent = `${formatDuration(item.latencyP50)} / ${formatDuration(item.latencyP95)}`;
    const retries = document.createElement("td");
    retries.className = "numeric-cell";
    retries.textContent = String(item.retries);
    const reason = document.createElement("td");
    const reasonParts = [...item.reasonCodes];
    if (item.httpStatus !== null) reasonParts.push(`HTTP ${item.httpStatus}`);
    if (item.errorCount || item.errorSamples) {
      reasonParts.push(`错误 ${item.errorCount + (item.errorSamples || 0)}`);
    }
    reason.textContent = reasonParts.join(" · ") || (item.stage || "—");
    row.append(station, status, quality, jsd, latency, retries, reason);
    elements.oneModelResultRows.append(row);
  });
}

function renderOneModelBatch(value) {
  const batch = normalizeOneModelBatch(value);
  if (!batch.id) return;
  state.oneModelBatchId = batch.id;
  state.oneModelBatchStatus = batch.status;
  state.oneModelBatchItems = batch.items;
  setOneModelQuery("batch_id", batch.id);
  const terminal = oneModelTerminalStatuses.has(batch.status);
  const itemTerminalCount = batch.items.filter((item) => oneModelTerminalStatuses.has(item.status)).length;
  elements.oneModelBatchStatus.textContent = `批次 ${batch.id} · ${verdictLabels[batch.status] || batch.status}`;
  elements.oneModelBatchMeta.textContent = [
    `${itemTerminalCount || batch.completedItems + batch.failedItems}/${batch.totalItems} 站终态`,
    batch.progressTotal ? `${batch.progressDone.toLocaleString()}/${batch.progressTotal.toLocaleString()} samples` : "等待采样",
    `更新 ${formatDate(batch.updatedAt || batch.createdAt)}`,
    batch.reportSha256 ? `report SHA-256 ${batch.reportSha256}` : "",
  ].filter(Boolean).join(" · ");
  elements.oneModelPause.classList.toggle("hidden", terminal);
  elements.oneModelCancel.classList.toggle("hidden", terminal);
  elements.oneModelPause.disabled = false;
  elements.oneModelCancel.disabled = false;
  elements.oneModelPause.textContent = batch.status === "paused" ? "恢复" : "暂停";
  elements.oneModelJsonDownload.classList.toggle("hidden", !terminal);
  elements.oneModelCsvDownload.classList.toggle("hidden", !terminal);
  if (terminal) {
    elements.oneModelJsonDownload.href = `/api/v1/console/one-model-batches/${batch.id}/report.json`;
    elements.oneModelCsvDownload.href = `/api/v1/console/one-model-batches/${batch.id}/report.csv`;
    window.clearTimeout(state.oneModelBatchPollTimer);
    state.oneModelBatchPollTimer = null;
  }
  renderOneModelResults();
}

function scheduleOneModelBatchPoll(delay = 1200) {
  window.clearTimeout(state.oneModelBatchPollTimer);
  if (!state.oneModelBatchId || oneModelTerminalStatuses.has(state.oneModelBatchStatus)) return;
  state.oneModelBatchPollTimer = window.setTimeout(pollOneModelBatch, delay);
}

async function pollOneModelBatch() {
  if (!state.oneModelBatchId) return;
  try {
    const body = await requestJson(`/api/v1/console/one-model-batches/${state.oneModelBatchId}`);
    renderOneModelBatch(body);
    if (!oneModelTerminalStatuses.has(state.oneModelBatchStatus)) scheduleOneModelBatchPoll();
  } catch (error) {
    elements.oneModelBatchStatus.textContent = safeApiError(error, "批次状态暂时不可读取");
    scheduleOneModelBatchPoll(3500);
  }
}

async function runOneModelBatch() {
  const referenceSetId = elements.oneModelReferenceSelect.value;
  if (!referenceSetId) {
    setInlineMessage(elements.oneModelImportMessage, "请选择 ready ReferenceSet。", "error");
    return;
  }
  const concurrency = oneModelConcurrencySettings();
  const validation = updateOneModelTargetValidation({ normalizeUrls: true, keepTargets: true });
  if (!concurrency.valid || !validation.valid) return;
  const payload = {
    reference_set_id: referenceSetId,
    default_model_id: elements.oneModelDefaultModel.value.trim(),
    targets: validation.targets,
    ...concurrency.value,
    request_timeout_seconds: 30,
    station_timeout_seconds: 7200,
    batch_timeout_seconds: 43200,
    retry_budget: 240,
  };
  elements.runOneModelBatch.disabled = true;
  setInlineMessage(elements.oneModelImportMessage, "正在提交；所有明文 Key 和粘贴区已清空…", "info");
  const pending = postJson("/api/v1/console/one-model-batches", payload);
  clearOneModelSecrets();
  validation.targets.forEach((target) => { target.credential = null; });
  validation.targets.length = 0;
  payload.targets = [];
  try {
    const body = await pending;
    const batch = normalizeOneModelBatch(body);
    if (!batch.id) throw new Error("missing_batch_id");
    setInlineMessage(elements.oneModelImportMessage, "批次已创建；刷新页面可通过 batch_id 恢复进度。", "success");
    renderOneModelBatch(body);
    scheduleOneModelBatchPoll();
  } catch (error) {
    setInlineMessage(elements.oneModelImportMessage, safeApiError(error, "批次创建失败；凭据需重新输入"), "error");
    updateOneModelTargetValidation();
  }
}

async function pauseOrResumeOneModelBatch() {
  if (!state.oneModelBatchId) return;
  const action = state.oneModelBatchStatus === "paused" ? "resume" : "pause";
  elements.oneModelPause.disabled = true;
  try {
    const body = await postJson(
      `/api/v1/console/one-model-batches/${state.oneModelBatchId}/${action}`,
      {},
    );
    renderOneModelBatch(body);
    scheduleOneModelBatchPoll();
  } catch (error) {
    elements.oneModelBatchStatus.textContent = safeApiError(error, "批次操作失败");
    elements.oneModelPause.disabled = false;
  }
}

async function cancelOneModelBatch() {
  if (!state.oneModelBatchId || !window.confirm("取消整个单模型批次？报告仍会包含全部输入行的终态。")) return;
  elements.oneModelCancel.disabled = true;
  try {
    const body = await postJson(
      `/api/v1/console/one-model-batches/${state.oneModelBatchId}/cancel`,
      {},
    );
    renderOneModelBatch(body);
    scheduleOneModelBatchPoll();
  } catch (error) {
    elements.oneModelBatchStatus.textContent = safeApiError(error, "取消批次失败");
    elements.oneModelCancel.disabled = false;
  }
}

async function initializeOneModelWorkbench() {
  if (!elements.referenceSetForm) return;
  syncReferenceSetForm();
  updateOneModelTargetValidation();
  await loadReferenceSets({ quiet: true });
  const referenceSetId = queryUuid("reference_set_id");
  if (referenceSetId) {
    try {
      const body = await requestJson(`/api/v1/console/reference-sets/${referenceSetId}`);
      const referenceSet = normalizeReferenceSet(body);
      renderActiveReferenceSet(referenceSet);
      if (referenceSet.selectable) {
        elements.oneModelReferenceSelect.value = referenceSet.id;
        updateOneModelTargetValidation();
      } else {
        scheduleReferenceSetPoll();
      }
    } catch {
      // The list panel already shows API availability without reflecting server details.
    }
  }
  const batchId = queryUuid("batch_id");
  if (batchId) {
    state.oneModelBatchId = batchId;
    try {
      const body = await requestJson(`/api/v1/console/one-model-batches/${batchId}`);
      renderOneModelBatch(body);
      scheduleOneModelBatchPoll();
    } catch (error) {
      elements.oneModelBatchStatus.textContent = safeApiError(error, "无法恢复 URL 中的批次");
    }
  }
}

async function checkHealth() {
  try {
    const body = await requestJson("/health");
    elements.appHealth.textContent = `服务在线 · v${body.version}`;
  } catch {
    elements.appHealth.textContent = "本地服务连接失败";
  }
}

elements.referenceForm.addEventListener("submit", collectReferences);
elements.pauseReference.addEventListener("click", pauseOrResumeReferenceCollection);
elements.cancelReference.addEventListener("click", cancelReferenceCollection);
elements.retryReferenceRecovery.addEventListener("click", retryReferenceRecovery);
elements.fetchReferenceModels.addEventListener("click", fetchReferenceModels);
elements.addReferenceModel.addEventListener("click", () => {
  addReferenceModel(elements.referenceManualModel.value, true);
  elements.referenceManualModel.value = "";
});
elements.selectAllReferenceModels.addEventListener("click", () => {
  state.referenceModels.forEach((_, model) => state.referenceModels.set(model, true));
  renderReferenceModelPicker();
  scheduleWorkspaceSave();
});
elements.clearReferenceModels.addEventListener("click", () => {
  state.referenceModels.forEach((_, model) => state.referenceModels.set(model, false));
  renderReferenceModelPicker();
  scheduleWorkspaceSave();
});
elements.refreshReferences.addEventListener("click", loadReferences);
elements.addTarget.addEventListener("click", () => addTarget());
elements.runAll.addEventListener("click", runAllMappings);
elements.retryComparisonRecovery.addEventListener("click", retryComparisonRecovery);
elements.pauseBatch.addEventListener("click", pauseOrResumeActiveBatch);
elements.cancelBatch.addEventListener("click", cancelActiveBatch);
elements.clearKeys.addEventListener("click", () => {
  document.querySelectorAll(".api-key").forEach((input) => {
    input.value = "";
  });
  if (elements.oneModelTsv) elements.oneModelTsv.value = "";
  updateOneModelTargetValidation();
});
elements.preset.addEventListener("change", updateControls);
elements.methodProfile.addEventListener("change", updateControls);
elements.concurrencyMode.addEventListener("change", updateControls);
elements.concurrency.addEventListener("change", updateControls);
elements.requestTimeout.addEventListener("change", updateControls);
elements.modelTimeout.addEventListener("change", updateControls);
elements.referenceSetForm.addEventListener("submit", createReferenceSet);
elements.referenceProtocol.addEventListener("change", syncReferenceSetForm);
elements.referenceCredentialMode.addEventListener("change", syncReferenceSetForm);
elements.refreshReferenceSets.addEventListener("click", () => loadReferenceSets());
elements.referenceSetPause.addEventListener("click", pauseOrResumeReferenceSet);
elements.referenceSetCancel.addEventListener("click", cancelReferenceSet);
elements.oneModelReferenceSelect.addEventListener("change", () => {
  setOneModelQuery("reference_set_id", elements.oneModelReferenceSelect.value);
  renderReferenceSetLibrary();
  updateOneModelTargetValidation();
});
elements.oneModelDefaultModel.addEventListener("input", updateOneModelTargetValidation);
elements.oneModelMaxStations.addEventListener("input", updateOneModelTargetValidation);
elements.oneModelPerStation.addEventListener("input", updateOneModelTargetValidation);
elements.oneModelGlobalConcurrency.addEventListener("input", updateOneModelTargetValidation);
elements.importOneModelTsv.addEventListener("click", importOneModelTsv);
elements.addOneModelTarget.addEventListener("click", () => addOneModelTargetRow());
elements.clearOneModelTargets.addEventListener("click", clearOneModelTargets);
elements.runOneModelBatch.addEventListener("click", runOneModelBatch);
elements.oneModelResultFilter.addEventListener("change", renderOneModelResults);
elements.oneModelResultSort.addEventListener("change", renderOneModelResults);
elements.oneModelPause.addEventListener("click", pauseOrResumeOneModelBatch);
elements.oneModelCancel.addEventListener("click", cancelOneModelBatch);

document.addEventListener("input", (event) => {
  if (event.target instanceof HTMLInputElement && event.target.classList.contains("api-key")) return;
  scheduleWorkspaceSave();
});
document.addEventListener("change", (event) => {
  if (event.target instanceof HTMLInputElement && event.target.classList.contains("api-key")) return;
  scheduleWorkspaceSave();
});

elements.resetWorkspace?.addEventListener("click", () => {
  const confirmed = window.confirm("重置当前工作区配置？历史对比记录和证据不会删除。");
  if (!confirmed) return;
  document.querySelectorAll(".api-key").forEach((input) => {
    input.value = "";
  });
  restoringWorkspace = true;
  seedDefaultWorkspace();
  restoringWorkspace = false;
  updateControls();
  saveWorkspaceNow();
});

async function initializeConsole() {
  setBusy(true, "initialization");
  restoringWorkspace = true;
  await loadReferences();
  const restored = restoreWorkspace();
  if (!restored) seedDefaultWorkspace();
  restoringWorkspace = false;
  // restoreWorkspace 会动态创建输入框；再次应用初始化闸门，避免恢复检查完成前重复提交。
  setBusy(true, "initialization");
  updateControls();
  saveWorkspaceNow();
  await Promise.all([
    loadLatestResults(),
    loadActiveReferenceCollection(),
    loadActiveBatch(),
  ]);
  state.ready = true;
  setBusy(false, "initialization");
  checkHealth();
}

initializeConsole();
initializeOneModelWorkbench();
