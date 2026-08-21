const presets = {
  quick: { cells: 4, samples: 15, label: "快速" },
  standard: { cells: 8, samples: 25, label: "标准" },
  strict: { cells: 16, samples: 25, label: "严格" },
};

const relayStatus = window.RelayStatus;
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

const workspaceStorageKey = "relay-auditor.workspace.v1";
const workspaceVersion = 1;
let workspaceSaveTimer = null;
let restoringWorkspace = false;

const state = {
  references: [],
  referenceModels: new Map(),
  observedRuns: [],
  running: false,
  targetSequence: 0,
  activeBatchId: null,
  activeBatchStatus: null,
  batchPollTimer: null,
};

const elements = {
  referenceForm: document.querySelector("#reference-form"),
  referenceName: document.querySelector("#reference-name"),
  referenceUrl: document.querySelector("#reference-url"),
  referenceKey: document.querySelector("#reference-key"),
  referenceManualModel: document.querySelector("#reference-manual-model"),
  referenceBadge: document.querySelector("#reference-badge"),
  referenceModelList: document.querySelector("#reference-model-list"),
  referenceModelCount: document.querySelector("#reference-model-count"),
  referenceProgress: document.querySelector("#reference-progress"),
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
};

function workspaceSnapshot() {
  return {
    version: workspaceVersion,
    reference: {
      name: elements.referenceName.value,
      baseUrl: elements.referenceUrl.value,
      manualModel: elements.referenceManualModel.value,
      models: [...state.referenceModels.entries()].map(([model, selected]) => ({
        model,
        selected,
      })),
    },
    settings: {
      preset: elements.preset.value,
      concurrencyMode: elements.concurrencyMode.value,
      concurrency: elements.concurrency.value,
      requestTimeout: elements.requestTimeout.value,
      modelTimeout: elements.modelTimeout.value,
    },
    targets: targetCards().map((card) => ({
      name: card.querySelector(".target-name").value,
      baseUrl: card.querySelector(".target-url").value,
      manualModel: card.querySelector(".target-manual-model").value,
      models: [...card.querySelectorAll(".mapping-row")].map((row) => ({
        model: row.dataset.model,
        referenceArtifactId: row.querySelector(".mapping-reference").value,
        enabled: row.querySelector(".mapping-enabled").checked,
        priority: Number(row.querySelector(".mapping-priority").value) || 50,
      })),
    })),
  };
}

function setWorkspaceStatus(message) {
  if (elements.workspaceStatus) elements.workspaceStatus.textContent = message;
}

function saveWorkspaceNow() {
  if (restoringWorkspace) return;
  try {
    localStorage.setItem(workspaceStorageKey, JSON.stringify(workspaceSnapshot()));
    setWorkspaceStatus("工作区已自动保存");
  } catch {
    setWorkspaceStatus("浏览器未允许保存工作区");
  }
}

function scheduleWorkspaceSave() {
  if (restoringWorkspace) return;
  setWorkspaceStatus("正在保存工作区…");
  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = window.setTimeout(saveWorkspaceNow, 250);
}

function restoreWorkspace() {
  let saved;
  try {
    saved = JSON.parse(localStorage.getItem(workspaceStorageKey) || "null");
  } catch {
    return false;
  }
  if (!saved || saved.version !== workspaceVersion) return false;

  elements.referenceName.value = saved.reference?.name || "";
  elements.referenceUrl.value = saved.reference?.baseUrl || "";
  elements.referenceManualModel.value = saved.reference?.manualModel || "";
  state.referenceModels.clear();
  (saved.reference?.models || []).forEach((item) => {
    if (item?.model) state.referenceModels.set(item.model, Boolean(item.selected));
  });
  if (presets[saved.settings?.preset]) elements.preset.value = saved.settings.preset;
  // v1 工作区原先没有并发策略；缺字段必须保持原来的固定并发语义。
  elements.concurrencyMode.value = saved.settings?.concurrencyMode === "auto" ? "auto" : "fixed";
  if (saved.settings?.concurrency) elements.concurrency.value = saved.settings.concurrency;
  if (saved.settings?.requestTimeout) elements.requestTimeout.value = saved.settings.requestTimeout;
  if (saved.settings?.modelTimeout) elements.modelTimeout.value = saved.settings.modelTimeout;

  elements.targetList.replaceChildren();
  state.targetSequence = 0;
  (saved.targets || []).forEach((target) => {
    const card = addTarget({ name: target.name, baseUrl: target.baseUrl });
    card.querySelector(".target-manual-model").value = target.manualModel || "";
    (target.models || []).forEach((item) => {
      addTargetModel(card, item.model, {
        referenceArtifactId: item.referenceArtifactId,
        enabled: item.enabled,
        priority: item.priority,
      });
    });
  });
  renderReferenceModelPicker();
  setWorkspaceStatus("已恢复上次工作区 · Key 未保存");
  return true;
}

function seedDefaultWorkspace() {
  elements.referenceName.value = "Local Mock";
  elements.referenceUrl.value = "http://127.0.0.1:8000/mock/v1";
  elements.referenceManualModel.value = "reference-model";
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

function settings() {
  const preset = presets[elements.preset.value] || presets.standard;
  return {
    cells: preset.cells,
    samples: preset.samples,
    concurrencyMode: elements.concurrencyMode.value === "fixed" ? "fixed" : "auto",
    concurrency: Number(elements.concurrency.value) || 4,
    requestTimeoutSeconds: Number(elements.requestTimeout.value) || 15,
    modelTimeoutSeconds: Number(elements.modelTimeout.value) || 300,
  };
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
      : rawDetail || `HTTP ${response.status}`;
    throw new Error(detail);
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

function setBusy(busy) {
  state.running = busy;
  document.body.classList.toggle("is-busy", busy);
  document.querySelectorAll("button, input, select").forEach((node) => {
    node.disabled = busy && node.dataset.allowBusy !== "true";
  });
  if (!busy) updateControls();
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
    status.className = "badge badge-match";
    status.textContent = "Active";
    heading.append(title, status);

    const endpoint = document.createElement("p");
    endpoint.className = "reference-url";
    endpoint.textContent = reference.baseUrl;

    const meta = document.createElement("dl");
    [
      ["采集时间", formatDate(reference.validFrom)],
      ["采样耗时", reference.durationMs === null ? "—" : formatClockDuration(reference.durationMs)],
      ["有效期至", formatDate(reference.expiresAt)],
      ["SHA-256", reference.sha256 ? reference.sha256.slice(0, 16) : "—"],
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

function startRunTimer(total, current, onTick) {
  const estimate = estimateDuration(1, current);
  const timing = {
    total,
    completed: 0,
    startedAt: performance.now(),
    currentStartedAt: null,
    currentLabel: "",
    initialPerModelMs: estimate.perModelMs,
    durations: [],
    current,
    onTick,
    interval: null,
  };
  timing.interval = window.setInterval(() => tickRunTimer(timing), 1000);
  return timing;
}

function currentPerModelEstimate(timing) {
  return median(timing.durations) || timing.initialPerModelMs;
}

function tickRunTimer(timing) {
  const now = performance.now();
  const elapsedMs = now - timing.startedAt;
  const perModelMs = currentPerModelEstimate(timing);
  const unfinished = Math.max(0, timing.total - timing.completed);
  let remainingMs = perModelMs * unfinished;
  let estimateExceeded = false;
  if (timing.currentStartedAt !== null && unfinished > 0) {
    const currentElapsed = now - timing.currentStartedAt;
    estimateExceeded = currentElapsed >= perModelMs;
    remainingMs = estimateExceeded
      ? null
      : perModelMs - currentElapsed + perModelMs * (unfinished - 1);
  }
  timing.onTick({
    completed: timing.completed,
    total: timing.total,
    currentLabel: timing.currentLabel,
    elapsedMs,
    remainingMs,
    estimateExceeded,
  });
}

function startTimedModel(timing, label) {
  timing.currentLabel = label;
  timing.currentStartedAt = performance.now();
  tickRunTimer(timing);
}

function finishTimedModel(timing, succeeded) {
  const now = performance.now();
  if (timing.currentStartedAt !== null) {
    const durationMs = now - timing.currentStartedAt;
    timing.durations.push(durationMs);
    if (succeeded) {
      state.observedRuns.push({ durationMs, ...timing.current });
    }
  }
  timing.completed += 1;
  timing.currentStartedAt = null;
  timing.currentLabel = "";
  tickRunTimer(timing);
}

function stopRunTimer(timing) {
  window.clearInterval(timing.interval);
  return performance.now() - timing.startedAt;
}

function progressTimingText(progress) {
  const remaining = progress.estimateExceeded
    ? "暂不可估（当前任务已超出初始估算）"
    : formatClockDuration(progress.remainingMs);
  return `已完成 ${progress.completed}/${progress.total} · 已用 ${formatClockDuration(progress.elapsedMs)} · 预计还需 ${remaining}`;
}

async function collectReferences(event) {
  event.preventDefault();
  if (!elements.referenceForm.reportValidity()) return;
  const models = selectedReferenceModels();
  if (!models.length) {
    showReferenceProgress("请至少选择一个待采集模型。", "error");
    return;
  }
  setBusy(true);
  const current = settings();
  const timing = startRunTimer(models.length, current, (progress) => {
    const model = progress.currentLabel ? `正在采集 ${progress.currentLabel} · ` : "";
    showReferenceProgress(`${model}${progressTimingText(progress)}`);
  });
  let completed = 0;
  let failed = 0;
  for (const [index, model] of models.entries()) {
    elements.referenceBadge.className = "badge badge-running";
    elements.referenceBadge.textContent = `第 ${index + 1}/${models.length} 个`;
    startTimedModel(timing, model);
    let succeeded = false;
    try {
      await postJson("/api/v1/console/references/collect", {
        reference_name: elements.referenceName.value.trim(),
        provider: "user_reference",
        endpoint: endpointPayload(elements.referenceUrl, model, elements.referenceKey),
        ...current,
      });
      completed += 1;
      succeeded = true;
    } catch (error) {
      failed += 1;
      showReferenceProgress(
        `${model} 采集失败：${error instanceof Error ? error.message : String(error)}`,
        "error",
      );
    }
    finishTimedModel(timing, succeeded);
  }
  const elapsedMs = stopRunTimer(timing);
  await loadReferences();
  elements.referenceBadge.className = failed ? "badge badge-uncertain" : "badge badge-match";
  elements.referenceBadge.textContent = failed ? `${completed} 成功 / ${failed} 失败` : `已保存 ${completed} 个`;
  if (!failed) {
    showReferenceProgress(`已保存 ${completed} 个参考模型 · 总耗时 ${formatClockDuration(elapsedMs)}。旧版本仍保留在本地证据目录。`);
  }
  setBusy(false);
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
    option.textContent = `${reference.name} · ${reference.model}`;
    select.append(option);
  });
  const exact = state.references.find((reference) => reference.model === targetModel);
  if (preferredArtifactId && state.references.some((item) => item.artifactId === preferredArtifactId)) {
    select.value = preferredArtifactId;
  } else if (exact) {
    select.value = exact.artifactId;
  }
  select.disabled = state.running || state.references.length === 0;
}

function updateMappingStatus(row) {
  const select = row.querySelector(".mapping-reference");
  const enabled = row.querySelector(".mapping-enabled");
  const status = row.querySelector(".mapping-state");
  const reference = state.references.find((item) => item.artifactId === select.value);
  if (!reference) {
    status.className = "mapping-state badge badge-muted";
    status.textContent = "未映射";
    return;
  }
  status.className = enabled.checked
    ? "mapping-state badge badge-match"
    : "mapping-state badge badge-muted";
  status.textContent = enabled.checked ? "已启用" : "已映射";
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
  row.querySelector(".mapping-model").textContent = clean;
  const select = row.querySelector(".mapping-reference");
  populateReferenceSelect(select, clean, values.referenceArtifactId || "");
  const priority = row.querySelector(".mapping-priority");
  const savedPriority = Number(values.priority);
  priority.value = [80, 50, 20].includes(savedPriority) ? String(savedPriority) : "50";
  const enabled = row.querySelector(".mapping-enabled");
  enabled.checked = values.enabled === undefined ? Boolean(select.value) : Boolean(values.enabled);
  row.dataset.userDisabled = enabled.checked ? "" : "true";
  enabled.addEventListener("change", () => {
    row.dataset.userDisabled = enabled.checked ? "" : "true";
    updateMappingStatus(row);
    updateControls();
  });
  select.addEventListener("change", () => {
    if (select.value) enabled.checked = true;
    row.dataset.userDisabled = "";
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
      const previous = select.value;
      populateReferenceSelect(select, row.dataset.model, previous);
      if (select.value && !row.dataset.userDisabled) {
        row.querySelector(".mapping-enabled").checked = true;
      }
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
    list.replaceChildren();
    (body.models || []).forEach((item) => addTargetModel(card, item.id));
    setTargetState(card, "match", `${body.count} 个模型`, "已按模型 ID 自动匹配可用参考指纹。 ");
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
    addTargetModel(card, input.value);
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
  const current = settings();
  const perModel = current.cells * current.samples;
  const total = perModel * (referenceSelected + mappings.length);
  const referenceEstimate = estimateDuration(referenceSelected, current);
  const mappingEstimate = estimateDuration(mappings.length, current);
  elements.referenceModelCount.textContent = `${referenceSelected} 个已选 / ${state.referenceModels.size} 个候选`;
  const autoConcurrency = current.concurrencyMode === "auto";
  elements.concurrency.disabled = state.running;
  elements.concurrencyNote.textContent = autoConcurrency
    ? "自动模式会按每个中转站的历史稳定性选择并发；连续无进度上限只在长期没有新响应时中断，不限制任务总时长。"
    : `所有任务固定使用并发 ${current.concurrency}；连续无进度上限只在长期没有新响应时中断，不限制任务总时长。`;
  elements.requestEstimate.textContent = `${total.toLocaleString("zh-CN")} 次（参考 ${referenceSelected} + 对比 ${mappings.length} 个模型${autoConcurrency ? "；自动并发不额外增加采样量" : ""}）`;
  elements.timeEstimate.textContent = durationRangeText(referenceEstimate);
  elements.timeEstimateNote.textContent = autoConcurrency
    ? "自动并发校准前按并发 1 保守估算；选定稳定并发后会更新。"
    : referenceEstimate.historical
      ? "根据本机已完成采样的实际速度估算；网络拥堵、限流与重试会造成波动。"
      : "首次按单请求 1.2–4 秒粗估；完成模型后会用实际速度更新剩余时间。";
  elements.mappingSummary.textContent = mappings.length
    ? `已选择 ${mappings.length} 组模型映射，预计产生 ${mappings.length} 份独立比较证据。`
    : "读取模型后，系统会优先按相同模型 ID 自动匹配参考指纹。";
  elements.mappingTimeEstimate.textContent = mappings.length
    ? `${durationRangeText(mappingEstimate)}${autoConcurrency ? "（校准前保守估算）" : mappingEstimate.historical ? "（按本机历史速度）" : "（首次网络粗估）"}`
    : "预计耗时将在选择模型后显示。";
  elements.runAll.disabled = state.running || mappings.length === 0;
  elements.referenceForm.querySelector("button[type='submit']").disabled = state.running || referenceSelected === 0;
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
    resultMetric("可比较探针", String(comparison.comparableCellCount ?? "—")),
    resultMetric("内部 JSD", formatNumber(target.splitHalfJsd)),
    resultMetric("错误请求", String(target.errorCount ?? "—")),
    resultMetric("任务耗时", formatDuration(target.durationMs)),
    resultMetric("推理适配", adapterText(target.adapter)),
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
  } catch {
    // 历史结果恢复失败不应阻塞新的对比。
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
  setBusy(polling);
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
  try {
    const body = await requestJson("/api/v1/console/comparison-batches/active");
    if (body.batch) {
      renderActiveBatch(body);
      scheduleBatchPoll();
      return;
    }
    const latest = await requestJson("/api/v1/console/comparisons/latest");
    const latestItems = latest.items || [];
    const latestBatch = latestItems.find((item) => item.batch)?.batch;
    if (latestBatch) renderActiveBatch({ batch: latestBatch, items: latestItems });
  } catch {
    // 活跃任务恢复失败不阻塞工作台配置恢复。
  }
}

async function runAllMappings() {
  if (state.running) return;
  const mappings = selectedMappings();
  if (!mappings.length) return;
  setBusy(true);
  elements.results.replaceChildren();
  elements.emptyResults.classList.remove("hidden");
  if (elements.resultsTitle) elements.resultsTitle.textContent = "本次对比结果";
  const current = settings();
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
    setBusy(false);
    elements.mappingSummary.textContent = `任务创建失败：${error instanceof Error ? error.message : String(error)}`;
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

async function checkHealth() {
  try {
    const body = await requestJson("/health");
    elements.appHealth.textContent = `服务在线 · v${body.version}`;
  } catch {
    elements.appHealth.textContent = "本地服务连接失败";
  }
}

elements.referenceForm.addEventListener("submit", collectReferences);
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
elements.pauseBatch.addEventListener("click", pauseOrResumeActiveBatch);
elements.cancelBatch.addEventListener("click", cancelActiveBatch);
elements.clearKeys.addEventListener("click", () => {
  document.querySelectorAll(".api-key").forEach((input) => {
    input.value = "";
  });
});
elements.preset.addEventListener("change", updateControls);
elements.concurrencyMode.addEventListener("change", updateControls);
elements.concurrency.addEventListener("change", updateControls);
elements.requestTimeout.addEventListener("change", updateControls);
elements.modelTimeout.addEventListener("change", updateControls);

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
  try {
    localStorage.removeItem(workspaceStorageKey);
  } catch {
    // 即使浏览器拒绝存储，也继续重置当前页面。
  }
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
  restoringWorkspace = true;
  await loadReferences();
  const restored = restoreWorkspace();
  if (!restored) seedDefaultWorkspace();
  restoringWorkspace = false;
  updateControls();
  saveWorkspaceNow();
  await loadLatestResults();
  await loadActiveBatch();
  checkHealth();
}

initializeConsole();
