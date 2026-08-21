const relayStatus = window.RelayStatus;
const verdictLabels = relayStatus?.statusLabels || {
  match: "较一致",
  uncertain: "不确定",
  mismatch: "明显不一致",
  insufficient: "证据不足",
  unverifiable: "不可验证",
  error: "执行失败",
  running: "执行中",
  queued: "等待执行",
  paused: "已暂停",
  pausing: "暂停中",
  canceling: "取消中",
  canceled: "已取消",
  interrupted: "服务重启中断",
};

const workspaceStorageKey = "relay-auditor.workspace.v1";
const pageSize = 50;
let currentOffset = 0;
let currentTotal = 0;
let historyPollTimer = null;

const elements = {
  filters: document.querySelector("#history-filters"),
  station: document.querySelector("#filter-station"),
  model: document.querySelector("#filter-model"),
  verdict: document.querySelector("#filter-verdict"),
  clearFilters: document.querySelector("#clear-filters"),
  summaryTotal: document.querySelector("#summary-total"),
  summarySuccess: document.querySelector("#summary-success"),
  summaryFailed: document.querySelector("#summary-failed"),
  summaryWaiting: document.querySelector("#summary-waiting"),
  summaryBlocked: document.querySelector("#summary-blocked"),
  summaryCanceled: document.querySelector("#summary-canceled"),
  summaryQueued: document.querySelector("#summary-queued"),
  summaryActive: document.querySelector("#summary-active"),
  groups: document.querySelector("#history-groups"),
  empty: document.querySelector("#history-empty"),
  error: document.querySelector("#history-error"),
  previous: document.querySelector("#previous-page"),
  next: document.querySelector("#next-page"),
  pageStatus: document.querySelector("#page-status"),
  health: document.querySelector("#history-health"),
};

async function requestJson(path) {
  const response = await fetch(path, { credentials: "same-origin", cache: "no-store" });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || `HTTP ${response.status}`);
  return body;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString("zh-CN", { hour12: false });
}

function formatNumber(value, digits = 3) {
  return typeof value === "number" && Number.isFinite(value) ? value.toFixed(digits) : "—";
}

function formatDuration(value) {
  if (typeof value !== "number") return "—";
  return value < 1000 ? `${Math.round(value)} ms` : `${(value / 1000).toFixed(1)} s`;
}

function shortId(value) {
  return value ? value.slice(0, 8) : "legacy";
}

function loadAsWorkspace(item) {
  let workspace = null;
  try {
    workspace = JSON.parse(localStorage.getItem(workspaceStorageKey) || "null");
  } catch {
    workspace = null;
  }
  if (!workspace || workspace.version !== 1) {
    workspace = {
      version: 1,
      reference: { name: "", baseUrl: "", manualModel: "", models: [] },
      settings: {
        preset: "standard",
        concurrencyMode: "auto",
        concurrency: "4",
        requestTimeout: "15",
        modelTimeout: "300",
      },
      targets: [],
    };
  }
  workspace.targets = [{
    name: item.station_name,
    baseUrl: item.target_base_url,
    manualModel: "",
    models: [{
      model: item.target_model,
      referenceArtifactId: item.reference_artifact_id || "",
      enabled: Boolean(item.reference_artifact_id),
      priority: [80, 50, 20].includes(Number(item.priority)) ? Number(item.priority) : 50,
    }],
  }];
  localStorage.setItem(workspaceStorageKey, JSON.stringify(workspace));
  window.location.assign("/");
}

function cell(text, className = "") {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function recordProgressText(item) {
  const progress = item.progress || {};
  const partial = relayStatus.partialEvidenceInfo(item);
  const retryText = relayStatus.retryWaitingText(item);
  if (retryText) return retryText;
  const planText = relayStatus.planBudgetText(item);
  if (planText) return planText;
  if (item.status === "completed") return `执行成功 · 已收到 ${progress.done || "全部"} 个采样响应`;
  if (item.status === "failed" || item.status === "interrupted") {
    const failure = item.error_message || progress.detail || "任务未完成";
    const evidence = relayStatus.incompleteEvidenceText(partial);
    return evidence ? `${failure} · ${evidence}` : failure;
  }
  if (item.status === "canceling") return progress.detail || "正在取消当前请求";
  if (item.status === "canceled") {
    const canceled = progress.detail || "已由用户取消";
    const evidence = relayStatus.incompleteEvidenceText(partial);
    return evidence ? `${canceled} · ${evidence}` : canceled;
  }
  if (item.status === "queued") return "排队 / 未执行：尚未向该模型发出请求";
  if (item.status === "paused") return progress.detail || "暂停中";
  if (["preflight", "preflight_retry", "healthcheck", "connection_check"].includes(progress.stage)) {
    return relayStatus.preflightText(item) || "请求预检：正在检查接口兼容性与中转站状态";
  }
  if (progress.stage === "sampling") {
    return `采样响应 ${progress.done || 0}/${progress.total || 0}${progress.errors ? ` · ${progress.errors} 错误` : ""}`;
  }
  return progress.detail || "正在启动或等待中转站响应";
}

function recordStatusClass(item, decision = relayStatus.recordDecision(item)) {
  if (item.status === "completed") return decision.operationalVerdict || "unverifiable";
  if (relayStatus.itemOperationalState(item) === "waiting") return "waiting";
  if (relayStatus.itemOperationalState(item) === "blocked") return "blocked";
  if (["failed", "interrupted"].includes(item.status)) return "error";
  if (["paused", "canceling"].includes(item.status)) return "uncertain";
  if (item.status === "canceled") return "muted";
  if (item.status === "running") return "running";
  return "muted";
}

function firstCandidate(item) {
  const identification = item.identification || item.response?.result?.identification || {};
  const candidates = Array.isArray(identification.candidates)
    ? identification.candidates
    : Array.isArray(item.candidates)
      ? item.candidates
      : [];
  if (candidates.length) return candidates[0];
  const directModel = item.candidate_model || item.top_candidate_model;
  if (!directModel) return null;
  return {
    referenceModel: directModel,
    referenceName: item.candidate_reference_name,
    meanJsd: item.candidate_mean_jsd ?? item.top_candidate_mean_jsd,
  };
}

function batchStatusClass(status, counts) {
  if (counts?.waiting) return "waiting";
  if (status === "completed" && counts?.failed) return "error";
  if (status === "completed" && (counts?.canceled || counts?.blocked)) return "uncertain";
  if (status === "completed") return "match";
  if (["interrupted", "failed"].includes(status)) return "error";
  if (["paused", "pausing", "canceling"].includes(status)) return "uncertain";
  if (status === "canceled") return "muted";
  return "running";
}

function renderBatch(batchId, items) {
  const section = document.createElement("section");
  section.className = "panel history-batch archive-batch";
  const heading = document.createElement("div");
  heading.className = "history-batch-heading";
  const title = document.createElement("div");
  const label = document.createElement("strong");
  const meta = document.createElement("span");
  const batch = items[0]?.batch;
  const stateCounts = relayStatus.batchStateCounts(items);
  label.textContent = formatDate(batch?.created_at || items[items.length - 1]?.started_at);
  const batchTotal = Number(batch?.total_items) || items.length;
  meta.textContent = `批次 ${shortId(batchId)} · ${batchTotal} 个模型`;
  title.append(label, meta);
  const counts = document.createElement("div");
  counts.className = "history-batch-counts";
  const batchStatus = document.createElement("span");
  const activeStatus = batch?.status
    || (items.some((item) => relayStatus.itemOperationalState(item) === "waiting") ? "running" : null)
    || items.find((item) => ["running", "paused", "canceling"].includes(item.status))?.status;
  batchStatus.className = `badge badge-${batchStatusClass(activeStatus, stateCounts)}`;
  batchStatus.textContent = relayStatus.batchStatusLabel(activeStatus, stateCounts);
  counts.append(batchStatus);
  relayStatus.batchSummaryParts(stateCounts).forEach((part) => {
    const summary = document.createElement("span");
    summary.className = `batch-progress-text batch-count-${part.key}`;
    summary.textContent = `${part.label} ${part.count}`;
    counts.append(summary);
  });
  heading.append(title, counts);

  const records = document.createElement("div");
  records.className = "archive-records";
  items.forEach((item) => {
    const decision = relayStatus.recordDecision(item);
    const row = document.createElement("article");
    row.className = "archive-record";
    const state = document.createElement("div");
    state.className = "archive-record-state";
    const verdictBadge = document.createElement("span");
    const operationalState = relayStatus.itemOperationalState(item);
    const displayVerdict = item.status === "completed"
      ? decision.operationalVerdict
      : operationalState === "waiting" || operationalState === "blocked"
        ? operationalState
        : item.status;
    verdictBadge.className = `badge badge-${recordStatusClass(item, decision)}`;
    verdictBadge.textContent = operationalState === "waiting" || operationalState === "blocked"
      ? relayStatus.itemStatusLabel(item)
      : verdictLabels[displayVerdict]
        || verdictLabels[item.status]
        || displayVerdict
        || item.status;
    const decisionSummary = relayStatus.decisionSummary(decision);
    if (decisionSummary) verdictBadge.title = decisionSummary;
    const time = document.createElement("small");
    time.textContent = formatDate(item.started_at);
    state.append(verdictBadge, time);

    const target = document.createElement("div");
    target.className = "archive-record-target";
    const station = document.createElement("strong");
    const model = document.createElement("code");
    const url = document.createElement("small");
    station.textContent = item.station_name;
    model.textContent = item.target_model;
    url.textContent = item.target_base_url;
    target.append(station, model, url);

    const reference = document.createElement("div");
    reference.className = "archive-record-reference";
    const referenceLabel = document.createElement("small");
    const referenceName = document.createElement("span");
    const referenceModel = document.createElement("code");
    referenceLabel.textContent = "对比参考";
    referenceName.textContent = item.reference_name || "历史参考端";
    referenceModel.textContent = item.reference_model || "未知";
    reference.append(referenceLabel, referenceName, referenceModel);
    const candidate = firstCandidate(item);
    if (candidate) {
      const candidateSummary = document.createElement("small");
      candidateSummary.className = "candidate-summary";
      const model = candidate.referenceModel || candidate.reference_model || candidate.model || "未知模型";
      const meanJsd = candidate.medianMeanJsd
        ?? candidate.median_mean_jsd
        ?? candidate.meanJsd
        ?? candidate.mean_jsd;
      candidateSummary.textContent = `最接近候选：${model} · JSD ${formatNumber(Number(meanJsd))}`;
      reference.append(candidateSummary);
    }

    const metrics = document.createElement("div");
    metrics.className = "archive-record-metrics";
    const jsd = document.createElement("div");
    const duration = document.createElement("div");
    const progressText = document.createElement("p");
    const decisionText = document.createElement("p");
    const diagnosticsText = document.createElement("p");
    const effectiveConcurrency = Number(item.task_options?.effective_concurrency);
    jsd.innerHTML = `<span>平均 JSD</span><strong>${formatNumber(item.mean_jsd)}</strong>`;
    duration.innerHTML = `<span>耗时 · 实际并发</span><strong>${formatDuration(item.duration_ms)} · ${Number.isFinite(effectiveConcurrency) && effectiveConcurrency > 0 ? effectiveConcurrency : "—"}</strong>`;
    progressText.textContent = recordProgressText(item);
    if (item.error_message && relayStatus.itemOperationalState(item) === "failed") {
      progressText.title = item.error_message;
    }
    decisionText.className = "history-decision-details";
    decisionText.textContent = decisionSummary;
    decisionText.classList.toggle("hidden", !decisionSummary);
    const diagnostics = relayStatus.progressDiagnostics(item).filter(
      (part) => !progressText.textContent.includes(part),
    );
    diagnosticsText.className = "history-network-diagnostics";
    diagnosticsText.textContent = diagnostics.join(" · ");
    diagnosticsText.classList.toggle("hidden", diagnostics.length === 0);
    metrics.append(jsd, duration, progressText, decisionText, diagnosticsText);

    const actions = document.createElement("div");
    actions.className = "history-row-actions";
    const partial = relayStatus.partialEvidenceInfo(item);
    if (item.evidence_available || partial.available) {
      const evidence = document.createElement("a");
      evidence.className = "evidence-link";
      evidence.href = `/api/v1/console/evidence/${partial.artifactId || item.artifact_id}`;
      evidence.textContent = partial.isPartial
        ? "部分采样 JSON"
        : partial.isTargetFingerprint
          ? "目标指纹 JSON"
          : item.evidence_state === "verification"
            ? "比较证据 JSON"
            : "证据 JSON";
      if (partial.isPartial || partial.isTargetFingerprint) {
        evidence.title = relayStatus.incompleteEvidenceText(partial);
      }
      actions.append(evidence);
    }
    const load = document.createElement("button");
    load.type = "button";
    load.className = "reference-delete history-load-button";
    load.textContent = "载入配置";
    load.addEventListener("click", () => loadAsWorkspace(item));
    actions.append(load);
    row.append(state, target, reference, metrics, actions);
    records.append(row);
  });
  section.append(heading, records);
  return section;
}

function renderHistory(body) {
  const items = body.items || [];
  currentTotal = body.total || 0;
  elements.groups.replaceChildren();
  elements.empty.classList.toggle("hidden", items.length > 0);
  const grouped = new Map();
  items.forEach((item) => {
    if (!grouped.has(item.batch_id)) grouped.set(item.batch_id, []);
    grouped.get(item.batch_id).push(item);
  });
  grouped.forEach((batchItems, batchId) => elements.groups.append(renderBatch(batchId, batchItems)));

  const stateCounts = relayStatus.batchStateCounts(items);
  const active = stateCounts.running + stateCounts.paused;
  const shouldPoll = active + stateCounts.waiting + stateCounts.queued > 0;
  elements.summaryTotal.textContent = String(currentTotal);
  elements.summarySuccess.textContent = String(stateCounts.success);
  elements.summaryFailed.textContent = String(stateCounts.failed);
  elements.summaryWaiting.textContent = String(stateCounts.waiting);
  elements.summaryBlocked.textContent = String(stateCounts.blocked);
  elements.summaryCanceled.textContent = String(stateCounts.canceled);
  elements.summaryQueued.textContent = String(stateCounts.queued);
  elements.summaryActive.textContent = String(active);

  const page = Math.floor(currentOffset / pageSize) + 1;
  const pages = Math.max(1, Math.ceil(currentTotal / pageSize));
  elements.pageStatus.textContent = `第 ${page}/${pages} 页`;
  elements.previous.disabled = currentOffset === 0;
  elements.next.disabled = currentOffset + pageSize >= currentTotal;
  window.clearTimeout(historyPollTimer);
  historyPollTimer = shouldPoll ? window.setTimeout(loadHistory, 2500) : null;
}

async function loadHistory() {
  elements.error.classList.add("hidden");
  const params = new URLSearchParams({ limit: String(pageSize), offset: String(currentOffset) });
  if (elements.station.value.trim()) params.set("station", elements.station.value.trim());
  if (elements.model.value.trim()) params.set("model", elements.model.value.trim());
  if (elements.verdict.value) params.set("verdict", elements.verdict.value);
  try {
    renderHistory(await requestJson(`/api/v1/console/comparisons?${params}`));
  } catch (error) {
    elements.error.textContent = error instanceof Error ? error.message : String(error);
    elements.error.classList.remove("hidden");
  }
}

elements.filters.addEventListener("submit", (event) => {
  event.preventDefault();
  currentOffset = 0;
  loadHistory();
});
elements.clearFilters.addEventListener("click", () => {
  elements.filters.reset();
  currentOffset = 0;
  loadHistory();
});
elements.previous.addEventListener("click", () => {
  currentOffset = Math.max(0, currentOffset - pageSize);
  loadHistory();
});
elements.next.addEventListener("click", () => {
  currentOffset += pageSize;
  loadHistory();
});

async function initializeHistory() {
  loadHistory();
  try {
    const health = await requestJson("/health");
    elements.health.textContent = `服务在线 · v${health.version}`;
  } catch {
    elements.health.textContent = "本地服务连接失败";
  }
}

initializeHistory();
