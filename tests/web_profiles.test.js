const test = require("node:test");
const assert = require("node:assert/strict");

const profiles = require("../src/relay_auditor/web/profiles.js");

test("协议只能映射到对应的冻结 transport profile", () => {
  assert.equal(
    profiles.transportProfileForProtocol("anthropic_messages"),
    "anthropic-messages-opus5-onetoken-v1",
  );
  assert.equal(
    profiles.transportProfileForProtocol("openai_chat"),
    "openai-chat-onetoken-v1",
  );
});

test("单模型 URL 校验要求 HTTPS 并移除尾部斜杠", () => {
  assert.deepEqual(
    profiles.normalizeOneModelBaseUrl(" https://Relay.Example:443/v1/// "),
    { valid: true, value: "https://relay.example/v1", error: "" },
  );
  assert.equal(profiles.normalizeOneModelBaseUrl("http://relay.example/v1").valid, false);
  assert.equal(profiles.normalizeOneModelBaseUrl("https://user@relay.example/v1").valid, false);
  assert.equal(profiles.normalizeOneModelBaseUrl("https://relay.example/v1?k=v").valid, false);
  assert.equal(profiles.normalizeOneModelBaseUrl("https://relay.example/v1#x").valid, false);
});

test("凭据明确区分临时 Key 和 env_ref", () => {
  assert.deepEqual(profiles.credentialSpec("env:RELAY_A_KEY"), {
    valid: true,
    value: { mode: "env_ref", name: "RELAY_A_KEY" },
    error: "",
  });
  assert.deepEqual(profiles.credentialSpec("secret-canary"), {
    valid: true,
    value: { mode: "ephemeral", api_key: "secret-canary" },
    error: "",
  });
  assert.equal(profiles.credentialSpec("env:lowercase").valid, false);
});

test("TSV 支持标题行与三或四列且保留输入顺序", () => {
  const parsed = profiles.parseOneModelTsv([
    "station_name\tbase_url\tcredential\tmodel_id",
    "Relay A\thttps://a.example/v1\tsk-a\tmodel-a",
    "Relay B\thttps://b.example/v1\tenv:RELAY_B_KEY",
  ].join("\n"));

  assert.deepEqual(parsed.errors, []);
  assert.equal(parsed.rows.length, 2);
  assert.equal(parsed.rows[0].stationName, "Relay A");
  assert.equal(parsed.rows[0].modelId, "model-a");
  assert.equal(parsed.rows[1].credentialText, "env:RELAY_B_KEY");
  assert.equal(parsed.rows[1].modelId, "");
});

test("TSV 拒绝错误列数和超过 20 行", () => {
  const malformed = profiles.parseOneModelTsv("Relay A\thttps://a.example/v1");
  assert.match(malformed.errors[0].message, /3 或 4/);

  const tooMany = profiles.parseOneModelTsv(
    Array.from({ length: 21 }, (_, index) => (
      `Relay ${index}\thttps://r${index}.example/v1\tsk-${index}`
    )).join("\n"),
  );
  assert.equal(tooMany.rows.length, 20);
  assert.match(tooMany.errors.at(-1).message, /最多 20/);
});

test("批量校验规范化 URL 并拒绝 URL 与实际模型重复", () => {
  const validation = profiles.validateOneModelTargets([
    {
      stationName: "Relay A",
      baseUrl: "https://relay.example/v1/",
      credentialText: "key-a",
      modelId: "",
    },
    {
      stationName: "Relay B",
      baseUrl: "https://RELAY.EXAMPLE:443/v1",
      credentialText: "key-b",
      modelId: "",
    },
  ], "model-default");

  assert.equal(validation.valid, false);
  assert.match(validation.errors.at(-1).message, /组合重复/);
  assert.equal(validation.targets[0].base_url, "https://relay.example/v1");
  assert.equal(validation.targets[0].model_id, null);
});

test("逐行错误绝不回显临时 Key", () => {
  const canary = "Canary-Secret-\u00c5";
  const validation = profiles.validateOneModelTargets([
    {
      stationName: "",
      baseUrl: "http://unsafe.example/v1",
      credentialText: canary,
      modelId: "",
    },
  ], "model-default");

  assert.equal(validation.valid, false);
  assert.equal(JSON.stringify(validation.errors).includes(canary), false);
  assert.equal(JSON.stringify(validation.errors).includes(canary.normalize("NFD")), false);
  assert.equal(JSON.stringify(validation.errors).toLowerCase().includes(canary.toLowerCase()), false);
});

test("请求估算固定为参考 3600 加每站 1200", () => {
  assert.deepEqual(profiles.oneModelRequestEstimate(0), {
    referenceRequests: 3600,
    targetRequests: 0,
    totalRequests: 3600,
  });
  assert.deepEqual(profiles.oneModelRequestEstimate(20), {
    referenceRequests: 3600,
    targetRequests: 24000,
    totalRequests: 27600,
  });
});
