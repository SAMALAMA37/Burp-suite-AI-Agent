// Exercise the installed combo loop with deterministic provider responses.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname,
  '../nine_router/node_modules/9router/app/.next-cli-build/server/chunks/5308.js'), 'utf8');
const start = source.indexOf('async function G(');
const end = source.indexOf('let H=', start);
assert.ok(start >= 0 && end > start, 'Locate the pinned 9Router combo implementation');
function loadModule(file, id, dependencies = {}) {
  const exports = {};
  const requireModule = key => dependencies[key];
  requireModule.d = (target, getters) => {
    for (const [key, get] of Object.entries(getters)) {
      Object.defineProperty(target, key, { get });
    }
  };
  require('../nine_router/node_modules/9router/app/.next-cli-build/server/chunks/' + file)
    .modules[id]({}, exports, requireModule);
  return exports;
}
const errorConstants = loadModule('2132.js', 3662);
const errorPolicy = loadModule('7187.js', 12557, { 3662: errorConstants });
const combo = vm.runInNewContext('(' + source.slice(start, end) + ')', {
  Response, Map, Set, B: new Map(),
  w: async () => null, // JSON responses do not enter the SSE peek path.
  t: reason => reason === 'content_filter',
  d: errorPolicy,
  g: { Xh: model => ({ provider: model.split('/')[0] }) },
});
const empty = { choices: [{ message: { content: '', reasoning_content: 'internal' } }] };
const answer = { choices: [{ message: { content: 'OK' }, finish_reason: 'stop' }] };

const request = {
  model: 'hub-chat', stream: false,
  messages: [
    { role: 'user', content: 'Review the saved notes.' },
    { role: 'assistant', tool_calls: [{ id: 'read-1', type: 'function',
      function: { name: 'document_read', arguments: '{"id":"notes"}' } }] },
    { role: 'tool', tool_call_id: 'read-1', content: '{"ok":true,"evidence_id":"EV0000516"}' },
  ],
  tools: [{ type: 'function', function: { name: 'document_read', parameters: { type: 'object' } } }],
};

async function run(responses, models = ['ag/test', 'backup/test']) {
  const calls = [];
  const original = JSON.stringify(request);
  const response = await combo({
    body: request,
    models, comboStrategy: 'fallback', autoSwitch: false,
    log: { info() {}, warn() {} },
    handleSingleModel: async (body, model) => {
      assert.strictEqual(body, request, 'Fallback receives the original request');
      assert.equal(JSON.stringify(body), original, 'Preserve tool results and context');
      calls.push(model);
      const result = responses.shift() || empty;
      return result instanceof Response ? result : Response.json(result);
    },
  });
  return { calls, response, body: await response.json() };
}

(async () => {
  for (const reason of [undefined, 'stop', 'length']) {
    const blank = { choices: [{ ...empty.choices[0], finish_reason: reason }] };
    const recovered = await run([blank, answer]);
    assert.deepEqual(recovered.calls, ['ag/test', 'ag/test']);
    assert.equal(recovered.body.choices[0].message.content, 'OK');
  }
  const fallback = await run([empty, empty, answer]);
  assert.deepEqual(fallback.calls, ['ag/test', 'ag/test', 'backup/test']);
  const exhausted = await run([]);
  assert.deepEqual(exhausted.calls, ['ag/test', 'ag/test', 'backup/test', 'backup/test']);
  assert.equal(exhausted.response.status, 502);
  for (const message of [
    { content: 'Answer' },
    { tool_calls: [{ function: { name: 'read', arguments: '{}' } }] },
    { refusal: 'Declined' },
  ]) {
    assert.deepEqual((await run([{ choices: [{ message }] }])).calls, ['ag/test']);
  }
  for (const finish_reason of ['content_filter', 'SAFETY', 'refusal']) {
    assert.deepEqual((await run([{ choices: [{ message: {}, finish_reason }] }])).calls, ['ag/test']);
  }
  const promptFeedback = {
    blockReason: 'OTHER', blockReasonMessage: 'Provider rejected the prompt',
  };
  for (const payload of [{ promptFeedback }, { response: { promptFeedback } }]) {
    const recovered = await run([payload, answer]);
    assert.deepEqual(recovered.calls, ['ag/test', 'backup/test']);
    assert.equal(recovered.response.status, 200);
    assert.equal(recovered.body.choices[0].message.content, 'OK');
    const exhausted = await run([payload, payload]);
    assert.deepEqual(exhausted.calls, ['ag/test', 'backup/test']);
    assert.equal(exhausted.response.status, 403);
    assert.equal(exhausted.body.error.code, 'provider_prompt_blocked');
    assert.match(exhausted.body.error.message, /Provider rejected the prompt/);
    const single = await run([payload], ['ag/test']);
    assert.deepEqual(single.calls, ['ag/test']);
    assert.equal(single.response.status, 403);
    const unavailable = await run([payload,
      Response.json({ error: { message: 'No credentials available' } }, { status: 503 })]);
    assert.deepEqual(unavailable.calls, ['ag/test', 'backup/test']);
    assert.equal(unavailable.body.error.code, 'provider_prompt_blocked');
  }
  const rejected = Response.json({ error: { code: 'provider_prompt_blocked',
    message: 'Provider rejected the prompt' } }, { status: 403 });
  const httpRecovered = await run([rejected, answer]);
  assert.deepEqual(httpRecovered.calls, ['ag/test', 'backup/test']);
  assert.equal(httpRecovered.response.status, 200);
  assert.deepEqual((await run([answer])).calls, ['ag/test'], 'Prompt blocks stay request-scoped');
  console.log('Passed empty retries, prompt-block fallback, preserved context, exhaustion, HTTP errors, and refusal handling.');
})().catch(error => { console.error(error); process.exitCode = 1; });
