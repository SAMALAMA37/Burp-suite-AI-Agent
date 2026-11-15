/* Connection dashboards with local fixtures; no service calls or stored keys. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM, VirtualConsole} = require('jsdom');
const root = path.resolve(__dirname, '../..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const copy = value => JSON.parse(JSON.stringify(value));
const settle = () => new Promise(resolve => setImmediate(resolve));
const response = (data, status = 200) => ({ok: status < 400, status, redirected: false, json: async () => copy(data)});

function page(html, url) {
  const errors = [], virtualConsole = new VirtualConsole();
  virtualConsole.on('jsdomError', error => errors.push(error));
  const dom = new JSDOM(html, {url, runScripts: 'outside-only', virtualConsole});
  const w = dom.window, d = w.document;
  w.XMLHttpRequest = function() { throw Error('Unexpected network request'); };
  w.WebSocket = function() { throw Error('Unexpected websocket'); };
  w.HTMLDialogElement.prototype.showModal = function() { this.open = true; };
  w.HTMLDialogElement.prototype.close = function() { this.open = false; };
  return {dom, w, d, errors, get: id => d.getElementById(id), close: () => {
    assert.deepEqual(errors, []);
    w.close();
  }};
}

function hub({locked = false} = {}) {
  const p = page(read('provider_hub/dist/index.html'), 'http://hub.test/#token=fixture-token');
  const state = {
    endpoint: 'http://hub.test/v1', fallback: true, order: ['openrouter', 'local'],
    embedding: {provider: 'local', model: 'fixture-embedding'}, events: [],
    providers: [
      {id: 'openrouter', name: 'OpenRouter', model: 'fixture:free', ready: true, enabled: true, has_key: true},
      {id: 'local', name: 'Local', model: 'fixture-local', ready: false, enabled: false, optional_key: true},
    ].map(p => ({base_url: 'http://fixture.test/v1', account_id: '', description: 'Fixture',
      key_url: 'https://example.test/keys', models: [{id: 'fixture:free'}], ...p})),
  };
  const calls = [], control = {locked, failSave: false};
  p.w.fetch = async (url, options) => {
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push({url, options, body});
    if (control.locked) return response({error: {code: 'hub_auth_required', message: 'Unlock required'}}, 401);
    if (url === '/api/state') return response(state);
    if (url === '/api/provider') {
      if (control.failSave) return response({error: {message: 'Fixture save failed'}}, 400);
      return response(state);
    }
    if (url === '/api/routing') { Object.assign(state, body); return response(state); }
    if (url === '/api/models') return response({data: [{id: 'new:free'}, {id: '+placeholder'}]});
    if (url === '/api/test') return response({message: 'Fixture connection passed'});
    if (url === '/api/connect') return response({message: 'Fixture connection saved'});
    throw Error('Unexpected fixture route: ' + url);
  };
  p.w.eval(read('provider_hub/dist/app.js'));
  return {...p, calls, control};
}

function priority({strategy = 'fallback', unauthorized = false} = {}) {
  const html = read('nine_router/burpai-top-priority.html');
  const p = page(html, 'http://router.test/top-priority');
  const control = {strategy, unauthorized, combo: {id: 'fixture-combo', name: 'hub-chat', kind: 'llm', models: [
    {provider: 'github', model: 'route-one', weight: 0.4}, 'openrouter/route-two',
    {fullModel: 'gh/route-three', temperature: 0.3},
  ]}, catalog: [{id: 'gh/route-one'}, {id: 'openrouter/route-two'}, {id: 'cx/route-new'},
    {id: 'ignored/embedding', kind: 'embedding'}, {id: 'combo/fixture', owned_by: 'combo'}]};
  const calls = [];
  p.w.fetch = async (url, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push({url, options, body});
    if (control.unauthorized) return response({}, 401);
    if (url === '/api/combos') return response({combos: [control.combo]});
    if (url === '/api/settings') return response({comboStrategy: control.strategy});
    if (url === '/v1/models') return response({data: control.catalog});
    if (url === '/api/combos/fixture-combo' && options.method === 'PUT') {
      control.combo.models = body.models;
      return response(control.combo);
    }
    throw Error('Unexpected fixture route: ' + url);
  };
  p.w.eval(p.d.querySelector('script').textContent);
  return {...p, calls, control, puts: () => calls.filter(c => c.options.method === 'PUT'),
    select: value => {p.get('provider').value = value; p.get('provider').dispatchEvent(new p.w.Event('change'));},
    submit: () => p.get('priority').dispatchEvent(new p.w.Event('submit', {bubbles: true, cancelable: true}))};
}

async function main() {
  const h = hub();
  await settle();
  assert.equal(h.get('workspace').hidden, false);
  assert.equal(h.get('cards').children.length, 2);
  assert.equal(h.get('ready').textContent, '1');
  assert.equal(h.w.location.hash, '');
  assert.equal(h.w.localStorage.getItem('burpai-hub-token'), 'fixture-token');
  assert.equal(h.calls[0].options.headers['X-Hub-Token'], 'fixture-token');
  h.get('search').value = 'local'; h.get('search').dispatchEvent(new h.w.Event('input'));
  assert.equal(h.get('cards').children.length, 1);
  assert.match(h.get('cards').textContent, /Local/);
  h.get('search').value = ''; h.get('search').dispatchEvent(new h.w.Event('input'));
  h.get('cards').querySelector('button').click();
  assert.equal(h.get('editor').open, true);
  assert.equal(h.get('api-key').value, '');
  assert.equal(h.get('key-status').textContent, 'Saved securely');
  h.get('discover').click(); await settle();
  const save = h.calls.find(c => c.url === '/api/provider');
  assert.equal(save.body.api_key, '');
  assert.equal(save.body.clear_key, false);
  assert.deepEqual([...h.get('model-options').children].map(o => o.value), ['new:free']);
  h.get('test').click(); await settle();
  assert.match(h.get('editor-status').textContent, /Fixture connection passed/);
  h.control.failSave = true;
  h.get('test').click(); await settle();
  assert.equal(h.get('test').disabled, false);
  assert.equal(h.get('editor-status').textContent, 'Fixture save failed');
  h.control.failSave = false;
  h.get('route-list').querySelector('[aria-label="Move Local up"]').click();
  h.get('fallback').checked = false;
  h.get('save-routing').click(); await settle();
  const route = h.calls.find(c => c.url === '/api/routing').body;
  assert.deepEqual(route.order, ['local', 'openrouter']);
  assert.equal(route.fallback, false);
  h.get('connect').click();
  assert.equal(h.get('connect-dialog').open, true);
  assert.equal(h.calls.some(c => c.url === '/api/connect'), false);
  h.get('confirm-connect').click(); await settle();
  assert.deepEqual(h.calls.find(c => c.url === '/api/connect').body, {embeddings: false});
  h.close();

  const locked = hub({locked: true}); await settle();
  assert.equal(locked.get('unlock').hidden, false);
  assert.equal(locked.get('workspace').hidden, true);
  locked.control.locked = false;
  locked.get('token').value = 'new-fixture-token';
  locked.get('unlock-form').dispatchEvent(new locked.w.Event('submit', {cancelable: true}));
  await settle();
  assert.equal(locked.get('workspace').hidden, false);
  assert.equal(locked.get('token').value, '');
  assert.equal(locked.calls.at(-1).options.headers['X-Hub-Token'], 'new-fixture-token');
  locked.close();

  const r = priority(); await settle();
  const original = copy(r.control.combo.models);
  assert.equal(r.get('provider').value, 'gh');
  assert.equal(r.get('provider').querySelectorAll('option').length, 4);
  r.select('openrouter'); r.submit(); await settle();
  assert.deepEqual(r.puts()[0].body.models, [original[1], original[0], original[2]]);
  r.select('gh'); r.submit(); await settle();
  assert.deepEqual(r.puts()[1].body.models, [original[0], original[2], original[1]]);
  r.submit(); await settle(); assert.equal(r.puts().length, 2);
  r.select('cx'); assert.equal(r.get('starting-model').hidden, false);
  r.get('model').value = 'cx/route-new'; r.submit(); await settle();
  assert.deepEqual(r.puts()[2].body.models, ['cx/route-new', original[0], original[2], original[1]]);
  assert.match(r.get('status').textContent, /Saved Codex/);
  r.close();

  const stale = priority(); await settle();
  stale.select('cx'); stale.get('model').value = 'cx/route-new';
  stale.control.catalog = stale.control.catalog.filter(m => m.id !== 'cx/route-new');
  stale.submit(); await settle();
  assert.equal(stale.puts().length, 0);
  assert.match(stale.get('status').textContent, /routes changed/);
  stale.close();

  const auth = priority({unauthorized: true}); await settle();
  assert.equal(auth.get('login').hidden, false);
  assert.equal(auth.get('save').disabled, true);
  assert.equal(auth.puts().length, 0);
  auth.close();

  const strategy = priority({strategy: 'round-robin'}); await settle();
  assert.equal(strategy.get('save').disabled, true);
  assert.match(strategy.get('status').textContent, /Set hub-chat to Fallback/);
  assert.equal(strategy.puts().length, 0);
  strategy.close();
  console.log('PASS: Hub rendering, auth, key preservation, model discovery, error recovery, routing and connect; 9Router priority, stable routes, new models, stale state, auth and strategy guards.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
