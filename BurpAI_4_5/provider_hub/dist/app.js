'use strict';
const $ = id => document.getElementById(id);
let token = localStorage.getItem('burpai-hub-token') || '', state, editing, order = [];
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has('token')) { token = fragment.get('token'); localStorage.setItem('burpai-hub-token', token); history.replaceState(null, '', '/'); }
function node(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
function notice(text, error = false) { $('notice').textContent = text; $('notice').className = error ? 'error' : ''; $('notice').hidden = false; }
async function api(path, body) {
  const response = await fetch(path, {method: body ? 'POST' : 'GET', headers: {'X-Hub-Token': token, 'Content-Type': 'application/json'}, body: body ? JSON.stringify(body) : undefined});
  const value = await response.json(); if (!response.ok) { if (response.status === 401 && value.error?.code === 'hub_auth_required') { $('unlock').hidden = false; $('workspace').hidden = true; } throw Error(value.error?.message || 'Connection failed.'); } return value;
}
function find(id) { return state.providers.find(p => p.id === id); }
function render() {
  $('unlock').hidden = true; $('workspace').hidden = false; $('count').textContent = state.providers.length;
  $('ready').textContent = state.providers.filter(p => p.ready && !p.cooldown_seconds).length;
  $('fallback-status').textContent = state.fallback ? 'Try next connection' : 'Stop on a limit'; $('endpoint').textContent = state.endpoint;
  $('fallback').checked = state.fallback; order = [...state.order];
  $('embed-provider').replaceChildren(...state.providers.map(p => {const option = node('option', p.name); option.value = p.id; return option;}));
  $('embed-provider').value = state.embedding.provider; $('embed-model').value = state.embedding.model;
  cards(); routes(); events();
}
function cards() {
  const q = $('search').value.toLowerCase();
  $('cards').replaceChildren(...state.order.map(find).filter(p => (p.name + ' ' + p.model).toLowerCase().includes(q)).map(p => {
    const card = node('article', undefined, 'card' + (p.ready ? ' active' : ''));
    const top = node('div', undefined, 'card-top'); top.append(node('div', p.name.split(' ').map(w => w[0]).slice(0, 2).join(''), 'avatar'), node('h3', p.name), node('span', p.cooldown_seconds ? 'Cooling down' : p.ready ? 'Enabled' : 'Not enabled', 'badge'));
    const foot = node('div', undefined, 'card-foot'); const manage = node('button', 'Configure'); manage.onclick = () => edit(p);
    foot.append(node('span', p.id === 'local' ? 'ON YOUR COMPUTER' : p.has_key ? 'KEY SAVED' : p.optional_key ? 'KEY OPTIONAL' : 'API KEY NEEDED'), manage);
    card.append(top, node('code', p.model || 'Choose a model'), foot); return card;
  }));
}
function routes() {
  $('route-list').replaceChildren(...order.map((id, i) => {
    const p = find(id), row = node('div', undefined, 'route-row'), name = node('div', p.name, 'route-name'); name.append(node('small', p.ready ? p.model : 'Skipped until enabled and configured'));
    row.append(node('span', String(i + 1).padStart(2, '0'), 'number'), name);
    for (const [label, offset] of [['↑', -1], ['↓', 1]]) {const b = node('button', label); b.setAttribute('aria-label', `Move ${p.name} ${offset < 0 ? 'up' : 'down'}`); b.disabled = i + offset < 0 || i + offset >= order.length; b.onclick = () => { [order[i], order[i + offset]] = [order[i + offset], order[i]]; routes(); }; row.append(b); } return row;
  }));
}
function events() {
  $('events').replaceChildren(...state.events.map(e => {
    const row = node('div', undefined, 'event'), name = node('div', e.provider); name.append(node('small', e.model || e.operation));
    const status = node('div', `HTTP ${e.status}`); status.append(node('small', `${e.latency_ms} ms`)); row.append(node('span', new Date(e.time * 1000).toLocaleTimeString()), name, status); if (e.message) name.append(node('small', e.message)); return row;
  })); if (!state.events.length) $('events').append(node('p', 'No requests yet. Test a connection to see its status here.'));
}
function edit(p) {
  editing = p.id; $('provider-title').textContent = p.name; $('provider-description').textContent = p.description;
  $('base-url').value = p.base_url; $('account-label').hidden = !p.base_url.includes('{account_id}'); $('account-id').value = p.account_id;
  $('api-key').value = ''; keyStatus(p); $('clear-key').checked = false;
  $('model').value = p.model; $('enabled').checked = p.enabled; $('editor-status').textContent = ''; modelOptions(p.models);
  $('key-link').hidden = !p.key_url?.startsWith('https://'); if (!$('key-link').hidden) $('key-link').href = p.key_url;
  $('editor').showModal();
}
function keyStatus(p) {
  $('key-status').textContent = p.has_key ? 'Saved securely' : p.optional_key ? 'Optional' : 'Required';
  $('api-key').placeholder = p.has_key ? 'Saved key in use — enter a new key to replace it' : 'Enter API key';
  $('key-help').textContent = p.has_key ? 'Your key is saved. The field stays blank for privacy; leaving it blank keeps your saved key.' : 'Saving stores your key securely on this computer.';
}
function modelOptions(models) { $('model-options').replaceChildren(...models.filter(m => m.id && !m.id.startsWith('+')).map(m => { const o = node('option', m.name || m.id); o.value = m.id; return o; })); }
async function saveProvider() { state = await api('/api/provider', {id: editing, base_url: $('base-url').value, account_id: $('account-id').value, api_key: $('api-key').value, clear_key: $('clear-key').checked, model: $('model').value, enabled: $('enabled').checked}); $('api-key').value = ''; $('clear-key').checked = false; keyStatus(find(editing)); render(); }
async function busy(button, action, output) { button.disabled = true; try {await action();} catch (e) { if (output) $(output).textContent = e.message; else notice(e.message, true); } finally {button.disabled = false;} }
async function refresh() { try { state = await api('/api/state'); render(); } catch (e) {notice(e.message, true);} }
$('unlock-form').onsubmit = e => {e.preventDefault(); token = $('token').value.trim(); localStorage.setItem('burpai-hub-token', token); $('token').value = ''; refresh();};
$('search').oninput = cards;
document.querySelectorAll('[data-view]').forEach(b => b.onclick = () => {document.querySelectorAll('[data-view]').forEach(n => n.classList.toggle('selected', n === b)); document.querySelectorAll('.view').forEach(v => v.hidden = v.id !== b.dataset.view); $('heading').textContent = {connections:'Your model connections', routing:'Routing & fallback', activity:'Connection activity'}[b.dataset.view]; });
$('provider-form').onsubmit = e => {e.preventDefault(); busy(e.submitter, async () => {await saveProvider(); $('editor').close(); notice('Connection saved.');}, 'editor-status');};
$('close-editor').onclick = () => $('editor').close();
$('discover').onclick = () => busy($('discover'), async () => {await saveProvider(); const result = await api('/api/models', {id: editing}); modelOptions(result.data || []); $('editor-status').textContent = `${result.data.length} live model IDs loaded. Choose one in the Chat model field. Live lists may include paid models.`;}, 'editor-status');
$('test').onclick = () => busy($('test'), async () => {await saveProvider(); $('editor-status').textContent = 'Connection saved. Testing…'; try {const result = await api('/api/test', {id: editing}); $('editor-status').textContent = result.message;} catch (e) {throw Error('Connection saved. Test failed: ' + e.message);}}, 'editor-status');
$('save-routing').onclick = () => busy($('save-routing'), async () => {state = await api('/api/routing', {order, fallback: $('fallback').checked, embedding: {provider: $('embed-provider').value, model: $('embed-model').value}}); render(); notice('Routing saved.');});
$('embed-preset').onclick = () => {$('embed-provider').value = 'openrouter'; $('embed-model').value = 'nvidia/nemotron-3.5-embed-8b:free';};
$('refresh').onclick = refresh;
$('connect').onclick = () => {if (!state) return notice('Unlock the dashboard first.', true); $('connect-status').textContent = ''; $('connect-dialog').showModal();};
$('cancel-connect').onclick = () => $('connect-dialog').close();
$('confirm-connect').onclick = () => busy($('confirm-connect'), async () => {const result = await api('/api/connect', {embeddings: $('connect-embeddings').checked}); $('connect-status').textContent = result.message; notice(result.message);}, 'connect-status');
refresh();
