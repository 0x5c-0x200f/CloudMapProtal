'use strict';
/* AI Chat: a drawer with streaming answers, conversation memory, an Ollama model picker and a custom-model builder.
   Loaded after agent.js (uses agMd) and app.js (S, $, esc, api, toast, showFinding). */

const CH = { open:false, msgs:[], busy:false, ctrl:null, st:null, skill:'', settings:false, wide:false, allowRemote:false,
             log:'', modelfile:'', creating:false };
const CH_SUGGEST = ['What are the top risks?', 'What is exposed to the internet?', 'Which resources look unused?',
                    'What breaks if I rotate a secret?', 'How should I harden this?'];
const CH_SKILLS = [['', 'Best fit'], ['aws', 'AWS Engineer'], ['azure', 'Azure Engineer'], ['gcp', 'GCP Engineer'], ['devsec', 'DevSecOps Engineer'], ['integration', 'Integration Engineer']];
const chLoad = (k, d) => { try { return localStorage.getItem('cloudmap-chat-' + k) || d; } catch (e) { return d; } };
const chSave = (k, v) => { try { localStorage.setItem('cloudmap-chat-' + k, v); } catch (e) { /* ignore */ } };

async function chStatus(refresh) {
  try { CH.st = await api('/api/agent/status' + (refresh ? '?refresh=1' : '')); }
  catch (e) { CH.st = {available:false, hint:e.message, ollama:{reachable:false, models:[]}}; }
  CH.skill = CH.skill || chLoad('skill', '');
}

function chPill() {
  const s = CH.st; if (!s) return '<span class="pill">checking…</span>';
  if (!s.available) return '<span class="pill off">Built-in analysis · no model</span>';
  const where = s.local ? 'local' : 'sends data out';
  return `<span class="pill ${s.local ? 'ok' : 'warn'}">${esc(s.mode)} · ${esc(s.model)} · ${where}</span>`;
}

function chModelSelect() {
  const s = CH.st || {}, models = s.ollama?.models || [];
  const cur = s.available && s.mode === 'ollama' ? s.model : '';
  const opts = models.map(m => `<option value="${esc(m.name)}"${m.name === cur ? ' selected' : ''}>${esc(m.name)}${m.params ? ' · ' + esc(m.params) : ''}</option>`).join('');
  const hosted = s.available && s.mode !== 'ollama' ? `<option value="" selected>${esc(s.mode)} · ${esc(s.model)}</option>` : '';
  return `<select id="ch-model" aria-label="Model">${hosted}${opts}<option value="__off"${!s.available ? ' selected' : ''}>Built-in analysis (no model)</option></select>`;
}

function chSettings() {
  const s = CH.st || {}, o = s.ollama || {models:[]};
  const rows = o.models.map(m => `<tr><td>${esc(m.name)}</td><td>${esc(m.params || '')}</td><td>${esc(m.quant || '')}</td></tr>`).join('')
    || `<tr><td colspan="3" class="muted">${o.reachable ? 'Ollama is running but has no models yet. Run <code>ollama pull llama3.1</code> or create one below.' : 'Ollama not reachable.'}</td></tr>`;
  return `<div class="ch-settings">
    <h4>Ollama server</h4>
    <form id="ch-conn" class="row"><input id="ch-url" type="text" value="${esc(o.base_url || 'http://localhost:11434')}" aria-label="Ollama URL" spellcheck="false">
      <button class="btn sm" type="submit">Connect</button><button class="btn sm" type="button" data-ch="refresh">Refresh</button></form>
    <p class="muted">${o.reachable ? `Connected${o.version ? ' · v' + esc(o.version) : ''}.` : 'Not connected. Start Ollama (<code>ollama serve</code>), then press Refresh.'}
      ${o.local === false ? ' <b>Remote server: your inventory summary will leave this machine.</b>' : ' Everything stays on this machine.'}</p>
    <table class="models"><thead><tr><th>Installed model</th><th>Size</th><th>Quant</th></tr></thead><tbody>${rows}</tbody></table>
    <h4>Create a custom CloudMap model</h4>
    <p class="muted">Builds an Ollama model with CloudMap's expert instructions baked in, so you can also use it from the terminal (<code>ollama run name</code>).</p>
    <form id="ch-create" class="grid">
      <label>Name<input id="cm-name" type="text" value="cloudmap-${esc((S.data?.meta?.provider) || 'agent')}" spellcheck="false" required></label>
      <label>Base model<select id="cm-base">${o.models.map(m => `<option>${esc(m.name)}</option>`).join('')}</select></label>
      <label>Expertise<select id="cm-skill">${CH_SKILLS.filter(x => x[0]).map(([k, t]) => `<option value="${k}">${esc(t)}</option>`).join('')}</select></label>
      <label>Temperature<input id="cm-temp" type="number" min="0" max="1.5" step="0.1" value="0.2"></label>
      <label>Context<input id="cm-ctx" type="number" min="2048" step="1024" value="8192"></label>
      <label class="wide">Extra instructions (optional)<textarea id="cm-extra" rows="2" placeholder="e.g. Answer in Hebrew. Our standard is CIS Level 2."></textarea></label>
      <button class="btn primary" type="submit"${CH.creating || !o.models.length ? ' disabled' : ''}>${CH.creating ? 'Creating…' : 'Create model'}</button>
    </form>
    ${CH.log ? `<pre class="log">${esc(CH.log)}</pre>` : ''}
    ${CH.modelfile ? `<details><summary>Modelfile used</summary><pre class="log">${esc(CH.modelfile)}</pre></details>` : ''}</div>`;
}

function chMsg(m, i) {
  if (m.role === 'user') return `<div class="m user"><div class="bub">${esc(m.content)}</div></div>`;
  const meta = m.meta || {};
  const tag = meta.mode && meta.mode !== 'offline' ? `${meta.mode} · ${meta.model || ''}` : 'built-in analysis';
  return `<div class="m bot"><div class="bub">${m.content ? agMd(m.content) : '<span class="dots" aria-label="Thinking"><i></i><i></i><i></i></span>'}</div>
    <div class="a-meta"><span class="badge">${esc(tag)}</span>${meta.note ? `<small>${esc(meta.note)}</small>` : ''}
    ${(meta.resources || []).length && !m.live ? `<button class="link-btn" data-ch-show="${i}">Show on the map</button>` : ''}
    ${meta.error ? `<small class="err">${esc(meta.error)}</small>` : ''}</div></div>`;
}

function chRender(keep) {
  const box = $('#chat'); if (!box) return;
  const noScan = !S.id;
  const stay = keep || {};
  const body = noScan ? '<p class="muted pad">Import a scan (or load a demo) and I can answer questions about it.</p>'
    : CH.msgs.length ? CH.msgs.map(chMsg).join('')
    : `<div class="welcome"><p><b>Ask me about this ${esc((S.data?.meta?.provider || '').toUpperCase())} cloud.</b></p>
        <p class="muted">${CH.st?.available ? 'I will answer with the model you selected, grounded in the scan.' : 'No model is connected, so I answer from the built-in analysis. Open ⚙ to connect Ollama.'}</p>
        <div class="chips">${CH_SUGGEST.map(q => `<button class="chip" data-ch-q="${esc(q)}">${esc(q)}</button>`).join('')}</div></div>`;
  box.classList.toggle('wide', CH.wide);
  box.innerHTML = `<header><b>✦ AI Chat</b>${chPill()}<span class="sp"></span>
      <button class="icon-btn" data-ch="settings" aria-label="Model settings" aria-pressed="${CH.settings}" title="Models">⚙</button>
      <button class="icon-btn" data-ch="wide" aria-label="Toggle wide view" title="Wider">⤢</button>
      <button class="icon-btn" data-ch="close" aria-label="Close chat">×</button></header>
    <div class="ch-bar"><label>Model ${chModelSelect()}</label><label>Expert <select id="ch-skill" aria-label="Expert">${CH_SKILLS.map(([k, t]) => `<option value="${k}"${CH.skill === k ? ' selected' : ''}>${esc(t)}</option>`).join('')}</select></label>
      <button class="link-btn" data-ch="clear"${CH.msgs.length ? '' : ' disabled'}>Clear</button></div>
    ${CH.settings ? chSettings() : ''}
    <div class="ch-msgs" id="ch-msgs" aria-live="polite">${body}</div>
    <form id="ch-form" class="ch-input"><label class="sr" for="ch-text">Message</label>
      <textarea id="ch-text" rows="2" placeholder="${noScan ? 'Import a scan first' : 'Ask about this cloud…  (Enter to send, Shift+Enter for a new line)'}"${noScan ? ' disabled' : ''}>${esc(stay.text || '')}</textarea>
      ${CH.busy ? '<button class="btn" type="button" data-ch="stop">Stop</button>' : `<button class="btn primary" type="submit"${noScan ? ' disabled' : ''}>Send</button>`}</form>`;
  const m = $('#ch-msgs'); if (m) m.scrollTop = stay.scroll ?? m.scrollHeight;
}

async function chOpen() {
  CH.open = true; $('#chat').hidden = false; $('#chat-fab').hidden = true;
  chRender(); await chStatus(); if (!CH.st.available && !CH.msgs.length && CH.st.ollama && !CH.st.ollama.reachable) CH.settings = false;
  chRender(); $('#ch-text')?.focus();
}
function chClose() { CH.open = false; $('#chat').hidden = true; $('#chat-fab').hidden = false; }

async function chSend(text) {
  text = (text || '').trim(); if (!text || CH.busy || !S.id) return;
  CH.msgs.push({role:'user', content:text});
  const bot = {role:'assistant', content:'', meta:{}, live:true}; CH.msgs.push(bot);
  CH.busy = true; CH.ctrl = new AbortController(); chRender();
  const send = async (allowRemote) => {
    const history = CH.msgs.slice(0, -1).filter(m => m.content).map(m => ({role:m.role, content:m.content}));
    const r = await fetch(`/api/imports/${S.id}/agent/chat`, {method:'POST', headers:{'content-type':'application/json'}, signal:CH.ctrl.signal,
      body:JSON.stringify({messages:history, skill:CH.skill || null, allow_remote:allowRemote, model:CH.st?.mode === 'ollama' ? CH.st.model : null})});
    if (!r.ok) { let j = null; try { j = await r.json(); } catch (e) { /* none */ } throw new Error(j?.error || `Request failed (${r.status})`); }
    const rd = r.body.getReader(), dec = new TextDecoder(); let buf = '', raf = 0;
    const paint = () => { raf = 0; const el = $('#ch-msgs .m.bot:last-child .bub'); if (el) el.innerHTML = bot.content ? agMd(bot.content) : el.innerHTML; const m = $('#ch-msgs'); if (m) m.scrollTop = m.scrollHeight; };
    for (;;) {
      const {value, done} = await rd.read(); if (done) break;
      buf += dec.decode(value, {stream:true});
      let i; while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1); if (!line) continue;
        let ev; try { ev = JSON.parse(line); } catch (e) { continue; }
        if (ev.type === 'meta') Object.assign(bot.meta, {mode:ev.mode, model:ev.model, note:ev.note});
        else if (ev.type === 'delta') { bot.content += ev.text; if (!raf) raf = requestAnimationFrame(paint); }
        else if (ev.type === 'done') Object.assign(bot.meta, {resources:ev.resources, note:ev.note || bot.meta.note, followups:ev.followups});
        else if (ev.type === 'error') bot.meta.error = ev.message;
        else if (ev.type === 'consent') return {consent:ev};
      }
    }
    return {};
  };
  try {
    let res = await send(CH.allowRemote);
    if (res.consent) {
      const c = res.consent;
      if (confirm(`This sends a redacted summary of your inventory and your question to ${c.backend} (${c.model}).\n\nContinue for this session?`)) { CH.allowRemote = true; res = await send(true); }
      else { bot.content = 'Cancelled. Pick a local Ollama model in ⚙ to keep everything on this machine, or choose the built-in analysis.'; bot.meta.mode = 'offline'; }
    }
  } catch (e) { if (e.name !== 'AbortError') bot.meta.error = e.message; else bot.meta.note = 'Stopped.'; }
  bot.live = false; CH.busy = false; CH.ctrl = null; chRender();
}

async function chCreate() {
  const v = id => $(id)?.value;
  CH.creating = true; CH.log = ''; CH.modelfile = ''; chRender();
  try {
    const r = await fetch('/api/agent/ollama/create', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({
      name:v('#cm-name'), base:v('#cm-base'), skill:v('#cm-skill'), temperature:v('#cm-temp'), num_ctx:v('#cm-ctx'),
      instructions:v('#cm-extra'), provider:S.data?.meta?.provider})});
    if (!r.ok) throw new Error((await r.json()).error || 'Request failed');
    const rd = r.body.getReader(), dec = new TextDecoder(); let buf = '', made = null;
    for (;;) {
      const {value, done} = await rd.read(); if (done) break; buf += dec.decode(value, {stream:true});
      let i; while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1); if (!line) continue;
        const ev = JSON.parse(line);
        if (ev.modelfile) CH.modelfile = ev.modelfile;
        if (ev.status) CH.log += ev.status + '\n';
        if (ev.error) CH.log += 'Error: ' + ev.error + '\n';
        if (ev.done) made = ev.name;
      }
    }
    if (made) { await api('/api/agent/config', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({backend:'ollama', model:made})}); toast(`Model ${made} created and selected`); }
  } catch (e) { CH.log += 'Error: ' + e.message + '\n'; }
  CH.creating = false; await chStatus(true); chRender();
}

document.addEventListener('click', async e => {
  const t = e.target.closest('[data-chat-open],[data-ch],[data-ch-q],[data-ch-show]'); if (!t) return;
  const d = t.dataset;
  if ('chatOpen' in d) chOpen();
  else if (d.chQ) chSend(d.chQ);
  else if (d.chShow) { const r = (CH.msgs[+d.chShow]?.meta?.resources || []).filter(x => S.byId[x]); if (r.length) showFinding({id:'answer', title:'Answer', resources:r, severity:'note'}); }
  else if (d.ch === 'close') chClose();
  else if (d.ch === 'wide') { CH.wide = !CH.wide; chRender({text:$('#ch-text')?.value}); }
  else if (d.ch === 'settings') { CH.settings = !CH.settings; if (CH.settings) await chStatus(true); chRender({text:$('#ch-text')?.value}); }
  else if (d.ch === 'refresh') { await chStatus(true); chRender(); }
  else if (d.ch === 'clear') { CH.msgs = []; chRender(); }
  else if (d.ch === 'stop') CH.ctrl?.abort();
});
document.addEventListener('submit', async e => {
  if (e.target.id === 'ch-form') { e.preventDefault(); const ta = $('#ch-text'); const v = ta.value; ta.value = ''; chSend(v); }
  else if (e.target.id === 'ch-conn') { e.preventDefault();
    try { await api('/api/agent/config', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({backend:'ollama', base_url:$('#ch-url').value})}); await chStatus(true); }
    catch (err) { toast(err.message); } chRender(); }
  else if (e.target.id === 'ch-create') { e.preventDefault(); chCreate(); }
});
document.addEventListener('change', async e => {
  if (e.target.id === 'ch-skill') { CH.skill = e.target.value; chSave('skill', CH.skill); }
  else if (e.target.id === 'ch-model') {
    const v = e.target.value;
    try { await api('/api/agent/config', {method:'POST', headers:{'content-type':'application/json'},
      body:JSON.stringify(v === '__off' ? {backend:'offline'} : {backend:'ollama', model:v})}); await chStatus(true); } catch (err) { toast(err.message); }
    chRender({text:$('#ch-text')?.value});
  }
});
document.addEventListener('keydown', e => {
  if (e.target.id === 'ch-text' && e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); const v = e.target.value; e.target.value = ''; chSend(v); }
});
