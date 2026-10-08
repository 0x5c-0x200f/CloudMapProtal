'use strict';
/* CloudMap Agent panel: findings by discipline, attack paths, hardening plan and Q&A.
   Loaded after app.js; uses its globals (S, $, esc, api, showFinding, toast, showTab). */

const AG = { data:null, cat:'security', skill:null };
const AG_CATS = [['security', 'Security'], ['misconfig', 'Misconfig'], ['unused', 'Unused'], ['hardening', 'Hardening']];
const CONF = {high:'', medium:'likely', low:'check manually'};

function agMd(text) {                         // tiny, safe markdown: escape first, then format
  let html = esc(text).replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>').replace(/_([^_]+)_/g, '<i>$1</i>');
  const out = []; let list = null;
  html.split('\n').forEach(line => {
    const m = line.match(/^(\s*)- (.*)$/);
    if (m) { if (!list) { list = []; out.push(list); } list.push(m[2]); }
    else { list = null; if (line.trim()) out.push(`<p>${line}</p>`); }
  });
  return out.map(x => Array.isArray(x) ? `<ul>${x.map(i => `<li>${i}</li>`).join('')}</ul>` : x).join('');
}

async function agentLoad() {
  AG.data = null;
  const box = $('#agent'); if (!box) return;
  box.innerHTML = '<p class="muted">The agent is reading this inventory…</p>';
  try {
    AG.data = await api(`/api/imports/${S.id}/agent`); renderAgent();
  } catch (e) { box.innerHTML = `<p class="msg err">The agent couldn't analyse this scan: ${esc(e.message)}</p>`; }
}

function agFinding(f) {
  const conf = CONF[f.confidence] ? `<span class="badge">${esc(CONF[f.confidence])}</span>` : '';
  const names = f.resources.slice(0, 8).map(r => `<button class="chip" data-go="${esc(r)}">${esc(S.byId[r]?.name || r)}</button>`).join('');
  const sk = f.skills.map(s => `<span class="badge sk">${esc(AG.data.skills[s]?.title || s)}</span>`).join('');
  return `<article class="finding sev-${f.severity}">
    <button class="f-head" data-ag-finding="${esc(f.id)}" aria-expanded="false"><span class="f-meta">${esc(SEV[f.severity] || f.severity)} · ${f.count}</span> ${conf}<br>${esc(f.title)}</button>
    <div class="f-body" hidden>
      <p>${esc(f.why)}</p>
      ${f.items.length ? `<ul>${f.items.slice(0, 6).map(i => `<li>${esc(i)}</li>`).join('')}</ul>` : ''}
      <p><b>What to do:</b> ${esc(f.fix)}</p>
      ${f.cli.map(c => `<div class="cli"><code>${esc(c)}</code><button class="chip" data-copy="${esc(c)}" aria-label="Copy command">Copy</button></div>`).join('')}
      ${f.refs.length ? `<p class="muted">${esc(f.refs.join(' · '))}</p>` : ''}
      <div class="chips">${names}${f.count > 8 ? `<span class="muted">and ${f.count - 8} more</span>` : ''}</div>
      ${f.resources.length ? `<button class="link-btn" data-ag-show="${esc(f.id)}">Show ${plural(f.count, 'resource')} on the map</button>` : ''}
      <div class="chips">${sk}</div>
    </div></article>`;
}

function agPaths() {
  const ps = AG.data.attack_paths;
  if (!ps.length) return '';
  return `<h3>Routes from the internet</h3><p class="muted">Each line is a way in that reaches data, storage or secrets. Structural, not proof of exploitability.</p>` +
    ps.slice(0, 6).map((p, i) => `<button class="path sev-${p.severity}" data-ag-path="${i}"><span class="f-meta">${esc(SEV[p.severity])}</span>
      <span class="hops">${p.hops.map(h => `<b>${esc(h.name)}</b>`).join(' → ')}</span><small>${esc(p.entry_reasons[0])}</small></button>`).join('');
}

function agPlan() {
  const P = AG.data.plan;
  const phases = P.phases.filter(p => p.items.length).map(p => `<h3>${esc(p.label)}</h3><ul class="plan">${p.items.map(i =>
    `<li><button class="link-btn" data-ag-open="${esc(i.finding)}">${esc(i.title)}</button> <small>${i.count}</small></li>`).join('')}</ul>`).join('');
  const base = P.baseline.map(b => `<li><b>${esc(b.title)}</b><br><small>${esc(b.why)}</small>${b.cli ? `<div class="cli"><code>${esc(b.cli)}</code><button class="chip" data-copy="${esc(b.cli)}">Copy</button></div>` : ''}</li>`).join('');
  return `${phases || '<p class="muted">Nothing urgent to fix from this scan.</p>'}
    <h3>Baseline controls to verify</h3><p class="muted">Good practice for what you run here. The scan can't see these settings, so check them in the cloud.</p><ul class="plan base">${base}</ul>`;
}

function renderAgent() {
  const box = $('#agent'), D = AG.data; if (!box || !D) return;
  const skills = Object.entries(D.skills).map(([k, s]) => `<button class="skill${AG.skill === k ? ' on' : ''}" data-ag-skill="${k}" aria-pressed="${AG.skill === k}" title="${esc(s.title)}">${esc(s.title.replace(' Engineer', '').replace('Cloud ', ''))}<small>${s.count}</small></button>`).join('');
  const cats = AG_CATS.map(([k, label]) => {
    const n = k === 'hardening' ? '' : D.categories[k]?.count ?? 0;
    return `<button role="tab" data-ag-cat="${k}" aria-selected="${AG.cat === k}">${label}${n !== '' ? ` <small>${n}</small>` : ''}</button>`;
  }).join('');
  let body = '';
  const mine = f => !AG.skill || f.skills.includes(AG.skill);
  if (AG.cat === 'hardening') body = agPlan();
  else {
    const fs = D.findings.filter(f => f.category === AG.cat && mine(f));
    body = (AG.cat === 'security' ? agPaths() : '') + (fs.length ? fs.map(agFinding).join('') :
      `<p class="muted">${AG.skill ? 'Nothing here for this expert.' : 'Nothing found in the data this scan collected.'}</p>`);
  }
  box.innerHTML = `<div class="score"><div class="ring g-${D.grade}" role="img" aria-label="Posture score ${D.score} of 100, grade ${D.grade}"><b>${D.score}</b><small>${D.grade}</small></div>
      <div><p class="lede">${esc(D.summary)}</p><button class="btn primary sm" data-chat-open>Ask the AI about this cloud</button></div></div>
    <div class="skills" role="group" aria-label="Filter by expert">${skills}</div>
    <div class="subtabs" role="tablist" aria-label="Agent sections">${cats}</div>
    <div class="ag-body">${body}</div>
    <p class="muted fine">${esc(D.coverage.note)} <a href="/api/imports/${esc(S.id)}/agent.md" download>Download agent report</a></p>`;
}

document.addEventListener('click', e => {
  const t = e.target.closest('[data-ag-cat],[data-ag-skill],[data-ag-finding],[data-ag-show],[data-ag-path],[data-ag-open]');
  if (!t || !AG.data) return;
  const d = t.dataset;
  if (d.agCat) { AG.cat = d.agCat; renderAgent(); }
  else if (d.agSkill) { AG.skill = AG.skill === d.agSkill ? null : d.agSkill; renderAgent(); }
  else if (d.agFinding) {
    const body = t.nextElementSibling, open = body.hidden;
    $$('#agent .f-body').forEach(b => { b.hidden = true; b.previousElementSibling.setAttribute('aria-expanded', 'false'); });
    body.hidden = !open; t.setAttribute('aria-expanded', open);
    const f = AG.data.findings.find(x => x.id === d.agFinding);
    if (open && f && f.resources.length) showFinding(f); else if (!open) clearMarks();
  }
  else if (d.agShow) { const f = AG.data.findings.find(x => x.id === d.agShow); if (f) showFinding(f); }
  else if (d.agPath) { const p = AG.data.attack_paths[+d.agPath]; if (p) showFinding({id:'path', title:p.text, resources:p.hops.map(h => h.id), severity:p.severity}); }
  else if (d.agOpen) { const f = AG.data.findings.find(x => x.id === d.agOpen); if (f) { AG.cat = f.category; renderAgent();
      const b = $(`[data-ag-finding="${CSS.escape(f.id)}"]`); b?.click(); b?.scrollIntoView?.({block:'nearest'}); } }
});
