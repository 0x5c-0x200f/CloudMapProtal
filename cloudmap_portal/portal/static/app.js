'use strict';
/* CloudMap portal: explorer, two map views (structure + network graph), briefing, inspector, sharing.
   No build step. The structure view is plain HTML boxes; the network graph uses Cytoscape. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cssv = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const REDUCED = matchMedia('(prefers-reduced-motion: reduce)').matches;
const MAX_FULL = 1500;                       // network graph only: above this, draw focused subsets
const GROUP_MIN = 5;                         // structure view: this many of one kind in one place become a single tile
const LAYER_NAMES = {network:'Network', compute:'Compute', data:'Data', storage:'Storage', iam:'Identity', scope:'Structure', other:'Other'};
const SHAPES = {compute:'ellipse', data:'barrel', storage:'round-diamond', iam:'round-hexagon', network:'round-rectangle', scope:'round-rectangle'};
const SEV = {high:'Urgent', medium:'Review soon', low:'Minor', note:'Good to know'};
const SEV_RANK = {high:0, medium:1, low:2, note:3};
const KIND_NAMES = {'network.vpc':'Network', 'network.public_ip':'Public IP', 'network.interface':'Network interface',
  'network.load_balancer':'Load balancer', 'network.backend_service':'Backend service', 'network.security_group':'Security group',
  'compute.instance_group':'Instance group', 'iam.role':'Role', 'data.server':'Database server',
  'iam.vault':'Key vault', 'iam.secret':'Secret', 'iam.key':'Key', 'iam.certificate':'Certificate', 'iam.encryption_set':'Encryption set'};

const S = { id:null, data:null, ins:null, cy:null, byId:{}, kids:{}, outE:{}, inE:{}, byFinding:{},
            hidden:new Set(), focus:null, selected:null, descMemo:{},
            view:'structure', collapsed:new Set(), openGroups:new Set(), dom:new Map(),
            hitSet:null, showSel:false, links:false, labels:false, quiet:true, zoom:1,
            search:null, query:'', searchHops:1, autoLabels:false,
            treeLinks:true, linkNote:'', trect:new Map(), tparent:new Map() };   // the tree shows relationships by default
try { const v = localStorage.getItem('cloudmap-view'); if (v === 'graph' || v === 'structure' || v === 'tree') S.view = v; } catch (e) { /* ignore */ }

const SCOPE = new Set(['organization', 'management_group', 'folder', 'account', 'resource_group', 'region']);
const layerOf = k => SCOPE.has(k) ? 'scope' : k.split('.')[0];
const colorOf = k => cssv('--l-' + layerOf(k)) || cssv('--ink-2');
const kindLabel = k => { const t = k.replace(/[._]/g, ' '); return t[0].toUpperCase() + t.slice(1); };
const shortKind = k => { if (KIND_NAMES[k]) return KIND_NAMES[k]; const t = (k.includes('.') ? k.split('.').slice(1).join(' ') : k).replace(/_/g, ' '); return t[0].toUpperCase() + t.slice(1); };
const pluralKind = (k, n) => { const w = shortKind(k); const p = /[^aeiou]y$/i.test(w) ? w.slice(0, -1) + 'ies' : /(s|x|ch)$/i.test(w) ? w + 'es' : w + 's';
  return `${n} ${p.replace(/^[A-Z](?![A-Z])/, c => c.toLowerCase())}`; };
const relLabel = r => r.replaceAll('_', ' ');
const isContainer = id => (S.kids[id] || []).length > 0;
const plural = (n, a, b) => `${n} ${n === 1 ? a : (b || a + 's')}`;
const KV_ITEMS = new Set(['iam.secret', 'iam.key', 'iam.certificate']);
function itemStatus(n) {                                   // status of a secret/key/certificate: from metadata only, never a value
  if (!KV_ITEMS.has(n.kind)) return null;
  const p = n.props || {};
  if (p.missing) return {text:'missing', level:'bad', rank:0};
  if (p.enabled === false) return {text:'disabled', level:'bad', rank:1};
  if (p.expires) {
    const d = Math.floor((Date.parse(p.expires) - Date.parse(S.data.meta.scanned_at)) / 864e5);
    if (d < 0) return {text:`expired ${-d}d ago`, level:'bad', rank:0};
    if (d <= 30) return {text:`expires in ${d}d`, level:'warn', rank:2};
    return {text:`expires in ${d}d`, level:'ok', rank:4};
  }
  return {text:'no expiry', level:'none', rank:3};
}
const depthOf = id => { let d = 0; for (let p = S.byId[id].parent; p; p = S.byId[p]?.parent) d++; return d; };

function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), 2400);
}

/* ---------- loading ---------- */
async function api(url, opts) {
  const r = await fetch(url, opts); let j = null;
  try { j = await r.json(); } catch (e) { /* non-JSON */ }
  if (!r.ok) throw new Error((j && j.error) || `Request failed (${r.status})`);
  return j;
}

async function upload(file) {
  const fd = new FormData(); fd.append('file', file);
  try { const j = await api('/api/import', {method:'POST', body:fd}); await loadImport(j.import_id); }
  catch (e) { const m = $('#import-error'); m.textContent = e.message + '. Check that the file came from “cloudmap-portal scan”.'; m.hidden = false; toast('Import failed'); }
}

async function loadImport(iid, nodeId, q, hops) {
  const [data, ins] = await Promise.all([api(`/api/imports/${iid}/graph`), api(`/api/imports/${iid}/insights`)]);
  Object.assign(S, {id:iid, data, ins, hidden:new Set(), focus:null, selected:null, descMemo:{}, hitSet:null, showSel:false, zoom:1, search:null, query:'', searchHops:hops === 0 ? 0 : (hops || 1)});
  index(); initCollapse();
  $('#q').value = q || ''; $('#q-clear').hidden = !q; if (q) applySearch(q, {redrawMap:false}); else renderResults();
  $('#empty').hidden = true; $('#share-btn').disabled = false;
  renderScan(); renderLegend(); renderTree(); renderBriefing();
  if (typeof agentLoad === 'function') agentLoad();
  setView(S.view);
  showTab('briefing');
  if (nodeId && S.byId[nodeId]) select(nodeId, {center:true});
  else history.replaceState(null, '', `#import=${iid}`);
}

function index() {
  S.byId = {}; S.kids = {}; S.outE = {}; S.inE = {}; S.byFinding = {};
  S.data.nodes.forEach(n => { S.byId[n.id] = n; (S.kids[n.parent || ''] ??= []).push(n.id); });
  S.data.edges.forEach(e => { (S.outE[e.from] ??= []).push(e); (S.inE[e.to] ??= []).push(e); });
  Object.values(S.kids).forEach(a => a.sort((x, y) => S.byId[x].name.localeCompare(S.byId[y].name)));
  S.ins.findings.forEach(f => f.resources.forEach(r => (S.byFinding[r] ??= []).push(f)));
}

function renderScan() {
  const m = S.data.meta; let when = m.scanned_at;
  try { when = new Date(m.scanned_at).toLocaleString(undefined, {dateStyle:'medium', timeStyle:'short'}); } catch (e) { /* keep raw */ }
  $('#scan').innerHTML = `<strong>${esc(m.provider.toUpperCase())}</strong><span>Scan ${esc(m.scan_id)}</span><span>${esc(when)}</span>`;
  $('#scan').hidden = false;
}

/* ---------- explorer ---------- */
function descCount(id) {
  if (S.descMemo[id] !== undefined) return S.descMemo[id];
  return S.descMemo[id] = (S.kids[id] || []).reduce((n, c) => n + 1 + descCount(c), 0);
}
function treeItem(id) {
  const n = S.byId[id], kids = S.kids[id] || [];
  const label = `<span class="item" data-go="${esc(id)}" data-id="${esc(id)}"><i class="sw" style="background:${colorOf(n.kind)}"></i>${esc(n.name)}</span>`;
  if (!kids.length) { const d = document.createElement('div'); d.className = 'leaf'; d.innerHTML = label; return d; }
  const det = document.createElement('details');
  det.innerHTML = `<summary>${label}<span class="count">${descCount(id)}</span></summary><div class="children"></div>`;
  det.addEventListener('toggle', () => {
    const box = det.querySelector(':scope > .children');
    if (det.open && !box.childElementCount) kids.forEach(k => box.appendChild(treeItem(k)));
  });
  return det;
}
function renderTree() {
  const t = $('#tree'); t.innerHTML = '';
  (S.kids[''] || []).forEach(id => { const el = treeItem(id); t.appendChild(el); if (el.tagName === 'DETAILS') el.open = true; });
}
/* =====================================================================
   SEARCH: a persistent filter. It keeps the matches AND everything related to them on the map,
   and stays in place while you select, switch views, resize panels or share the link.
   ===================================================================== */
const SEARCH_LIMIT = 600;                                 // never build a map bigger than this from one search
const COMPACT_MAX = 120;                                  // up to this many resources: show everything, no grouping or folding
function matchNode(n, q) {                                // names, tags, types. Paths (ids) only when the query looks like one
  if (n.name.toLowerCase().includes(q) || n.kind.includes(q) || (n.native_type || '').toLowerCase().includes(q) || (n.region || '').toLowerCase() === q) return true;
  if ((q.includes('/') || q.includes(':')) && n.id.toLowerCase().includes(q)) return true;
  return Object.entries(n.tags || {}).some(([k, v]) => `${k}=${v}`.toLowerCase().includes(q));
}
function runSearch(q, hops) {
  const ql = q.toLowerCase(), matches = new Set(S.data.nodes.filter(n => matchNode(n, ql)).map(n => n.id));
  const ids = new Set(matches), dist = new Map([...matches].map(i => [i, 0]));
  const below = id => (S.kids[id] || []).forEach(k => { if (!ids.has(k)) { ids.add(k); dist.set(k, 0); } below(k); });
  matches.forEach(below);                                 // a matched container brings what is inside it
  const max = hops === 0 ? Infinity : hops;
  let frontier = [...ids], depth = 0, truncated = false;
  while (frontier.length && depth < max && !truncated) {   // then follow relationships, in both directions
    depth++; const next = [];
    outer: for (const id of frontier) {
      for (const nb of [...(S.outE[id] || []).map(e => e.to), ...(S.inE[id] || []).map(e => e.from)]) {
        if (ids.has(nb)) continue;
        if (ids.size >= SEARCH_LIMIT) { truncated = true; break outer; }
        ids.add(nb); dist.set(nb, depth); next.push(nb);
      }
    }
    frontier = next;
  }
  return {q, hops, matches, ids, dist, truncated, compact:ids.size <= COMPACT_MAX};
}

function hashFor(node) {
  const p = new URLSearchParams(); p.set('import', S.id);
  if (node) p.set('node', node);
  if (S.query) { p.set('q', S.query); p.set('hops', S.searchHops); }
  return '#' + p.toString();
}

function applySearch(q, {redrawMap = true} = {}) {
  S.query = (q || '').trim();
  S.search = S.query.length >= 2 && S.data ? runSearch(S.query, S.searchHops) : null;
  $('#q-clear').hidden = !S.query;
  if (S.search && !S.search.compact) [...S.search.matches].slice(0, 80).forEach(reveal);   // big result: open the path to each match
  renderResults();
  if (redrawMap && S.data) redraw();
  else updateBanner();
  if (S.id) history.replaceState(null, '', hashFor(S.selected));
}
function clearSearch() { $('#q').value = ''; applySearch(''); }

function renderResults() {
  const box = $('#results'), s = S.search;
  if (!S.query) { box.innerHTML = ''; return; }
  if (!s) { box.innerHTML = '<p class="muted">Type at least 2 characters.</p>'; return; }
  if (!s.matches.size) { box.innerHTML = '<p class="muted">Nothing matches. Names, tags and types are searched.</p>'; return; }
  const row = n => `<button class="hit-row" data-go="${esc(n.id)}"><i class="sw" style="background:${colorOf(n.kind)}"></i>${esc(n.name)}<small>${esc(kindLabel(n.kind))}</small></button>`;
  const hits = [...s.matches].map(i => S.byId[i]);
  const rel = [...s.ids].filter(i => !s.matches.has(i)).sort((a, b) => s.dist.get(a) - s.dist.get(b)).map(i => S.byId[i]);
  box.innerHTML = `<h3>${plural(hits.length, 'match', 'matches')}</h3>` + hits.slice(0, 40).map(row).join('') +
    (hits.length > 40 ? `<p class="muted">Showing the first 40 matches.</p>` : '') +
    (rel.length ? `<h3>Related, ${s.hops === 0 ? 'all connected' : plural(s.hops, 'step')} away</h3>` + rel.slice(0, 40).map(row).join('') +
      (rel.length > 40 ? `<p class="muted">And ${rel.length - 40} more on the map.</p>` : '') : '');
}

let qTimer;
$('#q').addEventListener('input', e => { clearTimeout(qTimer); qTimer = setTimeout(() => { S.focus = null; applySearch(e.target.value); }, 120); });
$('#q').addEventListener('keydown', e => {
  if (e.key === 'Escape') { if ($('#q').value) { e.stopPropagation(); clearSearch(); } else $('#q').blur(); }
  else if (e.key === 'Enter' && S.search?.matches.size) { clearTimeout(qTimer); select([...S.search.matches][0], {center:true}); }
});
$('#q-clear').addEventListener('click', () => { clearSearch(); $('#q').focus(); });
document.addEventListener('keydown', e => {
  if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || '')) { e.preventDefault(); $('#q').focus(); }
});
document.addEventListener('change', e => { if (e.target.id === 'hops-search') { S.searchHops = +e.target.value; applySearch(S.query); } });

/* ---------- legend (layer filter) ---------- */
function renderLegend() {
  const counts = S.ins.stats.layers;
  $('#legend').innerHTML = Object.entries(counts).map(([l, c]) =>
    `<button class="layer" data-layer="${l}" aria-pressed="${!S.hidden.has(l)}"><i class="sw" style="background:${cssv('--l-' + l) || cssv('--ink-2')}"></i><b>${esc(LAYER_NAMES[l] || l)}</b><span>${c}</span></button>`).join('');
}

/* ---------- which nodes are on the map right now (shared by both views) ---------- */
function visibleSet() {
  const ids = new Set();
  if (S.focus) S.focus.ids.forEach(i => S.byId[i] && ids.add(i));
  else if (S.search) S.search.ids.forEach(i => { if (S.search.matches.has(i) || !S.hidden.has(layerOf(S.byId[i].kind))) ids.add(i); });
  else S.data.nodes.forEach(n => { if (!S.hidden.has(layerOf(n.kind))) ids.add(n.id); });
  [...ids].forEach(id => { for (let p = S.byId[id].parent; p; p = S.byId[p]?.parent) ids.add(p); });   // keep parents so groups render
  return ids;
}

/* ---------- views ---------- */
function setView(v) {
  S.view = v;
  try { localStorage.setItem('cloudmap-view', v); } catch (e) { /* ignore */ }
  $('#stage').dataset.mode = v;
  $('#links-toggle').setAttribute('aria-pressed', v === 'tree' ? S.treeLinks : S.links);
  $$('.viewsw [data-view]').forEach(b => b.setAttribute('aria-pressed', b.dataset.view === v));
  $('#struct').hidden = v === 'graph'; $('#sheet').hidden = v !== 'structure'; $('#cy').hidden = v !== 'graph';
  $('#tsvg').toggleAttribute('hidden', v !== 'tree');       // an SVG element has no .hidden property: assigning it does nothing, the attribute stays
  if (S.cy) { S.cy.destroy(); S.cy = null; }
  $('#canvas-note').hidden = true; $('#links').textContent = '';
  if (v === 'structure') renderStructure();
  else if (v === 'tree') { S.zoom = 1; renderTreeGraph(); fitTreeToWidth(); }
  else drawGraph();
}
const redraw = () => S.view === 'graph' ? drawGraph() : S.view === 'tree' ? renderTreeGraph() : renderStructure();

/* =====================================================================
   STRUCTURE VIEW: nested boxes. Relationships are drawn only on demand.
   ===================================================================== */
const COLLAPSE_BUDGET = 220;                              // roughly how many boxes and tiles to draw up front
function groupedCost(id) {                                // how many elements this container shows when open
  const byKind = {}; let cost = 0;
  (S.kids[id] || []).forEach(k => { if (isContainer(k)) cost++; else byKind[S.byId[k].kind] = (byKind[S.byId[k].kind] || 0) + 1; });
  Object.values(byKind).forEach(c => { cost += c >= GROUP_MIN ? 1 : c; });
  return cost;
}
function initCollapse() {                                 // open level by level, shallowest first, until the budget is spent
  S.collapsed = new Set(); S.openGroups = new Set();
  S.data.nodes.forEach(n => { if (isContainer(n.id)) S.collapsed.add(n.id); });
  let used = 0, queue = (S.kids[''] || []).filter(isContainer);
  while (queue.length) {
    const next = [];
    for (const id of queue) {
      const cost = groupedCost(id);
      if (used > 0 && used + cost > COLLAPSE_BUDGET) continue;     // too much: leave this one folded
      used += cost; S.collapsed.delete(id);
      (S.kids[id] || []).filter(isContainer).forEach(k => next.push(k));
    }
    queue = next;
  }
}

function renderStructure() {
  const root = $('#tree-root'); root.textContent = ''; S.dom = new Map(); $('#canvas-note').hidden = true;
  const vis = visibleSet(), memo = new Map(), compact = !!(S.focus || (S.search && S.search.compact)) && vis.size <= COMPACT_MAX;
  const visKids = id => (S.kids[id] || []).filter(k => vis.has(k));
  const hasKids = id => visKids(id).length > 0;
  const leafMix = id => {                                   // layer counts over the visible leaves below id
    if (memo.has(id)) return memo.get(id);
    const m = {}, kids = visKids(id);
    if (!kids.length) m[layerOf(S.byId[id].kind)] = 1;
    else kids.forEach(k => { const km = leafMix(k); for (const l in km) m[l] = (m[l] || 0) + km[l]; });
    memo.set(id, m); return m;
  };
  const sum = m => Object.values(m).reduce((a, b) => a + b, 0);
  const mk = (tag, cls) => { const e = document.createElement(tag); if (cls) e.className = cls; return e; };

  const tile = id => {
    const n = S.byId[id], fs = S.byFinding[id] || [], dep = (S.inE[id] || []).length;
    const sev = fs.length ? fs.map(f => f.severity).sort((a, b) => SEV_RANK[a] - SEV_RANK[b])[0] : null;
    const st = itemStatus(n); const b = mk('button', 'tile' + (st ? ' st-' + st.level : '')); b.type = 'button'; b.dataset.go = id; b.dataset.id = id; b.style.setProperty('--c', colorOf(n.kind));
    b.setAttribute('aria-label', `${n.name}, ${shortKind(n.kind)}${st ? ', ' + st.text : ''}`);
    b.innerHTML = `<i class="shape ${layerOf(n.kind)}"></i><span class="t-text"><span class="t-name">${esc(n.name)}</span><span class="t-kind">${esc(shortKind(n.kind) + (st ? ', ' + st.text : ''))}</span></span>` +
      (dep >= 2 ? `<span class="dep" title="${dep} resources use this">${dep}</span>` : '') +
      (sev ? `<i class="sev sev-${sev}" title="${esc(SEV[sev])}"></i>` : '');
    S.dom.set(id, b); return b;
  };
  const groupTile = (key, kind, ids) => {
    const bad = ids.filter(i => itemStatus(S.byId[i])?.level === 'bad').length;
    const b = mk('button', 'tile group' + (bad ? ' st-bad' : '')); b.type = 'button'; b.dataset.group = key; b.style.setProperty('--c', colorOf(kind));
    const worst = ids.flatMap(i => (S.byFinding[i] || []).map(f => f.severity)).sort((a, c) => SEV_RANK[a] - SEV_RANK[c])[0];
    b.setAttribute('aria-label', `${pluralKind(kind, ids.length)}. Show all`);
    b.innerHTML = `<i class="shape ${layerOf(kind)}"></i><span class="t-text"><span class="t-name">${esc(pluralKind(kind, ids.length))}</span><span class="t-kind">${bad ? `${bad} need attention` : 'Show all'}</span></span>` +
      (worst ? `<i class="sev sev-${worst}" title="${esc(SEV[worst])}"></i>` : '');
    ids.forEach(i => S.dom.set(i, b)); return b;
  };
  const regDesc = (el, id) => visKids(id).forEach(k => { S.dom.set(k, el); regDesc(el, k); });

  const box = id => {
    const kids = visKids(id);
    if (!kids.length) return tile(id);
    const n = S.byId[id], collapsed = S.collapsed.has(id) && !compact, mix = leafMix(id);
    const el = mk('section', 'box' + (collapsed ? ' collapsed' : '')); el.dataset.depth = Math.min(depthOf(id), 4);
    el.style.setProperty('--c', colorOf(n.kind));
    el.innerHTML = `<header class="box-h" data-id="${esc(id)}"><button class="tog" type="button" data-toggle="${esc(id)}" aria-expanded="${!collapsed}" aria-label="${collapsed ? 'Expand' : 'Collapse'} ${esc(n.name)}"></button>` +
      `<button class="box-name" type="button" data-go="${esc(id)}">${esc(n.name)}</button><span class="box-kind">${esc(shortKind(n.kind))}</span><span class="box-count">${sum(mix)}</span></header>`;
    const head = el.firstChild; S.dom.set(id, head);
    const body = mk('div', 'box-body');
    if (collapsed) {
      regDesc(head, id);
      body.innerHTML = `<div class="minimix">${Object.entries(mix).map(([l, c]) => `<i style="flex:${c};background:${cssv('--l-' + l) || cssv('--ink-2')}"></i>`).join('')}</div>` +
        `<p class="mix-text">${Object.entries(mix).map(([l, c]) => `${c} ${(LAYER_NAMES[l] || l).toLowerCase()}`).join(', ')}</p>`;
    } else {
      const leaves = kids.filter(k => !hasKids(k)), subs = kids.filter(hasKids);
      if (leaves.length) {
        const row = mk('div', 'row'), byKind = {};
        leaves.forEach(k => (byKind[S.byId[k].kind] ??= []).push(k));
        Object.entries(byKind).sort(([a], [b]) => a.localeCompare(b)).forEach(([kind, list]) => {
          const key = `${id}|${kind}`;
          if (list.length >= GROUP_MIN && !S.openGroups.has(key) && !compact) row.appendChild(groupTile(key, kind, list));
          else list.forEach(k => row.appendChild(tile(k)));
        });
        body.appendChild(row);
      }
      if (subs.length) { const sr = mk('div', 'subs'); subs.forEach(k => sr.appendChild(box(k))); body.appendChild(sr); }
    }
    el.appendChild(body); return el;
  };

  const roots = (S.kids[''] || []).filter(id => vis.has(id));
  if (!roots.length) { $('#canvas-note').innerHTML = S.search && !S.search.matches.size ? `<p>No resource matches “${esc(S.query)}”.</p>` : '<p>Nothing to show with these filters.<br>Switch a layer back on above.</p>'; $('#canvas-note').hidden = false; }
  const frag = document.createDocumentFragment(); roots.forEach(id => frag.appendChild(box(id))); root.appendChild(frag);
  updateBanner(); applyZoom(false); applyMarks(); drawLinks();
}

function elFor(id) {                                       // the element standing in for id: itself, or the folded box / group tile holding it
  return S.dom.get(id) || null;                            // a resource that is not on the map has no element: never borrow an ancestor's
}

function reveal(id) {                                      // open whatever hides id; true if anything changed
  let changed = false;
  for (let p = S.byId[id]?.parent; p; p = S.byId[p]?.parent) if (S.collapsed.delete(p)) changed = true;
  const n = S.byId[id];
  if (n && !isContainer(id) && n.parent) {
    const sib = (S.kids[n.parent] || []).filter(k => S.byId[k].kind === n.kind && !isContainer(k)).length, key = `${n.parent}|${n.kind}`;
    if (sib >= GROUP_MIN && !S.openGroups.has(key)) { S.openGroups.add(key); changed = true; }
  }
  return changed;
}

function scrollIfHidden(el) {                              // scroll only when the element is off-screen: no jumpy clicks
  if (!el || !el.getBoundingClientRect) return;
  const r = el.getBoundingClientRect(), h = $('#struct').getBoundingClientRect();
  if (r.top < h.top || r.bottom > h.bottom || r.left < h.left || r.right > h.right)
    el.scrollIntoView?.({block:'center', inline:'center', behavior:REDUCED ? 'auto' : 'smooth'});
}

function markTreePaths() {                                 // the route through the hierarchy to what is selected, related, matched or hit
  const svg = $('#tsvg'); svg.querySelectorAll('.tl.on').forEach(p => p.classList.remove('on'));
  const on = new Set();
  svg.querySelectorAll('.tn.sel, .tn.nb, .tn.hit, .tn.match').forEach(g => { for (let c = g.getAttribute('data-rid'); S.tparent.has(c); c = S.tparent.get(c)) on.add(c); });
  if (on.size) svg.querySelectorAll('.tl').forEach(p => { if (on.has(p.getAttribute('data-c'))) p.classList.add('on'); });
}
function applyMarks() { applyMarksCore(); if (S.view === 'tree') markTreePaths(); }
function applyMarksCore() {
  if (S.view === 'graph') return;
  const sheet = S.view === 'tree' ? $('#tsvg') : $('#sheet');
  sheet.classList.remove('has-sel', 'has-hit');
  $$('.sel, .nb, .hit, .match', sheet).forEach(e => e.classList.remove('sel', 'nb', 'hit', 'match'));
  S.search?.matches.forEach(id => elFor(id)?.classList.add('match'));
  if (S.hitSet) {
    S.hitSet.forEach(id => elFor(id)?.classList.add('hit')); sheet.classList.add('has-hit');
  } else if (S.showSel && S.selected) {
    const el = elFor(S.selected); if (!el) return;
    el.classList.add('sel');
    if (!isContainer(S.selected)) {
      [...(S.outE[S.selected] || []).map(e => e.to), ...(S.inE[S.selected] || []).map(e => e.from)].forEach(o => { const x = elFor(o); if (x && x !== el) x.classList.add('nb'); });
      sheet.classList.add('has-sel');
    }
  }
}

/* relationships: only for the selection, or aggregated to what is visible when asked */
function linkPairs() {                                    // WHICH relationships to show, as pairs of on-screen elements
  const pairs = []; S.linkNote = '';
  const searchMode = !!(S.search && S.search.compact && S.search.ids.size && !S.focus && !S.hitSet);
  if (searchMode) {                                       // the filtered resources and every relationship among them
    const sel = S.showSel && S.selected ? elFor(S.selected) : null, seen = new Map();
    S.data.edges.forEach(e => {
      const a = elFor(e.from), b = elFor(e.to); if (!a || !b || a === b) return;
      const m = seen.get(a) || seen.set(a, new Map()).get(a), cur = m.get(b);
      cur ? cur.count++ : m.set(b, {a, b, rel:e.rel, count:1, dir:sel ? (a === sel ? 'out' : b === sel ? 'in' : 'agg') : 'agg'});
    });
    seen.forEach(m => m.forEach(p => pairs.push(p)));
  } else if (S.showSel && S.selected && !S.hitSet) {
    const add = (from, to, rel, dir) => { const a = elFor(from), b = elFor(to); if (a && b && a !== b) pairs.push({a, b, rel, dir, count:1}); };
    (S.outE[S.selected] || []).forEach(e => add(e.from, e.to, e.rel, 'out'));
    (S.inE[S.selected] || []).forEach(e => add(e.from, e.to, e.rel, 'in'));
  } else if (S.view === 'tree' ? S.treeLinks : S.links) {
    const agg = new Map(), tree = S.view === 'tree';
    S.data.edges.forEach(e => {
      if (tree && S.quiet && (quietNode(e.from) || quietNode(e.to))) return;       // shared roles and groups would drown the diagram
      const a = elFor(e.from), b = elFor(e.to); if (!a || !b || a === b) return;
      const m = agg.get(a) || agg.set(a, new Map()).get(a), cur = m.get(b);
      cur ? cur.count++ : m.set(b, {a, b, rel:'', dir:'agg', count:1});
    });
    agg.forEach(m => m.forEach(p => pairs.push(p)));
    const cap = tree ? 150 : 500;
    if (pairs.length > cap) {
      S.linkNote = `Showing the ${cap} strongest of ${pairs.length} relationships. Fold, search or select to see others.`;
      pairs.sort((x, y) => y.count - x.count).length = cap;
    }
  }
  return {pairs, searchMode};
}

function quadRoute(A, B) {                                 // straight-ish curve between facing edges: used where there are no columns
  const edge = (r, tx, ty) => { const cx = r.x + r.w / 2, cy = r.y + r.h / 2, dx = tx - cx, dy = ty - cy;
    if (!dx && !dy) return {x:cx, y:cy};
    const k = Math.min(dx ? (r.w / 2) / Math.abs(dx) : Infinity, dy ? (r.h / 2) / Math.abs(dy) : Infinity);
    return {x:cx + dx * k, y:cy + dy * k}; };
  const ac = {x:A.x + A.w / 2, y:A.y + A.h / 2}, bc = {x:B.x + B.w / 2, y:B.y + B.h / 2};
  const s = edge(A, bc.x, bc.y), t = edge(B, ac.x, ac.y), mx = (s.x + t.x) / 2, my = (s.y + t.y) / 2;
  const len = Math.hypot(t.x - s.x, t.y - s.y) || 1, bend = Math.min(60, len * 0.14);
  const cx = mx - (t.y - s.y) / len * bend, cy = my + (t.x - s.x) / len * bend;
  return {d:`M${s.x.toFixed(1)} ${s.y.toFixed(1)} Q${cx.toFixed(1)} ${cy.toFixed(1)} ${t.x.toFixed(1)} ${t.y.toFixed(1)}`,
          lx:(s.x + 2 * cx + t.x) / 4, ly:(s.y + 2 * cy + t.y) / 4 - 4};
}

function treeRoute(A, B) {                                 // leave the right edge, arrive at the left edge (or bow out when in one column)
  const sy = A.y + A.h / 2, ty = B.y + B.h / 2;
  let sx, tx, c1, c2;
  if (Math.abs(A.x - B.x) < 1) {                           // same column: bow out to the right, more the further apart
    sx = A.x + A.w; tx = B.x + B.w; const bow = 44 + Math.min(44, Math.abs(ty - sy) / 8); c1 = sx + bow; c2 = tx + bow;
  } else if (A.x < B.x) { sx = A.x + A.w; tx = B.x; const k = Math.max(34, (tx - sx) / 2); c1 = sx + k; c2 = tx - k; }
  else { sx = A.x; tx = B.x + B.w; const k = Math.max(34, (sx - tx) / 2); c1 = sx - k; c2 = tx + k; }
  return {d:`M${sx.toFixed(1)} ${sy.toFixed(1)}C${c1.toFixed(1)} ${sy.toFixed(1)} ${c2.toFixed(1)} ${ty.toFixed(1)} ${tx.toFixed(1)} ${ty.toFixed(1)}`,
          lx:(sx + 3 * c1 + 3 * c2 + tx) / 8, ly:(sy + ty) / 2 - 4};
}

function linkMarkup(rectOf, pfx, route = quadRoute) {      // HOW: curves between element rectangles, in the view's own coordinates
  const {pairs, searchMode} = linkPairs();
  if (!pairs.length) return '';
  let out = '<defs>' + ['out', 'in', 'agg'].map(k => `<marker class="mk-${k}" id="${pfx}-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z"/></marker>`).join('') + '</defs>';
  pairs.forEach(p => {
    const A = rectOf(p.a), B = rectOf(p.b); if (!A || !B) return;
    const r = route(A, B);
    out += `<path class="l l-${p.dir}" marker-end="url(#${pfx}-${p.dir})" style="stroke-width:${p.dir === 'agg' ? 1 + Math.min(3, Math.log2(p.count + 1)) : 1.7}" d="${r.d}"/>`;
    if (p.rel && (!searchMode || pairs.length <= 40)) out += `<text class="l-text" x="${r.lx.toFixed(1)}" y="${r.ly.toFixed(1)}">${esc(relLabel(p.rel) + (searchMode && p.count > 1 ? ` +${p.count - 1}` : ''))}</text>`;
  });
  return out;
}

function drawLinks() {
  if (!S.data) return;
  const note = $('#links-note');
  if (S.view === 'tree') { const g = $('#tlinks'); if (g) g.innerHTML = linkMarkup(el => S.trect.get(el), 't', treeRoute); if (note) note.textContent = S.linkNote; return; }
  const svg = $('#links'); svg.textContent = '';
  if (note) note.textContent = '';
  if (S.view !== 'structure') return;
  const sheet = $('#sheet'), z = S.zoom || 1, base = sheet.getBoundingClientRect();
  const rect = el => { const r = el.getBoundingClientRect(); return {x:(r.left - base.left) / z, y:(r.top - base.top) / z, w:r.width / z, h:r.height / z}; };
  svg.innerHTML = linkMarkup(rect, 'm');
  if (note) note.textContent = S.linkNote;
}

function applyZoom(redrawLinks = true) {
  if (S.view === 'tree') { applyTreeSize(); return; }       // the tree scales through its viewBox: no relayout, no link redraw
  const sheet = $('#sheet'), host = $('#struct');
  sheet.style.transform = `scale(${S.zoom})`;
  sheet.style.width = Math.max(320, host.clientWidth / S.zoom) + 'px';     // wider sheet when zoomed out, so more fits per row
  if (redrawLinks) drawLinks();
}
function fitStructure() {
  const host = $('#struct'), sheet = $('#sheet');
  for (const z of [1, .85, .7, .55, .45]) {
    S.zoom = z; applyZoom(false);
    if (sheet.offsetHeight * z <= host.clientHeight || z === .45) break;
  }
  host.scrollTo?.(0, 0); drawLinks();
}

/* =====================================================================
   TREE GRAPH VIEW: the organisation tree, left to right.
   Same hierarchy and the same folded/open state as the Structure view; drawn as an org chart.
   ===================================================================== */
const TREE = {W:208, H:44, COL:68, ROW:12, PADX:32, PADTOP:62, PADBOT:40};

function buildTree() {
  const vis = visibleSet(), memo = new Map(), recs = [];
  const compact = !!(S.focus || (S.search && S.search.compact)) && vis.size <= COMPACT_MAX;
  const visKids = id => (S.kids[id] || []).filter(k => vis.has(k));
  const cnt = id => { if (memo.has(id)) return memo.get(id); const k = visKids(id); const c = k.length ? k.reduce((a, x) => a + cnt(x), 0) : 1; memo.set(id, c); return c; };
  const mk = r => (recs.push(r), r);
  const cover = (rec, id) => visKids(id).forEach(k => { rec.covers.push(k); cover(rec, k); });   // a folded node stands in for everything under it
  const nodeRec = (id, depth) => {
    const n = S.byId[id], kids = visKids(id);
    const rec = mk({rid:id, kind:'node', id, n, depth, children:[], covers:[id], folded:false, hasKids:kids.length > 0, count:cnt(id)});
    if (!kids.length) return rec;
    if (S.collapsed.has(id) && !compact) { rec.folded = true; cover(rec, id); return rec; }
    const leaves = kids.filter(k => !visKids(k).length), subs = kids.filter(k => visKids(k).length);
    subs.forEach(k => rec.children.push(nodeRec(k, depth + 1)));                   // sub-organisations first, then resources
    const byKind = {}; leaves.forEach(k => (byKind[S.byId[k].kind] ??= []).push(k));
    Object.entries(byKind).sort(([a], [b]) => a.localeCompare(b)).forEach(([kind, list]) => {
      const key = `${id}|${kind}`;
      if (list.length >= GROUP_MIN && !S.openGroups.has(key) && !compact)
        rec.children.push(mk({rid:key, kind:'group', gkey:key, gkind:kind, depth:depth + 1, children:[], covers:list.slice(), count:list.length}));
      else list.forEach(k => rec.children.push(nodeRec(k, depth + 1)));
    });
    return rec;
  };
  const roots = (S.kids[''] || []).filter(id => vis.has(id));
  if (!roots.length) return null;
  let root;
  if (roots.length === 1) root = nodeRec(roots[0], 0);
  else {                                                   // several top-level scopes: hang them under one scan root
    root = mk({rid:'__root__', kind:'virtual', depth:0, children:[], covers:[], count:roots.reduce((a, k) => a + cnt(k), 0)});
    roots.forEach(k => root.children.push(nodeRec(k, 1)));
  }
  return {root, recs, compact};
}

function layoutTree(root) {                                // leaves take rows in order; a parent sits at the middle of its children
  let row = 0, maxDepth = 0;
  (function place(r) {
    maxDepth = Math.max(maxDepth, r.depth);
    if (!r.children.length) r.y = TREE.PADTOP + (row++) * (TREE.H + TREE.ROW);
    else { r.children.forEach(place); r.y = (r.children[0].y + r.children[r.children.length - 1].y) / 2; }
    r.x = TREE.PADX + r.depth * (TREE.W + TREE.COL);
  })(root);
  S.tw = TREE.PADX * 2 + (maxDepth + 1) * TREE.W + maxDepth * TREE.COL;
  S.th = TREE.PADTOP + Math.max(row, 1) * (TREE.H + TREE.ROW) - TREE.ROW + TREE.PADBOT;
}

const trunc = (s, n) => s.length > n ? s.slice(0, n - 1) + '…' : s;

function renderTreeGraph() {
  const svg = $('#tsvg'); S.dom = new Map(); S.trect = new Map(); S.tparent = new Map(); $('#canvas-note').hidden = true;
  const built = buildTree();
  if (!built) {
    svg.innerHTML = ''; S.tw = S.th = 0; applyTreeSize();
    $('#canvas-note').innerHTML = S.search && !S.search.matches.size ? `<p>No resource matches “${esc(S.query)}”.</p>` : '<p>Nothing to show with these filters.<br>Switch a layer back on above.</p>';
    $('#canvas-note').hidden = false; updateBanner(); return;
  }
  const {root, recs, compact} = built; layoutTree(root);
  const worst = ids => ids.flatMap(i => (S.byFinding[i] || []).map(f => f.severity)).sort((a, b) => SEV_RANK[a] - SEV_RANK[b])[0];
  const {W, H} = TREE;
  const levelName = d => {                                 // what this column is: its containers first, then "and resources" if loose ones share it
    if (d === 0 && root.kind === 'virtual') return 'Scan';
    const here = recs.filter(r => r.depth === d), boxes = new Map();
    here.filter(r => r.kind === 'node' && r.hasKids).forEach(r => boxes.set(shortKind(r.n.kind), (boxes.get(shortKind(r.n.kind)) || 0) + 1));
    const loose = here.some(r => r.kind === 'group' || (r.kind === 'node' && !r.hasKids));
    const names = [...boxes].sort((x, y) => y[1] - x[1]).map(x => x[0]);
    if (!names.length) return loose ? 'Resources' : '';
    return (names.length <= 2 ? names.join(' and ') : 'Containers') + (loose ? ' and resources' : '');
  };
  let lines = '', nodes = '', head = '';
  const maxDepth = Math.max(...recs.map(r => r.depth));
  for (let d = 0; d <= maxDepth; d++) head += `<text class="lvl" x="${TREE.PADX + d * (W + TREE.COL)}" y="${TREE.PADTOP - 22}">${esc(levelName(d))}</text>`;
  recs.forEach(r => {
    r.children.forEach(c => {
      const x1 = r.x + W, y1 = r.y + H / 2, x2 = c.x, y2 = c.y + H / 2, xm = x1 + TREE.COL / 2;
      lines += `<path class="tl" data-c="${esc(c.rid)}" d="M${x1} ${y1}H${xm}V${y2}H${x2}"/>`; S.tparent.set(c.rid, r.rid);
    });
    let name, sub, color, cls = 'tn', attrs = `data-rid="${esc(r.rid)}"`, st = null, sevIds = r.covers;
    if (r.kind === 'virtual') { name = `${S.data.meta.provider.toUpperCase()} scan`; sub = plural(r.children.length, 'top-level scope'); color = cssv('--l-scope'); cls += ' virtual'; }
    else if (r.kind === 'group') {
      name = pluralKind(r.gkind, r.count); color = colorOf(r.gkind); cls += ' group'; attrs += ` data-group="${esc(r.gkey)}"`;
      const bad = r.covers.filter(i => itemStatus(S.byId[i])?.level === 'bad').length; sub = bad ? `${bad} need attention, show all` : 'Show all';
      if (bad) cls += ' st-bad';
    } else {
      const n = r.n; st = itemStatus(n); name = n.name; color = colorOf(n.kind); attrs += ` data-go="${esc(r.id)}" data-id="${esc(r.id)}"`;
      sub = r.hasKids ? `${shortKind(n.kind)}, ${plural(r.count, 'resource')}` : shortKind(n.kind) + (st ? `, ${st.text}` : '');
      if (st) cls += ` st-${st.level}`;
    }
    const sev = r.kind === 'virtual' ? null : worst(sevIds);
    const tog = r.kind === 'node' && r.hasKids && !compact
      ? `<g class="tog" data-toggle="${esc(r.id)}" role="button" aria-label="${r.folded ? 'Expand' : 'Collapse'} ${esc(name)}" transform="translate(${W} ${H / 2})"><circle r="9"/><path d="M-4 0H4${r.folded ? 'M0 -4V4' : ''}"/></g>` : '';
    nodes += `<g class="${cls}" ${attrs} role="button" tabindex="0" aria-label="${esc(name + ', ' + sub)}" transform="translate(${r.x} ${r.y})">` +
      `<title>${esc(name)} (${esc(sub)})</title><rect class="tn-box" width="${W}" height="${H}" rx="9"/><rect class="tn-bar" width="5" height="${H}" rx="2.5" fill="${color}"/>` +
      `<text class="tn-name" x="16" y="19">${esc(trunc(name, 24))}</text><text class="tn-kind" x="16" y="35">${esc(trunc(sub, 31))}</text>` +
      (sev ? `<circle class="sev sev-${sev}" cx="${W - 8}" cy="8" r="5"><title>${esc(SEV[sev])}</title></circle>` : '') + tog + `</g>`;
  });
  svg.innerHTML = head + `<g>${lines}</g>` + '<g id="tlinks" class="links-layer" style="pointer-events:none"></g>' + nodes;   // arrows behind boxes: never over text
  const byRid = new Map(); svg.querySelectorAll('.tn').forEach(g => byRid.set(g.getAttribute('data-rid'), g));
  recs.forEach(r => { const g = byRid.get(r.rid); if (!g) return; S.trect.set(g, {x:r.x, y:r.y, w:W, h:H}); r.covers.forEach(id => S.dom.set(id, g)); });
  updateBanner(); applyTreeSize(); applyMarks(); drawLinks();
}

function applyTreeSize() {
  const svg = $('#tsvg'), z = S.zoom || 1;
  svg.setAttribute('viewBox', `0 0 ${S.tw || 1} ${S.th || 1}`);
  svg.setAttribute('width', Math.round((S.tw || 0) * z)); svg.setAttribute('height', Math.round((S.th || 0) * z));
}
function fitTreeToWidth() {                                // on first show: make a wide tree fit, never shrink below legibility
  const host = $('#struct');
  if (host.clientWidth && S.tw > host.clientWidth) { S.zoom = Math.max(.5, +((host.clientWidth - 24) / S.tw).toFixed(2)); applyTreeSize(); }
}
function fitTree() {
  const host = $('#struct');
  S.zoom = Math.max(.35, Math.min(1, +Math.min((host.clientWidth - 24) / S.tw, (host.clientHeight - 24) / S.th).toFixed(2)));
  applyTreeSize(); host.scrollTo?.(0, 0);
}

function exportTreeSvg() {                                 // a self-contained SVG: colours resolved, no page CSS needed
  if (!S.tw) return null;
  const c = n => cssv(n), svg = $('#tsvg');
  const css = `.tl{fill:none;stroke:${c('--ink-2')};stroke-opacity:.38;stroke-width:1.6}.lvl{font:600 11.5px sans-serif;fill:${c('--ink-2')}}` +
    `.tn-box{fill:${c('--panel')};stroke:${c('--line')}}.tn-name{font:600 13px sans-serif;fill:${c('--ink')}}.tn-kind{font:11.5px sans-serif;fill:${c('--ink-2')}}` +
    `.group .tn-box,.virtual .tn-box{stroke-dasharray:4 3}.virtual .tn-box{fill:none}.st-bad .tn-kind{fill:${c('--sev-high')}}.st-warn .tn-kind{fill:${c('--sev-medium')}}` +
    `.tog circle{fill:${c('--panel')};stroke:${c('--ink-2')};stroke-width:1.2}.tog path{stroke:${c('--ink-2')};stroke-width:1.6;stroke-linecap:round;fill:none}` +
    ['high', 'medium', 'low', 'note'].map(k => `.sev-${k}{fill:${c('--sev-' + k)};stroke:${c('--panel')};stroke-width:2}`).join('') + '.links-layer{display:none}';
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${S.tw} ${S.th}" width="${S.tw}" height="${S.th}"><style>${css}</style>` +
    `<rect width="100%" height="100%" fill="${c('--canvas')}"/>${svg.innerHTML}</svg>`;
}

$('#tsvg').addEventListener('keydown', e => {              // keyboard: Enter selects, arrows fold and unfold
  const g = e.target.closest?.('.tn'); if (!g || !['Enter', ' ', 'ArrowRight', 'ArrowLeft'].includes(e.key)) return;
  e.preventDefault();
  const rid = g.getAttribute('data-rid'), goto = g.getAttribute('data-go'), grp = g.getAttribute('data-group');
  const tog = g.querySelector('[data-toggle]'), id = tog?.getAttribute('data-toggle');
  const refocus = () => $('#tsvg').querySelector(`[data-rid="${CSS.escape(rid)}"]`)?.focus?.();
  if (e.key === 'Enter' || e.key === ' ') { if (goto) select(goto, {center:false}); else if (grp) { S.openGroups.add(grp); redraw(); refocus(); } }
  else if (id && e.key === 'ArrowRight' && S.collapsed.has(id)) { S.collapsed.delete(id); redraw(); refocus(); }
  else if (id && e.key === 'ArrowLeft' && !S.collapsed.has(id)) { S.collapsed.add(id); redraw(); refocus(); }
});

/* =====================================================================
   NETWORK GRAPH VIEW (Cytoscape)
   ===================================================================== */
function styleSheet() {
  const ink = cssv('--ink'), ink2 = cssv('--ink-2'), canvas = cssv('--canvas'), accent = cssv('--accent'), warn = cssv('--sev-medium');
  const font = '"Instrument Sans", system-ui, sans-serif';
  return [
    {selector:'node', style:{'background-color':'data(color)', shape:'data(shape)', width:'data(size)', height:'data(size)',
      label:'data(label)', color:ink, 'font-family':font, 'font-size':10, 'text-valign':'bottom', 'text-margin-y':4,
      'text-outline-color':canvas, 'text-outline-width':2, 'min-zoomed-font-size':8, 'border-width':2, 'border-color':canvas}},
    {selector:':parent', style:{'background-opacity':'data(tint)', 'border-width':1, 'border-color':'data(color)', 'border-opacity':.6,
      shape:'round-rectangle', 'text-valign':'top', 'font-size':11, 'font-weight':600, padding:18, 'text-margin-y':-4}},
    {selector:'edge', style:{width:1.2, 'line-color':ink2, 'target-arrow-color':ink2, 'target-arrow-shape':'triangle', 'arrow-scale':.8,
      'curve-style':'bezier', opacity:.5, label:(S.labels || S.autoLabels) ? 'data(label)' : '', 'font-size':8, color:ink2, 'font-family':font,
      'text-rotation':'autorotate', 'text-background-color':canvas, 'text-background-opacity':.85, 'text-background-padding':2}},
    {selector:'.dim', style:{opacity:.12}},
    {selector:'edge.quiet', style:{display:'none'}},
    {selector:'edge.hl', style:{'line-color':accent, 'target-arrow-color':accent, width:2.2, opacity:1, label:'data(label)', display:'element'}},
    {selector:'node.sel', style:{'border-color':accent, 'border-width':4}},
    {selector:'node.hit', style:{'border-color':warn, 'border-width':4}},
    {selector:'node.match', style:{'underlay-color':accent, 'underlay-opacity':.3, 'underlay-padding':8, 'font-weight':600}},
  ];
}

const quietNode = id => layerOf(S.byId[id].kind) === 'iam' || (S.inE[id]?.length || 0) >= 4;   // shared hubs that clutter the graph

function drawGraph() {
  if (S.cy) { S.cy.destroy(); S.cy = null; }
  $('#canvas-note').hidden = true;
  const nodes = S.data.nodes; let ids = new Set();
  if (!S.focus && !S.search && nodes.length > MAX_FULL) {
    $('#canvas-note').innerHTML = `<p>${nodes.length} resources is too many to draw as a graph.<br>Use the Structure view, or pick a resource or finding to see just that part.</p>`;
    $('#canvas-note').hidden = false;
  } else ids = visibleSet();
  updateBanner();
  if (!ids.size) {
    if (S.search) { $('#canvas-note').innerHTML = `<p>No resource matches “${esc(S.query)}”.</p>`; $('#canvas-note').hidden = false; }
    return;
  }

  const els = [];
  ids.forEach(id => {
    const n = S.byId[id], layer = layerOf(n.kind), deg = (S.outE[id]?.length || 0) + (S.inE[id]?.length || 0);
    els.push({data:{id, label:n.name, color:colorOf(n.kind), shape:SHAPES[layer] || 'ellipse',
      size:14 + Math.min(18, deg * 2), tint:Math.min(.16, .05 + depthOf(id) * .03),
      parent:(n.parent && ids.has(n.parent)) ? n.parent : undefined}, classes:S.search?.matches.has(id) ? 'match' : ''});
  });
  S.data.edges.forEach((e, i) => { if (ids.has(e.from) && ids.has(e.to)) {
    const quiet = quietNode(e.from) || quietNode(e.to);
    els.push({data:{id:'e' + i, source:e.from, target:e.to, label:relLabel(e.rel), quiet:quiet ? 1 : 0}, classes:(S.quiet && !S.search && quiet) ? 'quiet' : ''}); } });
  S.autoLabels = !!S.search && els.filter(e => e.data.source).length <= 40;     // few relationships: say what each one is

  S.cy = cytoscape({container:$('#cy'), elements:els, wheelSensitivity:.3, style:styleSheet(),
    layout:{name:'cose', animate:false, randomize:true, nodeDimensionsIncludeLabels:true, nodeRepulsion:() => 12000, idealEdgeLength:() => 100, componentSpacing:80, padding:50}});
  S.cy.on('tap', 'node', e => select(e.target.id(), {tab:true}));
  S.cy.on('tap', e => { if (e.target === S.cy) clearMarks(); });
  if (S.selected && S.showSel) markGraph(S.selected);
}

function markGraph(id) {
  if (!S.cy) return; S.cy.elements().removeClass('dim sel hl hit');
  const el = S.cy.getElementById(id); if (el.empty()) return;
  el.addClass('sel');
  if (!el.isParent()) {
    const nb = el.closedNeighborhood();
    S.cy.nodes().not(nb).not(':parent').addClass('dim'); S.cy.edges().not(nb).addClass('dim');
    el.connectedEdges().addClass('hl');
  }
}

/* ---------- shared: banner, marks, focus, selection ---------- */
function updateBanner() {
  const b = $('#banner');
  if (!S.focus && S.search) {
    const s = S.search, hops = S.searchHops;
    b.innerHTML = !s.matches.size
      ? `<span>No resource matches “${esc(S.query)}”</span><button class="btn" data-act="clearsearch">Clear search</button>`
      : `<span><b>${esc(S.query)}</b>: ${plural(s.matches.size, 'match', 'matches')} and ${plural(s.ids.size - s.matches.size, 'related resource')}${s.truncated ? ` (stopped at ${SEARCH_LIMIT})` : ''}</span>` +
        `<label>Within <select id="hops-search" aria-label="How many steps of relationships to include">${[1, 2, 3].map(h => `<option value="${h}"${hops === h ? ' selected' : ''}>${h}</option>`).join('')}<option value="0"${hops === 0 ? ' selected' : ''}>all</option></select> ${hops === 1 ? 'step' : 'steps'}</label>` +
        `<button class="btn" data-act="clearsearch">Clear search</button>`;
    b.hidden = false; return;
  }
  if (!S.focus) { b.hidden = true; return; }
  b.innerHTML = `<span>Showing ${plural(S.focus.ids.length, 'resource')}: ${esc(S.focus.label)}</span><button class="btn" data-act="unfocus">Show full map</button>`;
  b.hidden = false;
}
function setFocus(label, ids) { S.focus = {label, ids}; redraw(); }

function clearMarks() {
  S.hitSet = null; S.showSel = false;
  if (S.view !== 'graph') { applyMarks(); drawLinks(); } else if (S.cy) S.cy.elements().removeClass('dim sel hl hit');
}

function select(id, {center = false, tab = true} = {}) {
  const n = S.byId[id]; if (!n) return;
  S.selected = id; S.showSel = true; S.hitSet = null;
  if (S.search && !S.focus && !visibleSet().has(id)) toast(`${n.name} is outside the search. Include more steps, or clear the search to see it on the map.`);
  let again = false;                                         // selecting something the current filters hide? undo the filter
  if (S.focus && !S.focus.ids.includes(id)) { S.focus = null; again = true; }
  if (S.hidden.has(layerOf(n.kind))) { S.hidden.delete(layerOf(n.kind)); renderLegend(); again = true; }
  if (S.view !== 'graph') {
    if (reveal(id) || again) redraw(); else { applyMarks(); drawLinks(); }
    if (center) scrollIfHidden(elFor(id));
  } else {
    if (again) drawGraph();
    markGraph(id);
    if (center && S.cy) { const el = S.cy.getElementById(id);
      if (el.nonempty()) S.cy.animate({center:{eles:el}, zoom:Math.max(S.cy.zoom(), 1)}, {duration:REDUCED ? 0 : 200}); }
  }
  renderResource(id);
  if (tab) showTab('resource');
  $$('#tree .item').forEach(e => e.classList.toggle('active', e.dataset.id === id));
  history.replaceState(null, '', hashFor(id));
}

function showFinding(f) {
  if (!f.resources.length) return;
  if (S.search && !S.focus && !f.resources.some(r => S.search.ids.has(r))) { clearSearch(); toast('Search cleared to show this finding.'); }
  if (S.view !== 'graph') {
    if (S.focus && f.resources.some(r => !S.focus.ids.includes(r))) S.focus = null;
    S.hitSet = new Set(f.resources); S.showSel = false;
    let changed = false;
    if (f.resources.length <= 80) f.resources.forEach(r => { if (reveal(r)) changed = true; });
    changed ? redraw() : (applyMarks(), drawLinks());
    scrollIfHidden(f.resources.map(elFor).find(Boolean));
    return;
  }
  const missing = !S.cy || f.resources.some(i => S.cy.getElementById(i).empty());
  if (missing) setFocus(f.title, f.resources.slice(0, 300));
  if (!S.cy) return;
  S.cy.elements().removeClass('dim sel hl hit');
  const set = new Set(f.resources), hits = S.cy.nodes().filter(n => set.has(n.id()));
  hits.addClass('hit');
  S.cy.nodes().not(':parent').not(hits).addClass('dim'); S.cy.edges().addClass('dim');
  S.cy.animate({fit:{eles:hits, padding:90}}, {duration:REDUCED ? 0 : 250});
}

/* ---------- inspector: resource panel ---------- */
function renderResource(id) {
  const n = S.byId[id], box = $('#resource');
  const path = []; for (let p = n.parent; p; p = S.byId[p]?.parent) path.unshift(p);
  const kv = (k, v) => v == null || v === '' ? '' : `<dt>${esc(k)}</dt><dd>${v}</dd>`;
  const props = Object.entries(n.props || {}).map(([k, v]) => kv(relLabel(k), esc(typeof v === 'object' ? JSON.stringify(v) : v))).join('');
  const tags = Object.entries(n.tags || {}).map(([k, v]) => `<span class="tag">${esc(k)}: ${esc(v)}</span>`).join('');
  const rel = (list, dir) => list.length ? list.map(e => { const other = dir === 'out' ? e.to : e.from;
      const bad = e.status && e.status !== 'Resolved';
      return `<button class="rel" data-go="${esc(other)}"><em>${esc(relLabel(e.rel))}</em><b>${esc(S.byId[other].name)}</b>` +
        (bad ? `<span class="badge bad">${esc(e.status)}</span>` : '') + (e.label ? `<small>${esc(e.label)}</small>` : '') + `</button>`; }).join('')
    : '<p class="muted">None found in this scan.</p>';
  let inside = '';
  if (isContainer(id)) {
    const c = {}; const walk = x => (S.kids[x] || []).forEach(k => { if (!isContainer(k)) c[S.byId[k].kind] = (c[S.byId[k].kind] || 0) + 1; walk(k); }); walk(id);
    inside = `<h3>Inside</h3><p>${Object.entries(c).map(([k, v]) => `${v} ${esc(kindLabel(k).toLowerCase())}`).join(', ') || 'Nothing directly.'}</p>`;
  }
  const st = itemStatus(n);
  const itemRows = st ? kv('Status', `<span class="st-${st.level}">${esc(st.text)}</span>`) + kv(n.kind === 'iam.key' ? 'Key material' : 'Value', 'Not collected, by design') : '';
  let contents = '';
  if (n.kind === 'iam.vault') {                            // what is in the vault and what depends on each item: names and status only
    const list = (S.kids[id] || []).map(k => S.byId[k]).filter(x => KV_ITEMS.has(x.kind))
      .sort((a, b) => (itemStatus(a).rank - itemStatus(b).rank) || a.name.localeCompare(b.name));
    contents = `<h3>Contents</h3><p class="muted">Names and status only. Values and key material are never read.</p>` + (list.length ? list.map(x => {
      const s = itemStatus(x), users = (S.inE[x.id] || []).filter(e => ['reads_secret', 'encrypted_with'].includes(e.rel)).map(e => S.byId[e.from].name);
      return `<button class="rel" data-go="${esc(x.id)}"><em class="st-${s.level}">${esc(s.text)}</em><b>${esc(x.name)}</b><small>${esc(shortKind(x.kind))}${users.length ? ', used by ' + esc(users.slice(0, 3).join(', ')) + (users.length > 3 ? ` and ${users.length - 3} more` : '') : ', no known users'}</small></button>`; }).join('')
      : '<p class="muted">Nothing was listed for this vault. The scan may not have been allowed to read it, see the briefing.</p>');
    if (n.props?.other_principals) contents += `<p class="muted">${plural(n.props.other_principals, 'other person or app', 'other people or apps')} outside this scan can also access this vault.</p>`;
  }
  const fs = (S.byFinding[id] || []).map(f => `<button class="rel" data-finding-open="${esc(f.id)}"><em>${esc(SEV[f.severity])}</em><b>${esc(f.title)}</b></button>`).join('');
  box.innerHTML = `
    <div class="res-head"><span class="kind" style="--c:${colorOf(n.kind)}">${esc(kindLabel(n.kind))}</span>
      <h2>${esc(n.name)}</h2>
      <nav class="crumbs" aria-label="Location">${path.map(p => `<button data-go="${esc(p)}">${esc(S.byId[p].name)}</button>`).join('')}</nav></div>
    <h3>Details</h3>
    <dl class="kv">${kv('ID', `<span class="code">${esc(n.id)}</span><button class="mini" data-copy="${esc(n.id)}">Copy</button>`)}${kv('Provider type', esc(n.native_type))}${kv('Region', esc(n.region))}${itemRows}${props}</dl>
    ${tags ? `<h3>Tags</h3>${tags}` : ''}${inside}${contents}
    ${fs ? `<h3>Findings that mention this</h3>${fs}` : ''}
    <h3>Depends on</h3>${rel(S.outE[id] || [], 'out')}
    <h3>${n.kind === 'iam.vault' ? 'Who can access it' : 'Used by'}</h3>${rel(S.inE[id] || [], 'in')}
    <h3>Reach</h3>
    <div class="focus"><label for="hops">Show everything within</label>
      <select id="hops"><option>1</option><option selected>2</option><option>3</option><option>4</option></select><span>steps</span>
      <button class="btn" data-act="focus">Focus map</button></div>`;
}

/* ---------- inspector: briefing ---------- */
function renderBriefing() {
  const I = S.ins, st = I.stats;
  const bar = Object.entries(st.layers).map(([l, c]) => `<i style="flex:${c};background:${cssv('--l-' + l) || cssv('--ink-2')}" title="${esc(LAYER_NAMES[l] || l)} ${c}"></i>`).join('');
  const mix = Object.entries(st.layers).map(([l, c]) => `<div><i class="sw" style="background:${cssv('--l-' + l) || cssv('--ink-2')}"></i>${esc(LAYER_NAMES[l] || l)}<span>${c}</span></div>`).join('');
  const findings = I.findings.length ? I.findings.map(f => `
    <article class="finding sev-${f.severity}">
      <button class="f-head" data-finding="${esc(f.id)}" aria-expanded="false">
        <span class="f-meta">${esc(SEV[f.severity])}</span><br>${esc(f.title)}</button>
      <div class="f-body" hidden>
        <p>${esc(f.why)}</p><p><b>What to do:</b> ${esc(f.advice)}</p>
        ${f.details.length ? `<ul>${f.details.map(d => `<li>${esc(d)}</li>`).join('')}</ul>` : ''}
        ${f.resources.length ? `<div class="chips">${f.resources.slice(0, 8).map(r => `<button class="chip" data-go="${esc(r)}">${esc(S.byId[r]?.name || r)}</button>`).join('')}${f.count > 8 ? `<span class="muted">and ${f.count - 8} more</span>` : ''}</div>
          <button class="link-btn" data-finding-show="${esc(f.id)}">Show ${plural(f.count, 'resource')} on the map</button>` : ''}
      </div></article>`).join('') : '<p class="muted">No findings. Nothing in this scan stood out.</p>';
  const maxDep = Math.max(1, ...I.hubs.map(h => h.dependents));
  const hubs = I.hubs.length ? I.hubs.map(h => `
    <button class="hub" data-go="${esc(h.id)}"><span>${esc(h.name)} <small>${esc(kindLabel(h.kind))}</small></span><small>${h.dependents} depend on it</small>
      <span class="track"><i style="width:${100 * h.dependents / maxDep}%"></i></span></button>`).join('') : '<p class="muted">No resource has more than one dependent.</p>';
  const gaps = S.data.errors.length ? S.data.errors.map(e => `<li><span class="code">${esc(e.scope)}</span> ${esc(e.message)}</li>`).join('') : '';

  $('#briefing').innerHTML = `
    <p class="lede">${esc(I.headline)}</p><p class="verdict">${esc(I.verdict)}</p>
    <div class="mix" role="img" aria-label="Resource mix by layer">${bar}</div><div class="mixlist">${mix}</div>
    <h3>Worth knowing first</h3>${findings}
    <h3>Most depended-on</h3><p class="muted">Changes to these ripple furthest.</p>${hubs}
    <h3>This scan</h3>
    <dl class="facts"><dt>Relationships</dt><dd>${st.relationships}</dd><dt>Regions</dt><dd>${esc(st.regions.join(', ') || 'none')}</dd>
      <dt>Tag coverage</dt><dd>${st.tag_coverage == null ? 'n/a' : st.tag_coverage + '%'}</dd><dt>Unreadable areas</dt><dd>${st.scan_errors}</dd></dl>
    ${gaps ? `<ul class="muted">${gaps}</ul>` : ''}
    ${S.data.warnings.length ? `<h3>Import notes</h3><ul class="muted">${S.data.warnings.slice(0, 5).map(w => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}`;
}

const findingById = id => S.ins.findings.find(f => f.id === id);
function showTab(name) {
  ['briefing', 'resource', 'agent'].forEach(t => { $('#tab-' + t).setAttribute('aria-selected', t === name); $('#' + t).hidden = t !== name; });
}

/* ---------- sharing ---------- */
function download(href, name) { const a = document.createElement('a'); a.href = href; if (name) a.download = name; document.body.appendChild(a); a.click(); a.remove(); }
async function copyText(text, done) {
  try { await navigator.clipboard.writeText(text); toast(done); } catch (e) { window.prompt('Copy this:', text); }
}
function shareAction(kind) {
  closeMenu(); if (!S.id) return;
  const stem = `cloudmap-${S.data.meta.provider}-${S.data.meta.scan_id}`;
  if (kind === 'html' || kind === 'md') { download(`/api/imports/${S.id}/report.${kind}?download=1`); toast('Report downloaded'); }
  else if (kind === 'png') {
    if (S.view === 'tree') {
      const svg = exportTreeSvg(); if (!svg) return toast('There is no tree to export yet.');
      download(URL.createObjectURL(new Blob([svg], {type:'image/svg+xml'})), `${stem}-tree.svg`); return toast('Tree downloaded as SVG');
    }
    if (S.view !== 'graph' || !S.cy) return toast('Switch to the Tree graph or the Network graph to export an image of the map.');
    download(S.cy.png({full:true, scale:2, bg:cssv('--canvas')}), `${stem}.png`); toast('Map image downloaded');
  } else if (kind === 'json') {
    const blob = new Blob([JSON.stringify({meta:S.data.meta, ...S.ins}, null, 2)], {type:'application/json'});
    download(URL.createObjectURL(blob), `${stem}-findings.json`); toast('Findings downloaded');
  } else if (kind === 'link') copyText(location.origin + location.pathname + location.hash, 'Link copied. It opens this view on this server.');
}
function closeMenu() { $('#share-menu').hidden = true; $('#share-btn').setAttribute('aria-expanded', 'false'); }

/* ---------- events ---------- */
const zoomBy = f => {
  if (S.view !== 'graph') { S.zoom = Math.max(.35, Math.min(1.6, +(S.zoom * f).toFixed(2))); applyZoom(); }
  else if (S.cy) S.cy.zoom({level:S.cy.zoom() * f, renderedPosition:{x:S.cy.width() / 2, y:S.cy.height() / 2}});
};

document.addEventListener('click', async e => {
  if (!e.target.closest('.menu-wrap')) closeMenu();
  const t = e.target.closest('[data-go],[data-act],[data-finding],[data-finding-show],[data-finding-open],[data-copy],[data-layer],[data-share],[data-tab],[data-iid],[data-toggle],[data-group],[data-view]');
  if (!t) return;
  const d = t.dataset;
  if (d.go) select(d.go, {center:true});
  else if (d.toggle) { S.collapsed.has(d.toggle) ? S.collapsed.delete(d.toggle) : S.collapsed.add(d.toggle); redraw(); }
  else if (d.group) { S.openGroups.add(d.group); redraw(); }
  else if (d.view) setView(d.view);
  else if (d.tab) showTab(d.tab);
  else if (d.layer) { S.hidden.has(d.layer) ? S.hidden.delete(d.layer) : S.hidden.add(d.layer); renderLegend(); S.focus = null; redraw(); }
  else if (d.finding) {
    const body = t.nextElementSibling, open = body.hidden;
    $$('.f-body').forEach(b => { b.hidden = true; b.previousElementSibling.setAttribute('aria-expanded', 'false'); });
    body.hidden = !open; t.setAttribute('aria-expanded', open);
    if (open) { const f = findingById(d.finding); if (f && f.resources.length) showFinding(f); } else clearMarks();
  }
  else if (d.findingShow) showFinding(findingById(d.findingShow));
  else if (d.findingOpen) { showTab('briefing'); const b = $(`[data-finding="${CSS.escape(d.findingOpen)}"]`); if (b && b.nextElementSibling.hidden) b.click(); b?.scrollIntoView?.({block:'nearest'}); }
  else if (d.copy) copyText(d.copy, 'Copied');
  else if (d.share) shareAction(d.share);
  else if (d.iid) loadImport(d.iid).catch(err => toast(err.message));
  else if (d.act) {
    const a = d.act;
    if (a === 'pick') $('#file').click();
    else if (a === 'demo') { try { const j = await api('/api/demo?provider=' + encodeURIComponent(t.dataset.provider || 'aws'), {method:'POST'}); await loadImport(j.import_id); } catch (err) { toast(err.message); } }
    else if (a === 'focus' && S.selected) {
      try { const j = await api(`/api/imports/${S.id}/blast?node=${encodeURIComponent(S.selected)}&hops=${$('#hops').value}`);
        setFocus(`everything within ${$('#hops').value} steps of ${S.byId[S.selected].name}`, j.nodes); } catch (err) { toast(err.message); }
    }
    else if (a === 'unfocus') { S.focus = null; redraw(); }
    else if (a === 'clearsearch') clearSearch();
    else if (a === 'fit') { S.view === 'tree' ? fitTree() : S.view === 'structure' ? fitStructure() : S.cy?.animate({fit:{padding:50}}, {duration:REDUCED ? 0 : 200}); }
    else if (a === 'zoomin') zoomBy(1.2);
    else if (a === 'zoomout') zoomBy(1 / 1.2);
    else if (a === 'labels') { S.labels = !S.labels; t.setAttribute('aria-pressed', S.labels); S.cy?.style(styleSheet()); }
    else if (a === 'quiet') { S.quiet = !S.quiet; t.setAttribute('aria-pressed', S.quiet); S.cy?.edges('[quiet = 1]').toggleClass('quiet', S.quiet); if (S.view === 'tree') drawLinks(); }
    else if (a === 'links') { if (S.view === 'tree') S.treeLinks = !S.treeLinks; else S.links = !S.links; t.setAttribute('aria-pressed', S.view === 'tree' ? S.treeLinks : S.links); drawLinks(); }
    else if (a === 'expandall') { S.collapsed.clear(); S.data.nodes.forEach(n => { const kinds = {}; (S.kids[n.id] || []).forEach(k => { const kk = S.byId[k]; if (!isContainer(k)) kinds[kk.kind] = 1; });
        Object.keys(kinds).forEach(k => S.openGroups.add(`${n.id}|${k}`)); }); redraw(); }
    else if (a === 'collapseall') { initCollapse(); S.data.nodes.forEach(n => { if (isContainer(n.id) && depthOf(n.id) >= 1) S.collapsed.add(n.id); }); redraw(); }
  }
});

let panMoved = false;
$('#struct').addEventListener('click', e => { if (panMoved) { panMoved = false; return; } if (!e.target.closest('button,[data-go],[data-toggle],[data-group]')) clearMarks(); });
$('#struct').addEventListener('wheel', e => { if (e.ctrlKey || e.metaKey) { e.preventDefault(); zoomBy(e.deltaY < 0 ? 1.1 : 1 / 1.1); } }, {passive:false});
let pan = null;                                                          // drag empty space to pan (mouse only)
$('#struct').addEventListener('pointerdown', e => {
  if (e.pointerType !== 'mouse' || e.button !== 0 || e.target.closest('button,[data-go],[data-toggle],[data-group]')) return;
  pan = {x:e.clientX, y:e.clientY, l:$('#struct').scrollLeft, t:$('#struct').scrollTop}; panMoved = false;
});
window.addEventListener('pointermove', e => { if (!pan) return; const h = $('#struct');
  if (Math.abs(e.clientX - pan.x) + Math.abs(e.clientY - pan.y) > 4) panMoved = true;
  h.scrollLeft = pan.l - (e.clientX - pan.x); h.scrollTop = pan.t - (e.clientY - pan.y); });
window.addEventListener('pointerup', () => { pan = null; });

$('#pick').addEventListener('click', () => $('#file').click());
$('#file').addEventListener('change', e => e.target.files[0] && upload(e.target.files[0]));
$('#share-btn').addEventListener('click', () => {
  const m = $('#share-menu'); m.hidden = !m.hidden; $('#share-btn').setAttribute('aria-expanded', String(!m.hidden));
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeMenu(); clearMarks(); } });
['dragenter', 'dragover'].forEach(t => window.addEventListener(t, e => { e.preventDefault(); $('#drop').classList.add('over'); }));
['dragleave', 'drop'].forEach(t => window.addEventListener(t, e => { e.preventDefault(); $('#drop').classList.remove('over'); }));
window.addEventListener('drop', e => e.dataTransfer.files[0] && upload(e.dataTransfer.files[0]));

$('#theme').addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('cloudmap-theme', next); } catch (e) { /* private mode */ }
  if (S.data) { renderLegend(); renderTree(); renderBriefing(); redraw(); if (S.selected) renderResource(S.selected); }
});

/* ---------- resizable panels: drag, arrow keys, double-click or Enter to hide/show ---------- */
(function panels() {
  const app = $('.app');
  const cfg = {rail:{v:'--rail-w', min:220, max:520, def:300, el:$('#split-rail'), dir:1},
               insp:{v:'--insp-w', min:280, max:700, def:370, el:$('#split-insp'), dir:-1}};
  let saved = {}; try { saved = JSON.parse(localStorage.getItem('cloudmap-panels') || '{}'); } catch (e) { /* ignore */ }
  const save = () => { try { localStorage.setItem('cloudmap-panels', JSON.stringify({rail:cfg.rail.w, insp:cfg.insp.w})); } catch (e) { /* ignore */ } };
  function apply(key, w) {
    const c = cfg[key], off = !(w > 0);
    c.w = off ? 0 : Math.max(c.min, Math.min(c.max, w));
    app.style.setProperty(c.v, c.w + 'px');
    app.toggleAttribute('data-' + key + '-off', off);
    c.el.setAttribute('aria-valuenow', c.w); c.el.setAttribute('aria-valuemin', 0); c.el.setAttribute('aria-valuemax', c.max);
  }
  Object.entries(cfg).forEach(([key, c]) => {
    apply(key, saved[key] !== undefined ? saved[key] : c.def);
    c.el.addEventListener('pointerdown', e => { e.preventDefault(); c.el.setPointerCapture?.(e.pointerId); c.el.classList.add('drag'); document.body.style.userSelect = 'none'; });
    c.el.addEventListener('pointermove', e => {
      if (!c.el.hasPointerCapture?.(e.pointerId)) return;
      const r = app.getBoundingClientRect(), raw = c.dir === 1 ? e.clientX - r.left : r.right - e.clientX;
      apply(key, raw < c.min * 0.6 ? 0 : raw);
    });
    const end = e => { c.el.releasePointerCapture?.(e.pointerId); c.el.classList.remove('drag'); document.body.style.userSelect = ''; save(); };
    c.el.addEventListener('pointerup', end); c.el.addEventListener('pointercancel', end);
    c.el.addEventListener('dblclick', () => { apply(key, c.w === 0 ? c.def : 0); save(); });
    c.el.addEventListener('keydown', e => {
      const step = e.shiftKey ? 60 : 24; let w = c.w;
      if (e.key === 'ArrowRight') w += c.dir * step; else if (e.key === 'ArrowLeft') w -= c.dir * step;
      else if (e.key === 'Enter') w = c.w === 0 ? c.def : 0; else if (e.key === 'Home') w = c.def; else return;
      e.preventDefault(); apply(key, w); save();
    });
  });
  if ('ResizeObserver' in window) new ResizeObserver(() => { if (S.cy) S.cy.resize(); if (S.view === 'structure' && S.data) applyZoom(); }).observe($('#stage'));
})();

/* ---------- start: open a shared link, or list what this server already holds ---------- */
(async function start() {
  $$('.viewsw [data-view]').forEach(b => b.setAttribute('aria-pressed', b.dataset.view === S.view));
  $('#stage').dataset.mode = S.view;
  const h = new URLSearchParams(location.hash.slice(1));
  try {
    const list = await api('/api/imports');
    if (h.get('import') && list.some(i => i.import_id === h.get('import'))) return loadImport(h.get('import'), h.get('node'), h.get('q'), h.has('hops') ? +h.get('hops') : undefined);
    if (list.length) $('#recent').innerHTML = '<h3>Already open on this server</h3>' + list.map(i =>
      `<button class="hit-row" data-iid="${esc(i.import_id)}">${esc(i.filename)}<small>${plural(i.summary.nodes, 'resource')}</small></button>`).join('');
  } catch (e) { /* server unreachable: leave the empty state */ }
})();
