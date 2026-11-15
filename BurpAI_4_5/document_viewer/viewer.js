/* BurpAI offline document viewer. User content is data, never executable code. */
(() => {
  'use strict';
  const doc = JSON.parse(document.getElementById('document-data').textContent);
  const $ = id => document.getElementById(id);
  const isMap = doc.kind === 'mind_map';
  const setText = (id, text) => { $(id).textContent = text; };
  let toastTimer;
  function toast(text) {
    setText('toast', text); $('toast').classList.add('visible');
    clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').classList.remove('visible'), 2600);
  }
  function download(content, filename, type) {
    const url = URL.createObjectURL(new Blob([content], {type}));
    const link = document.createElement('a'); link.href = url; link.download = filename;
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const filename = doc.title.replace(/[<>:"/\\|?*\x00-\x1f]/g, '-').slice(0, 100) || 'note';
  setText('title', doc.title);
  setText('metadata', new Date(doc.updated * 1000).toLocaleDateString(undefined, {year:'numeric', month:'long', day:'numeric'}) +
    '  ·  ' + (isMap ? doc.node_count + ' connected ideas' : Math.max(1, Math.ceil(doc.markdown.split(/\s+/).length / 220)) + ' min read'));
  setText('revision', 'REVISION ' + String(doc.revision).padStart(2, '0'));
  doc.tags.forEach(tag => { const node = document.createElement('span'); node.className = 'tag'; node.textContent = tag; $('tags').appendChild(node); });
  $('download').onclick = () => download(doc.markdown, filename + '.md', 'text/markdown;charset=utf-8');
  $('copy').onclick = async () => {
    try { await navigator.clipboard.writeText(doc.markdown); toast('Markdown copied'); }
    catch (_) {
      const field = document.createElement('textarea'); field.value = doc.markdown;
      document.body.appendChild(field); field.select();
      const copied = document.execCommand('copy'); field.remove();
      toast(copied ? 'Markdown copied' : 'Use Download .md to save the original');
    }
  };
  $('print').onclick = () => window.print();
  function theme(name) { document.documentElement.dataset.theme = name; setText('theme', name === 'dark' ? 'Light theme' : 'Dark theme'); }
  try { theme(localStorage.getItem('burpai-notes-theme') || 'light'); } catch (_) { theme('light'); }
  $('theme').onclick = () => {
    const name = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; theme(name);
    try { localStorage.setItem('burpai-notes-theme', name); } catch (_) { /* file viewers may disallow storage */ }
  };

  const reader = $('reader');
  reader.innerHTML = DOMPurify.sanitize(marked.parse(doc.markdown, {gfm: true, breaks: false}), {
    ALLOWED_TAGS: ['h1','h2','h3','h4','h5','h6','p','a','strong','em','b','i','del','s','ul','ol','li','blockquote','pre','code','br','hr','table','thead','tbody','tr','th','td','input'],
    ALLOWED_ATTR: ['href','title','class','type','checked','disabled','start','align'],
    ALLOW_DATA_ATTR: false, ALLOW_ARIA_ATTR: false
  });
  reader.querySelectorAll('a').forEach(link => {
    const href = (link.getAttribute('href') || '').trim();
    if (/^https?:\/\//i.test(href) || /^mailto:/i.test(href)) {
      link.target = '_blank'; link.rel = 'noopener noreferrer';
    } else if (!href.startsWith('#')) { link.removeAttribute('href'); }
  });
  reader.querySelectorAll('input').forEach(input => { input.type = 'checkbox'; input.disabled = true; });
  reader.querySelectorAll('pre code').forEach(code => {
    const match = (code.className || '').match(/language-([a-z0-9_+-]+)/i);
    if (match) code.parentElement.dataset.language = match[1];
  });
  const first = reader.firstElementChild;
  if (first && first.tagName === 'H1' && first.textContent.trim().toLowerCase() === doc.title.toLowerCase()) first.remove();
  let usedIds = new Set();
  reader.querySelectorAll('h1,h2,h3').forEach((heading, index) => {
    const base = heading.textContent.toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, '').trim().replace(/\s+/g, '-') || 'section';
    let id = base, suffix = 1; while (usedIds.has(id)) id = base + '-' + suffix++;
    usedIds.add(id); heading.id = id;
    const link = document.createElement('a'); link.href = '#' + id; link.textContent = heading.textContent;
    if (heading.tagName === 'H3') link.className = 'sub'; $('outline').appendChild(link);
  });
  if (!$('outline').children.length) {
    const line = document.createElement('span'); line.textContent = isMap ? 'Select a branch to explore.' : 'A note, ready to revisit.';
    line.style.cssText = 'font-size:12px;color:var(--muted)'; $('outline').appendChild(line);
  }
  if (!isMap) return;

  document.body.classList.add('is-map');
  setText('eyebrow', 'IDEAS, CONNECTED'); setText('kind-badge', 'VISUAL MIND MAP');
  $('map-controls').hidden = false; $('map-panel').hidden = false; reader.hidden = true;
  const svg = $('map'), NS = 'http://www.w3.org/2000/svg';
  const colors = ['#82d5b5','#aab9ff','#f3bf83','#e5a4cb','#8fcce8','#d5cc8c'];
  const context = document.createElement('canvas').getContext('2d');
  const collapsed = new Set();
  let nodes = [], edges = [], fullBox, box, dragged = false;
  function make(tag, attrs, parent, text) {
    const node = document.createElementNS(NS, tag);
    Object.entries(attrs || {}).forEach(([key, value]) => node.setAttribute(key, value));
    if (text !== undefined) node.textContent = text;
    if (parent) parent.appendChild(node); return node;
  }
  function wrap(label, width, root) {
    context.font = (root ? '600 14px' : '500 13px') + ' "Segoe UI",sans-serif';
    const result = []; let line = '';
    // Break long tokens too, so a URL or a long Unicode label cannot overflow a card.
    for (const token of label.split(/\s+/)) {
      if (line && context.measureText(line + ' ' + token).width <= width) { line += ' ' + token; continue; }
      if (line) { result.push(line); line = ''; }
      for (const char of token) {
        if (line && context.measureText(line + char).width > width) { result.push(line); line = ''; }
        line += char;
      }
    }
    if (line) result.push(line); return result;
  }
  function prepare(raw, id, color, root = false) {
    const node = {raw, id, color, width: root ? 220 : 194, root};
    node.lines = wrap(raw.label, node.width - 36, root);
    node.height = Math.max(root ? 76 : 54, node.lines.length * 19 + 28);
    node.children = collapsed.has(id) ? [] : raw.children.map((child, i) => prepare(child, id + '.' + i, color));
    node.span = Math.max(node.height, node.children.reduce((sum, child) => sum + child.span, 0) + Math.max(0, node.children.length - 1) * 20);
    return node;
  }
  function place(node, x, center, side, parent) {
    node.x = x; node.y = center - node.height / 2; nodes.push(node);
    if (parent) edges.push({from: parent, to: node, side});
    let y = center - node.span / 2;
    node.children.forEach(child => {
      place(child, side > 0 ? x + node.width + 60 : x - child.width - 60, y + child.span / 2, side, node);
      y += child.span + 20;
    });
  }
  function viewBox(value) { box = value; svg.setAttribute('viewBox', [box.x,box.y,box.w,box.h].join(' ')); }
  function fit() {
    if (!fullBox || !svg.clientWidth || !svg.clientHeight) return;
    const ratio = svg.clientWidth / svg.clientHeight;
    let w = fullBox.w + 90, h = fullBox.h + 90;
    if (w / h < ratio) w = h * ratio; else h = w / ratio;
    viewBox({x: fullBox.x + fullBox.w / 2 - w / 2, y: fullBox.y + fullBox.h / 2 - h / 2, w, h});
  }
  function draw(reset = false) {
    svg.replaceChildren(); nodes = []; edges = [];
    const root = prepare({label: doc.tree.label, children: []}, '0', '#82d5b5', true);
    place(root, -root.width / 2, 0, 1, null);
    const branches = doc.tree.children.map((child, i) => prepare(child, '0.' + i, colors[i % colors.length]));
    [-1,1].forEach(side => {
      const selected = branches.filter((_, i) => (i % 2 ? -1 : 1) === side);
      const span = selected.reduce((sum, child) => sum + child.span, 0) + Math.max(0, selected.length - 1) * 34;
      let y = -span / 2;
      selected.forEach(child => {
        place(child, side > 0 ? root.width / 2 + 80 : -root.width / 2 - child.width - 80, y + child.span / 2, side, root);
        y += child.span + 34;
      });
    });
    edges.forEach(({from,to,side}) => {
      const x1 = from.x + (side > 0 ? from.width : 0), y1 = from.y + from.height / 2;
      const x2 = to.x + (side > 0 ? 0 : to.width), y2 = to.y + to.height / 2;
      const bend = (x1 + x2) / 2;
      make('path', {d:`M${x1} ${y1} C${bend} ${y1},${bend} ${y2},${x2} ${y2}`,stroke:to.color,'stroke-width':2,fill:'none',opacity:.6},svg);
    });
    nodes.forEach(node => {
      const attrs = {'data-node-id':node.id};
      if (node.raw.children.length) Object.assign(attrs, {role:'button', tabindex:0, 'aria-label': node.raw.label, 'aria-expanded': String(!collapsed.has(node.id))});
      const group = make('g', attrs, svg);
      make('title', {}, group, node.raw.label + (node.raw.children.length ? ' — click to fold or unfold' : ''));
      make('rect', {x:node.x,y:node.y,width:node.width,height:node.height,rx:11,fill:node.root?'#254f47':'#1c2c3d',stroke:node.color,'stroke-width':node.root?1.8:1,'stroke-opacity':node.root?1:.48},group);
      if (!node.root) make('rect',{x:node.x,y:node.y+13,width:3,height:node.height-26,rx:1.5,fill:node.color},group);
      const label = make('text', {x:node.x+18,y:node.y+(node.height-node.lines.length*19)/2+14,fill:node.root?'#ddfff0':'#e2eaf1','font-family':'Segoe UI, sans-serif','font-size':node.root?14:13,'font-weight':node.root?600:500},group);
      node.lines.forEach((line,i) => make('tspan',{x:node.x+18,dy:i?19:0},label,line));
      if (node.raw.children.length) {
        make('circle',{cx:node.x+node.width-1,cy:node.y+node.height/2,r:9,fill:'#172a3a',stroke:node.color,'stroke-width':1},group);
        make('text',{x:node.x+node.width-1,y:node.y+node.height/2+4,'text-anchor':'middle',fill:node.color,'font-family':'Segoe UI, sans-serif','font-size':13},group,collapsed.has(node.id)?'+':'−');
        const toggle = () => { if (collapsed.has(node.id)) collapsed.delete(node.id); else collapsed.add(node.id); draw(); };
        group.onclick = () => { if (!dragged) toggle(); };
        group.onkeydown = event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggle(); } };
      }
    });
    const left = Math.min(...nodes.map(node=>node.x)), top = Math.min(...nodes.map(node=>node.y));
    fullBox = {x:left,y:top,w:Math.max(...nodes.map(node=>node.x+node.width))-left,h:Math.max(...nodes.map(node=>node.y+node.height))-top};
    setText('map-count', nodes.length + ' / ' + doc.node_count + ' IDEAS');
    if (reset || !box) fit(); else viewBox(box);
  }
  function zoom(factor, screenX = .5, screenY = .5) {
    if (!box) return;
    const w = Math.max(180,Math.min(30000,box.w*factor)), h = box.h * w / box.w;
    viewBox({x:box.x+(box.w-w)*screenX,y:box.y+(box.h-h)*screenY,w,h});
  }
  $('zoom-in').onclick = () => zoom(.8); $('zoom-out').onclick = () => zoom(1.25); $('fit').onclick = fit;
  svg.addEventListener('wheel', event => { event.preventDefault(); const rect = svg.getBoundingClientRect(); zoom(event.deltaY>0?1.12:.89,(event.clientX-rect.left)/rect.width,(event.clientY-rect.top)/rect.height); }, {passive:false});
  let drag;
  svg.addEventListener('pointerdown', event => {
    if (event.button !== 0) return;
    drag={x:event.clientX,y:event.clientY,box:{...box}}; dragged=false;
  });
  svg.addEventListener('pointermove', event => {
    if (!drag) return;
    const dx=event.clientX-drag.x,dy=event.clientY-drag.y;
    if (!dragged && Math.abs(dx)+Math.abs(dy)>5) { dragged=true; svg.setPointerCapture(event.pointerId); }
    if (dragged) viewBox({...drag.box,x:drag.box.x-dx*drag.box.w/svg.clientWidth,y:drag.box.y-dy*drag.box.h/svg.clientHeight});
  });
  const endDrag = () => { drag=null; setTimeout(()=>{dragged=false;},0); };
  svg.addEventListener('pointerup',endDrag); svg.addEventListener('pointercancel',endDrag);
  $('expand').onclick = () => {collapsed.clear();draw(true);};
  $('collapse').onclick = () => {doc.tree.children.forEach((_,i)=>collapsed.add('0.'+i));draw(true);};
  $('view-map').onclick = () => {reader.hidden=true;$('map-panel').hidden=false;$('view-map').classList.add('active');$('view-outline').classList.remove('active');fit();};
  $('view-outline').onclick = () => {reader.hidden=false;$('map-panel').hidden=true;$('view-outline').classList.add('active');$('view-map').classList.remove('active');};
  $('export-svg').onclick = () => {
    const clone=svg.cloneNode(true), b={x:fullBox.x-30,y:fullBox.y-30,w:fullBox.w+60,h:fullBox.h+60};
    clone.setAttribute('viewBox',[b.x,b.y,b.w,b.h].join(' ')); clone.setAttribute('width',b.w);clone.setAttribute('height',b.h);
    clone.removeAttribute('id');clone.removeAttribute('style');
    const background=make('rect',{x:b.x,y:b.y,width:b.w,height:b.h,fill:'#111e2d'});
    clone.insertBefore(background,clone.firstChild);
    download(new XMLSerializer().serializeToString(clone),filename+'.svg','image/svg+xml;charset=utf-8');
  };
  $('outline').replaceChildren();
  doc.tree.children.forEach((branch,i) => {
    const link=document.createElement('a');link.href='#map-panel';link.textContent=branch.label;
    link.onclick=()=>{$('view-map').click();collapsed.delete('0.'+i);draw(true);};$('outline').appendChild(link);
  });
  window.addEventListener('resize',fit);
  window.addEventListener('beforeprint',fit);window.addEventListener('afterprint',fit);
  draw(true);
})();
