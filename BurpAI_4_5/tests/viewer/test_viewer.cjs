/* Local DOM tests: no browser, network access, user files or remote resources. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM, VirtualConsole} = require('jsdom');
const assets = path.resolve(__dirname, '../../document_viewer');
const source = name => fs.readFileSync(path.join(assets, name), 'utf8');
function viewer(data) {
  data = {id:'doc-0000000000000001',title:'A note',kind:'note',tags:['example'],created:1,updated:1,revision:1,...data};
  const replacements = {'TITLE':'Preview','POLICY':"default-src 'none'",'CSS':source('viewer.css'),
    'DATA':JSON.stringify(data).replace(/</g,'\\u003c'),'VENDOR':'','SCRIPT':''};
  const html=source('viewer.html').replace(/@@(TITLE|POLICY|CSS|DATA|VENDOR|SCRIPT)@@/g,(_,key)=>replacements[key]);
  const errors=[];
  const virtualConsole=new VirtualConsole();virtualConsole.on('jsdomError',error=>errors.push(error));
  // Leave resources disabled (the jsdom default). Evaluate only our local code.
  const dom=new JSDOM(html,{runScripts:'outside-only',virtualConsole});
  const w=dom.window, d=w.document, downloads=[], blobs=[];
  w.fetch=()=>{throw new Error('Unexpected fetch');};
  w.XMLHttpRequest=function(){throw new Error('Unexpected network request');};
  w.WebSocket=function(){throw new Error('Unexpected websocket');};
  w.HTMLCanvasElement.prototype.getContext=()=>({font:'',measureText:text=>({width:Array.from(text).length*7})});
  const svg=d.getElementById('map');
  Object.defineProperties(svg,{clientWidth:{value:1000},clientHeight:{value:550}});
  svg.setPointerCapture=()=>{};
  svg.getBoundingClientRect=()=>({x:0,y:0,left:0,top:0,width:1000,height:550});
  w.URL.createObjectURL=blob=>{blobs.push(blob);return 'blob:document-'+blobs.length;};
  w.URL.revokeObjectURL=()=>{};
  w.HTMLAnchorElement.prototype.click=function(){downloads.push({filename:this.download,href:this.href});};
  let printed=0, copied='';
  w.print=()=>{printed++;};
  Object.defineProperty(w.navigator,'clipboard',{value:{writeText:async text=>{copied=text;}}});
  w.eval(source('vendor.js'));
  w.eval(source('viewer.js'));
  return {dom,w,d,data,errors,downloads,blobs,click:id=>d.getElementById(id).click(),
    printed:()=>printed,copied:()=>copied};
}
function blobText(w,blob){return new Promise((resolve,reject)=>{const reader=new w.FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=reject;reader.readAsText(blob);});}
async function main(){
  const note=viewer({markdown:'# A note\n\n## Summary\nA **clear** answer.\n\n## Summary-2\n\n## Summary\n\n- [x] Done\n- [ ] Next\n\n| Topic | Status |\n| --- | --- |\n| Plan | Ready |\n\n```js\nconst ready = true;\n```\n'});
  assert.equal(note.d.querySelectorAll('#reader h1').length,0);
  assert.equal(note.d.querySelector('#reader strong').textContent,'clear');
  assert.equal(note.d.querySelectorAll('#reader table').length,1);
  assert.equal(note.d.querySelectorAll('#reader input[type=checkbox]:disabled').length,2);
  assert.equal(note.d.querySelector('#reader pre').dataset.language,'js');
  assert.equal(note.d.querySelectorAll('#outline a').length,3);
  const ids=[...note.d.querySelectorAll('#reader h2')].map(h=>h.id);
  assert.equal(new Set(ids).size,3);
  note.click('theme');assert.equal(note.d.documentElement.dataset.theme,'dark');
  note.click('copy');await Promise.resolve();assert.equal(note.copied(),note.data.markdown);
  note.click('download');assert.equal(note.downloads[0].filename,'A note.md');
  assert.equal(await blobText(note.w,note.blobs[0]),note.data.markdown);
  note.click('print');assert.equal(note.printed(),1);
  assert.deepEqual(note.errors,[]);note.dom.window.close();

  const unsafe=viewer({title:'<script>bad</script>',markdown:'# Security sample\n\n</script><script>window.pwned=true</script><img src="https://example.test/pixel" onerror="window.pwned=true"><iframe src="https://example.test"></iframe><svg onload="window.pwned=true"></svg>\n\n[run](javascript:alert(1)) [local](file:///C:/secret) [web](https://example.test)\n\n<input type="text" onfocus="window.pwned=true">'});
  assert.equal(unsafe.w.pwned,undefined);
  assert.equal(unsafe.d.querySelectorAll('#reader script,#reader img,#reader svg,#reader iframe,#reader [onerror],#reader [onfocus]').length,0);
  assert.equal(unsafe.d.getElementById('title').textContent,'<script>bad</script>');
  const links=[...unsafe.d.querySelectorAll('#reader a')];
  assert.equal(links[0].getAttribute('href'),null);assert.equal(links[1].getAttribute('href'),null);
  assert.equal(links[2].rel,'noopener noreferrer');assert.equal(links[2].target,'_blank');
  assert.deepEqual(unsafe.errors,[]);unsafe.dom.window.close();

  const tree={label:'A project',children:[
    {label:'Research',children:[{label:'Questions',children:[]},{label:'Sources',children:[]}]},
    {label:'Delivery',children:[{label:'Review',children:[]}]}
  ]};
  const map=viewer({title:'A project',kind:'mind_map',markdown:'- Research\n  - Questions\n  - Sources\n- Delivery\n  - Review',tree,node_count:6});
  const count=()=>map.d.querySelectorAll('#map g[data-node-id]').length;
  const box=()=>map.d.getElementById('map').getAttribute('viewBox').split(' ').map(Number);
  assert.equal(count(),6);assert.equal(map.d.getElementById('reader').hidden,true);
  const originalBox=box();map.click('zoom-in');assert.ok(box()[2]<originalBox[2]);map.click('fit');assert.deepEqual(box(),originalBox);
  map.d.querySelector('[data-node-id="0.0"]').dispatchEvent(new map.w.MouseEvent('click',{bubbles:true}));
  assert.equal(count(),4);assert.equal(map.d.querySelector('[data-node-id="0.0"]').getAttribute('aria-expanded'),'false');
  map.d.querySelector('[data-node-id="0.0"]').dispatchEvent(new map.w.KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
  assert.equal(count(),6);
  map.click('collapse');assert.equal(count(),3);map.click('expand');assert.equal(count(),6);
  map.click('view-outline');assert.equal(map.d.getElementById('reader').hidden,false);assert.equal(map.d.getElementById('map-panel').hidden,true);
  map.click('view-map');assert.equal(map.d.getElementById('map-panel').hidden,false);
  // Cards must not overlap even where one branch is deeper than another.
  const cards=[...map.d.querySelectorAll('#map g>rect:first-of-type')].map(el=>Object.fromEntries(['x','y','width','height'].map(key=>[key,Number(el.getAttribute(key))])));
  for(let i=0;i<cards.length;i++) for(let j=i+1;j<cards.length;j++){
    const a=cards[i],b=cards[j];assert.ok(a.x+a.width<=b.x||b.x+b.width<=a.x||a.y+a.height<=b.y||b.y+b.height<=a.y,'overlapping nodes');
  }
  map.click('export-svg');assert.equal(map.downloads[0].filename,'A project.svg');
  const exported=await blobText(map.w,map.blobs[0]);
  const xml=new map.w.DOMParser().parseFromString(exported,'image/svg+xml');
  assert.equal(xml.querySelector('parsererror'),null);assert.equal(xml.querySelectorAll('g[data-node-id]').length,6);
  assert.equal(xml.querySelectorAll('script,foreignObject').length,0);
  assert.deepEqual(map.errors,[]);map.dom.window.close();
  console.log('PASS: Markdown formatting, outline anchors, themes, copy/download, print, sanitization, map layout, folding, keyboard controls, zoom, and SVG export.');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
