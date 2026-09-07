const fs = require('fs'), vm = require('vm'), assert = require('assert');
const source = fs.readFileSync('static/app.js', 'utf8').split('// DASHBOARD INITIALIZATION')[0];
function boot(saved, blocked = false) {
  const styles = {}, controls = {}, events = {}, windowEvents = {};
  let stored = saved;
  const system = {matches: true, addEventListener(_, fn) { this.change = fn; }};
  const root = {style: {setProperty(k,v) { styles[k] = v; }}, dataset: {}};
  for (const id of ['theme-mode','theme-palette','theme-status']) controls[id] = {append(){},addEventListener(_, fn){this.change=fn;}};
  const context = vm.createContext({window:{matchMedia:()=>system,addEventListener(k,fn){windowEvents[k]=fn;}},document:{documentElement:root,getElementById:id=>controls[id],createElement:()=>({}),addEventListener(k,fn){events[k]=fn;}},localStorage:{getItem(){if(blocked) throw Error();return stored;},setItem(_,v){if(blocked) throw Error();stored=v;}}});
  vm.runInContext(source,context); events.DOMContentLoaded();
  return {styles,root,system,controls,windowEvents,get stored(){return stored;},set stored(v){stored=v;}};
}
const env = boot('bad json');
assert.equal(env.root.dataset.theme,'dark'); assert.equal(env.controls['theme-mode'].value,'system');
const choose = (id,value)=>env.controls[id].change({target:{value}});
function luminance(hex){const rgb=hex.slice(1).match(/../g).slice(0,3).map(v=>parseInt(v,16)/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4);return rgb[0]*.2126+rgb[1]*.7152+rgb[2]*.0722;}
function contrast(a,b){const x=luminance(a),y=luminance(b);return (Math.max(x,y)+.05)/(Math.min(x,y)+.05);}
for(const mode of ['dark','light']) for(const palette of ['emerald','ocean','violet','amber']) {
 choose('theme-mode',mode);choose('theme-palette',palette);
 assert.equal(env.root.dataset.theme,mode);assert.equal(env.root.dataset.palette,palette);
 for(const value of Object.values(env.styles)) assert.match(value,/^#[0-9A-F]{6}([0-9A-F]{2})?$/);
 for(const [fg,bg] of [['text','panel'],['muted','panel'],['muted','control'],['accent','active'],['accent','bg'],...['critical','high','medium','low','unknown'].map(s=>[s,s+'-bg'])]) assert.ok(contrast(env.styles['--'+fg],env.styles['--'+bg])>=4.5,`${mode}/${palette}: ${fg}/${bg}`);
}
choose('theme-mode','light');env.system.matches=true;env.system.change();assert.equal(env.root.dataset.theme,'light');
choose('theme-mode','system');assert.equal(env.root.dataset.theme,'dark');env.system.matches=false;env.system.change();assert.equal(env.root.dataset.theme,'light');
assert.equal(boot(env.stored).root.dataset.palette,'amber');
env.stored='{"mode":"dark","palette":"ocean"}';env.windowEvents.storage({key:'panopticon.theme.v1'});assert.equal(env.root.dataset.palette,'ocean');
env.stored=null;env.windowEvents.storage({key:null});assert.equal(env.controls['theme-mode'].value,'system');
assert.equal(boot('{"mode":"bad","palette":"__proto__"}').root.dataset.palette,'emerald');
const locked=boot(null,true);locked.controls['theme-mode'].change({target:{value:'light'}});assert.equal(locked.root.dataset.theme,'light');
const html=fs.readFileSync('static/index.html','utf8');assert.ok(!/#[0-9a-f]{6}/i.test(html));assert.ok(html.indexOf('/app.js')<html.indexOf('<body>'));
console.log('PASS: 8 palette/mode combinations, contrast, system changes, persistence, cross-tab sync, invalid/blocked storage, centralized tokens');
