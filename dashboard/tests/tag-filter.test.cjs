const assert=require('node:assert/strict');
const fs=require('node:fs');
const test=require('node:test');
const vm=require('node:vm');
const F=require('../filters.js');
const L=require('../locations.js');

function environment(respond) {
  const elements=new Map(),requests=[],timers=new Map();let timer=0;
  const element=selector=>{if(!elements.has(selector))elements.set(selector,{innerHTML:'',textContent:'',focus(){}});return elements.get(selector);};
  const context={state:{filters:F.empty(),authType:'session',role:'read_only',user:{id:'reader-one'},token:''},F,L,JSON,Array,Number,Object,Set,String,encodeURIComponent,
    h:value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char])),
    format:String,icon:()=>'', $:element,
    workspaceCSVIdentity(){return JSON.stringify([context.state.authType,context.state.role,context.state.user?.id,context.state.user?.tenant_id,context.state.token]);},
    showModal(title,html){context.tagFilterModalChanged(html);context.modal={title,html};element('#modal').open=true;element('#modal-content').innerHTML=html;},
    closeModal(){context.tagFilterClose();element('#modal').open=false;element('#modal-content').innerHTML='';context.closed=(context.closed || 0)+1;},
    render(){context.renders=(context.renders || 0)+1;},
    setTimeout(callback){timers.set(++timer,callback);return timer;},clearTimeout(id){timers.delete(id);},
    api:async path=>{requests.push(path);return respond(path,requests.length);}};
  vm.createContext(context);vm.runInContext(fs.readFileSync(require.resolve('../tag-filter-page.js'),'utf8'),context);
  return {context,requests,element,run:code=>vm.runInContext(code,context),async flush(){for(const callback of [...timers.values()])callback();timers.clear();await new Promise(setImmediate);},
    action:(action,extra={})=>context.tagFilterAction({dataset:{action,...extra},...('checked'in extra?{checked:extra.checked}:{})})};
}
function page(items,offset=0,total=items.length) {return {items,offset,total,limit:200,has_more:offset+200<total};}

test('saved tags are searchable selectable values and preserve unrelated scope when applied',async()=>{
  const env=environment(()=>page([{id:'one',key:'owner',value:'finance, payments=team'},{id:'two',key:'application',value:'billing'}]));
  env.context.state.filters.ports=['443/tcp'];env.context.state.filters.locations=['location-one'];
  await env.action('tag-filter-open');
  assert.equal(env.requests[0],'/tags?limit=200&offset=0&q=');
  assert.match(env.context.modal.html,/Find a saved tag/);
  assert.match(env.element('#tag-filter-results').innerHTML,/finance, payments=team/);
  await env.action('tag-filter-select',{key:'owner',value:'finance, payments=team',checked:true});
  await env.action('tag-filter-select',{key:'application',value:'billing',checked:true});
  assert.deepEqual(env.context.state.filters.custom,{});
  await env.action('tag-filter-apply');
  assert.deepEqual(JSON.parse(JSON.stringify(env.context.state.filters.custom)),{owner:['finance, payments=team']});
  assert.deepEqual([...env.context.state.filters.application],['billing']);
  assert.deepEqual(env.context.state.filters.ports,['443/tcp']);
  assert.deepEqual(env.context.state.filters.locations,['location-one']);
  assert.equal(env.context.closed,1);assert.equal(env.context.renders,1);
  assert.match(env.context.savedTagFilterHTML(),/Choose saved tag filters/);
});

test('tag selections survive search and pagination without depending on cached catalogue pages',async()=>{
  const env=environment(path=>path.includes('offset=200')?page([{id:'late',key:'region',value:'north'}],200,201):
    path.includes('q=bill')?page([{id:'billing',key:'application',value:'billing'}]):
    page([{id:'owner',key:'owner',value:'finance'}],0,201));
  await env.action('tag-filter-open');
  await env.action('tag-filter-select',{key:'owner',value:'finance',checked:true});
  await env.action('tag-filter-page',{offset:'200'});
  await env.action('tag-filter-select',{key:'region',value:'north',checked:true});
  assert.equal(env.context.tagFilterInput({target:{id:'tag-filter-search',value:'bill'}}),true);await env.flush();
  assert.match(env.requests.at(-1),/offset=0&q=bill$/);
  await env.action('tag-filter-select',{key:'application',value:'billing',checked:true});
  await env.action('tag-filter-apply');
  assert.deepEqual(JSON.parse(JSON.stringify(env.context.state.filters.custom)),{owner:['finance'],region:['north']});
  assert.deepEqual([...env.context.state.filters.application],['billing']);
});

test('a stale tag search cannot overwrite newer results or reappear after cancelling',async()=>{
  let resolveOld;
  const old=new Promise(resolve=>{resolveOld=resolve;});
  const env=environment(path=>path.includes('q=new')?page([{id:'new',key:'owner',value:'new'}]):old);
  const opening=env.action('tag-filter-open');
  env.context.tagFilterInput({target:{id:'tag-filter-search',value:'new'}});await env.flush();
  assert.match(env.element('#tag-filter-results').innerHTML,/data-value="new"/);
  resolveOld(page([{id:'old',key:'owner',value:'old'}]));await opening;
  assert.doesNotMatch(env.element('#tag-filter-results').innerHTML,/data-value="old"/);
  await env.action('tag-filter-cancel');
  assert.equal(env.run('tagFilterPicker'),null);
  assert.equal(env.context.renders,undefined);
});

test('failed catalogue loads show retry and never drop existing selected filters',async()=>{
  let fail=true;
  const env=environment(()=>{if(fail)throw new Error('Catalogue unavailable');return page([{id:'tag',key:'constructor',value:'custom tag'}]);});
  env.context.state.filters.custom={owner:['finance']};
  await env.action('tag-filter-open');
  assert.match(env.element('#tag-filter-results').innerHTML,/Catalogue unavailable/);
  assert.match(env.element('#tag-filter-results').innerHTML,/Try again/);
  fail=false;await env.action('tag-filter-retry');
  await env.action('tag-filter-select',{key:'constructor',value:'custom tag',checked:true});
  await env.action('tag-filter-select',{key:'dc',value:'untrusted',checked:true});
  await env.action('tag-filter-apply');
  assert.deepEqual(JSON.parse(JSON.stringify(env.context.state.filters.custom)),{owner:['finance'],constructor:['custom tag']});
  assert.deepEqual(env.context.state.filters.dc,[]);
  assert.ok(env.requests.every(path=>path.startsWith('/tags?limit=200&offset=0&q=')));
});

test('closing through the modal X clears private draft state and fences late responses and timers',async()=>{
  let resolve;
  const env=environment(()=>new Promise(done=>{resolve=done;}));
  env.context.state.filters.custom={owner:['private-team']};
  const pending=env.action('tag-filter-open'),picker=env.run('tagFilterPicker');
  env.context.tagFilterInput({target:{id:'tag-filter-search',value:'private'}});
  env.context.closeModal();
  const before=env.element('#tag-filter-results').innerHTML;
  assert.equal(env.run('tagFilterPicker'),null);assert.equal(picker.draft,null);assert.equal(picker.page,null);
  await env.flush();assert.equal(env.requests.length,1);
  resolve(page([{id:'late',key:'owner',value:'late'}]));await pending;
  assert.equal(env.element('#tag-filter-results').innerHTML,before);
  await env.action('tag-filter-apply');
  assert.deepEqual(env.context.state.filters.custom,{owner:['private-team']});
  assert.equal(env.context.renders,undefined);
});

test('replacing the dialog cannot redirect a late tag response into another modal',async()=>{
  let resolve;
  const env=environment(()=>new Promise(done=>{resolve=done;}));
  const pending=env.action('tag-filter-open'),old=env.run('tagFilterPicker');
  env.context.showModal('Unrelated dialog','<div id="tag-filter-results">Other dialog</div>');
  env.element('#tag-filter-results').innerHTML='Other dialog';
  resolve(page([{id:'late',key:'owner',value:'private'}]));await pending;
  assert.equal(env.run('tagFilterPicker'),null);assert.equal(old.draft,null);
  assert.equal(env.element('#tag-filter-results').innerHTML,'Other dialog');
  assert.equal(env.context.modal.title,'Unrelated dialog');
  await env.action('tag-filter-apply');assert.equal(env.context.closed,undefined);
});

test('new identity and logout invalidate retained tag results and stale actions before applying filters',async()=>{
  let resolve;
  const env=environment(()=>new Promise(done=>{resolve=done;}));
  const pending=env.action('tag-filter-open'),old=env.run('tagFilterPicker');
  env.context.state.user={id:'different-reader'};
  env.element('#tag-filter-results').innerHTML='Different identity';
  resolve(page([{id:'private',key:'owner',value:'prior-identity'}]));await pending;
  assert.equal(env.run('tagFilterPicker'),null);assert.equal(old.draft,null);
  assert.equal(env.element('#tag-filter-results').innerHTML,'Different identity');
  env.context.api=async()=>page([{id:'tag',key:'owner',value:'new-identity'}]);
  await env.action('tag-filter-open');
  await env.action('tag-filter-select',{key:'owner',value:'new-identity',checked:true});
  env.context.state.authType='';env.context.state.user=null;
  await env.action('tag-filter-apply');
  assert.equal(env.run('tagFilterPicker'),null);assert.deepEqual(env.context.state.filters.custom,{});
  assert.equal(env.context.renders,undefined);
  await env.action('tag-filter-open');assert.equal(env.run('tagFilterPicker'),null);
});

test('modal marker is required even when a caller bypasses the standard replacement hook',async()=>{
  const env=environment(()=>page([{id:'tag',key:'owner',value:'finance'}]));
  await env.action('tag-filter-open');
  await env.action('tag-filter-select',{key:'owner',value:'finance',checked:true});
  env.element('#modal-content').innerHTML='<div>Replacement modal</div>';
  await env.action('tag-filter-apply');
  assert.equal(env.run('tagFilterPicker'),null);assert.deepEqual(env.context.state.filters.custom,{});
  assert.equal(env.context.closed,undefined);assert.equal(env.context.renders,undefined);
});
