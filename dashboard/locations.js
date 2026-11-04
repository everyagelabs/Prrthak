(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PrithakLocations = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  const clean=value=>typeof value==='string'?value.trim():'';
  const providerNames={aws:'AWS',azure:'Azure',gcp:'Google Cloud',other:'Other cloud'};
  const reservedNames=new Set(['dc','dc_id','datacenter','datacenter_id','data_center','data_centre','location','location_id','location_type']);
  const normalizeKey=key=>String(key).toLowerCase().replace(/-/g,'_');
  const isReserved=key=>reservedNames.has(normalizeKey(key));
  let records=[];
  function setCatalog(items=[]) { records=items.filter(item=>item&&typeof item.id==='string'&&['datacenter','cloud'].includes(item.type)).map(item=>({...item,key:'location:'+item.id})); }
  function catalog() { return [...records].sort((a,b)=>a.name.localeCompare(b.name)); }
  function find(value) {
    const input=clean(value),exact=records.find(record=>record.id===input||record.key===input);
    if(exact)return exact;
    const matches=records.filter(record=>[record.name,...(record.aliases || [])].some(alias=>typeof alias==='string'&&alias.trim().toLowerCase()===input.toLowerCase()));
    return matches.length===1?matches[0]:null;
  }
  function fromRecord(record) { return {id:record.id,key:'location:'+record.id,kind:record.type,label:record.name,location:record.location || '',provider:record.provider || '',region:record.region || '',account:record.account || '',countryCode:record.country_code || '',latitude:record.latitude,longitude:record.longitude,selector:{location_id:record.id},typeLabel:record.type==='cloud'?'Cloud region':'Data centre',synthetic:!!record.synthetic}; }
  function of(server={}) {
    const id=clean(server.location_id),resolved=id&&(server.location?.id===id?server.location:records.find(record=>record.id===id));
    if(resolved && ['datacenter','cloud'].includes(resolved.type))return fromRecord(resolved);
    return {id:id || null,key:id?'location:'+id:'unknown',kind:'unknown',label:id?'Location details unavailable':'Unassigned location',location:'',provider:'',region:'',account:'',selector:id?{location_id:id}:{},typeLabel:id?'Unresolved assignment':'Unassigned'};
  }
  function all(servers=[],includeEmpty=false) {
    const entries=new Map();
    if(includeEmpty)records.forEach(record=>{const location=fromRecord(record);entries.set(location.key,{...location,members:[]});});
    servers.forEach(server=>{const location=of(server);if(!entries.has(location.key))entries.set(location.key,{...location,members:[]});entries.get(location.key).members.push(server);});
    const rank={datacenter:0,cloud:1,unknown:2};
    return [...entries.values()].sort((a,b)=>rank[a.kind]-rank[b.kind]||a.label.localeCompare(b.label));
  }
  function selectorLocationId(selector={}) {
    if(selector.location_id)return find(selector.location_id)?.id || clean(selector.location_id);
    const values=Object.entries(selector).filter(([key])=>isReserved(key));
    if(!values.length)return null;
    const matches=values.map(([,value])=>find(value)?.id);
    return matches.every(Boolean)&&new Set(matches).size===1?matches[0]:null;
  }
  function selectorFromKey(key) {
    if(key==='unknown')return null;
    const direct=find(key);if(direct)return {location_id:direct.id};
    if(typeof key==='string'&&key.startsWith('location:')&&key.length>9)return {location_id:key.slice(9)};
    try{const value=JSON.parse(key);if(!value||Array.isArray(value)||typeof value!=='object')return null;const id=selectorLocationId(value);return id?{location_id:id}:null;}catch{return null;}
  }
  function equivalent(a,b) { if(a===b)return true;const left=selectorFromKey(a),right=selectorFromKey(b);return !!left&&!!right&&left.location_id===right.location_id; }
  function matchesKey(server,key) { if(key==='unknown')return !server.location_id;const selector=selectorFromKey(key);return !!selector&&server.location_id===selector.location_id; }
  function describe(key) { if(key==='unknown')return 'Unassigned location';const selector=selectorFromKey(key),record=selector&&find(selector.location_id);return record?record.name:'Unresolved location filter'; }
  function customTags(tags={}) { return Object.fromEntries(Object.entries(tags).filter(([key])=>!isReserved(key))); }
  function legacyTags(tags={}) { return Object.fromEntries(Object.entries(tags).filter(([key])=>isReserved(key))); }
  function assertCustomTags(tags) { const reserved=Object.keys(tags).find(isReserved);if(reserved)throw new Error(`${reserved} is reserved for location assignment. Choose one saved location using the location selector.`);return tags; }
  function matchesSelector(server,selector={}) { return Object.entries(selector).every(([key,value])=>isReserved(key)?(normalizeKey(key)==='location_id'?server.location_id===value:!!server.location_id&&find(value)?.id===server.location_id):server.tags?.[key]===value); }
  function selectorTags(selector={}) { return selectorLocationId(selector)?customTags(selector):selector; }
  function withLocation(selector={},id='') { return id?{...customTags(selector),location_id:id}:{...selector}; }
  return {setCatalog,catalog,find,of,all,selectorFromKey,describe,equivalent,matchesKey,customTags,legacyTags,assertCustomTags,isReserved,matchesSelector,selectorLocationId,selectorTags,withLocation,providerNames};
}));
