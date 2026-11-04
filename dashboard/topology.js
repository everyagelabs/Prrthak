(function (global) {
  'use strict';
  const L = global.PrithakLocations || (typeof require === 'function' ? require('./locations.js') : null);
  const outlines = global.PrithakCountryOutlines || (typeof require === 'function' ? require('./country-outlines.js') : {});
  const maxPins = 6;
  const cities = {
    IN: [
      ['noida',28.5355,77.3910], ['new delhi|delhi',28.6139,77.2090], ['gurugram|gurgaon',28.4595,77.0266],
      ['mumbai|bombay',19.0760,72.8777], ['navi mumbai',19.0330,73.0297], ['pune',18.5204,73.8567],
      ['hyderabad',17.3850,78.4867], ['bengaluru|bangalore',12.9716,77.5946], ['chennai|madras',13.0827,80.2707],
      ['kolkata|calcutta',22.5726,88.3639], ['ahmedabad',23.0225,72.5714], ['jaipur',26.9124,75.7873],
      ['lucknow',26.8467,80.9462], ['kochi|cochin',9.9312,76.2673], ['bhubaneswar',20.2961,85.8245],
      ['nagpur',21.1458,79.0882], ['visakhapatnam|vizag',17.6868,83.2185]
    ],
    AU: [
      ['sydney',-33.8688,151.2093], ['melbourne',-37.8136,144.9631], ['brisbane',-27.4705,153.0260],
      ['perth',-31.9523,115.8613], ['adelaide',-34.9285,138.6007], ['canberra',-35.2809,149.1300],
      ['darwin',-12.4634,130.8456], ['hobart',-42.8821,147.3272]
    ]
  };
  const awsRegions = {
    'ap-south-1':['IN',19.0760,72.8777], 'ap-south-2':['IN',17.3850,78.4867],
    'ap-southeast-2':['AU',-33.8688,151.2093], 'ap-southeast-4':['AU',-37.8136,144.9631]
  };
  const external = {key:'external',label:'External / other sources',x:380,y:51};
  const units = {connections:'transport connections',packets:'denied packets',log_records:'legacy log records',sample_minutes:'communication samples'};
  let sequence = 0, paused = false, expanded = false, selectedCountry = '';
  const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[char]));
  const time = value => Date.parse(value || '');
  const count = value => Math.max(0, Number(value) || 0);
  const short = (value, length) => value.length > length ? value.slice(0,length-1) + '…' : value;
  const quantity = (n, singular, plural = singular + 's') => n.toLocaleString('en-US') + ' ' + (n === 1 ? singular : plural);
  const recent = (stamp, now, seconds) => stamp <= now + 30000 && stamp >= now - seconds * 1000;
  const mapCache = new Map();

  function countryName(code) {
    return outlines[code]?.[0] || code;
  }

  function inferredCity(label, countries) {
    const matches = [];
    for (const country of countries) for (const [aliases, latitude, longitude] of cities[country] || []) {
      for (const alias of aliases.split('|')) if (new RegExp('\\b' + alias + '\\b','i').test(label)) {
        matches.push({country, latitude, longitude, alias});
      }
    }
    const names = matches.filter(match=>!matches.some(other=>other.alias !== match.alias && other.alias.includes(match.alias)));
    return names.length && names.every(match=>match.country===names[0].country && match.latitude===names[0].latitude) ? names[0] : null;
  }

  function geography(site, members) {
    if (site.kind === 'unknown') return null;
    const {countryCode, latitude, longitude} = site;
    if (countryCode && Number.isFinite(latitude) && Number.isFinite(longitude)) return {country:countryCode, latitude, longitude};
    if (site.kind === 'cloud' && (!site.provider || site.provider.toLowerCase() === 'aws')) {
      let region = (site.region || [site.location,site.label].join(' ')).toLowerCase().match(/\bap-(?:south|southeast)-\d+[a-z]?\b/)?.[0]?.replace(/[a-z]$/,'');
      if (!site.region && !region && (site.provider.toLowerCase() === 'aws' || /\bAWS\b/i.test(site.label))) {
        const hostRegions = members.map(server=>server.hostname?.toLowerCase().match(/\.(ap-(?:south|southeast)-\d+)\.compute\.internal\.?$/)?.[1]);
        if (hostRegions[0] && hostRegions.every(value=>value===hostRegions[0])) region = hostRegions[0];
      }
      const match = awsRegions[region];
      if (match && (!countryCode || countryCode === match[0])) return {country:match[0], latitude:match[1], longitude:match[2]};
    }
    const candidates = countryCode ? [countryCode] : Object.keys(cities);
    return inferredCity(site.location || '', candidates) || inferredCity(site.label || '', candidates) || (countryCode ? {country:countryCode} : null);
  }

  function countryMap(code) {
    if (mapCache.has(code)) return mapCache.get(code);
    const rings = outlines[code]?.[1];
    if (!rings?.length) return null;
    const longitudes = [], latitudes = [];
    for (const ring of rings) for (let i=0; i<ring.length; i+=2) {
      longitudes.push(ring[i]/100);
      latitudes.push(ring[i+1]/100);
    }
    const seam = Math.max(...longitudes) - Math.min(...longitudes) > 270;
    const wrap = longitude => seam && longitude < 0 ? longitude + 360 : longitude;
    const left = Math.min(...longitudes.map(wrap)), right = Math.max(...longitudes.map(wrap));
    const top = Math.max(...latitudes), bottom = Math.min(...latitudes);
    const longitudeFactor = Math.cos((top+bottom)*Math.PI/360);
    const scale = Math.min(421 / Math.max(.02,(right-left)*longitudeFactor), 343 / Math.max(.02,top-bottom));
    const project = (latitude, longitude) => ({x:380 + (wrap(longitude)-(left+right)/2)*longitudeFactor*scale, y:222 + ((top+bottom)/2-latitude)*scale});
    const path = rings.map(ring=>{
      let d = 'M';
      for (let i=0; i<ring.length; i+=2) {
        const {x,y} = project(ring[i+1]/100,ring[i]/100);
        d += `${i?' ':''}${x.toFixed(1)} ${y.toFixed(1)}`;
      }
      return d+'Z';
    }).join('');
    const map = {path, locate(point) {
      if (!Number.isFinite(point.latitude) || !Number.isFinite(point.longitude) ||
          point.latitude < bottom-.25 || point.latitude > top+.25 ||
          wrap(point.longitude) < left-.25 || wrap(point.longitude) > right+.25) return null;
      return project(point.latitude,point.longitude);
    }};
    mapCache.set(code,map);
    return map;
  }

  function address(value) {
    const ip = String(value || '').trim().toLowerCase();
    if (!ip.includes(':')) return ip;
    try { return new URL('http://[' + ip + ']').hostname.slice(1,-1); }
    catch { return ip; }
  }

  function siteHealth(site, now) {
    let healthy = 0, reporting = 0, fresh = false;
    for (const server of site.members) {
      if (server.status === 'offline' || server.status_stale ||
          !recent(time(server.last_seen),now,count(server.heartbeat_timeout_seconds) || 180)) continue;
      reporting++;
      fresh ||= recent(time(server.last_seen),now,60);
      if (server.status === 'healthy' && server.apply_status !== 'error') healthy++;
    }
    return {healthy,reporting,fresh,kind:healthy === site.members.length ? 'healthy' : reporting ? 'warning' : 'offline'};
  }

  function toolIcon(name) {
    const shapes = {
      pause:'<path d="M8 5v14m8-14v14"/>', play:'<path d="m8 5 11 7-11 7Z"/>',
      expand:'<path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5"/>'
    };
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true">' + shapes[name] + '</svg>';
  }

  function mapBackground(prefix, map) {
    return `<defs>
      <linearGradient id="${prefix}-land" x2=".72" y2="1"><stop stop-color="#fff0f3"/><stop offset="1" stop-color="#f8d9e3"/></linearGradient>
      <pattern id="${prefix}-dots" width="17" height="17" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r=".8" fill="#e9cdd6" opacity=".62"/></pattern>
      <marker id="${prefix}-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="4" markerHeight="4" orient="auto"><path d="M0 0L10 5 0 10Z" fill="context-stroke"/></marker>
    </defs>
    <rect width="760" height="425" fill="#fffcfd"/><rect width="760" height="425" fill="url(#${prefix}-dots)"/>
    ${map?`<path class="pseg-country-shape" d="${map.path}" fill="url(#${prefix}-land)" fill-rule="evenodd"/>`:''}`;
  }

  function placeLabels(sites) {
    const sides = [[],[]];
    [...sites].sort((a,b)=>a.x-b.x).forEach((site,index)=>sides[index < Math.ceil(sites.length/2) ? 0 : 1].push(site));
    for (const [side, labels] of sides.entries()) {
      labels.sort((a,b)=>a.y-b.y);
      let nextTop = 69;
      for (const [index,site] of labels.entries()) {
        const remaining = labels.length-index-1;
        site.top = Math.max(nextTop,Math.min(358-remaining*60,site.y-25));
        site.left = side ? 582 : 14;
        nextTop = site.top+60;
      }
    }
    return sites;
  }

  function siteHTML(site, now, active) {
    const {x,y,left,top,key,label,typeLabel,members,kind} = site;
    const health = siteHealth(site,now);
    const title = `${label} · ${typeLabel} · ${health.healthy}/${members.length} healthy · ${site.mapPosition}`;
    const width = 164, attach = left < x ? left + width : left;
    return `<g class="pseg-site" data-location-type="${escape(kind)}">
      <path class="pseg-leader" d="M${x} ${y}L${attach + (left < x ? 24 : -24)} ${top + 25}H${attach}"/>
      ${active || health.fresh?`<circle class="pseg-site-pulse" cx="${x}" cy="${y}" r="11"/>`:''}
      <circle class="pseg-site-halo" cx="${x}" cy="${y}" r="9"/><circle class="pseg-site-point is-${health.kind}" cx="${x}" cy="${y}" r="4.7"/>
      <g class="pseg-site-button" transform="translate(${left} ${top})" tabindex="0" role="button" data-location-key="${escape(key)}" aria-label="Filter ${escape(title)}"><title>${escape(title)}</title>
        <rect width="${width}" height="51" rx="8"/><circle class="pseg-health-dot is-${health.kind}" cx="16" cy="18" r="3.4"/>
        <text class="pseg-site-label" x="26" y="22">${escape(short(label,20))}</text>
        <text class="pseg-site-meta" x="16" y="39">${escape(typeLabel)} · ${quantity(members.length,'host')}</text>
      </g>
    </g>`;
  }

  function siteListHTML(sites, now, label, compact=false) {
    if (!sites.length) return '';
    return `<div class="pseg-off-map${compact?' pseg-compact-sites':''}"><strong>${escape(label)}</strong>${sites.slice(0,maxPins).map(site=>{
      const health = siteHealth(site,now);
      return `<button type="button" data-location-key="${escape(site.key)}" title="${escape(site.label)} · ${health.healthy}/${site.members.length} healthy"><i class="pseg-health-dot is-${health.kind}"></i>${escape(site.label)} <small>${quantity(site.members.length,'host')}</small></button>`;
    }).join('')}${sites.length>maxPins?`<a href="/locations">+${sites.length-maxPins} sites</a>`:''}</div>`;
  }

  function observedLinks(flows, inventory, displayed, sessions, now) {
    const sitesByServer = new Map(), owners = new Map(), activeByServer = new Map();
    for (const site of displayed) for (const server of site.members) sitesByServer.set(server.id,site);
    for (const server of inventory) {
      for (const ip of server.ips || []) {
        const key = address(ip);
        if (key && !owners.has(key)) owners.set(key,server.id);
        else if (key && owners.get(key) !== server.id) owners.set(key,null);
      }
    }
    for (const session of sessions) {
      if (!['active','learning'].includes(session.status) || !(time(session.expires_at) > now) ||
          !(time(session.starts_at) <= now)) continue;
      for (const id of session.server_ids || []) {
        if (!activeByServer.has(id)) activeByServer.set(id,new Set());
        activeByServer.get(id).add(session.id);
      }
    }
    const links = new Map(), sourceIPs = new Set(), targetById = new Map(inventory.map(server=>[server.id,server]));
    for (const flow of flows) {
      const stamp = time(flow.last_seen);
      const end = sitesByServer.get(flow.server_id);
      if (!end || !flow.source_ip || !Number.isFinite(stamp) || stamp > now + 30000) continue;
      const sourceIP = address(flow.source_ip);
      const start = sitesByServer.get(owners.get(sourceIP)) || external;
      if (start === external) sourceIPs.add(sourceIP);
      const key = JSON.stringify([start.key,end.key]);
      if (!links.has(key)) links.set(key,{start,end,counts:{},latest:0,active:false});
      const link = links.get(key);
      const unit = flow.count_unit === 'sample_minutes' ? 'sample_minutes' : flow.capture_kind === 'accepted_connection' ? 'connections' : flow.capture_kind === 'denied_packet' ? 'packets' : 'log_records';
      link.counts[unit] = (link.counts[unit] || 0) + count(flow.count);
      link.latest = Math.max(stamp,link.latest);
      const target = targetById.get(flow.server_id);
      link.active ||= !!target && target.collector_status === 'learning' && !target.learning_discovery_pending &&
        !['pending','error','no_listeners','unsupported'].includes(target.learning_discovery_status) &&
        !target.status_stale && target.status !== 'offline' &&
        recent(time(target.last_seen),now,count(target.heartbeat_timeout_seconds) || 180) &&
        recent(stamp,now,120) && !!flow.session_id && !!activeByServer.get(flow.server_id)?.has(flow.session_id);
    }
    return {links:[...links.values()],sourceIPs};
  }

  function linkHTML(link, prefix) {
    const {start,end,active} = link;
    const path = start.x === end.x && start.y === end.y ?
      `M${start.x-7} ${start.y-5}c-52 -63 54 -63 14 0` :
      `M${start.x} ${start.y}Q${(start.x+end.x)/2 + (end.y-start.y)*.26} ${(start.y+end.y)/2 - (end.x-start.x)*.26} ${end.x} ${end.y}`;
    const summary = Object.keys(units).filter(unit=>link.counts[unit]).map(unit=>link.counts[unit].toLocaleString('en-US') + ' ' + units[unit]).join(' / ');
    const title = `${start.label} → ${end.label} · ${summary} · ${new Date(link.latest).toISOString()}`;
    return `<g class="pseg-edge ${active?'is-current':'is-historical'}"><title>${escape(title)}</title>
      <path class="pseg-edge-line" d="${path}" marker-end="url(#${prefix}-arrow)"/>
      ${active?`<path class="pseg-edge-pulse" d="${path}" pathLength="100"/>`:''}</g>`;
  }

  function render({servers=[],inventory=servers,flows=[],learningSessions=[],sessionsLimited=false,now=Date.now(),country=selectedCountry} = {}) {
    const prefix = 'pseg-country-' + ++sequence;
    const locations = L.all(servers), grouped = new Map(), unmapped = [];
    const membersByLocation = new Map();
    for (const server of inventory) {
      if (!membersByLocation.has(server.location_id)) membersByLocation.set(server.location_id,[]);
      membersByLocation.get(server.location_id).push(server);
    }
    for (const site of locations) {
      const geo = geography(site,membersByLocation.get(site.id) || site.members);
      const map = geo && countryMap(geo.country);
      if (!map) { unmapped.push(site); continue; }
      if (!grouped.has(geo.country)) grouped.set(geo.country,[]);
      const mapPosition = Number.isFinite(site.latitude) && Number.isFinite(site.longitude) ? 'Saved coordinates' : 'Approximate city location';
      grouped.get(geo.country).push({...site,point:map.locate(geo),mapPosition});
    }
    const countries = [...grouped.keys()].sort((a,b)=>countryName(a).localeCompare(countryName(b)));
    const activeCountry = grouped.has(country) ? country : countries.reduce((best,code)=>
      !best || grouped.get(code).length>grouped.get(best).length ? code : best,'');
    const map = countryMap(activeCountry);
    const inCountry = grouped.get(activeCountry) || [];
    const positioned = inCountry.filter(site=>site.point);
    const displayed = placeLabels(positioned.slice(0,maxPins).map(site=>({...site,...site.point})));
    const {links,sourceIPs} = observedLinks(flows,inventory,displayed,learningSessions,now);
    const activeSites = new Set(links.filter(link=>link.active).flatMap(link=>[link.start.key,link.end.key]));
    const counted = activeCountry ? inCountry : locations;
    const centres = counted.filter(site=>site.kind==='datacenter').length;
    const cloud = counted.filter(site=>site.kind==='cloud').length;
    const note = servers.some(server=>server.synthetic===true) ? 'Synthetic observations' : (activeCountry ? countryName(activeCountry) : '');
    const linkStatus = !links.length ? 'No observed links' : quantity(links.length,'observed link');
    const empty = !servers.length ? 'No endpoints match this scope' : 'No sites have a map location';
    return `<section class="card pseg-topology" data-paused="${paused}" data-expanded="${expanded}" aria-label="Infrastructure topology">
      <header class="overview-panel-head">
        <div><h2>Infrastructure map</h2><p>${activeCountry?`${escape(countryName(activeCountry))} · `:''}${quantity(centres,'data centre')} · ${quantity(cloud,'cloud region')}</p></div>
        <div class="pseg-topology-tools">
          ${countries.length>1?`<select class="button secondary small" id="topology-country" data-topology-country aria-label="Map country">${countries.map(code=>`<option value="${escape(code)}"${code===activeCountry?' selected':''}>${escape(countryName(code))}</option>`).join('')}</select>`:''}
          <button class="button secondary small" type="button" data-topology-action="location-help">Locations</button>
          <button class="button secondary small" type="button" data-topology-action="pause" aria-pressed="${paused}">${toolIcon(paused?'play':'pause')}<span>${paused?'Resume':'Pause'}</span></button>
          <button class="button secondary small" type="button" data-topology-action="expand" aria-label="Expand infrastructure map" aria-pressed="${expanded}">${toolIcon('expand')}</button>
        </div>
      </header>
      <div class="pseg-map-wrap"><svg class="pseg-map" viewBox="0 0 760 425" role="group" aria-label="${activeCountry?`Infrastructure in ${escape(countryName(activeCountry))}`:'Infrastructure sites'}">
        ${mapBackground(prefix,map)}
        ${links.map(link=>linkHTML(link,prefix)).join('')}
        ${displayed.map(site=>siteHTML(site,now,activeSites.has(site.key))).join('')}
        ${sourceIPs.size?`<g class="pseg-external" transform="translate(292 13)"><title>${quantity(sourceIPs.size,'observed source IP')}</title><rect width="176" height="33" rx="6"/><text x="88" y="14" text-anchor="middle">External / other sources</text><text x="88" y="26" text-anchor="middle" class="pseg-site-meta">${quantity(sourceIPs.size,'observed source IP')}</text></g>`:''}
        ${note?`<rect x="17" y="16" width="169" height="23" rx="11" fill="#fff0f4"/><text x="28" y="31" class="pseg-map-label">${escape(short(note,24))}</text>`:''}
        ${!map?`<text x="380" y="220" text-anchor="middle" class="pseg-empty">${empty}</text>`:''}
      </svg></div>
      <footer class="pseg-topology-footer"><div class="pseg-topology-legend"><span${sessionsLimited?' title="Animation uses the loaded learning session page"':''}><i></i>Recent observation</span><span><i></i>Historical observation</span></div>
        <strong>${linkStatus}</strong>
      </footer>
      ${siteListHTML(displayed,now,'Mapped sites',true)}
      ${siteListHTML(unmapped,now,'Unmapped sites')}
      ${siteListHTML(inCountry.filter(site=>!site.point),now,'Needs map coordinates')}
      ${siteListHTML(positioned.slice(maxPins),now,'Additional sites in '+countryName(activeCountry))}
    </section>`;
  }

  function healthHTML(servers, now = Date.now()) {
    const sites = L.all(servers);
    const reporting = sites.map(site=>siteHealth(site,now).reporting).reduce((sum,value)=>sum+value,0);
    const chips = sites.slice(0,maxPins).map(site=>{
      const health = siteHealth(site,now);
      const title = `${site.label} · ${health.reporting}/${site.members.length} reporting`;
      return `<button type="button" data-action="overview-location" data-key="${escape(site.key)}" title="${escape(title)}"><i class="pseg-health-dot is-${health.kind}"></i>${escape(site.label)}</button>`;
    }).join('');
    return `<section class="card overview-summary-card">
      <div><h2>Site health</h2><p>${servers.length?`${reporting.toLocaleString('en-US')} of ${quantity(servers.length,'endpoint')} reporting`:'No endpoints in this scope'}</p></div>
      <div class="overview-site-chips">${chips}${sites.length>maxPins?`<a href="/locations">+${sites.length-maxPins} sites</a>`:''}</div>
    </section>`;
  }

  function bind(root, callbacks = {}) {
    const panel = root?.querySelector?.('.pseg-topology');
    if (!panel) return () => {};
    function click(event) {
      const target = event.target.closest?.('[data-topology-action], [data-location-key]');
      if (!target || !panel.contains(target)) return;
      const action = target.getAttribute('data-topology-action');
      if (action === 'location-help') callbacks.onLocationHelp?.();
      else if (action === 'pause') {
        paused = !paused;
        panel.setAttribute('data-paused',String(paused));
        target.setAttribute('aria-pressed',String(paused));
        target.innerHTML = toolIcon(paused?'play':'pause') + `<span>${paused?'Resume':'Pause'}</span>`;
      } else if (action === 'expand') {
        expanded = !expanded;
        panel.setAttribute('data-expanded',String(expanded));
        target.setAttribute('aria-pressed',String(expanded));
      } else callbacks.onLocationSelect?.(target.getAttribute('data-location-key'));
    }
    function keydown(event) {
      if ((event.key === 'Enter' || event.key === ' ') && event.target.matches?.('g[role="button"]')) {
        event.preventDefault();
        click(event);
      }
    }
    function change(event) {
      if (!event.target.matches?.('[data-topology-country]')) return;
      selectedCountry = event.target.value;
      callbacks.onCountryChange?.();
    }
    panel.addEventListener('click',click);
    panel.addEventListener('change',change);
    panel.addEventListener('keydown',keydown);
    return () => {
      panel.removeEventListener('click',click);
      panel.removeEventListener('change',change);
      panel.removeEventListener('keydown',keydown);
    };
  }

  global.PSegraTopology = {render, healthHTML, bind, countryName, countries:()=>Object.keys(outlines).sort((a,b)=>countryName(a).localeCompare(countryName(b)))};
})(globalThis);
