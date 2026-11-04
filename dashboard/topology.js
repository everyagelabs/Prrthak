(function (global) {
  'use strict';
  const L = global.PrithakLocations || (typeof require === 'function' ? require('./locations.js') : null);
  const slots = [
    {x:420,y:128,left:538,top:49}, {x:294,y:218,left:32,top:228},
    {x:352,y:291,left:479,top:326}, {x:479,y:225,left:564,top:165},
    {x:273,y:144,left:31,top:91}, {x:280,y:294,left:38,top:325}
  ];
  const external = {key:'external',label:'External / other sources',x:380,y:51};
  const units = {connections:'transport connections',packets:'denied packets',log_records:'legacy log records',sample_minutes:'communication samples'};
  let sequence = 0, paused = false, expanded = false;
  const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[char]));
  const time = value => Date.parse(value || '');
  const count = value => Math.max(0, Number(value) || 0);
  const short = (value, length) => value.length > length ? value.slice(0,length-1) + '…' : value;
  const quantity = (n, singular, plural = singular + 's') => n.toLocaleString('en-US') + ' ' + (n === 1 ? singular : plural);
  const recent = (stamp, now, seconds) => stamp <= now + 30000 && stamp >= now - seconds * 1000;

  function address(value) {
    const ip = String(value || '').trim().toLowerCase();
    if (!ip.includes(':')) return ip;
    try { return new URL('http://[' + ip + ']').hostname.slice(1,-1); }
    catch { return ip; }
  }

  function siteHealth(site, now) {
    let healthy = 0, reporting = 0;
    for (const server of site.members) {
      if (server.status === 'offline' || server.status_stale ||
          !recent(time(server.last_seen),now,count(server.heartbeat_timeout_seconds) || 180)) continue;
      reporting++;
      if (server.status === 'healthy' && server.apply_status !== 'error') healthy++;
    }
    return {healthy,reporting,kind:healthy === site.members.length ? 'healthy' : reporting ? 'warning' : 'offline'};
  }

  function toolIcon(name) {
    const shapes = {
      pause:'<path d="M8 5v14m8-14v14"/>', play:'<path d="m8 5 11 7-11 7Z"/>',
      expand:'<path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5"/>'
    };
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true">' + shapes[name] + '</svg>';
  }

  function globe(prefix) {
    return `<defs>
      <radialGradient id="${prefix}-sphere" cx=".38" cy=".29" r=".72"><stop stop-color="#fff"/><stop offset=".72" stop-color="#fff2f5"/><stop offset="1" stop-color="#fbe0e8"/></radialGradient>
      <pattern id="${prefix}-dots" width="17" height="17" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r=".8" fill="#e9cdd6" opacity=".62"/></pattern>
      <clipPath id="${prefix}-clip"><circle cx="374" cy="211" r="159"/></clipPath>
      <marker id="${prefix}-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="4" markerHeight="4" orient="auto"><path d="M0 0L10 5 0 10Z" fill="context-stroke"/></marker>
    </defs>
    <rect width="760" height="425" fill="#fffcfd"/><rect width="760" height="425" fill="url(#${prefix}-dots)"/>
    <ellipse cx="374" cy="211" rx="246" ry="93" transform="rotate(-16 374 211)" fill="none" stroke="#efd8df" stroke-dasharray="4 8"/>
    <ellipse cx="374" cy="211" rx="229" ry="97" transform="rotate(17 374 211)" fill="none" stroke="#f3dfe5"/>
    <circle cx="374" cy="211" r="172" fill="none" stroke="#f4e2e8"/>
    <circle cx="374" cy="211" r="159" fill="url(#${prefix}-sphere)" stroke="#e9b5c4" stroke-width="1.3"/>
    <g clip-path="url(#${prefix}-clip)" fill="none" stroke="#eac1cc" stroke-width=".85" opacity=".84">
      <ellipse cx="374" cy="211" rx="114" ry="159"/><ellipse cx="374" cy="211" rx="63" ry="159"/><path d="M374 52v318"/>
      <path d="M219 172Q374 209 529 172M215 211Q374 264 533 211M222 255Q374 302 526 255M247 302Q374 336 501 302M245 114Q374 145 503 114"/>
      <path d="M266 136l13-13 17 4 11-12 19 5 6 13 13 6 4 19-10 9-20-2-9 11-18-5-12-14-14-4Zm54 52 18 7 8 16 16 5 8 16-17 29-9 6-10-16-3-22-11-11Zm60-49 15-11 21 3 12-8 22 1 14 15 20-3 17 11 10 12-18 14-27 7-12 14-17-5-8-17-18-2-6 17-17 5-14-15-11-11 7-12Zm9 51 18-5 16 14 9 23-9 14-11 10-7 17-12-12-8-17 1-15-8-12Zm64 54 14-7 13 9 3 11-8 9-16-5Z" fill="#eac4ce" fill-opacity=".41" stroke="none"/>
    </g>`;
  }

  function siteHTML(site, now) {
    const {x,y,left,top,key,label,typeLabel,members,kind} = site;
    const health = siteHealth(site,now);
    const title = `${label} · ${typeLabel} · ${health.healthy}/${members.length} healthy`;
    const width = 164, attach = left < x ? left + width : left;
    return `<g class="pseg-site" data-location-type="${escape(kind)}">
      <path class="pseg-leader" d="M${x} ${y}L${attach + (left < x ? 24 : -24)} ${top + 25}H${attach}"/>
      <circle class="pseg-site-halo" cx="${x}" cy="${y}" r="9"/><circle class="pseg-site-point" cx="${x}" cy="${y}" r="4.7"/>
      <g class="pseg-site-button" transform="translate(${left} ${top})" tabindex="0" role="button" data-location-key="${escape(key)}" aria-label="Filter ${escape(title)}"><title>${escape(title)}</title>
        <rect width="${width}" height="51" rx="8"/><circle class="pseg-health-dot is-${health.kind}" cx="16" cy="18" r="3.4"/>
        <text class="pseg-site-label" x="26" y="22">${escape(short(label,20))}</text>
        <text class="pseg-site-meta" x="16" y="39">${escape(typeLabel)} · ${quantity(members.length,'host')}</text>
      </g>
    </g>`;
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
    const path = start === end ?
      `M${start.x-7} ${start.y-5}c-52 -63 54 -63 14 0` :
      `M${start.x} ${start.y}Q${(start.x+end.x)/2 + (end.y-start.y)*.26} ${(start.y+end.y)/2 - (end.x-start.x)*.26} ${end.x} ${end.y}`;
    const summary = Object.keys(units).filter(unit=>link.counts[unit]).map(unit=>link.counts[unit].toLocaleString('en-US') + ' ' + units[unit]).join(' / ');
    const title = `${start.label} → ${end.label} · ${summary} · ${new Date(link.latest).toISOString()}`;
    return `<g class="pseg-edge ${active?'is-current':'is-historical'}"><title>${escape(title)}</title>
      <path class="pseg-edge-line" d="${path}" marker-end="url(#${prefix}-arrow)"/>
      ${active?`<path class="pseg-edge-pulse" d="${path}" pathLength="100"/>`:''}</g>`;
  }

  function render({servers=[],inventory=servers,flows=[],learningSessions=[],sessionsLimited=false,now=Date.now()} = {}) {
    const prefix = 'pseg-globe-' + ++sequence;
    const locations = L.all(servers);
    const displayed = locations.slice(0,slots.length).map((site,index)=>({...site,...slots[index]}));
    const {links,sourceIPs} = observedLinks(flows,inventory,displayed,learningSessions,now);
    const centres = locations.filter(site=>site.kind==='datacenter').length;
    const cloud = locations.filter(site=>site.kind==='cloud').length;
    const note = servers.some(server=>server.synthetic===true) ? 'Synthetic observations' : 'Logical topology';
    const hidden = locations.length - displayed.length;
    const linkStatus = !links.length ? 'No observed links' : quantity(links.length,'observed link');
    return `<section class="card pseg-topology" data-paused="${paused}" data-expanded="${expanded}" aria-label="Infrastructure topology">
      <header class="overview-panel-head">
        <div><h2>Infrastructure map</h2><p>${quantity(centres,'data centre')} · ${quantity(cloud,'cloud region')} · Logical layout</p></div>
        <div class="pseg-topology-tools">
          <button class="button secondary small" type="button" data-topology-action="location-help">Locations</button>
          <button class="button secondary small" type="button" data-topology-action="pause" aria-pressed="${paused}">${toolIcon(paused?'play':'pause')}<span>${paused?'Resume':'Pause'}</span></button>
          <button class="button secondary small" type="button" data-topology-action="expand" aria-label="Expand infrastructure map" aria-pressed="${expanded}">${toolIcon('expand')}</button>
        </div>
      </header>
      <div class="pseg-map-wrap"><svg class="pseg-map" viewBox="0 0 760 425" role="group" aria-label="Logical globe showing site groups and observed communication paths. Coordinates are not geographic.">
        ${globe(prefix)}
        ${links.map(link=>linkHTML(link,prefix)).join('')}
        ${displayed.map(site=>siteHTML(site,now)).join('')}
        ${sourceIPs.size?`<g class="pseg-external" transform="translate(292 13)"><title>${quantity(sourceIPs.size,'observed source IP')}</title><rect width="176" height="33" rx="6"/><text x="88" y="14" text-anchor="middle">External / other sources</text><text x="88" y="26" text-anchor="middle" class="pseg-site-meta">${quantity(sourceIPs.size,'observed source IP')}</text></g>`:''}
        <rect x="17" y="16" width="160" height="23" rx="11" fill="#fff0f4"/><text x="28" y="31" class="pseg-map-label">${escape(note)}</text>
        ${!displayed.length?'<text x="380" y="220" text-anchor="middle" class="pseg-empty">No endpoints match this scope</text>':''}
      </svg></div>
      <footer class="pseg-topology-footer"><div class="pseg-topology-legend"><span${sessionsLimited?' title="Animation uses the loaded learning session page"':''}><i></i>Recent observation</span><span><i></i>Historical observation</span></div>
        <strong>${linkStatus}${hidden?` · ${quantity(hidden,'additional location')} off map`:''}</strong>
      </footer>
    </section>`;
  }

  function healthHTML(servers, now = Date.now()) {
    const sites = L.all(servers);
    const reporting = sites.map(site=>siteHealth(site,now).reporting).reduce((sum,value)=>sum+value,0);
    const chips = sites.slice(0,slots.length).map(site=>{
      const health = siteHealth(site,now);
      const title = `${site.label} · ${health.reporting}/${site.members.length} reporting`;
      return `<button type="button" data-action="overview-location" data-key="${escape(site.key)}" title="${escape(title)}"><i class="pseg-health-dot is-${health.kind}"></i>${escape(site.label)}</button>`;
    }).join('');
    return `<section class="card overview-summary-card">
      <div><h2>Site health</h2><p>${servers.length?`${reporting.toLocaleString('en-US')} of ${quantity(servers.length,'endpoint')} reporting`:'No endpoints in this scope'}</p></div>
      <div class="overview-site-chips">${chips}${sites.length>slots.length?`<a href="/locations">+${sites.length-slots.length} sites</a>`:''}</div>
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
    panel.addEventListener('click',click);
    panel.addEventListener('keydown',keydown);
    return () => {
      panel.removeEventListener('click',click);
      panel.removeEventListener('keydown',keydown);
    };
  }

  global.PSegraTopology = {render, healthHTML, bind};
})(globalThis);
