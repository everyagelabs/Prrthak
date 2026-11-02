(function (global) {
  'use strict';
  const L = global.PrithakLocations || (typeof require === 'function' ? require('./locations.js') : null);
  const LIMIT_DCS = 6, LIMIT_HOSTS = 9, LIMIT_EDGES = 100;
  let sequence = 0, paused = false;
  const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[char]));
  const array = value => Array.isArray(value) ? value : [];
  const text = value => typeof value === 'string' ? value : '';
  const time = value => { const result = value instanceof Date ? value.getTime() : new Date(value || '').getTime(); return Number.isFinite(result) ? result : null; };
  const count = value => Number.isFinite(Number(value)) ? Math.max(0, Number(value)) : 0;
  const compact = value => count(value) >= 1000000 ? `${(count(value) / 1000000).toFixed(1)}m` : count(value) >= 1000 ? `${(count(value) / 1000).toFixed(1)}k` : String(Math.round(count(value)));
  const short = (value, length) => { const string = String(value ?? ''); return string.length > length ? `${string.slice(0, length - 1)}…` : string; };
  const age = (value, now) => { const stamp = time(value); if (stamp === null) return 'Not reported'; const seconds = Math.max(0, (now - stamp) / 1000); return seconds < 60 ? `${Math.floor(seconds)}s ago` : seconds < 3600 ? `${Math.floor(seconds / 60)}m ago` : seconds < 86400 ? `${Math.floor(seconds / 3600)}h ago` : `${Math.floor(seconds / 86400)}d ago`; };
  const fresh = (value, now, seconds = 180) => { const stamp = time(value); return stamp !== null && stamp <= now + 30000 && now - stamp <= seconds * 1000; };
  const heartbeatFresh = (server, now) => fresh(server.last_seen, now, count(server.heartbeat_timeout_seconds) || 180);
  function address(value) {
    const ip = text(value).trim().toLowerCase();
    if (!ip) return '';
    if (ip.includes(':')) { try { return new URL(`http://[${ip}]`).hostname.replace(/^\[|\]$/g, ''); } catch (_) { return ip; } }
    return ip;
  }
  const icon = name => {
    const shapes = {building:'<path d="M4 21V5l8-3v19M12 8h8v13M2 21h20M7 7h2M7 11h2M7 15h2M15 11h2M15 15h2"/>',cloud:'<path d="M7 18a4 4 0 0 1-.7-7.9A6 6 0 0 1 18 8a5 5 0 0 1 0 10H7Z"/>',network:'<circle cx="5" cy="12" r="2"/><circle cx="18" cy="5" r="2"/><circle cx="18" cy="19" r="2"/><path d="m7 11 9-5M7 13l9 5"/>', server:'<rect x="4" y="3" width="16" height="7" rx="2"/><rect x="4" y="14" width="16" height="7" rx="2"/><path d="M8 6.5h.01M8 17.5h.01M14 6.5h3M14 17.5h3"/>', pause:'<path d="M8 5v14M16 5v14"/>', play:'<path d="m8 5 11 7-11 7Z"/>', fit:'<path d="M8 3H3v5M16 3h5v5M3 16v5h5M21 16v5h-5"/>', clock:'<circle cx="12" cy="12" r="8"/><path d="M12 7v5l3 2"/>', alert:'<path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5M12 17h.01"/>', check:'<path d="m5 12 4 4L19 6"/>', plus:'<path d="M12 5v14M5 12h14"/>'};
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${shapes[name] || shapes.network}</svg>`;
  };

  function render(input = {}) {
    const servers = array(input.servers).filter(server => server && typeof server.id === 'string');
    const flows = array(input.flows).filter(flow => flow && typeof flow.server_id === 'string' && text(flow.source_ip));
    const alerts = array(input.alerts).filter(alert => alert && (!alert.server_id || servers.some(server => server.id === alert.server_id)));
    const sessions = array(input.learningSessions ?? input.learning_sessions);
    const now = time(input.now) ?? (typeof input.now === 'number' && Number.isFinite(input.now) ? input.now : Date.now());
    const selected = text(input.selectedServerId);
    const synthetic = servers.some(server => server.synthetic === true);
    const prefix = `pseg-map-${++sequence}`;
    const serverById = new Map(servers.map(server => [server.id, server]));
    const activeTargets = new Set(), activeSessionIds = new Map();
    sessions.forEach(session => {
      if (!session || !['active', 'learning'].includes(session.status) || (time(session.expires_at) ?? 0) <= now || (time(session.starts_at) ?? 0) > now) return;
      array(session.server_ids).forEach(id => { activeTargets.add(id); if (!activeSessionIds.has(id)) activeSessionIds.set(id, new Set()); activeSessionIds.get(id).add(session.id); });
    });
    const learning = server => activeTargets.has(server.id) && !server.learning_discovery_pending && !['pending','error','no_listeners','unsupported'].includes(server.learning_discovery_status) && server.collector_status === 'learning' && !server.status_stale && heartbeatFresh(server, now);
    const status = server => server.status === 'offline' || server.status_stale || !heartbeatFresh(server, now) ? 'offline' : server.status === 'warning' || server.apply_status === 'error' ? 'warning' : 'healthy';
    const activeCount = servers.filter(learning).length;
    const locations=L.all(servers), locationByKey=new Map(locations.map(location=>[location.key,location]));
    const allGroups=locations.map(location=>[location.key,location.members]);
    const physicalCount=locations.filter(location=>location.kind==='datacenter').length,cloudCount=locations.filter(location=>location.kind==='cloud').length;
    const displayed = allGroups.slice(0, LIMIT_DCS);
    const anchors = new Map(), nodes = [], dcBoxes = [];
    const height=displayed.length?84+Math.ceil(displayed.length/2)*198+14:282;
    displayed.forEach(([dc, members], index) => {
      const x = displayed.length === 1 || displayed.length % 2 === 1 && index === displayed.length-1 ? 290 : 22 + index % 2 * 520;
      const y = 84 + Math.floor(index / 2) * 198;
      const sorted = [...members].sort((a, b) => (a.id === selected ? -1 : b.id === selected ? 1 : 0) || ({offline:0, warning:1, healthy:2}[status(a)] - {offline:0, warning:1, healthy:2}[status(b)]) || String(a.hostname || a.id).localeCompare(String(b.hostname || b.id)));
      const hasOverflow = sorted.length > LIMIT_HOSTS;
      const visible = sorted.slice(0, hasOverflow ? LIMIT_HOSTS - 1 : LIMIT_HOSTS);
      visible.forEach((server, number) => {
        const nx = x + 15 + number % 3 * 147, ny = y + 60 + Math.floor(number / 3) * 40;
        const anchor = {x: nx + 70, y: ny + 17, key: server.id, dc, ids: [server.id]};
        anchors.set(server.id, anchor);
        nodes.push({server, x:nx, y:ny, anchor});
      });
      let overflow = null;
      if (hasOverflow) {
        const hidden = sorted.slice(LIMIT_HOSTS - 1);
        overflow = {x:x + 15 + 2 * 147, y:y + 60 + 2 * 40, count:hidden.length, ids:hidden.map(server => server.id), key:`dc-overflow-${index}`};
        hidden.forEach(server => anchors.set(server.id, {x:overflow.x + 70, y:overflow.y + 17, key:overflow.key, dc, ids:overflow.ids}));
      }
      dcBoxes.push({dc, members, x, y, overflow});
    });
    const ipOwners = new Map();
    servers.forEach(server => array(server.ips).forEach(ip => { const key = address(ip); if (!key) return; if (!ipOwners.has(key)) ipOwners.set(key, new Set()); ipOwners.get(key).add(server.id); }));
    const externalIPs = new Set(), edgeMap = new Map();
    let omittedTargets = 0, latestObserved = null;
    flows.forEach(flow => {
      const target = serverById.get(flow.server_id);
      if (!target) return;
      const stamp = time(flow.last_seen);
      if (stamp !== null && stamp <= now + 30000) latestObserved = Math.max(latestObserved ?? 0, stamp);
      const end = anchors.get(target.id);
      if (!end) { omittedTargets++; return; }
      const owners = ipOwners.get(address(flow.source_ip));
      const sourceId = owners?.size === 1 ? [...owners][0] : null;
      const start = sourceId && anchors.get(sourceId);
      const source = start || {x:520, y:56, key:'external', ids:sourceId ? [sourceId] : []};
      if (!start) externalIPs.add(text(flow.source_ip));
      const key = `${source.key}\u0000${end.key}`;
      if (!edgeMap.has(key)) edgeMap.set(key, {start:source, end, ids:new Set(), counts:{connections:0,packets:0,log_records:0}, ports:new Set(), latest:null, active:false, verdicts:new Set()});
      const edge = edgeMap.get(key);
      if (sourceId) edge.ids.add(sourceId);
      edge.ids.add(target.id);
      const unit = flow.capture_kind === 'accepted_connection' ? 'connections' : flow.capture_kind === 'denied_packet' ? 'packets' : 'log_records';
      edge.counts[unit] += count(flow.count);
      edge.ports.add(`${flow.port}/${text(flow.protocol) || 'tcp'}`);
      edge.verdicts.add(text(flow.verdict));
      if (stamp !== null) edge.latest = Math.max(edge.latest ?? 0, stamp);
      edge.active ||= learning(target) && fresh(flow.last_seen, now, 120) && !!flow.session_id && activeSessionIds.get(target.id)?.has(flow.session_id);
    });
    const allEdges = [...edgeMap.values()].sort((a, b) => Number(b.active) - Number(a.active) || (b.latest ?? 0) - (a.latest ?? 0));
    const edges = allEdges.slice(0, LIMIT_EDGES);
    const edgeHTML = edges.map((edge, index) => {
      const {start, end} = edge;
      let d;
      if (start.key === end.key) d = `M${start.x - 18},${start.y - 16} C${start.x - 45},${start.y - 62} ${start.x + 45},${start.y - 62} ${start.x + 18},${start.y - 16}`;
      else if (Math.abs(start.y - end.y) < 22) d = `M${start.x},${start.y - 16} C${start.x},${start.y - 55} ${end.x},${end.y - 55} ${end.x},${end.y - 16}`;
      else { const direction = end.y > start.y ? 1 : -1, startY = start.y + (start.key === 'external' ? 0 : 17 * direction), endY = end.y - 17 * direction, middle = (startY + endY) / 2; d = `M${start.x},${startY} C${start.x},${middle} ${end.x},${middle} ${end.x},${endY}`; }
      const denied = edge.verdicts.size === 1 && edge.verdicts.has('denied');
      const counts = Object.entries(edge.counts).filter(([,value]) => value > 0).map(([unit,value]) => `${compact(value)} ${{connections:'transport connections',packets:'denied packets',log_records:'legacy log records'}[unit]}`).join(' / ');
      const title = `${edge.start.key === 'external' ? 'External / other source' : serverById.get(edge.start.key)?.hostname || 'Grouped hosts'} → ${serverById.get(edge.end.key)?.hostname || 'Grouped hosts'} · ${[...edge.ports].join(', ')} · ${counts} · last observed ${age(edge.latest, now)}`;
      return `<g class="pseg-edge${edge.active ? ' is-current' : ' is-historical'}${denied ? ' is-denied' : ''}" data-server-ids="${escape(JSON.stringify([...edge.ids]))}" aria-label="${escape(title)}"><title>${escape(title)}</title><path class="pseg-edge-halo" d="${d}"/><path class="pseg-edge-line" d="${d}" marker-end="url(#${prefix}-arrow)"/>${edge.active ? `<path class="pseg-edge-pulse" style="animation-delay:-${index % 7 * .31}s" d="${d}"/>` : ''}</g>`;
    }).join('');
    const nodeHTML = nodes.map(({server, x, y}) => {
      const kind = status(server), isLearning = learning(server), heartbeat = kind !== 'offline' && heartbeatFresh(server, now);
      const ports = [...new Set(array(server.listeners).map(listener => listener.port))].slice(0, 3).join(' · ');
      const label = `${server.hostname || server.id} · ${kind} · heartbeat ${age(server.last_seen, now)}${ports ? ` · listening ${ports}` : ' · no listeners reported'}${isLearning ? ' · collecting observed traffic' : ''}${server.synthetic ? ' · synthetic demo endpoint' : ''}`;
      return `<g class="pseg-node is-${kind}${heartbeat ? ' has-fresh-heartbeat' : ''}${isLearning ? ' is-learning' : ''}${server.id === selected ? ' is-selected' : ''}" transform="translate(${x} ${y})" tabindex="0" role="button" aria-label="${escape(label)}" aria-pressed="${server.id === selected}" data-server-id="${escape(server.id)}"><title>${escape(label)}</title><rect class="pseg-node-halo" x="-3" y="-3" width="146" height="40" rx="8"/><rect class="pseg-node-body" width="140" height="34" rx="5"/><g class="pseg-server-glyph" transform="translate(10 8)"><rect width="11" height="7" rx="1"/><rect y="9" width="11" height="7" rx="1"/><path d="M3 3.5h.1M3 12.5h.1M7 3.5h2M7 12.5h2"/></g><text class="pseg-hostname" x="29" y="14">${escape(short(server.hostname || server.id, 16))}</text><text class="pseg-hostmeta" x="29" y="27">${escape(isLearning ? `● learning${ports ? ' · ' + short(ports, 12) : ''}` : ports ? short(ports, 18) : 'no listeners')}</text><circle class="pseg-node-status" cx="130" cy="9" r="2.2"/></g>`;
    }).join('');
    const boxHTML = dcBoxes.map(({dc, members, x, y, overflow}) => {
      const location = locationByKey.get(dc), healthy = members.filter(server => status(server) === 'healthy').length;
      const attention = members.length - healthy, ids = new Set(members.map(server=>server.id));
      const openAlerts = alerts.filter(alert=>ids.has(alert.server_id)&&alert.status!=='resolved'&&!alert.resolved_at).length;
      const glyph = icon(location.kind==='cloud'?'cloud':location.kind==='datacenter'?'building':'network').replace('<svg ',`<svg x="${x+15}" y="${y+13}" width="17" height="17" `);
      return `<g class="pseg-dc" data-location-type="${escape(location.kind)}" data-dc-group="${escape(dc)}"><rect class="pseg-dc-background" x="${x}" y="${y}" width="474" height="184" rx="10"/><path class="pseg-dc-divider" d="M${x+15} ${y+49}H${x+459}"/><g class="pseg-dc-button" tabindex="0" role="button" aria-label="Filter ${escape(location.typeLabel)} ${escape(location.label)}, ${members.length} endpoints" data-location-key="${escape(dc)}"><title>${escape(location.typeLabel)} · ${escape(location.label)}${location.account?' · Account '+escape(location.account):''}</title><rect x="${x+9}" y="${y+7}" width="330" height="36" rx="5"/>${glyph}<text class="pseg-dc-name" x="${x+41}" y="${y+23}">${escape(short(location.label,32))}</text><text class="pseg-location-kind" x="${x+41}" y="${y+39}">${escape(location.typeLabel)}${location.account?' · '+escape(short(location.account,22)):''}</text></g><text class="pseg-dc-health${attention?' has-attention':''}" x="${x+458}" y="${y+22}" text-anchor="end">${healthy}/${members.length} healthy</text><text class="pseg-dc-count${openAlerts?' has-alerts':''}" x="${x+458}" y="${y+39}" text-anchor="end">${openAlerts} open alert${openAlerts===1?'':'s'} · ${members.length} host${members.length===1?'':'s'}</text>${overflow?`<g class="pseg-overflow pseg-dc-button" transform="translate(${overflow.x} ${overflow.y})" tabindex="0" role="button" data-location-key="${escape(dc)}" aria-label="${overflow.count} additional endpoints in ${escape(location.label)}; filter to explore"><rect width="140" height="34" rx="5"/><text x="70" y="14" text-anchor="middle">+${overflow.count} endpoints</text><text class="pseg-overflow-label" x="70" y="27" text-anchor="middle">filter to explore</text></g>`:''}</g>`;
    }).join('');
    const locationBars = allGroups.slice(0,LIMIT_DCS).map(([key,members])=>{const location=locationByKey.get(key),healthy=members.filter(server=>status(server)==='healthy').length;return `<button class="pseg-location-bar" data-location-key="${escape(key)}" aria-label="Filter ${escape(location.label)}, ${members.length} endpoints"><span class="pseg-location-bar-icon">${icon(location.kind==='cloud'?'cloud':location.kind==='datacenter'?'building':'network')}</span><span class="pseg-location-bar-body"><span><strong>${escape(short(location.label,32))}</strong><small>${members.length} host${members.length===1?'':'s'}</small></span><i><b style="width:${members.length?healthy/members.length*100:0}%"></b></i></span><span class="pseg-location-bar-stat">${healthy} healthy</span></button>`;}).join('');
    const events = [];
    alerts.forEach(alert => {
      const stamp = time(alert.updated_at || alert.created_at);
      if (stamp === null || stamp > now + 30000) return;
      const resolved = alert.status === 'resolved' || alert.kind === 'recovered';
      events.push({stamp, id:text(alert.server_id), kind:resolved ? 'recovery' : 'alert', title:resolved ? 'Endpoint recovered' : alert.kind === 'service_down' ? 'Service listener down' : alert.kind === 'agent_offline' ? 'Heartbeat missing' : 'Security event', detail:text(alert.message) || text(alert.kind).replaceAll('_', ' '), synthetic:serverById.get(alert.server_id)?.synthetic === true});
    });
    array(input.activity).forEach(event=>{const stamp=time(event.created_at);if(stamp===null||stamp>now+30000)return;const action=text(event.action).replace(/[._]/g,' '),details=event.details||{};events.push({stamp,id:text(details.server_id),kind:'audit',title:action?action[0].toUpperCase()+action.slice(1):'Workspace activity',detail:[text(event.actor),text(details.name)||text(details.hostname)||text(details.group_id)].filter(Boolean).join(' · '),synthetic:details.synthetic===true});});
    servers.forEach(server => { const stamp = time(server.last_seen); if (stamp !== null && stamp <= now + 30000) events.push({stamp, id:server.id, kind:'heartbeat', title:'Heartbeat received', detail:server.hostname || server.id, synthetic:server.synthetic === true}); });
    const recentEvents = events.sort((a, b) => b.stamp - a.stamp || (a.kind === 'heartbeat' ? 1 : -1)).slice(0, 6);
    const eventHTML=recentEvents.map(event=>{const tag=event.id?'button':'article';return `<${tag} class="pseg-event is-${event.kind}" ${event.id?`type="button" data-server-id="${escape(event.id)}"`:''} aria-label="${escape(`${event.title}: ${event.detail}, ${age(event.stamp,now)}`)}"><span class="pseg-event-icon">${icon(event.kind==='alert'?'alert':event.kind==='recovery'?'check':event.kind==='audit'?'check':'server')}</span><span class="pseg-event-body"><strong>${escape(event.title)}</strong><span title="${escape(event.detail)}">${escape(short(event.detail,68))}</span><time datetime="${escape(new Date(event.stamp).toISOString())}">${escape(age(event.stamp,now))}${event.synthetic?' · synthetic':''}</time></span>${event.id?'<span class="pseg-event-arrow" aria-hidden="true">↗</span>':''}</${tag}>`;}).join('');
    const hiddenDCs = allGroups.length - displayed.length;
    const hiddenServers = allGroups.slice(LIMIT_DCS).reduce((sum, entry) => sum + entry[1].length, 0);
    const edgeCurrent = edges.filter(edge => edge.active).length;
    const externalHTML = externalIPs.size ? `<g class="pseg-external"><rect x="403" y="12" width="234" height="44" rx="7"/><circle cx="419" cy="28" r="3"/><text x="430" y="30">External / other sources</text><text class="pseg-external-detail" x="430" y="44">${externalIPs.size} observed source IP${externalIPs.size === 1 ? '' : 's'} · outside this view</text></g>` : `<text class="pseg-map-caption" x="520" y="34" text-anchor="middle">${edges.length ? 'Observed host-to-host communication' : 'Logical infrastructure grouped by location'}</text>`;
    return `<section class="pseg-topology${selected ? ' has-selection' : ''}" data-paused="${paused}" aria-label="Infrastructure topology"><header class="pseg-topology-header"><div class="pseg-topology-heading"><span class="pseg-topology-symbol">${icon('network')}</span><div><div class="pseg-topology-eyebrow">INFRASTRUCTURE TOPOLOGY${synthetic ? '<span class="pseg-synthetic-label">SYNTHETIC</span>' : ''}</div><h2>Infrastructure map <span>Data centres & cloud</span></h2><p>${physicalCount} data centre${physicalCount===1?'':'s'} · ${cloudCount} cloud region${cloudCount===1?'':'s'} <span class="pseg-heading-separator">/</span> ${activeCount ? `<span class="pseg-capture-indicator"></span>${activeCount} endpoint${activeCount === 1 ? '' : 's'} collecting flows` : 'Historical flow observations'}</p></div></div><div class="pseg-topology-tools"><button type="button" data-topology-action="location-help" aria-label="How location grouping works" title="How location grouping works">${icon('network')}<span>Locations</span></button><button type="button" data-topology-action="pause" aria-pressed="${paused}" aria-label="${paused ? 'Resume' : 'Pause'} topology animation" title="${paused ? 'Resume' : 'Pause'} animation">${icon(paused ? 'play' : 'pause')}<span>${paused ? 'Resume' : 'Pause'}</span></button><button type="button" data-topology-action="fit" title="Fit full topology" aria-label="Fit full topology">${icon('fit')}</button></div></header><div class="pseg-topology-layout"><div class="pseg-map-wrap"><div class="pseg-map-status"><span>${displayed.length} OF ${allGroups.length} LOCATIONS</span><span>${servers.length} ENDPOINT${servers.length===1?'':'S'} <i>·</i> ${edges.length} OBSERVED LINKS</span></div>${servers.length ? `<svg class="pseg-map" viewBox="0 0 1040 ${height}" data-original-viewbox="0 0 1040 ${height}" role="group" aria-label="Logical location groups and observed communication paths. Coordinates are not geographic. Tab to a server, press Enter to inspect it."><defs><pattern id="${prefix}-grid" width="20" height="20" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r=".65" fill="#e1e2e8" opacity=".75"/></pattern><marker id="${prefix}-arrow" viewBox="0 0 6 6" refX="5" refY="3" markerWidth="4" markerHeight="4" orient="auto-start-reverse"><path d="m0 0 6 3-6 3Z" fill="currentColor"/></marker></defs><rect width="1040" height="${height}" fill="url(#${prefix}-grid)"/>${boxHTML}<g class="pseg-edges">${edgeHTML}</g>${externalHTML}<g class="pseg-nodes">${nodeHTML}</g></svg>` : `<div class="pseg-topology-empty">${icon('network')}<strong>No endpoints match this view</strong><span>Change your filters to explore connected infrastructure.</span></div>`}<div class="pseg-location-breakdown" aria-label="Location health summary">${locationBars}</div><div class="pseg-map-bottom"><span class="pseg-map-hint">Select a server to inspect its connections</span><div class="pseg-zoom-controls" aria-label="Topology zoom"><button type="button" data-topology-action="zoom-out" aria-label="Zoom out">−</button><span data-topology-zoom>100%</span><button type="button" data-topology-action="zoom-in" aria-label="Zoom in">+</button></div></div></div><aside class="pseg-event-rail" aria-label="Recent endpoint events"><div class="pseg-event-heading"><span>Recent activity</span><span class="pseg-event-count">${recentEvents.length}</span></div><p class="pseg-event-caption">${synthetic ? 'Reported synthetic timestamps' : 'Reports, policy changes & alerts'}</p><div class="pseg-events">${eventHTML || '<div class="pseg-events-empty">No reported events in this view.</div>'}</div><a class="pseg-view-activity" href="/activity">View all activity <span aria-hidden="true">↗</span></a><div class="pseg-event-footnote">${icon('clock')}Logical layout · no geographic inference.<br>Traffic appears only while collected.</div></aside></div><footer class="pseg-topology-footer"><div class="pseg-topology-legend"><span><i class="is-healthy"></i>Healthy</span><span><i class="is-warning"></i>Attention</span><span><i class="is-offline"></i>Offline / stale</span><span><b class="pseg-line-sample${edgeCurrent ? ' is-current' : ''}"></b>${edgeCurrent ? 'Recent observation' : 'Last observed'}</span></div><span class="pseg-topology-scope">${hiddenDCs ? `+${hiddenDCs} location${hiddenDCs === 1 ? '' : 's'} · ${hiddenServers} endpoints outside canvas. Refine filters.` : allEdges.length > LIMIT_EDGES || omittedTargets ? 'Links are bounded; refine filters to explore.' : latestObserved !== null ? `Last observed ${escape(age(latestObserved, now))}` : 'No captured flows in this view'}</span></footer></section>`;
  }

  function bind(root, callbacks = {}) {
    const panel = root?.matches?.('.pseg-topology') ? root : root?.querySelector?.('.pseg-topology');
    if (!panel) return () => {};
    let selected = panel.querySelector('.pseg-node.is-selected')?.getAttribute('data-server-id') || '', zoom = 1;
    const edges = [...panel.querySelectorAll('.pseg-edge')].map(element => { let ids; try { ids = JSON.parse(element.getAttribute('data-server-ids') || '[]'); } catch (_) { ids = []; } return {element, ids:new Set(ids)}; });
    const nodes = [...panel.querySelectorAll('.pseg-node')];
    function highlight(id) {
      const related = new Set(id ? [id] : []);
      edges.forEach(edge => { const match = !!id && edge.ids.has(id); edge.element.classList.toggle('is-highlight', match); if (match) edge.ids.forEach(value => related.add(value)); });
      panel.classList.toggle('has-highlight', !!id);
      nodes.forEach(node => { const nodeId = node.getAttribute('data-server-id'); node.classList.toggle('is-related', related.has(nodeId)); node.classList.toggle('is-selected', nodeId === selected); node.setAttribute('aria-pressed', String(nodeId === selected)); });
    }
    function changeZoom(value) {
      zoom = Math.max(1, Math.min(2.5, value));
      const svg = panel.querySelector('.pseg-map');
      if (!svg) return;
      const original = (svg.getAttribute('data-original-viewbox') || '0 0 1040 456').split(' ').map(Number);
      const width = original[2] / zoom, height = original[3] / zoom;
      svg.setAttribute('viewBox', `${(original[2] - width) / 2} ${(original[3] - height) / 2} ${width} ${height}`);
      const label = panel.querySelector('[data-topology-zoom]'); if (label) label.textContent = `${Math.round(zoom * 100)}%`;
    }
    function click(event) {
      const target = event.target.closest?.('[data-topology-action], [data-server-id], [data-location-key], [data-dc]');
      if (!target || !panel.contains(target)) return;
      const action = target.getAttribute('data-topology-action');
      if(action==='location-help'){callbacks.onLocationHelp?.();}
      else if (action === 'pause') {
        paused = !paused; panel.setAttribute('data-paused', String(paused)); target.setAttribute('aria-pressed', String(paused)); target.setAttribute('aria-label', `${paused ? 'Resume' : 'Pause'} topology animation`); target.title = `${paused ? 'Resume' : 'Pause'} animation`; target.innerHTML = `${icon(paused ? 'play' : 'pause')}<span>${paused ? 'Resume' : 'Pause'}</span>`;
      } else if (action === 'fit') changeZoom(1);
      else if (action === 'zoom-in') changeZoom(zoom + .25);
      else if (action === 'zoom-out') changeZoom(zoom - .25);
      else if (target.hasAttribute('data-server-id')) { selected = target.getAttribute('data-server-id'); highlight(selected); callbacks.onServerSelect?.(selected); }
      else if(target.hasAttribute('data-location-key')){const key=target.getAttribute('data-location-key');if(callbacks.onLocationSelect)callbacks.onLocationSelect(key);else {const selector=L.selectorFromKey(key)||{};callbacks.onDCSelect?.(selector.datacenter||selector.dc||'');}}
      else if (target.hasAttribute('data-dc')) callbacks.onDCSelect?.(target.getAttribute('data-dc'));
    }
    function keydown(event) { if ((event.key === 'Enter' || event.key === ' ') && event.target.matches?.('g[role="button"]')) { event.preventDefault(); event.target.dispatchEvent(new MouseEvent('click', {bubbles:true})); } }
    function over(event) { const target = event.target.closest?.('[data-server-id]'); if (target && panel.contains(target)) highlight(target.getAttribute('data-server-id')); }
    function leave(event) { if (!panel.contains(event.relatedTarget)) highlight(selected); else { const next = event.relatedTarget?.closest?.('[data-server-id]'); highlight(next?.getAttribute('data-server-id') || selected); } }
    panel.addEventListener('click', click); panel.addEventListener('keydown', keydown); panel.addEventListener('pointerover', over); panel.addEventListener('pointerout', leave); panel.addEventListener('focusin', over); panel.addEventListener('focusout', leave);
    highlight(selected);
    return () => { panel.removeEventListener('click', click); panel.removeEventListener('keydown', keydown); panel.removeEventListener('pointerover', over); panel.removeEventListener('pointerout', leave); panel.removeEventListener('focusin', over); panel.removeEventListener('focusout', leave); };
  }
  global.PSegraTopology = {render, bind};
})(typeof window !== 'undefined' ? window : globalThis);
