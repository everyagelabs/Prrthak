"""Read-only, bounded-memory common-rule inventory and lazy evidence views."""
import heapq
import json
import re
from functools import lru_cache

from .inventory_views import canonical_servers, rows


def options(value):
    if not isinstance(value,dict): raise ValueError("Firewall query must be an object")
    result={}
    for key in ("server_ids","search_server_ids"):
        ids=value.get(key)
        if ids is not None and (not isinstance(ids,list) or len(ids)>20000 or any(not isinstance(item,str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}",item) for item in ids)):
            raise ValueError("Firewall scope requires at most 20000 enrolled endpoint IDs")
        result[key]=set(ids) if ids is not None else None
    ports=value.get("ports",[])
    if not isinstance(ports,list) or len(ports)>100 or any(not isinstance(item,str) or not re.fullmatch(r"[0-9]{1,5}(?:/(?:tcp|udp))?",item) or not 1<=int(item.split('/')[0])<=65535 for item in ports):
        raise ValueError("Firewall ports must be 1..65535, optionally /tcp or /udp")
    after=value.get("after","")
    limit=value.get("limit",50)
    search=value.get("search","")
    if not isinstance(after,str) or after and not re.fullmatch(r"[a-f0-9]{64}",after) or isinstance(limit,bool) or not isinstance(limit,int) or not 1<=limit<=100 or not isinstance(search,str) or len(search)>256:
        raise ValueError("Invalid firewall page cursor, limit or search")
    view,zone_usage=value.get("view","raw"),value.get("zone_usage","relevant")
    if view not in ("raw","access") or zone_usage not in ("relevant","all"):
        raise ValueError("Invalid firewall query view or zone usage")
    result.update(ports=ports,after=after,limit=limit,search=search,view=view,zone_usage=zone_usage)
    return result


def matches_ports(rule,selections):
    if not selections: return True
    kind,value=rule.get('kind',''),rule.get('value','')
    if 'target' in kind or kind=='rich_rule' and rule.get('action') in ('accept','drop','reject') and not re.search(r'\b(?:port\s+port|service\s+name|protocol\s+value|source-port\s+port)=?',value): return True
    from .firewall import resolved_ports
    for item in resolved_ports(kind,value,rule.get('ports',[])):
        low,_,high=str(item['port']).partition('-')
        for selection in selections:
            port,_,protocol=selection.partition('/')
            if int(low)<=int(port)<=int(high or low) and (not protocol or protocol==item['protocol']): return True
    return False


def snapshot_summary(snapshot):
    return {**{key:snapshot.get(key) for key in ('status','digest','collected_at','last_attempt_at','error','stale')},'rule_count':len(snapshot.get('rules',[])),'summary_only':True}


def zone_usage_evidence(snapshot):
    """Use runtime bindings to describe zone assignment, never traffic usage."""
    if snapshot.get('status') != 'ok' or snapshot.get('stale'):
        return None, set(), set()
    runtime = [rule for rule in snapshot.get('rules', []) if rule['scope'] == 'runtime']
    defaults = {rule['value'] for rule in runtime if rule['kind'] == 'default_zone'}
    bound = {rule['zone'] for rule in runtime if rule['kind'] in ('interface', 'source') and rule['value']}
    reported = {rule['zone'] for rule in runtime if rule['kind'] in ('target', 'zone_target')}
    return next(iter(defaults)) if len(defaults) == 1 else None, bound, reported


def access_zone_usage(rule, evidence):
    if rule['kind'] == 'direct':
        return 'host'
    default, bound, reported = evidence
    zone = rule['zone']
    if zone and zone in bound:
        return 'active'
    if zone and zone == default:
        return 'default'
    if default and zone in reported:
        return 'unbound'
    return 'unknown'


def rich_attributes(tokens, element):
    if element not in tokens:
        return {}, False
    index = tokens.index(element) + 1
    inverted = index < len(tokens) and tokens[index].lower() == 'not'
    if inverted:
        index += 1
    attributes = {}
    for token in tokens[index:]:
        key, separator, value = token.partition('=')
        if not separator:
            break
        attributes[key] = value
    return attributes, inverted


def rich_address(tokens, element, default):
    attributes, inverted = rich_attributes(tokens, element)
    if element not in tokens:
        return default
    for key, label in (('address', ''), ('ipset', 'IP set '), ('mac', 'MAC ')):
        if attributes.get(key):
            return ('Except ' if inverted else '') + label + attributes[key]
    return 'Address not resolved'


def access_description(kind, value):
    """Describe reported access selectors without interpreting rule precedence."""
    from .firewall import direct_fields, rich_tokens

    source, destination = 'Any source', 'Endpoint'
    port_scope, qualifier = 'specific', ''
    if kind in ('target', 'zone_target'):
        port_scope = 'any'
    elif kind == 'service':
        qualifier = value
    elif kind == 'direct':
        fields = direct_fields(value)
        source = fields.get('-s') or ('Any IPv4 source' if value.startswith('ipv4 ') else 'Any IPv6 source')
    elif kind == 'rich_rule':
        tokens = rich_tokens(value)
        family = next((token.split('=', 1)[1] for token in tokens if token.startswith('family=')), '')
        source = rich_address(tokens, 'source', {'ipv4': 'Any IPv4 source', 'ipv6': 'Any IPv6 source'}.get(family, source))
        destination = rich_address(tokens, 'destination', destination)
        if 'service' in tokens:
            qualifier = rich_attributes(tokens, 'service')[0].get('name', '')
        elif 'port' not in tokens:
            if 'source-port' in tokens:
                attrs = rich_attributes(tokens, 'source-port')[0]
                qualifier = attrs.get('protocol', '')
                if attrs.get('port'):
                    source += ' · source port ' + attrs['port'] + ('/' + qualifier if qualifier else '')
                port_scope = 'protocol' if qualifier else 'unresolved'
            elif 'protocol' in tokens:
                qualifier = rich_attributes(tokens, 'protocol')[0].get('value', '')
                port_scope = 'protocol' if qualifier else 'unresolved'
            elif 'icmp-block' in tokens or 'icmp-type' in tokens:
                element = 'icmp-block' if 'icmp-block' in tokens else 'icmp-type'
                port_scope, qualifier = 'icmp', rich_attributes(tokens, element)[0].get('name', '')
            elif all('=' in token or token.lower() in ('rule','source','destination','not','log','nflog','audit','limit','accept','drop','reject') for token in tokens):
                port_scope = 'any'
            else:
                port_scope = 'unresolved'
    return source, destination, port_scope, qualifier


def matches_access_ports(rule, selections, description):
    if not selections:
        return True
    _, _, port_scope, qualifier = description
    if port_scope == 'any':
        return True
    if port_scope == 'protocol':
        return qualifier in ('tcp', 'udp') and any('/' not in item or item.endswith('/' + qualifier) for item in selections)
    if port_scope == 'specific':
        return matches_ports(rule, selections)
    return False


def access_fields(group, description):
    source, destination, port_scope, qualifier = description
    ports = group['ports']
    if port_scope == 'any':
        port_text = 'Any port'
    elif port_scope == 'protocol':
        port_text = 'Any ' + qualifier.upper() + ' port' if qualifier in ('tcp', 'udp', 'sctp', 'dccp') else 'Protocol ' + qualifier
    elif port_scope == 'icmp':
        port_text = 'ICMP' + (' ' + qualifier if qualifier else '')
    elif port_scope == 'specific' and ports:
        port_text = ', '.join(item['port'] + '/' + item['protocol'] for item in ports)
    elif group['port_resolution'] == 'mixed':
        port_text = 'Varies by endpoint or configuration'
    else:
        port_text = 'Service ' + qualifier + ' (ports not reported)' if qualifier else 'Port not reported'
    counts = group.pop('_zone_usage')
    return {'source':source,'destination':destination,'destination_port':port_text,
            'decision':'allow' if group['action']=='accept' else 'deny',
            'zone_usage':next(iter(counts)) if len(counts)==1 else 'mixed','zone_usage_counts':counts}


def endpoint_access_snapshot(server):
    """Project inbound runtime configuration without guessing packet precedence."""
    from .firewall import snapshot_view
    from .store import Store

    snapshot = snapshot_view(server)
    runtime = [rule for rule in snapshot['rules'] if rule['scope'] == 'runtime']
    status = snapshot['status']
    firewall_state = server.get('firewalld_state')
    offline = Store._heartbeat_stale(dict(server)) if server.get('last_seen') else server.get('status') == 'offline'
    if status == 'missing' or status == 'error' and not runtime:
        state = 'unavailable'
    elif snapshot['stale'] or offline or firewall_state in ('not-running', 'stopped', 'inactive', 'failed') or status == 'error':
        state = 'stale'
    elif status == 'partial':
        state = 'partial'
    else:
        state = 'reported'
    row_status = {'reported': 'Reported runtime', 'partial': 'Partial inventory', 'stale': 'Last reported'}.get(state)
    reason = {
        'unavailable': 'Current firewalld inventory is unavailable.',
        'stale': 'Showing the last runtime snapshot. Current rules and bindings are unverified.',
        'partial': 'The agent reported incomplete firewall inventory.',
    }.get(state)

    # The original snapshot can retain bindings after a collection failure.
    # Preserve positive evidence but avoid inferring an unbound zone from a partial report.
    default, bound, known = zone_usage_evidence({**snapshot, 'status': 'ok', 'stale': False})
    evidence = default, bound, known if status == 'ok' else set()
    bindings = {name: {'name': name, 'usage': 'active' if name in bound else 'default', 'is_default': name == default,
                       'interfaces': [], 'sources': []} for name in sorted(bound | ({default} if default else set()))}
    for rule in runtime:
        if rule['zone'] in bindings and rule['kind'] in ('interface', 'source') and rule['value']:
            field = 'interfaces' if rule['kind'] == 'interface' else 'sources'
            bindings[rule['zone']][field].append(rule['value'])
    for zone in bindings.values():
        zone['interfaces'].sort()
        zone['sources'].sort()

    labels = {'target': 'Zone fallback', 'zone_target': 'Zone fallback', 'direct': 'Direct INPUT rule',
              'port': 'Port rule', 'rich_rule': 'Rich rule'}
    entries = []
    for rule in runtime if row_status else ():
        kind = rule['kind']
        if kind not in ('service', *labels) or rule['action'] not in ('accept', 'drop', 'reject'):
            continue
        usage = access_zone_usage(rule, evidence)
        if usage == 'unbound':
            continue
        description = access_description(kind, rule['value'])
        fields = access_fields({'ports': rule['ports'], 'action': rule['action'], 'port_resolution': 'consistent',
                                '_zone_usage': {usage: 1}}, description)
        entries.append({'policy_name': rule['value'] if kind == 'service' else labels[kind],
                        'sources': [fields['source']], 'source_groups': [], 'destination_port': fields['destination_port'],
                        'destination': fields['destination'], 'action': fields['decision'], 'zone': rule['zone'],
                        'status': row_status, 'zone_usage': usage})
    entries.sort(key=lambda row: (row['zone'], row['policy_name'], row['destination_port'], row['sources'], row['action']))
    return {'state': state, 'observed_at': snapshot.get('collected_at'), 'reason': reason, 'rows': entries, 'total': len(entries),
            'zones': list(bindings.values())}


def plan_summaries(store,db,selected=None,ports=(),search='',search_ids=None,limit=20):
    from .firewall import public_plan
    result=[]
    for row in rows(db,'SELECT data FROM firewall_changes ORDER BY id'):
        plan=json.loads(row[0])
        ids=set(plan.get('server_ids',[]))
        if selected is not None: ids &= selected
        if search and search.casefold() not in plan.get('name','').casefold(): ids &= search_ids or set()
        if ports:
            evidence=plan.get('preview',{})
            ids &= {item.get('server_id') for item in evidence.get('before',[])+evidence.get('after',[]) if matches_ports(item,ports)}
        if not ids: continue
        # Detailed canonical preview is fetched only when an operator opens it.
        summary={key:plan.get(key) for key in ('id','name','status','operation','created_at','expires_at','scopes','requires_double_confirmation')}
        summary.update(target_count=len(plan.get('server_ids',[])),matching_server_ids=sorted(ids),matching_host_count=len(ids),result_counts={name:sum(item.get('status')==name for item in plan.get('results',{}).values()) for name in ('applied','preview','failed','conflict')},summary_only=True)
        result.append(summary)
        result.sort(key=lambda item:(item.get('created_at') or '',item['id']),reverse=True)
        del result[limit:]
    return result


def matching_rules(snapshot, server_id, ports, search, search_ids, describe, zone_usage):
    local = {}
    for rule in snapshot.get('rules', []):
        local.setdefault(rule['logical_key'], []).append(rule)
    usage_evidence = zone_usage_evidence(snapshot) if describe else None
    needle = search.casefold()
    for key, host_rules in local.items():
        rule = host_rules[0]
        usage = None
        if describe:
            if rule['kind'] not in ('service', 'port', 'rich_rule', 'target', 'zone_target', 'direct') or rule['action'] not in ('accept', 'drop', 'reject'):
                continue
            usage = access_zone_usage(rule, usage_evidence)
            if usage == 'unbound' and zone_usage != 'all':
                continue
        direct = not needle or needle in json.dumps([rule.get(field) for field in ('zone', 'kind', 'value', 'action', 'risk')], ensure_ascii=False).casefold()
        if describe and not direct:
            fields = describe(rule['kind'], rule['value'])
            direct = any(needle in value.casefold() for value in (*fields, 'allow' if rule['action'] == 'accept' else 'deny', usage))
        if not direct and (not search_ids or server_id not in search_ids):
            continue
        if describe and ports:
            fields = describe(rule['kind'], rule['value'])
            matched = [item for item in host_rules if matches_access_ports(item, ports, fields)]
        else:
            matched = [item for item in host_rules if matches_ports(item, ports)]
        if matched:
            yield key, host_rules, matched, usage


def inventory(store,selected=None,*,after='',limit=50,ports=(),search='',search_server_ids=None,include_snapshots=None,view='raw',zone_usage='relevant'):
    from .firewall import snapshot_view
    checked=options({'server_ids':list(selected) if selected is not None else None,'after':after,'limit':limit,'ports':list(ports),'search':search,'search_server_ids':list(search_server_ids) if search_server_ids is not None else None,'view':view,'zone_usage':zone_usage})
    selected,ports,search_ids=checked['server_ids'],checked['ports'],checked['search_server_ids']
    access = view == 'access'
    describe = lru_cache(maxsize=512)(access_description) if access else None
    if access: include_snapshots=False
    if include_snapshots is None: include_snapshots=selected is not None and len(selected)==1
    if include_snapshots and (selected is None or len(selected)>1): raise ValueError('Fetch full firewall evidence for one endpoint at a time')
    candidates,heap,snapshots={},[],[]
    matching_hosts,high_hosts=set(),set()
    with store.read_meta() as db:
        for server in canonical_servers(db,selected):
            snapshot=snapshot_view(server)
            snapshots.append({'server_id':server['id'],'hostname':server['hostname'],'snapshot':snapshot if include_snapshots else snapshot_summary(snapshot)})
            for key,host_rules,matched,usage in matching_rules(snapshot, server['id'], ports, search, search_ids, describe, zone_usage):
                rule=host_rules[0]
                matching_hosts.add(server['id'])
                if any(item.get('risk')=='high' for item in host_rules): high_hosts.add(server['id'])
                if after and key<=after: continue
                if key not in candidates:
                    rank=int(key,16)
                    if len(candidates)>=limit+1 and rank>=-heap[0][0]: continue
                    candidates[key]={'rule_key':key,**{field:rule.get(field) for field in ('zone','kind','value','action','risk')},'editable':True,'reason':'','scopes':set(),'server_ids':set(),'scope_host_counts':{'runtime':set(),'permanent':set()},'_port_versions':set(),'_port_hosts':set()}
                    if access:
                        candidates[key]['_zone_usage']={}
                    heapq.heappush(heap,(-rank,key))
                    if len(candidates)>limit+1:
                        _,discard=heapq.heappop(heap);del candidates[discard]
                group=candidates[key]
                group['server_ids'].add(server['id'])
                if access:
                    counts=group['_zone_usage']
                    counts[usage]=counts.get(usage,0)+1
                for item in host_rules:
                    # Only equality versus mixed definitions is needed; never
                    # retain every host's different resolved service definition.
                    if len(group['_port_versions'])<2: group['_port_versions'].add(json.dumps(item.get('ports',[]),sort_keys=True))
                    if item.get('ports'): group['_port_hosts'].add(server['id'])
                    group['scopes'].add(item['scope']);group['scope_host_counts'][item['scope']].add(server['id'])
                    # Runtime target mutation needs a global reload, which this
                    # exact adapter never performs. It must not hide a safely
                    # editable permanent target sharing the same logical key.
                    runtime_target = item.get('kind')=='target' and item['scope']=='runtime'
                    if (not item.get('editable') and not runtime_target) or snapshot.get('status')!='ok' or snapshot.get('stale'):
                        group['editable']=False;group['reason']=item.get('reason') or 'A matching endpoint snapshot is incomplete or stale'
                if ports and len(matched)!=len(host_rules):
                    group['editable']=False;group['reason']='Different service ports are reported across configuration scopes. Clear the port filter and review scope-specific definitions.'
        keys=sorted(candidates)
        has_more=len(keys)>limit
        result=[]
        for key in keys[:limit]:
            group=candidates[key]
            if group.get('kind')=='target':
                group['editable']=group['editable'] and group['scope_host_counts']['permanent']==group['server_ids']
                group['editable_scopes']=['permanent'] if group['editable'] else []
                if group['editable']:
                    group['reason']='Permanent target replacement only; the running target is unchanged and no reload is performed'
            group['scopes']=sorted(group['scopes']);group['server_ids']=sorted(group['server_ids']);group['host_count']=len(group['server_ids'])
            group['scope_host_counts']={scope:len(ids) for scope,ids in group['scope_host_counts'].items()}
            versions=group.pop('_port_versions');group['port_definition_host_count']=len(group.pop('_port_hosts'))
            group['ports']=json.loads(next(iter(versions))) if len(versions)==1 else []
            group['port_resolution']='consistent' if group['ports'] else 'mixed' if len(versions)>1 else 'unresolved'
            if access:
                group.update(access_fields(group,describe(group['kind'],group['value'])))
            result.append(group)
        changes=plan_summaries(store,db,selected,ports,search,search_ids)
    return {'servers':snapshots,'common_rules':result,'changes':changes,'scoped_query':True,'pagination':{'after':after,'limit':limit,'has_more':has_more,'next_cursor':keys[limit-1] if has_more else None},'summary':{'reported_snapshots':sum(item['snapshot'].get('status')!='missing' for item in snapshots),'matching_endpoint_count':len(matching_hosts),'high_risk_endpoint_count':len(high_hosts)},'plan_limit':20,**({'view':'access'} if access else {})}
