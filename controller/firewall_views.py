"""Read-only, bounded-memory common-rule inventory and lazy evidence views."""
import heapq
import json
import re

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
    result.update(ports=ports,after=after,limit=limit,search=search)
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


def inventory(store,selected=None,*,after='',limit=50,ports=(),search='',search_server_ids=None,include_snapshots=None):
    from .firewall import snapshot_view
    checked=options({'server_ids':list(selected) if selected is not None else None,'after':after,'limit':limit,'ports':list(ports),'search':search,'search_server_ids':list(search_server_ids) if search_server_ids is not None else None})
    selected,ports,search_ids=checked['server_ids'],checked['ports'],checked['search_server_ids']
    if include_snapshots is None: include_snapshots=selected is not None and len(selected)==1
    if include_snapshots and (selected is None or len(selected)>1): raise ValueError('Fetch full firewall evidence for one endpoint at a time')
    candidates,heap,snapshots={},[],[]
    matching_hosts,high_hosts=set(),set()
    with store.read_meta() as db:
        for server in canonical_servers(db,selected):
            snapshot=snapshot_view(server)
            snapshots.append({'server_id':server['id'],'hostname':server['hostname'],'snapshot':snapshot if include_snapshots else snapshot_summary(snapshot)})
            local={}
            for rule in snapshot.get('rules',[]): local.setdefault(rule['logical_key'],[]).append(rule)
            for key,host_rules in local.items():
                rule=host_rules[0]
                direct=not search or search.casefold() in json.dumps([rule.get(field) for field in ('zone','kind','value','action','risk')],ensure_ascii=False).casefold()
                if not direct and server['id'] not in (search_ids or set()): continue
                matched=[item for item in host_rules if matches_ports(item,ports)]
                if not matched: continue
                matching_hosts.add(server['id'])
                if any(item.get('risk')=='high' for item in host_rules): high_hosts.add(server['id'])
                if after and key<=after: continue
                if key not in candidates:
                    rank=int(key,16)
                    if len(candidates)>=limit+1 and rank>=-heap[0][0]: continue
                    candidates[key]={'rule_key':key,**{field:rule.get(field) for field in ('zone','kind','value','action','risk')},'editable':True,'reason':'','scopes':set(),'server_ids':set(),'scope_host_counts':{'runtime':set(),'permanent':set()},'_port_versions':set(),'_port_hosts':set()}
                    heapq.heappush(heap,(-rank,key))
                    if len(candidates)>limit+1:
                        _,discard=heapq.heappop(heap);del candidates[discard]
                group=candidates[key]
                group['server_ids'].add(server['id'])
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
            result.append(group)
        changes=plan_summaries(store,db,selected,ports,search,search_ids)
    return {'servers':snapshots,'common_rules':result,'changes':changes,'scoped_query':True,'pagination':{'after':after,'limit':limit,'has_more':has_more,'next_cursor':keys[limit-1] if has_more else None},'summary':{'reported_snapshots':sum(item['snapshot'].get('status')!='missing' for item in snapshots),'matching_endpoint_count':len(matching_hosts),'high_risk_endpoint_count':len(high_hosts)},'plan_limit':20}
