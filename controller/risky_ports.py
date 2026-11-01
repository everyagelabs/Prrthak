"""Source-backed listener review indicators. Never firewall mutations or CVE verdicts."""
from __future__ import annotations
import copy
import ipaddress
import json
import re
from .store import digest, stamp

SETTING='risky_port_catalog'
SOURCES={
 'cisa_services':{'title':'CISA: weak controls and exposed remote services','url':'https://www.cisa.gov/sites/default/files/publications/AA22-137A-Weak_Security_Controls_and_Practices_Routinely_Exploited_for_Initial_Access.pdf'},
 'cisa_hardening':{'title':'CISA: securing network infrastructure','url':'https://www.cisa.gov/sites/default/files/ar-16-20173.pdf'},
 'iana':{'title':'IANA service and transport port registry','url':'https://www.iana.org/assignments/service-names-port-numbers/'},
 'docker':{'title':'Docker: protect daemon access','url':'https://docs.docker.com/engine/security/protect-access/'},
 'redis':{'title':'Redis security model','url':'https://redis.io/docs/latest/operate/oss_and_stack/management/security/'},
 'cert_in':{'title':'CERT-In directions, 28 April 2022','url':'https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf'},
 'rbi_it':{'title':'RBI IT Governance, Risk, Controls and Assurance Practices, 2023','url':'https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=12562'},
 'rbi_payment':{'title':'RBI Digital Payment Security Controls, 2021','url':'https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=12032'},
}

def _rule(identifier,name,port,protocol,severity,reason,action,category='remote_access',source='cisa_services',end=None):
 return {'id':identifier,'name':name,'port_start':port,'port_end':end or port,'protocol':protocol,'severity':severity,'reason':reason,'recommendation':action,'category':category,'enabled':True,'source_ids':[source,'iana']}

DEFAULT_RULES=[
 _rule('ftp','FTP',21,'tcp','high','FTP can transmit credentials and data without encryption; TLS use is not established by a listener.','Verify TLS or replace with an approved encrypted transfer service.',source='cisa_hardening'),
 _rule('telnet','Telnet',23,'tcp','high','Telnet commonly exposes remote login traffic in cleartext.','Replace with an approved encrypted administration service.',source='cisa_hardening'),
 _rule('tftp','TFTP',69,'udp','high','TFTP commonly lacks user authentication and transport encryption.','Disable when unnecessary; limit required access to approved provisioning hosts.',source='cisa_hardening'),
 _rule('rpcbind-tcp','RPC service discovery',111,'tcp','medium','RPC discovery can reveal network services and facilitate access to shared resources.','Limit to required peers and verify the underlying RPC services.',category='file_sharing'),
 _rule('rpcbind-udp','RPC service discovery',111,'udp','medium','RPC discovery can reveal network services and facilitate access to shared resources.','Limit to required peers and verify the underlying RPC services.',category='file_sharing'),
 _rule('netbios-name','NetBIOS name service',137,'udp','medium','Legacy name discovery can aid reconnaissance across network segments.','Restrict discovery to required hosts and remove unused legacy services.',category='file_sharing'),
 _rule('netbios-datagram','NetBIOS datagram',138,'udp','medium','Legacy datagram sharing can extend access across application boundaries.','Restrict to required hosts; remove unused legacy sharing.',category='file_sharing'),
 _rule('netbios-session','NetBIOS session',139,'tcp','high','Legacy file-sharing access can support unauthorized access or lateral movement.','Restrict to explicit business peers and review authentication.',category='file_sharing'),
 _rule('smb','SMB file sharing',445,'tcp','high','SMB is a high-risk remote service when unnecessarily exposed or poorly controlled.','Restrict to approved sharing peers; review patching and authentication.',category='file_sharing'),
 _rule('rsh','Legacy remote shell',514,'tcp','high','Legacy remote-shell authentication and transport require security review.','Replace with encrypted, strongly authenticated administration.',source='cisa_hardening'),
 _rule('snmp','SNMP',161,'udp','medium','The listener does not establish whether secure SNMPv3 or weak community access is used.','Verify SNMPv3 and restrict monitoring sources.',category='management',source='cisa_hardening'),
 _rule('ldap','LDAP',389,'tcp','medium','Directory traffic and authentication may be exposed unless transport protection is configured.','Verify StartTLS or approved encrypted directory access.',category='identity',source='cisa_hardening'),
 _rule('nfs-tcp','NFS',2049,'tcp','medium','Network file access can cross server and application trust boundaries.','Review exports and restrict approved clients.',category='file_sharing'),
 _rule('nfs-udp','NFS',2049,'udp','medium','Network file access can cross server and application trust boundaries.','Review exports and restrict approved clients.',category='file_sharing'),
 _rule('rdp','Remote Desktop',3389,'tcp','high','Remote Desktop is a high-risk remote-access service when insufficiently restricted.','Limit administration sources and verify strong authentication.'),
 _rule('rdp-udp','Remote Desktop transport',3389,'udp','high','Remote Desktop transport requires the same approved administration boundary.','Limit administration sources and review the associated RDP service.'),
 _rule('vnc','VNC remote desktop',5900,'tcp','high','Remote screen access can expose privileged sessions if authentication or transport is weak.','Restrict administration peers and verify encryption/authentication.',end=5909),
 _rule('x11','X11 display',6000,'tcp','high','Network display access may expose screen contents or input control.','Disable TCP display access when unnecessary; use an approved protected channel.',end=6063),
 _rule('docker-api','Docker daemon API',2375,'tcp','high','This is a commonly used plain-HTTP Docker API port; unrestricted daemon control can compromise a host.','Use a protected local socket or authenticated TLS/SSH and restrict access.',category='management',source='docker'),
 _rule('etcd-client','etcd client API',2379,'tcp','medium','Quorum data access is sensitive infrastructure and should have a narrow trusted audience.','Verify mTLS, authorization and controller-only access.',category='management',source='cisa_hardening'),
 _rule('etcd-peer','etcd peer API',2380,'tcp','medium','Quorum peer traffic should be restricted to approved cluster members.','Verify peer mTLS and explicit member access.',category='management',source='cisa_hardening'),
 _rule('mysql','MySQL / MariaDB',3306,'tcp','medium','A database listener exposes a sensitive data service to its network boundary.','Allow only approved application and administration sources; verify authentication/TLS.',category='database',source='cisa_hardening'),
 _rule('postgresql','PostgreSQL',5432,'tcp','medium','A database listener exposes a sensitive data service to its network boundary.','Allow only approved application and administration sources; verify authentication/TLS.',category='database',source='cisa_hardening'),
 _rule('mssql','Microsoft SQL Server',1433,'tcp','medium','A database listener exposes a sensitive data service to its network boundary.','Restrict approved clients and verify authentication/TLS.',category='database',source='cisa_hardening'),
 _rule('redis','Redis',6379,'tcp','high','Redis expects a trusted client boundary; broad access can expose data or administrative operations.','Restrict approved clients and verify ACLs, authentication and TLS.',category='database',source='redis'),
 _rule('mongodb','MongoDB',27017,'tcp','medium','A database listener exposes a sensitive data service to its network boundary.','Restrict approved clients and verify authentication/TLS.',category='database',source='cisa_hardening'),
 _rule('elastic-http','Elasticsearch HTTP API',9200,'tcp','medium','Search and administrative APIs can expose indexed data or control operations.','Restrict approved clients and verify API authentication/TLS.',category='database',source='cisa_hardening'),
 _rule('memcached-tcp','Memcached',11211,'tcp','high','A cache listener may expose application data to unintended clients.','Bind and filter to approved application clients.',category='database',source='cisa_hardening'),
 _rule('memcached-udp','Memcached UDP',11211,'udp','high','UDP cache access can expose data or provide an amplification surface when reachable.','Disable unnecessary UDP access and restrict approved clients.',category='database',source='cisa_hardening'),
]

def configuration(store,db):
 row=store._get(db,'maintenance_settings',SETTING)
 return copy.deepcopy(row) if row else {'id':SETTING,'revision':0,'rules':copy.deepcopy(DEFAULT_RULES),'updated_at':None,'updated_by':'built-in review baseline'}

def public_catalog(store):
 with store.read_meta() as db: value=configuration(store,db)
 value['sources']=copy.deepcopy(SOURCES);value['checked_on']='2026-11-01'
 value['notice']='Configurable review indicators. Port/service names are hints; listener discovery does not prove a vulnerability, internet reachability, encryption or a regulatory breach.'
 return value

def validate_rules(value):
 if not isinstance(value,list) or len(value)>100:raise ValueError('Provide at most 100 risky-port rules')
 result=[];seen=set()
 for row in value:
  if not isinstance(row,dict) or set(row)-{'id','name','port_start','port_end','protocol','severity','reason','recommendation','category','enabled','source_ids'}:raise ValueError('Unsupported risky-port rule field')
  identifier=row.get('id')
  if not isinstance(identifier,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',identifier) or identifier in seen:raise ValueError('Risk rule IDs must be unique')
  seen.add(identifier)
  for key,limit in (('name',120),('reason',600),('recommendation',600),('category',60)):
   if not isinstance(row.get(key),str) or not row[key].strip() or len(row[key])>limit:raise ValueError('Provide a bounded '+key)
  start,end=row.get('port_start'),row.get('port_end')
  if any(isinstance(n,bool) or not isinstance(n,int) for n in (start,end)) or not 1<=start<=end<=65535:raise ValueError('Use valid port boundaries')
  if row.get('protocol') not in ('tcp','udp') or row.get('severity') not in ('high','medium','low') or type(row.get('enabled')) is not bool:raise ValueError('Invalid protocol, severity or enabled value')
  sources=row.get('source_ids',[])
  if not isinstance(sources,list) or len(sources)>5 or any(not isinstance(source,str) or source not in SOURCES for source in sources):raise ValueError('Use known source references')
  result.append(copy.deepcopy(row))
 return result

def save(store,body,actor):
 if not isinstance(body,dict) or set(body)-{'expected_revision','rules'}:raise ValueError('Risk catalog accepts rules and expected_revision')
 rules=validate_rules(body.get('rules'));revision=body.get('expected_revision')
 if isinstance(revision,bool) or not isinstance(revision,int):raise ValueError('Current catalog revision is required')
 with store.lock,store.meta() as db:
  if getattr(db,'dialect','sqlite')!='postgresql' and not db.in_transaction:db.execute('BEGIN IMMEDIATE')
  current=configuration(store,db)
  if revision!=current['revision']:raise ValueError('Risk catalog changed; refresh before saving')
  value={'id':SETTING,'revision':revision+1,'rules':rules,'updated_at':stamp(),'updated_by':actor}
  store._put(db,'maintenance_settings',value);store.audit('risk.catalog.updated',actor,{'revision':value['revision'],'rule_count':len(rules)},db)
 store.evaluate_health()
 return public_catalog(store)

def exposure(address):
 address=str(address or '').strip().strip('[]').split('%',1)[0]
 if address in ('*','0.0.0.0','::'):return 'wildcard'
 try:
  parsed=ipaddress.ip_address(address)
  if isinstance(parsed,ipaddress.IPv6Address) and parsed.ipv4_mapped:parsed=parsed.ipv4_mapped
  return 'loopback' if parsed.is_loopback else 'network_bound'
 except ValueError:return 'unknown'

def _matches(server,catalog):
 # One highest-priority indicator per listener; exact rules beat broad ranges.
 ranking={'high':0,'medium':1,'low':2}
 rules=sorted((r for r in catalog['rules'] if r['enabled']),key=lambda r:(ranking[r['severity']],r['port_end']-r['port_start'],r['id']))
 result=[];seen=set()
 for index,listener in enumerate(server.get('listeners',[])):
  port,protocol=listener.get('port'),listener.get('protocol')
  if type(port) is not int:continue
  for rule in rules:
   if protocol==rule['protocol'] and rule['port_start']<=port<=rule['port_end']:
    key=(port,protocol,listener.get('address',''))
    if key not in seen:result.append([index,rule['id']]);seen.add(key)
    break
 by_id={r['id']:r for r in rules}
 result.sort(key=lambda row:(ranking[by_id[row[1]]['severity']],server['listeners'][row[0]]['port'],row[0]))
 return result

def _hydrate(server,entry,rules):
 listener=server['listeners'][entry[0]];rule=rules[entry[1]];address=listener.get('address','')
 return {'rule_id':rule['id'],'port':listener['port'],'protocol':listener['protocol'],'address':address,'exposure':exposure(address),
  'name':rule['name'],'severity':rule['severity'],'reason':rule['reason'],'recommendation':rule['recommendation'],
  'source_ids':rule['source_ids'],'service':listener.get('service',''),'process':listener.get('process',''),
  'application':listener.get('application',''),'observed_at':server.get('last_discovery_at')}

def _classification(server,catalog):
 matches=_matches(server,catalog);rules={r['id']:r for r in catalog['rules']}
 findings=[_hydrate(server,entry,rules) for entry in matches[:256]]
 summary={'total':len(matches),'stored':len(findings),'truncated':len(matches)>256,
  'high':sum(rules[entry[1]]['severity']=='high' for entry in matches),
  'network_bound':sum(exposure(server['listeners'][entry[0]].get('address')) in ('wildcard','network_bound') for entry in matches),
  'catalog_revision':catalog['revision']}
 return matches,findings,summary

def classify(server,catalog):
 _,findings,summary=_classification(server,catalog)
 return findings,summary

def _cache_current(server,catalog):
 return (isinstance(server.get('_risk_matches'),list) and server.get('risk_summary',{}).get('catalog_revision')==catalog['revision']
  and server.get('_risk_cache_discovery_at')==server.get('last_discovery_at'))

def refresh_cache(store,db,server):
 catalog=configuration(store,db)
 matches,display,summary=_classification(server,catalog)
 server.update(risky_ports=display,risk_summary=summary,_risk_matches=matches,
  _risk_cache_discovery_at=server.get('last_discovery_at'),_risk_alerts_fresh=None)

def sync(store,db,server,catalog):
 fresh=server.get('discovery_status')=='current' and server.get('status')!='offline'
 if _cache_current(server,catalog) and server.get('_risk_alerts_fresh')==fresh:return False
 if _cache_current(server,catalog):matches=server['_risk_matches']
 else:
  matches,display,summary=_classification(server,catalog)
  server.update(risky_ports=display,risk_summary=summary,_risk_matches=matches,_risk_cache_discovery_at=server.get('last_discovery_at'))
 server['_risk_alerts_fresh']=fresh
 if fresh:
  active=set();rules={r['id']:r for r in catalog['rules']}
  for entry in matches:
   finding=_hydrate(server,entry,rules)
   if finding['exposure']=='loopback':continue
   key='risky-port:'+server['id']+':'+digest((finding['rule_id'],finding['port'],finding['protocol'],finding['address']))[:24];active.add(key)
   severity={'high':'high','medium':'warning','low':'info'}[finding['severity']]
   message=f"Risky port in use: {finding['port']}/{finding['protocol']} · {finding['name']}"
   existing=store._get(db,'alerts',key)
   if existing and existing.get('status') in ('open','acknowledged'):
    previous={k:v for k,v in existing.get('details',{}).items() if k!='observed_at'}
    current={k:v for k,v in finding.items() if k!='observed_at'}
    if previous!=current or existing.get('severity')!=severity or existing.get('message')!=message:
     existing.update(details=copy.deepcopy(finding),severity=severity,message=message,updated_at=stamp());store._put(db,'alerts',existing)
   else:store._event(db,key,'risky_port_in_use',severity,server['id'],message,finding)
  # Reconcile the durable alert ledger, not a capped/possibly stale display list.
  prefix='risky-port:'+server['id']+':'
  status="data::jsonb->>'status'" if getattr(db,'dialect','sqlite')=='postgresql' else "json_extract(data,'$.status')"
  for row in db.execute('SELECT id,data FROM alerts WHERE id>=? AND id<? AND '+status+" IN ('open','acknowledged')",(prefix,prefix+'g')):
   if row[0] in active:continue
   alert=json.loads(row[1])
   if alert.get('kind')!='risky_port_in_use' or alert.get('server_id')!=server['id']:continue
   alert.update(status='resolved',updated_at=stamp(),resolved_at=stamp(),resolution_reason='listener_or_catalog_changed');store._put(db,'alerts',alert)
 return True

def _risk_rows(db,server_id=''):
 from .inventory_views import rows
 fields=('hostname','ips','tags','location_id','status','discovery_status','last_discovery_at','listeners','risk_summary','_risk_matches','_risk_cache_discovery_at')
 if getattr(db,'dialect','sqlite')=='postgresql':
  pairs=','.join("'%s',document->'%s'"%(key,key) for key in fields)
  sql="SELECT jsonb_build_object('id',id,"+pairs+")::text FROM servers CROSS JOIN LATERAL (SELECT data::jsonb AS document OFFSET 0) projected"
 else:
  pairs=','.join("'%s',json_extract(data,'$.%s')"%(key,key) for key in fields)
  sql="SELECT json_object('id',id,"+pairs+") FROM servers"
 if server_id:sql+=' WHERE id=?'
 for row in rows(db,sql,(server_id,) if server_id else ()):yield json.loads(row[0])

def findings(store,query):
 def number(key,default,maximum):
  try:value=int(query.get(key,default))
  except (ValueError,TypeError):raise ValueError('Invalid pagination') from None
  if not 0<=value<=maximum:raise ValueError('Invalid pagination')
  return value
 offset=number('offset',0,1000000);limit=number('limit',100,200)
 if not limit:raise ValueError('Limit must be positive')
 severity=query.get('severity','');port=query.get('port','');server_id=query.get('server_id','');search=str(query.get('search','')).casefold()[:200]
 if severity and severity not in ('high','medium','low'):raise ValueError('Invalid severity')
 if port and (not str(port).isdigit() or not 1<=int(port)<=65535):raise ValueError('Invalid port')
 items=[];total=0;servers=set();high=0;truncated=set();pending=0
 with store.read_meta() as db:
  catalog=configuration(store,db);rules={r['id']:r for r in catalog['rules']}
  for server in _risk_rows(db,server_id):
   if not _cache_current(server,catalog):pending+=1;continue
   if server.get('risk_summary',{}).get('truncated'):truncated.add(server['id'])
   for entry in server['_risk_matches']:
    listener=server['listeners'][entry[0]];rule=rules[entry[1]]
    if severity and rule['severity']!=severity or port and listener['port']!=int(port):continue
    if search and search not in (' '.join((server.get('hostname') or '',rule['name'],listener.get('service',''),listener.get('process',''),' '.join(server.get('ips') or []),' '.join((server.get('tags') or {}).values()),str(listener['port'])))).casefold():continue
    total+=1;servers.add(server['id']);high+=rule['severity']=='high'
    if offset<total<=offset+limit:items.append({**_hydrate(server,entry,rules),'server_id':server['id'],'hostname':server.get('hostname'),'ips':server.get('ips') or [],'tags':server.get('tags') or {},'location_id':server.get('location_id'),'discovery_status':server.get('discovery_status','unknown'),'server_status':server.get('status')})
 return {'items':items,'total':total,'offset':offset,'limit':limit,'server_count':len(servers),'high_count':high,'truncated_server_count':len(truncated),'classification_pending_servers':pending,'stored_reason_limit':256,'sources':copy.deepcopy(SOURCES),'basis':'All classified listeners are filtered before paging. Detailed endpoint panels retain at most 256 full reasons. Reachability, TLS and authentication require verification.'}

def regulatory(store):
 # These are control mappings and explicit gaps, never compliance certification.
 return {'checked_on':'2026-11-01','status':'control_mapping','sources':copy.deepcopy(SOURCES),
 'notice':'Applicability and evidence require the regulated entity’s review. No universal CERT-In/RBI banned-port list is asserted. Port flags are product review indicators.',
 'controls':[
  {'id':'CERT-IV','framework':'CERT-In','clause':'Direction (iv)','requirement':'Secure ICT logs for at least 180 days within India.','status':'operator_evidence_required','support':'Audit history and exports are available. Temporary learning/hit retention is shorter; it does not establish this requirement. Verify the organization’s security-log archive and location.','source_id':'cert_in'},
  {'id':'CERT-I','framework':'CERT-In','clause':'Direction (i)','requirement':'Synchronize ICT clocks to approved, traceable reference time.','status':'operator_evidence_required','support':'UTC timestamps are recorded. NTP configuration and traceability must be verified on actual hosts.','source_id':'cert_in'},
  {'id':'CERT-II','framework':'CERT-In','clause':'Direction (ii), Annexure I','requirement':'Assess listed incidents for reporting within six hours of noticing.','status':'operator_process_required','support':'Alerts support triage; a risky listener alone is not an incident verdict. Reporting is the organization’s process.','source_id':'cert_in'},
  {'id':'CERT-III','framework':'CERT-In','clause':'Direction (iii)','requirement':'Designate and maintain a CERT-In point of contact.','status':'operator_process_required','support':'Record ownership and reporting contacts in the incident runbook.','source_id':'cert_in'},
  {'id':'RBI-13','framework':'RBI IT 2023','clause':'13','requirement':'Documented, authorized changes and recovery from failure.','status':'partial','support':'Role-authorized direct Admin changes, version history and rollback. Organizational change governance needs evidence.','source_id':'rbi_it'},
  {'id':'RBI-15','framework':'RBI IT 2023','clause':'15','requirement':'Detailed audit trails and regular log monitoring.','status':'partial','support':'Audit/events and alert review support evidence; retention and operational review remain external.','source_id':'rbi_it'},
  {'id':'RBI-19','framework':'RBI IT 2023','clause':'19','requirement':'Business-need access and privileged-user safeguards.','status':'partial','support':'Three roles, Entra integration and source policies. Verify MFA enforcement and periodic access review separately.','source_id':'rbi_it'},
  {'id':'RBI-26','framework':'RBI IT 2023','clause':'26','requirement':'Risk-based vulnerability and penetration testing.','status':'operator_evidence_required','support':'Code/dependency checks support testing; port indicators are not a VA/PT report.','source_id':'rbi_it'},
  {'id':'RBI-29','framework':'RBI IT 2023','clause':'29','requirement':'Tested disaster recovery and continuity.','status':'operator_evidence_required','support':'HA/backup controls exist; actual DC/DR and native OS acceptance remain pending.','source_id':'rbi_it'},
  {'id':'RBI-D19','framework':'RBI Payments 2021','clause':'19','requirement':'Separate application, database and presentation tiers.','status':'partial','support':'Tags/groups and source restrictions support segmentation. Validate actual network/application architecture.','source_id':'rbi_payment'},
  {'id':'RBI-D24','framework':'RBI Payments 2021','clause':'24','requirement':'Application security review and VA/PT.','status':'operator_evidence_required','support':'Release checks provide supporting evidence; independent assessment and applicable testing schedules remain organizational.','source_id':'rbi_payment'},
 ]}
