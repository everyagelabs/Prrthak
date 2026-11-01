#!/usr/bin/env python3
"""Read-only native acceptance evidence collector. Never injects a fault.

It does not open/arm/feed a watchdog, stop services, change networking or mark
physical fencing validated. Operators execute faults in their approved lab;
this records bounded public manager/kernel observations for independent review.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from controller.appliance import NodeClient


SCENARIOS=('baseline','controller_loss','database_process_loss','watchdog_reset','site_partition','site_loss','recovery')


def kernel_facts():
    def read(path):
        try:return Path(path).read_text()[:1024].strip()
        except OSError:return None
    result={key:read('/sys/class/watchdog/watchdog0/'+key) for key in ('identity','dev','state','timeout','timeleft','nowayout','bootstatus')}
    result['boot_id']=read('/proc/sys/kernel/random/boot_id')
    try:
        device=Path('/dev/watchdog0').stat();result['character_device']=stat.S_ISCHR(device.st_mode);result['device_number']=str(os.major(device.st_rdev))+':'+str(os.minor(device.st_rdev))
    except OSError:result.update(character_device=False,device_number=None)
    result['native_identity_candidate']=bool(result.get('identity')) and not any(word in result['identity'].lower() for word in ('software','softdog','dummy'))
    return result


def assess(snapshot,previous=None):
    health=snapshot['manager'].get('health',{});hardware=snapshot['kernel'];scenario=snapshot['scenario'];issues=[]
    if health.get('status')!='observed' or health.get('checked_at',0)<snapshot['captured_at']-45:issues.append('Fresh authenticated manager health is required')
    if health.get('primary_count')!=1:issues.append('Exactly one observed primary is required')
    if not health.get('quorum_healthy'):issues.append('Surviving authenticated etcd quorum is required')
    if not health.get('database_ready'):issues.append('Database readiness/synchronous replica proof is required')
    if scenario in ('baseline','recovery') and not health.get('all_voters_healthy'):issues.append('All three voters must recover before this checkpoint')
    if scenario=='baseline' and not (hardware.get('character_device') and hardware.get('native_identity_candidate') and hardware.get('dev')==hardware.get('device_number') and hardware.get('state')=='active'):issues.append('An armed approved native watchdog must be observed on this voter')
    if previous:
        if previous.get('manager',{}).get('cluster',{}).get('deployment_id')!=snapshot['manager'].get('cluster',{}).get('deployment_id'):issues.append('Before/after evidence belongs to different deployments')
        if scenario=='watchdog_reset':
            if previous.get('manager',{}).get('identity',{}).get('id')!=snapshot['manager'].get('identity',{}).get('id'):issues.append('Watchdog reboot evidence must be collected from the same victim after recovery')
            if not hardware.get('boot_id') or hardware.get('boot_id')==previous.get('kernel',{}).get('boot_id'):issues.append('A changed kernel boot identity was not observed')
    elif scenario!='baseline':issues.append('Bind this checkpoint to a prior reviewed baseline evidence file')
    return {'observations_ready_for_review':not issues,'issues':issues,'hardware_fencing_validated':False,'production_approved':False,'requires_independent_review':['Old-primary write denial throughout the fault, not only after recovery','External power/reset/network evidence and acknowledged-write loss checks','Approved RPO/RTO and full controller/endpoint recovery measurements']}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--scenario',choices=SCENARIOS,default='baseline');parser.add_argument('--output',required=True);parser.add_argument('--before');parser.add_argument('--external-evidence');parser.add_argument('--socket',default='/run/prthak-appliance/manager.sock');parser.add_argument('--token-file',default='/run/prthak-appliance/manager-token');args=parser.parse_args()
    manager=NodeClient(args.socket,args.token_file).status();snapshot={'schema_version':1,'id':uuid.uuid4().hex,'scenario':args.scenario,'captured_at':time.time(),'manager':manager,'kernel':kernel_facts(),'faults_injected':False}
    previous=json.loads(Path(args.before).read_text()) if args.before else None
    if args.before:snapshot['before_sha256']=hashlib.sha256(Path(args.before).read_bytes()).hexdigest()
    if args.external_evidence:
        evidence=Path(args.external_evidence)
        if evidence.stat().st_size>16*1024*1024:raise ValueError('External evidence exceeds bounded collection size')
        snapshot['external_evidence_sha256']=hashlib.sha256(evidence.read_bytes()).hexdigest()
    snapshot['assessment']=assess(snapshot,previous);data=json.dumps(snapshot,sort_keys=True,indent=2).encode()
    path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'wb') as output:output.write(data);output.flush();os.fsync(output.fileno())
    print(json.dumps({'evidence_file':str(path),'sha256':hashlib.sha256(data).hexdigest(),**snapshot['assessment']}))


if __name__=='__main__':main()
