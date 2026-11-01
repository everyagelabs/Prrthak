"""Evidence-assessment boundaries; no fault injection or real host devices."""
import copy
import importlib.util
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('native_acceptance',Path(__file__).resolve().parents[1]/'deploy/appliance/acceptance.py');acceptance=importlib.util.module_from_spec(spec);spec.loader.exec_module(acceptance)


class NativeAcceptanceEvidenceTests(unittest.TestCase):
    def snapshot(self,scenario='baseline'):
        return {'captured_at':1000,'scenario':scenario,'manager':{'identity':{'id':'node1'},'cluster':{'deployment_id':'same'},'health':{'status':'observed','checked_at':990,'primary_count':1,'quorum_healthy':True,'database_ready':True,'all_voters_healthy':True}},'kernel':{'character_device':True,'native_identity_candidate':True,'dev':'10:130','device_number':'10:130','state':'active','boot_id':'new'}}
    def test_healthy_snapshot_never_certifies_hardware_or_production(self):
        result=acceptance.assess(self.snapshot());self.assertTrue(result['observations_ready_for_review']);self.assertFalse(result['hardware_fencing_validated']);self.assertFalse(result['production_approved'])
    def test_stale_split_primary_quorum_or_software_watchdog_blocks_checkpoint(self):
        for fields in ({'checked_at':900},{'primary_count':2},{'quorum_healthy':False},{'database_ready':False}):
            value=self.snapshot();value['manager']['health'].update(fields)
            self.assertFalse(acceptance.assess(value)['observations_ready_for_review'])
        value=self.snapshot();value['kernel']['native_identity_candidate']=False;self.assertFalse(acceptance.assess(value)['observations_ready_for_review'])
    def test_reset_requires_same_victim_changed_boot_and_same_deployment(self):
        before=self.snapshot();after=self.snapshot('watchdog_reset')
        self.assertFalse(acceptance.assess(after,before)['observations_ready_for_review'])
        before['kernel']['boot_id']='old';self.assertTrue(acceptance.assess(after,before)['observations_ready_for_review'])
        after['manager']['identity']['id']='other';self.assertFalse(acceptance.assess(after,before)['observations_ready_for_review'])
        after['manager']['cluster']['deployment_id']='other';self.assertFalse(acceptance.assess(after,before)['observations_ready_for_review'])
    def test_kernel_collection_stats_watchdog_without_opening_it(self):
        def read(path,*args,**kwargs):
            self.assertNotEqual(str(path),'/dev/watchdog0')
            return 'hardware-test' if path.name=='identity' else 'active' if path.name=='state' else '10:130' if path.name=='dev' else 'public-test'
        with patch.object(Path,'read_text',read),patch.object(Path,'stat',return_value=SimpleNamespace(st_mode=stat.S_IFCHR|0o600,st_rdev=os.makedev(10,130))),patch.object(Path,'open',side_effect=AssertionError('Never open a watchdog during evidence collection')):
            result=acceptance.kernel_facts()
        self.assertTrue(result['character_device']);self.assertTrue(result['native_identity_candidate'])


if __name__=='__main__':unittest.main()
