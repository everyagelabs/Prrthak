"""Explicit small-pilot timing proposal; never changes fleet defaults/security."""
import copy
from . import agent_settings as settings
from .firewall import WorkflowConflict

PRESET_ID = 'pilot-30-60'
MAX_SERVERS = 20


def preview(store, value):
    if not isinstance(value, dict) or set(value) != {'server_ids', 'expected_revision'}:
        raise ValueError('Choose explicit pilot servers and the current polling revision')
    identifiers = value['server_ids']
    if not isinstance(identifiers, list) or not 1 <= len(identifiers) <= MAX_SERVERS or any(not isinstance(item, str) for item in identifiers) or len(set(identifiers)) != len(identifiers):
        raise ValueError('Choose 1..20 distinct explicit pilot servers')
    with store.read_meta() as db:
        from .inventory_views import server_rows
        servers, memberships = settings._context(store, db, list(server_rows(db)))
        by_id = {server['id']: server for server in servers}
        if any(item not in by_id or by_id[item].get('retired_at') for item in identifiers):
            raise ValueError('Choose existing enrolled pilot endpoints')
        if any(settings.CAPABILITY not in by_id[item].get('capabilities', []) for item in identifiers):
            raise ValueError('Upgrade selected endpoints to agent_polling_config_v1 before using this preset')
        current = settings._config(store, db)
        prior = next((rule for rule in current['rules'] if rule['id'] == PRESET_ID), None)
        if prior and (prior.get('group_ids') or prior.get('selector') or not 1 <= len(prior.get('server_ids', [])) <= MAX_SERVERS
                      or prior.get('priority') != 10000 or prior.get('control_interval_seconds') != 30
                      or prior.get('discovery_interval_seconds') != 60):
            raise WorkflowConflict('The reserved pilot rule was edited into a different override. Rename or review that override before replacing the pilot preset', {'rule_id': PRESET_ID})
        rules = [copy.deepcopy(rule) for rule in current['rules'] if rule['id'] != PRESET_ID]
        rules.append({'id': PRESET_ID, 'name': 'Pilot · 30s control / 60s discovery', 'enabled': True, 'priority': 10000,
                      'server_ids': sorted(identifiers), 'group_ids': [], 'selector': {},
                      'control_interval_seconds': 30, 'discovery_interval_seconds': 60})
        configuration = {'expected_revision': value['expected_revision'], 'defaults': copy.deepcopy(current['defaults']), 'rules': rules}
        before, after, changed = settings._proposal(store, db, configuration)
        impacts = []
        for server in servers:
            previous, desired = settings._desired(before, server, memberships), settings._desired(after, server, memberships)
            if server['id'] in identifiers and (desired['control_interval_seconds'], desired['discovery_interval_seconds']) != (30, 60):
                raise WorkflowConflict('Another equal-priority override wins for a selected server; review that override before using the pilot preset', {'server_id': server['id']})
            if previous['digest'] != desired['digest']:
                impacts.append({'server_id': server['id'], 'hostname': server['hostname'], 'before': previous, 'after': desired, 'supported': settings.CAPABILITY in server.get('capabilities', [])})
        removed = sorted(set(prior.get('server_ids', []) if prior else []) - set(identifiers))
        return {'before': before, 'after': after, 'changed': changed, 'affected_servers': impacts,
                'effective_change_count': len(impacts), 'target_server_count': len(servers), 'configuration': configuration,
                'pilot': {'server_ids': sorted(identifiers), 'control_interval_seconds': 30, 'discovery_interval_seconds': 60,
                          'removed_server_ids': removed, 'global_defaults_unchanged': True,
                          'notice': 'Only this explicit pilot scope uses the preset. Previous preset members removed from this selection return to their remaining rules/defaults. No firewall or monitoring settings change.'}}
