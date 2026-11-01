"""Compatibility readers for archived approval-mode settings.

Role-authorized direct changes are the only current workflow. Legacy settings
and review rows remain untouched as audit evidence and grant no authority.
"""
KEY = "approval_settings"
PLAN_PREFIX = "approval_settings_review:"
MODE = "single_admin_pilot"  # Historical storage value, never a current option.
CAPABILITY = "approval_mode_proof_v1"


def current(store, db):
    return store._get(db, "maintenance_settings", KEY)


def get(store):
    return {"mode":"single_admin", "effective_mode":"single_admin", "label":"Role-authorized direct changes", "selectable":False}


def active(store, db, value=None):
    return False


def capture(store, db, endpoint_ids):
    return None


def authorized(store, db, pilot):
    return False


def preview(app, body, principal):
    raise ValueError("Approval modes have been retired; authorized Admin changes apply directly")


def confirm(app, body, principal):
    raise ValueError("Approval modes have been retired; old mode reviews cannot be activated")
