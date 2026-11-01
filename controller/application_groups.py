"""Persistent application groups derived from administrator-approved server tags.

Groups describe reusable target membership; creating one never grants policy
authorization. Exact existing application groups keep their identity and name.
"""
from __future__ import annotations

import uuid

from .store import stamp


def application_selector(group):
    selector = group.get("selector", {})
    value = selector.get("application") if isinstance(selector, dict) else None
    return value if group.get("type") == "dynamic" and set(selector) == {"application"} and isinstance(value, str) and value.strip() else None


def managed(group):
    return group.get("origin") == "application" and group.get("managed") is True


def sync(store, db, servers=None):
    servers = store._all(db, "servers") if servers is None else servers
    applications = sorted({value for server in servers if isinstance(value := server.get("tags", {}).get("application"), str) and value.strip()})
    groups = store._all(db, "groups")
    exact = {}
    for group in groups:
        value = application_selector(group)
        if value is not None:
            exact.setdefault(value, []).append(group)
    for application in applications:
        candidates = exact.get(application, [])
        if candidates:
            # A previous saved Billing group is the same target set. Keep its ID,
            # name and policy references rather than adding a second Billing row.
            # Saved groups remain editable: reusing their membership must not
            # silently turn an operator-created group into a protected object.
            continue
        else:
            identifier = str(uuid.uuid5(uuid.NAMESPACE_URL, "prthak:application-group:" + application))
            existing = store._get(db, "groups", identifier)
            if existing is not None:
                raise RuntimeError("Automatic application group identity collision")
            group = {"id": identifier, "name": (application[:1].upper() + application[1:])[:120],
                "type": "dynamic", "selector": {"application": application}, "server_ids": [],
                "created_at": stamp(), "updated_at": stamp(), "origin": "application",
                "managed": True, "application": application}
            groups.append(group)
            store._put(db, "groups", group)
            store.audit("group.application_created", "system", {"group_id": identifier, "application": application}, db)
    # Empty managed groups remain stable, including groups already referenced by
    # policies. An empty selector is never used as a substitute for no members.
    return groups


def public(group):
    result = {**group, "managed": managed(group), "origin": "application" if managed(group) else group.get("origin", "saved")}
    application = application_selector(group)
    if application is not None:
        result["application"] = application
    return result


def equivalent_group(groups, selector):
    application = selector.get("application") if set(selector) == {"application"} else None
    if not application:
        return None
    matches = [group for group in groups if application_selector(group) == application]
    return min(matches, key=lambda group: (not managed(group), group.get("created_at", ""), group["id"])) if matches else None
