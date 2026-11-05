"""Reusable central tags, independent of endpoint assignments."""
import json
import re

from .locations import tags
from .store import digest, stamp


MAX_TAGS = 10000
MAX_PAGE = 200
MAX_SEED_RECORDS = 100000


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS tag_catalogue (id TEXT PRIMARY KEY, data TEXT NOT NULL)")


def register(db, tag_maps, actor, source):
    """Remember valid central assignments without changing them or their audit.

    Runs inside the caller's metadata transaction. Implicit registration is
    best effort at catalogue capacity; assigning an existing/free tag must not
    fail just because the optional saved-choice list has reached its bound.
    """
    if getattr(db, "dialect", "sqlite") == "sqlite" and not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    known = {row[0] for row in db.execute("SELECT id FROM tag_catalogue")}
    created = 0
    for values in tag_maps:
        if len(known) >= MAX_TAGS:
            break
        if not isinstance(values, dict):
            continue
        for key, text in sorted(values.items(), key=lambda pair: str(pair[0])):
            try:
                tags({key: text})
            except (ValueError, TypeError):
                continue
            identifier = digest([key, text])
            if identifier in known:
                continue
            if len(known) >= MAX_TAGS:
                return created
            record = {"id": identifier, "key": key, "value": text, "created_at": stamp(),
                      "created_by": actor, "created_from": source}
            db.execute("INSERT OR IGNORE INTO tag_catalogue(id,data) VALUES(?,?)",
                       (identifier, json.dumps(record, separators=(",", ":"))))
            known.add(identifier)
            created += 1
    return created


def seed_existing(db):
    """Startup-only backfill; picker reads never scan endpoint inventory."""
    def assignments():
        remaining = MAX_SEED_RECORDS
        for table in ("servers", "metadata_ip_profiles"):
            for row in db.execute(f"SELECT data FROM {table} ORDER BY id LIMIT ?", (remaining,)):
                remaining -= 1
                value = json.loads(row[0])
                yield value.get("tags", {})
            if not remaining:
                break

    return register(db, assignments(), "system:metadata", "existing_metadata")


def options(query):
    if set(query) - {"limit", "offset", "q"} or any(len(values) != 1 for values in query.values()):
        raise ValueError("Use one limit, offset and search value for the tag catalogue")
    result = {}
    for field, default in (("limit", MAX_PAGE), ("offset", 0)):
        raw = query.get(field, [str(default)])[0]
        if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{1,5}", raw):
            raise ValueError("Invalid tag catalogue pagination")
        result[field] = int(raw)
    result["q"] = query.get("q", [""])[0]
    _validate_options(**result)
    return result


def _validate_options(limit, offset, q):
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE or type(offset) is not int or not 0 <= offset <= MAX_TAGS:
        raise ValueError("Tag catalogue pages contain at most 200 entries")
    if not isinstance(q, str) or len(q) > 200:
        raise ValueError("Tag search must contain at most 200 characters")


def listing(store, limit=MAX_PAGE, offset=0, q=""):
    _validate_options(limit, offset, q)
    # Definitions are capped independently of the fleet. No compiled endpoint
    # records or policy assignments are loaded for a picker request.
    with store.read_meta() as db:
        records = store._all(db, "tag_catalogue")
    needle = q.casefold()
    records = sorted((record for record in records if needle in (record["key"] + "=" + record["value"]).casefold()),
                     key=lambda record: (record["key"].casefold(), record["key"], record["value"].casefold(), record["value"]))
    return {"items": records[offset:offset + limit], "total": len(records), "limit": limit,
            "offset": offset, "has_more": offset + limit < len(records)}


def create(store, value, actor):
    if not isinstance(value, dict) or set(value) != {"key", "value"}:
        raise ValueError("A saved tag requires a key and value")
    key, text = value["key"], value["value"]
    # Match the validation and exact case used by endpoint metadata and policy
    # selectors. Location identities retain their separate catalogue.
    if not isinstance(key, str):
        raise ValueError("Invalid tag key")
    tags({key: text})
    identifier = digest([key, text])
    with store.lock, store.meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN IMMEDIATE")
        existing = store._get(db, "tag_catalogue", identifier)
        if existing:
            return existing
        if db.execute("SELECT COUNT(*) FROM tag_catalogue").fetchone()[0] >= MAX_TAGS:
            raise ValueError("The tag catalogue contains the maximum 10000 entries")
        record = {"id": identifier, "key": key, "value": text, "created_at": stamp(), "created_by": actor}
        store._put(db, "tag_catalogue", record)
        store.audit("tag.created", actor, {"id": identifier, "key": key, "value": text}, db)
        return record
