"""Indexed endpoint learning leases; retained history is never a polling input."""
import hashlib
import json
from datetime import timedelta

from .store import digest, now, parse_time

MARKER = "learning_session_targets_v1"


def _time(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def checkpoint(db):
    """A real canonical session write checkpoints its own synchronized index.

    Keeping this in the same transaction means migration snapshots already
    contain the checkpoint; initializing an imported target cannot invent an
    extra business row and invalidate an otherwise identical replay.
    """
    db.execute("INSERT OR IGNORE INTO maintenance_settings(id,data) VALUES(?,?)", (MARKER, json.dumps({"id":MARKER,"version":1},separators=(",",":"))))


def initialize(store, db):
    db.executescript("""
      CREATE TABLE IF NOT EXISTS learning_session_targets(id TEXT PRIMARY KEY,session_id TEXT NOT NULL,server_id TEXT NOT NULL,status TEXT NOT NULL,starts_at TEXT NOT NULL,expires_at TEXT NOT NULL,cutoff_at TEXT NOT NULL,state_digest TEXT NOT NULL,UNIQUE(session_id,server_id));
      CREATE INDEX IF NOT EXISTS learning_target_endpoint_active ON learning_session_targets(server_id,status,starts_at,expires_at);
      CREATE INDEX IF NOT EXISTS learning_target_endpoint_stop ON learning_session_targets(server_id,cutoff_at);
      CREATE INDEX IF NOT EXISTS learning_target_session ON learning_session_targets(session_id);
    """)
    if store._get(db, "maintenance_settings", MARKER):
        return
    # Schema creation on an empty PostgreSQL target must remain data-empty:
    # migration admission deliberately refuses ANY pre-existing business row.
    # With no canonical sessions there is nothing to backfill or checkpoint.
    # A later canonical write synchronizes its targets; the next initializer
    # can idempotently checkpoint the now non-empty session catalogue.
    if db.execute("SELECT 1 FROM sessions LIMIT 1").fetchone() is None:
        return
    # Upgrade old inline sessions once, including terminal history. Keyset
    # batches avoid fetching every historical scope into startup memory.
    after = ""
    while True:
        rows = db.execute("SELECT id,data FROM sessions WHERE id>? ORDER BY id LIMIT 100", (after,)).fetchall()
        if not rows:
            break
        for row in rows:
            sync(db, json.loads(row[1]))
        after = rows[-1][0]
    checkpoint(db)


def sync(db, session):
    """Called with every canonical session write, in its writer transaction."""
    identifiers = sorted(set(session.get("server_ids", [])))
    try:
        start, expiry = parse_time(session["starts_at"]), parse_time(session["expires_at"])
        cutoff = min(expiry, parse_time(session.get("stopped_at") or session["expires_at"]))
    except (KeyError, TypeError, ValueError):
        # Legacy audit-only records can lack a usable lease. Preserve their
        # history while refusing to create an endpoint collection assignment.
        db.execute("DELETE FROM learning_session_targets WHERE session_id=?", (session["id"],))
        return
    state = digest([identifiers, session["status"], _time(start), _time(expiry), _time(cutoff)])
    old = db.execute("SELECT state_digest FROM learning_session_targets WHERE session_id=? LIMIT 1", (session["id"],)).fetchone()
    # Discovery receipts revise the large canonical session repeatedly without
    # changing membership or lease times. Do not rewrite the whole target index.
    if old and old[0] == state:
        return
    db.execute("DELETE FROM learning_session_targets WHERE session_id=?", (session["id"],))
    values = [(hashlib.sha256((session["id"] + "\0" + identifier).encode()).hexdigest(), session["id"], identifier,
               session["status"], _time(start), _time(expiry), _time(cutoff), state) for identifier in identifiers]
    sql = "INSERT INTO learning_session_targets(id,session_id,server_id,status,starts_at,expires_at,cutoff_at,state_digest) VALUES(?,?,?,?,?,?,?,?)"
    if hasattr(db, "executemany"):
        db.executemany(sql, values)
    else:
        for value in values:
            db.execute(sql, value)


def for_endpoint(db, identifier, *, at=None, recent=False):
    """Project only active leases and optional five-minute stop tombstones."""
    at = at or now()
    current = _time(at)
    active = "SELECT session_id FROM learning_session_targets WHERE server_id=? AND status='active' AND starts_at<=? AND expires_at>?"
    arguments = [identifier, current, current]
    eligible = active
    if recent:
        eligible += " UNION SELECT session_id FROM learning_session_targets WHERE server_id=? AND cutoff_at>=? AND cutoff_at<=?"
        arguments.extend([identifier, _time(at - timedelta(minutes=5)), current])
    sql = "SELECT data FROM sessions WHERE id IN (" + eligible + ") ORDER BY id"
    result = []
    for row in db.execute(sql, tuple(arguments)):
        session = json.loads(row[0])
        # Canonical data remains authoritative after recovery and direct
        # maintenance deletes; an index can never revive a stopped scope.
        if identifier not in session.get("server_ids", []):
            continue
        expiry = parse_time(session["expires_at"])
        cutoff = min(expiry, parse_time(session.get("stopped_at") or session["expires_at"]))
        if session["status"] == "active" and parse_time(session["starts_at"]) <= at < expiry or recent and cutoff <= at <= cutoff + timedelta(minutes=5):
            result.append(session)
    return result


def rebuild(store, db):
    """Recovery derives this index solely from the restored canonical rows."""
    db.execute("DELETE FROM learning_session_targets")
    db.execute("DELETE FROM maintenance_settings WHERE id=?", (MARKER,))
    initialize(store, db)
