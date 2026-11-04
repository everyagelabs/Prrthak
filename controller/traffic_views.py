"""Complete scoped relationship reads; pagination never precedes filtering.

Learning traffic remains evidence, not proof of successful application access.
Connection, packet and historical log counts are separate grouping dimensions.
"""
from contextlib import contextmanager
from datetime import timedelta
import csv
import io
import json
import re
import tempfile

from .evidence_views import EXPORT_SLOTS, ExportBusy
from .inventory_views import endpoint_labels, rows
from .store import now, parse_time, stamp
from .traffic_capture import public as capture_public

MAX_EXPORT_ROWS = 250000
MAX_EXPORT_BYTES = 64 * 1024 * 1024
DIMENSIONS = ("server_id", "session_id", "source_ip", "port", "protocol", "verdict", "capture_kind", "capture_backend", "count_unit", "address_family")
FIELDS = (*DIMENSIONS, "count", "first_seen", "last_seen")
DESTINATION_FIELDS = ("destination_hostname", "destination_reported_ips")
ORDER = "last_seen DESC," + ",".join(DIMENSIONS)
COVERAGE = "Filtered over all retained processed learning observations. Connections, denied packets and historical logs have separate units. Collection gaps and limited windows prevent a complete connection-ledger or application-success claim. Each page is a consistent read; late uploads, processing and retention may change later pages. Refresh to see newer data."


def _validate(store, value, *, export=False):
    allowed = {"window_seconds", "server_ids", "search_server_ids", "ports", "search", "as_of"}
    if not export:
        allowed |= {"limit", "offset"}
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("Provide supported traffic navigation fields only")
    result = {"window_seconds": 3600, "server_ids": None, "search_server_ids": [], "ports": [], "search": "", **({} if export else {"limit": 50, "offset": 0}), **value}
    if type(result["window_seconds"]) is not int or not 60 <= result["window_seconds"] <= store.retention_hours * 3600:
        raise ValueError("Traffic window is outside retained history")
    if not export and (type(result["limit"]) is not int or not 1 <= result["limit"] <= 100 or type(result["offset"]) is not int or not 0 <= result["offset"] <= 10000000):
        raise ValueError("Traffic pagination requires limit1..100 and a bounded nonnegative offset")
    for key in ("server_ids", "search_server_ids"):
        ids = result[key]
        if key == "server_ids" and ids is None:
            continue
        if not isinstance(ids, list) or len(ids) > 10000 or any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in ids):
            raise ValueError("Traffic endpoint scope requires at most10000 bounded IDs")
        result[key] = sorted(set(ids))
    ports = result["ports"]
    if not isinstance(ports, list) or len(ports) > 128 or any(not isinstance(port, str) or not re.fullmatch(r"[1-9]\d{0,4}(?:/(?:tcp|udp))?", port) or int(port.split('/')[0]) > 65535 for port in ports):
        raise ValueError("Choose at most128 valid traffic port/protocol pairs")
    result["ports"] = sorted(set(ports))
    if not isinstance(result["search"], str) or len(result["search"]) > 256:
        raise ValueError("Traffic literal search is limited to256 characters")
    at = now()
    if "as_of" in result:
        if not isinstance(result["as_of"], str) or len(result["as_of"]) > 64:
            raise ValueError("Invalid traffic query time")
        try:
            selected = parse_time(result["as_of"])
            if selected > at + timedelta(seconds=5) or selected < at - timedelta(hours=store.retention_hours):
                raise ValueError()
        except (ValueError, TypeError, OverflowError):
            raise ValueError("Traffic query time must be recent and not in the future") from None
    else:
        selected = at
    result["as_of"] = stamp(selected)
    # Keep the original window bound across navigation. The retention worker may
    # remove expired rows in later requests; do not claim an immutable export.
    result["from_time"] = stamp(max(selected - timedelta(seconds=result["window_seconds"]), at - timedelta(hours=store.retention_hours)))
    return result


def _ids(db, field, selected):
    source = "SELECT jsonb_array_elements_text(?::jsonb)" if getattr(db, "dialect", "sqlite") == "postgresql" else "SELECT value FROM json_each(?)"
    return field + " IN (" + source + ")", [json.dumps(selected)]


def _grouped(db, value):
    clause = ["capture_processed=1", "last_seen>=?", "last_seen<=?"]
    args = [value["from_time"], value["as_of"]]
    if value["server_ids"] is not None:
        text, parameters = _ids(db, "server_id", value["server_ids"])
        clause.append(text); args += parameters
    if value["ports"]:
        selections = []
        for port in value["ports"]:
            number, _, protocol = port.partition('/')
            selections.append("(port=?" + (" AND protocol=?" if protocol else "") + ")")
            args += [int(number)] + ([protocol] if protocol else [])
        clause.append("(" + " OR ".join(selections) + ")")
    if value["search"]:
        metadata, parameters = _ids(db, "server_id", value["search_server_ids"])
        haystack = "lower(source_ip || ' ' || CAST(port AS TEXT) || '/' || protocol || ' ' || verdict || ' ' || capture_kind || ' ' || capture_backend || ' ' || count_unit || ' ' || address_family)"
        contains = "strpos(" + haystack + ",?)>0" if getattr(db, "dialect", "sqlite") == "postgresql" else "instr(" + haystack + ",?)>0"
        clause.append("(" + metadata + " OR " + contains + ")")
        args += parameters + [value["search"].lower()]
    # Normalize historical capture metadata before grouping, as public() does.
    # Otherwise pre-migration empty families and later explicit families would
    # create duplicate-looking public relationship rows with split counts.
    legacy = "capture_kind IN ('','legacy_log')"
    # Avoid a literal LIKE percent in parameterized PostgreSQL SQL: psycopg
    # treats it as a placeholder prefix even inside a quoted SQL string.
    colon = "strpos(source_ip,':')>0" if getattr(db, "dialect", "sqlite") == "postgresql" else "instr(source_ip,':')>0"
    normalized = "SELECT server_id,session_id,source_ip,port,protocol,verdict,CASE WHEN " + legacy + " THEN 'legacy_log' ELSE capture_kind END AS capture_kind,CASE WHEN " + legacy + " THEN 'journal' ELSE capture_backend END AS capture_backend,CASE WHEN " + legacy + " THEN 'log_records' ELSE count_unit END AS count_unit,CASE WHEN address_family='' THEN CASE WHEN " + colon + " THEN 'ipv6' ELSE 'ipv4' END ELSE address_family END AS address_family,count,first_seen,last_seen,capture_processed FROM flows"
    query = "SELECT " + ",".join(DIMENSIONS) + ",SUM(count) AS count,MIN(first_seen) AS first_seen,MAX(last_seen) AS last_seen FROM (" + normalized + ") normalized_flows WHERE " + " AND ".join(clause) + " GROUP BY " + ",".join(DIMENSIONS)
    return query, tuple(args)


def listing(store, value=None):
    value = _validate(store, value)
    with store.read_traffic() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN")
        grouped, args = _grouped(db, value)
        summary = db.execute("SELECT COUNT(*),COUNT(DISTINCT server_id),COALESCE(SUM(CASE WHEN count_unit='connections' THEN count ELSE 0 END),0),COALESCE(SUM(CASE WHEN count_unit='packets' THEN count ELSE 0 END),0),COALESCE(SUM(CASE WHEN count_unit='log_records' THEN count ELSE 0 END),0) FROM (" + grouped + ") relationships", args).fetchone()
        result = [capture_public(dict(row)) for row in db.execute(grouped + " ORDER BY " + ORDER + " LIMIT ? OFFSET ?", args + (value["limit"], value["offset"]))]
    total = int(summary[0])
    return {"items": result, "total": total, "endpoint_count": int(summary[1]), "counts_by_unit": {name: int(summary[index]) for index, name in enumerate(("connections", "packets", "log_records"), 2)}, "limit": value["limit"], "offset": value["offset"], "has_more": value["offset"] + len(result) < total, "window_seconds": value["window_seconds"], "as_of": value["as_of"], "from_time": value["from_time"], "coverage": COVERAGE, "filter_before_pagination": True}


def _cell(value):
    text = str(value if value is not None else "")
    return "'" + text if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) else text


@contextmanager
def csv_spool(store, value=None, *, max_rows=None, max_bytes=None):
    value = _validate(store, value, export=True)
    max_rows = MAX_EXPORT_ROWS if max_rows is None else max_rows
    max_bytes = MAX_EXPORT_BYTES if max_bytes is None else max_bytes
    if type(max_rows) is not int or not 1 <= max_rows <= MAX_EXPORT_ROWS or type(max_bytes) is not int or not 3 <= max_bytes <= MAX_EXPORT_BYTES:
        raise ValueError("Invalid complete traffic export bound")
    if not EXPORT_SLOTS.acquire(blocking=False):
        raise ExportBusy("CSV export capacity is busy; retry shortly")
    try:
        with tempfile.TemporaryFile(mode="w+b", dir=store.path if getattr(store, "path", None) else None) as output:
            output.write(b"\xef\xbb\xbf")
            def write(values):
                line = io.StringIO(newline="")
                csv.writer(line).writerow([_cell(item) for item in values])
                raw = line.getvalue().encode("utf-8")
                if output.tell() + len(raw) > max_bytes:
                    raise ValueError("Complete traffic CSV exceeds its byte bound; narrow the endpoint/time scope")
                output.write(raw)
            write((*FIELDS, *DESTINATION_FIELDS))
            with store.read_meta() as db:
                destinations = endpoint_labels(db)
            with store.read_traffic() as db:
                if getattr(db, "dialect", "sqlite") == "sqlite":
                    db.execute("BEGIN")
                grouped, args = _grouped(db, value)
                if int(db.execute("SELECT COUNT(*) FROM (" + grouped + ") relationships", args).fetchone()[0]) > max_rows:
                    raise ValueError("Complete traffic CSV exceeds its row bound; narrow the endpoint/time scope")
                for row in rows(db, grouped + " ORDER BY " + ORDER, args, batch_size=64):
                    # Streaming PostgreSQL cursors expose raw tuples, unlike
                    # the adapter's ordinary named SQLite-compatible rows.
                    record = capture_public(dict(zip(FIELDS, row)))
                    write([*(record.get(field) for field in FIELDS), *destinations.get(record["server_id"], ("", ""))])
            size = output.tell()
            output.flush(); output.seek(0)
            yield output, size
    finally:
        EXPORT_SLOTS.release()
