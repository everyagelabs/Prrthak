"""Bounded audit history navigation and complete, filtered private CSV spools."""
from contextlib import contextmanager
import csv
import io
import json
import re
import tempfile
import threading

from .approval_views import _expression
from .inventory_views import rows
from .store import parse_time

MAX_EXPORT_BYTES = 64 * 1024 * 1024
MAX_EVENT_BYTES = 8 * 1024 * 1024
MAX_DETAIL_CHARS = 32768
EXPORT_SLOTS = threading.BoundedSemaphore(2)
FILTERS = ("search", "action", "actor", "from_at", "to_at")
FIELDS = ("id", "action", "actor", "created_at")
SENSITIVE = re.compile(r"(?:password|passwd|secret|token(?!_id$)|private[_-]?key|authorization|cookie|credential|(?:^|_)dsn$|database_url|ca_key|signing_seed|^seed$|(?:^|_)(?:api|access|auth|shared|ssh|tls|signing|replication|cluster)[_-]?key(?:$|_))", re.I)
PRIVATE_TEXT = re.compile(r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----|(?:postgres(?:ql)?|mysql)://[^\s]+|\bBearer\s+[A-Za-z0-9._~+/-]+", re.I)


class ExportBusy(RuntimeError):
    pass


def _timestamp(value):
    if value == "":
        return ""
    return parse_time(value).isoformat().replace("+00:00", "Z")


def validate(value=None, *, export=False):
    if value is None:
        value = {}
    allowed = set(FILTERS) | (set() if export else {"limit", "offset"})
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("Provide supported audit filters only")
    result = {key: "" for key in FILTERS}
    result.update(value)
    for key, maximum in (("search", 256), ("action", 128), ("actor", 1024)):
        if not isinstance(result[key], str) or len(result[key]) > maximum:
            raise ValueError("Audit search/action/actor exceeds its text bound")
        result[key] = result[key].strip()
    for key in ("from_at", "to_at"):
        if not isinstance(result[key], str):
            raise ValueError("Audit dates must be timezone-aware timestamps")
        result[key] = _timestamp(result[key])
    if result["from_at"] and result["to_at"] and parse_time(result["from_at"]) > parse_time(result["to_at"]):
        raise ValueError("Audit start date must not follow its end date")
    if not export:
        result.setdefault("limit", 50)
        result.setdefault("offset", 0)
        if type(result["limit"]) is not int or not 1 <= result["limit"] <= 100 or type(result["offset"]) is not int or not 0 <= result["offset"] <= 10000000:
            raise ValueError("Audit page limit must be 1..100 and offset bounded/nonnegative")
    return result


def query_parameters(query, *, export=False):
    """GET parsing rejects repeated/unknown values instead of silently widening."""
    allowed = set(FILTERS) | (set() if export else {"limit", "offset"})
    if not isinstance(query, dict) or set(query) - allowed or any(not isinstance(values, list) or len(values) != 1 for values in query.values()):
        raise ValueError("Use supported single-value audit query parameters")
    values = {key: items[0] for key, items in query.items()}
    for key in ("limit", "offset"):
        if key in values:
            if not isinstance(values[key], str) or not re.fullmatch(r"\d{1,8}", values[key]):
                raise ValueError("Audit pagination values must be bounded integers")
            values[key] = int(values[key])
    return validate(values, export=export)


def _where(db, value):
    field = lambda key: _expression(db, (key,), "a")
    terms, parameters = ["1=1"], []
    for key in ("action", "actor"):
        if value[key]:
            terms.append(field(key) + "=?")
            parameters.append(value[key])
    for key, operator in (("from_at", ">="), ("to_at", "<=")):
        if value[key]:
            created = field("created_at")
            if getattr(db, "dialect", "sqlite") == "postgresql":
                temporal = "CASE WHEN pg_input_is_valid(" + created + ",'timestamp with time zone') THEN CAST(" + created + " AS timestamptz) END"
                terms.append("(" + temporal + ")" + operator + "CAST(? AS timestamptz)")
            else:
                terms.append("julianday(" + created + ")" + operator + "julianday(?)")
            parameters.append(value[key])
    if value["search"]:
        # Only known public scalars are searchable. Arbitrary nested values may
        # have been redacted by their producer; do not create a secret oracle.
        text = "lower(" + " || ' ' || ".join("COALESCE(" + field(key) + ",'')" for key in ("id", "action", "actor")) + ")"
        terms.append(("strpos(" + text + ",?)>0") if getattr(db, "dialect", "sqlite") == "postgresql" else ("instr(" + text + ",?)>0"))
        parameters.append(value["search"].lower())
    return " AND ".join(terms), tuple(parameters)


def redact(value, depth=0):
    """Defense in depth for historical records; producers still omit secrets."""
    if depth > 24:
        return "[REDACTED: nesting bound]"
    if isinstance(value, dict):
        return {key: "[REDACTED]" if SENSITIVE.search(str(key)) else redact(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, depth + 1) for item in value]
    if isinstance(value, str) and PRIVATE_TEXT.search(value):
        return "[REDACTED]"
    return value


def listing(store, value=None):
    value = validate(value)
    with store.read_meta() as db:
        if getattr(db, "dialect", "sqlite") == "sqlite":
            db.execute("BEGIN")
        where, parameters = _where(db, value)
        field = lambda key: _expression(db, (key,), "a")
        total = int(db.execute("SELECT COUNT(*) FROM audit a WHERE " + where, parameters).fetchone()[0])
        # Full event bodies never enter a history page. A bounded detail field
        # is decoded after the database has selected only this page.
        projection = ",".join("substr(CAST(" + field(key) + " AS TEXT),1," + str(bound) + ")" for key, bound in zip(FIELDS, (128, 256, 2048, 64)))
        if getattr(db, "dialect", "sqlite") == "postgresql":
            detail_expression = "CAST(a.data::jsonb->'details' AS TEXT)"
        else:
            detail_expression = "CASE json_type(a.data,'$.details') WHEN 'true' THEN 'true' WHEN 'false' THEN 'false' ELSE json_quote(json_extract(a.data,'$.details')) END"
        projection += ",substr(" + detail_expression + ",1," + str(MAX_DETAIL_CHARS + 1) + ")"
        selected = db.execute("SELECT " + projection + " FROM audit a WHERE " + where + " ORDER BY " + field("created_at") + " DESC,a.id DESC LIMIT ? OFFSET ?", parameters + (value["limit"], value["offset"]))
        items = []
        for row in selected:
            item = {key: row[index] or "" for index, key in enumerate(FIELDS)}
            raw = row[len(FIELDS)]
            invalid = False
            try:
                detail = json.loads(raw) if isinstance(raw, str) and len(raw) <= MAX_DETAIL_CHARS else None
                if not isinstance(raw, str):
                    detail = raw
            except (ValueError, TypeError):
                detail = None
                invalid = True
            if invalid or isinstance(raw, str) and len(raw) > MAX_DETAIL_CHARS:
                item.update(details={"omitted": True, "reason": "Details exceed the navigation bound; use filtered CSV export"}, details_omitted=True)
            else:
                item["details"] = redact(detail if detail is not None else {})
            items.append(item)
    return {"items": items, "total": total, "limit": value["limit"], "offset": value["offset"],
            "has_more": value["offset"] + len(items) < total, "filters": {key: value[key] for key in FILTERS}, "summary_only": True}


def _cell(value):
    text = str(value if value is not None else "")
    return "'" + text if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")) else text


@contextmanager
def csv_spool(store, value=None, *, max_bytes=None):
    value = validate(value, export=True)
    maximum = MAX_EXPORT_BYTES if max_bytes is None else max_bytes
    if type(maximum) is not int or not 3 <= maximum <= MAX_EXPORT_BYTES:
        raise ValueError("Invalid complete audit export size bound")
    if not EXPORT_SLOTS.acquire(blocking=False):
        raise ExportBusy("Audit export capacity is busy; retry shortly")
    try:
        with tempfile.TemporaryFile(mode="w+b", dir=store.path if getattr(store, "path", None) else None) as output:
            output.write(b"\xef\xbb\xbf")
            def write(values):
                line = io.StringIO(newline="")
                csv.writer(line).writerow([_cell(item) for item in values])
                raw = line.getvalue().encode("utf-8")
                if output.tell() + len(raw) > maximum:
                    raise ValueError("Complete audit CSV exceeds64MiB; narrow the date/action/actor filters")
                output.write(raw)
            write((*FIELDS, "details_json"))
            with store.read_meta() as db:
                if getattr(db, "dialect", "sqlite") == "sqlite":
                    db.execute("BEGIN")
                where, parameters = _where(db, value)
                size = "octet_length(a.data)" if getattr(db, "dialect", "sqlite") == "postgresql" else "length(CAST(a.data AS BLOB))"
                sql = "SELECT CASE WHEN " + size + "<=? THEN a.data ELSE NULL END FROM audit a WHERE " + where + " ORDER BY " + _expression(db, ("created_at",), "a") + " DESC,a.id DESC"
                for row in rows(db, sql, (MAX_EVENT_BYTES,) + parameters, batch_size=8):
                    if row[0] is None:
                        raise ValueError("An audit event exceeds the 8MiB per-event export bound; inspect the retained event through an approved archive")
                    event = json.loads(row[0])
                    # Preserve the producer's data, with consistent defensive
                    # redaction; no 500-row cutoff or silent row truncation.
                    details = json.dumps(redact(event.get("details", {})), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    write([redact(event.get(key, "")) for key in FIELDS] + [details])
            output.flush()
            size = output.tell()
            output.seek(0)
            yield output, size
    finally:
        EXPORT_SLOTS.release()
