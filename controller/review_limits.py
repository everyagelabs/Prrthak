"""Storage-encoding review bounds, independent of database/store modules."""
import json

MAX_REVIEW_BYTES = 8 * 1024 * 1024


def encoded_size(value, maximum=None):
    """Count compact, ASCII-escaped storage JSON without allocating its full bytes.

    Call incrementally before appending candidate authority rows, and once on
    the complete persisted enclosing record before any write/audit. Raises;
    never truncates or returns a partly reviewed grant matrix.
    """
    maximum = MAX_REVIEW_BYTES if maximum is None else maximum
    size = 0
    for fragment in json.JSONEncoder(separators=(",", ":")).iterencode(value):
        size += len(fragment.encode("utf-8"))
        if size > maximum:
            raise ValueError("Exact authorization review exceeds the 8 MiB bound; select a smaller reviewed scope")
    return size
