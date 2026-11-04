"""Sustained, opt-in resource alerts for each Linux controller node."""
from pathlib import Path
import os
import sys

from .local_auth import write_fence
from .notification_events import queue, subscribed_revision
from .store import digest, now, parse_time, stamp


EVENT = "controller_resource_pressure"
MIN_SAMPLE_SECONDS = 25
MAX_SAMPLE_GAP_SECONDS = 90
SUSTAINED_SECONDS = 120
REARM_MARGIN = 5
THRESHOLDS = {
    "CPU": (85, "Linux host CPU activity"),
    "memory": (85, "Linux host memory use"),
    "storage": (90, "local controller data filesystem use"),
}


def _cpu_counters(path):
    try:
        with path.open(encoding="ascii") as source:
            fields = source.readline(1024).split()
        if len(fields) < 9 or fields[0] != "cpu":
            return None
        ticks = [int(value) for value in fields[1:9]]
        if min(ticks) < 0:
            return None
        user, nice, system, _, _, irq, softirq, _ = ticks
        return [sum(ticks), user + nice + system + irq + softirq]
    except (OSError, ValueError):
        return None


def _cpu_percent(previous, current):
    if not previous or not current:
        return None
    total, busy = [current[index] - previous[index] for index in range(2)]
    return 100 * busy / total if total > 0 and 0 <= busy <= total else None


def _memory_percent(path):
    try:
        with path.open(encoding="ascii") as source:
            values = {}
            for line in source.read(32768).splitlines():
                fields = line.split()
                if len(fields) == 3 and fields[0] in ("MemTotal:", "MemAvailable:") and fields[2] == "kB":
                    values[fields[0]] = int(fields[1])
        total, available = values.get("MemTotal:", 0), values.get("MemAvailable:", -1)
        return 100 * (total - available) / total if total > 0 and 0 <= available <= total else None
    except (OSError, ValueError):
        return None


def _storage_percent(data_path):
    try:
        usage = os.statvfs(Path(data_path).resolve(strict=True))
        total, free, available = usage.f_blocks, usage.f_bfree, usage.f_bavail
        if not 0 <= available <= free <= total:
            return None
        used = total - free
        return 100 * used / (used + available) if used + available else None
    except (OSError, ValueError):
        return None


def sample(store, controller_id, site, data_path, *, at=None):
    if sys.platform != "linux":
        return 0
    with store.read_meta() as db:
        if subscribed_revision(store, db, EVENT) is None:
            return 0
    at = at or now()
    sampled_at = stamp(at)
    cpu = _cpu_counters(Path("/proc/stat"))
    memory = _memory_percent(Path("/proc/meminfo"))
    storage = _storage_percent(data_path)
    identifier = "controller-resource:" + digest(controller_id)
    with store.lock, store.meta() as db:
        write_fence(db)
        revision = subscribed_revision(store, db, EVENT)
        if revision is None:
            return 0
        previous = store._get(db, "maintenance_settings", identifier) or {}
        elapsed = (at - parse_time(previous["sampled_at"])).total_seconds() if previous else -1
        if previous and -MAX_SAMPLE_GAP_SECONDS <= elapsed < MIN_SAMPLE_SECONDS:
            return 0
        continuous = 0 <= elapsed <= MAX_SAMPLE_GAP_SECONDS
        values = {"CPU": _cpu_percent(previous.get("cpu"), cpu) if continuous else None,
                  "memory": memory, "storage": storage}
        episodes = previous.get("episodes", {})
        sent = 0
        for metric, (threshold, label) in THRESHOLDS.items():
            value = values[metric]
            episode = episodes.setdefault(metric, {})
            if not continuous or value is None or value < threshold:
                episode.pop("since", None)
            if value is None:
                continue
            if value < threshold - REARM_MARGIN:
                episode.pop("notified", None)
            if episode.get("notified") or value < threshold:
                continue
            since = episode.setdefault("since", sampled_at)
            if (at - parse_time(since)).total_seconds() < SUSTAINED_SECONDS:
                continue
            node = " ".join(controller_id.split())
            location = " ".join(site.split())
            queue(db, revision, identifier + ":" + digest([metric, since]), EVENT,
                  f"Controller {node} ({location}) reported {label} of {value:.1f}% after at least "
                  f"{SUSTAINED_SECONDS // 60} minutes at or above {threshold}%.",
                  severity="warning", created_at=sampled_at)
            episode["notified"] = True
            sent += 1
        store._put(db, "maintenance_settings", {
            "id": identifier, "sampled_at": sampled_at, "cpu": cpu, "episodes": episodes,
        })
        return sent
