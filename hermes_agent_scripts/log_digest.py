"""Compress raw Railway + Supabase logs into a bounded JSON digest.

Raw collection produces ~1M+ pretty-printed lines for a single day, which no
model can ingest. build_digest() aggregates the rows into counts, top-N tables,
time-bucketed histograms, and a handful of redacted samples. Every list is
capped, so the output size is bounded regardless of how many rows came in.

Read-only: operates purely on already-collected rows, modifies nothing.
"""

import re
from collections import Counter
from datetime import timedelta

from fetch_logs import _iso, _utcnow
from log_common import (
    _auth_parse,
    _edge_country,
    _edge_parse,
    _pg_parsed,
    _sample,
    normalize_message,
    to_datetime,
    url_path,
)

# --- Caps that bound the output size -----------------------------------------
TOP_MESSAGES = 30
TOP_ENDPOINTS = 30
TOP_COUNTRIES = 15
TOP_USER_AGENTS = 15
TOP_IPS = 15
TOP_PATHS = 20
TOP_STATEMENTS = 25
SAMPLE_CAP = 8
HISTOGRAM_BUCKETS = 24

# Railway instability markers (descriptive count, mirrors the detector's intent).
_CRASH = re.compile(
    r"OOMKilled|out of memory|\bpanic\b|segfault|core dumped|\bcrashed\b|"
    r"fatal error|npm ERR!|Traceback \(most recent call last\)",
    re.I,
)


def _top(counter: Counter, n: int, key_name: str) -> list[dict]:
    return [{key_name: k, "count": c} for k, c in counter.most_common(n)]


def _status_class(status: int) -> str:
    return f"{status // 100}xx"


def _time_range(rows, ts_field="timestamp") -> list:
    times = [to_datetime(r.get(ts_field)) for r in rows]
    times = [t for t in times if t]
    if not times:
        return [None, None]
    return [_iso(min(times)), _iso(max(times))]


def _histogram(rows, start, bucket, ts_field="timestamp") -> dict:
    """Bucket row timestamps into <=HISTOGRAM_BUCKETS slots -> {iso: count}."""
    counts: Counter = Counter()
    for r in rows:
        dt = to_datetime(r.get(ts_field))
        if dt is None:
            continue
        idx = int((dt - start) / bucket)
        idx = max(0, min(HISTOGRAM_BUCKETS - 1, idx))
        counts[idx] += 1
    return {_iso(start + i * bucket): counts[i] for i in sorted(counts)}


# --- Per-source digests ------------------------------------------------------
def _railway_digest(rows, start, bucket) -> dict:
    by_severity: Counter = Counter()
    templates: Counter = Counter()
    crashes: Counter = Counter()
    samples = []
    for r in rows:
        msg = str(r.get("message", ""))
        by_severity[str(r.get("severity", "unknown"))] += 1
        templates[normalize_message(msg)] += 1
        for m in _CRASH.findall(msg):
            crashes[m.lower()] += 1
        is_err = str(r.get("severity", "")).lower() in ("error", "warn", "warning",
                                                         "critical", "fatal")
        if (is_err or _CRASH.search(msg)) and len(samples) < SAMPLE_CAP:
            samples.append(_sample(msg))
    return {
        "rows": len(rows),
        "time_range": _time_range(rows),
        "by_severity": dict(by_severity),
        "crash_markers": dict(crashes),
        "top_messages": _top(templates, TOP_MESSAGES, "template"),
        "error_samples": samples,
        "histogram": _histogram(rows, start, bucket),
    }


def _edge_digest(rows, start, bucket) -> dict:
    by_class: Counter = Counter()
    by_status: Counter = Counter()
    endpoints: Counter = Counter()
    countries: Counter = Counter()
    agents: Counter = Counter()
    samples = []
    for r in rows:
        rec = _edge_parse(r)
        if not rec:
            continue
        by_class[_status_class(rec["status"])] += 1
        by_status[rec["status"]] += 1
        endpoints[f"{rec['method']} {url_path(rec['url'])}"] += 1
        agents[rec["ua"] or "unknown"] += 1
        country = _edge_country(r)
        if country:
            countries[country] += 1
        if rec["status"] >= 400 and len(samples) < SAMPLE_CAP:
            samples.append(_sample(r.get("event_message", "")))
    return {
        "rows": len(rows),
        "time_range": _time_range(rows),
        "by_status_class": dict(sorted(by_class.items())),
        "by_status": {str(k): v for k, v in sorted(by_status.items())},
        "top_endpoints": _top(endpoints, TOP_ENDPOINTS, "endpoint"),
        "top_countries": _top(countries, TOP_COUNTRIES, "country"),
        "top_user_agents": _top(agents, TOP_USER_AGENTS, "user_agent"),
        "error_samples": samples,
        "histogram": _histogram(rows, start, bucket),
    }


def _auth_digest(rows, start, bucket) -> dict:
    by_status: Counter = Counter()
    paths: Counter = Counter()
    ips: Counter = Counter()
    failures = 0
    samples = []
    for r in rows:
        rec = _auth_parse(r)
        if not rec:
            continue
        status = rec.get("status")
        if isinstance(status, int):
            by_status[status] += 1
        if rec.get("path"):
            paths[rec["path"]] += 1
        if rec.get("remote_addr"):
            ips[rec["remote_addr"]] += 1
        if isinstance(status, int) and status >= 400:
            failures += 1
            if len(samples) < SAMPLE_CAP:
                samples.append(_sample(r.get("event_message", "")))
    return {
        "rows": len(rows),
        "time_range": _time_range(rows),
        "by_status": {str(k): v for k, v in sorted(by_status.items())},
        "top_paths": _top(paths, TOP_PATHS, "path"),
        "top_ips": _top(ips, TOP_IPS, "ip"),
        "failures": failures,
        "failure_samples": samples,
        "histogram": _histogram(rows, start, bucket),
    }


def _postgres_digest(rows, start, bucket) -> dict:
    by_severity: Counter = Counter()
    statements: Counter = Counter()
    samples = []
    for r in rows:
        parsed = _pg_parsed(r)
        sev = str(parsed.get("error_severity", "UNKNOWN")).upper()
        by_severity[sev] += 1
        statements[normalize_message(r.get("event_message", ""))] += 1
        if sev in ("ERROR", "FATAL", "PANIC") and len(samples) < SAMPLE_CAP:
            samples.append(_sample(r.get("event_message", "")))
    return {
        "rows": len(rows),
        "time_range": _time_range(rows),
        "by_severity": dict(by_severity),
        "top_statements": _top(statements, TOP_STATEMENTS, "template"),
        "error_samples": samples,
        "histogram": _histogram(rows, start, bucket),
    }


def _generic_digest(rows, start, bucket) -> dict:
    """Fallback for low-volume datasets (function/storage/realtime)."""
    templates: Counter = Counter()
    for r in rows:
        templates[normalize_message(r.get("event_message", ""))] += 1
    return {
        "rows": len(rows),
        "time_range": _time_range(rows),
        "top_messages": _top(templates, TOP_MESSAGES, "template"),
        "histogram": _histogram(rows, start, bucket),
    }


_SUPABASE_DIGESTERS = {
    "edge_logs": _edge_digest,
    "auth_logs": _auth_digest,
    "postgres_logs": _postgres_digest,
}


def build_digest(railway: list, supabase: dict, period_hours: float) -> dict:
    end = _utcnow()
    start = end - timedelta(hours=period_hours)
    bucket = (end - start) / HISTOGRAM_BUCKETS

    digest = {
        "generated_at": _iso(end),
        "period_hours": period_hours,
        "railway": _railway_digest(railway, start, bucket),
        "supabase": {},
    }
    for dataset, value in supabase.items():
        # High-volume datasets arrive already aggregated server-side (a dict);
        # low-volume ones arrive as raw row lists to digest here. (--raw mode
        # bypasses build_digest entirely, so values are always one or the other.)
        if isinstance(value, dict):
            digest["supabase"][dataset] = value
        else:
            digester = _SUPABASE_DIGESTERS.get(dataset, _generic_digest)
            digest["supabase"][dataset] = digester(value, start, bucket)
    return digest
