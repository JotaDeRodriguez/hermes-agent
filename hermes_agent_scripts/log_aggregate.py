"""Server-side aggregation for the high-volume Supabase datasets.

The Management API analytics endpoint runs BigQuery SQL, so instead of pulling
every row and recursively bisecting the 1000-row cap (which never finished
``edge_logs`` within the cron window — see fetch_logs history), we push the
counts / top-N tables / histograms straight into ``GROUP BY`` queries. Each
query returns at most a top-N result, so the 1000-row cap is never hit and no
bisection happens: ~6 bounded round-trips per dataset instead of hundreds.

Only ``edge_logs`` and ``auth_logs`` are handled here — they're the two that
blow the time budget. The low-volume datasets (postgres/function/storage/
realtime) stay on the raw-row path in fetch_logs (one query each).

Verified against the live endpoint (2026-06-25):
  * BigQuery dialect, ``split(event_message, ' | ')`` on the
    'METHOD | STATUS | URL | UA' edge_logs message,
  * ``json_value(event_message, '$.field')`` on the JSON auth_logs message,
  * ``cross join unnest`` for nested ``metadata.request.cf.country``,
  * ``div(unix_micros(timestamp) - <start_us>, <bucket_us>)`` for time buckets.

Output dicts mirror log_digest._edge_digest / _auth_digest exactly so
build_digest can pass them through unchanged. Read-only.
"""

import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from fetch_logs import (
    SUPABASE_MAX_WORKERS,
    _iso,
    _log,
    _supabase_sql,
)
from log_common import _sample
from log_digest import (
    HISTOGRAM_BUCKETS,
    SAMPLE_CAP,
    TOP_COUNTRIES,
    TOP_ENDPOINTS,
    TOP_IPS,
    TOP_PATHS,
    TOP_USER_AGENTS,
    _status_class,
)

# Mirrors log_common.url_path() in SQL: take the URL field (split offset 2),
# reduce to its path, then collapse numeric ids (/123 -> /<N>) and UUIDs so
# endpoints group by shape rather than by id.
_PATH_NORM = (
    "regexp_replace(regexp_replace("
    "regexp_extract(split(event_message,' | ')[safe_offset(2)], r'https?://[^/]+(/[^?\\s]*)'),"
    " r'/[0-9]+', '/<N>'),"
    " r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '<UUID>')"
)

# edge_logs queries time out in BigQuery around the 12h mark on the live
# project, while 6h windows finish reliably. Keep long report windows chunked
# below that threshold and merge the aggregate rows locally.
EDGE_CHUNK_HOURS = 6
EDGE_CHUNK_TOP_MULTIPLIER = 4


def _hist_expr(start, bucket) -> str:
    """SQL expression mapping each row's timestamp to a 0..N-1 bucket index,
    matching log_digest._histogram's client-side bucketing."""
    start_us = int(start.timestamp() * 1_000_000)
    bucket_us = max(1, int(bucket.total_seconds() * 1_000_000))
    return f"div(unix_micros(timestamp) - {start_us}, {bucket_us})"


def _histogram(rows, start, bucket) -> dict:
    counts: Counter = Counter()
    for r in rows:
        idx = r.get("b")
        if idx is None:
            continue
        idx = max(0, min(HISTOGRAM_BUCKETS - 1, int(idx)))
        counts[idx] += int(r.get("c") or 0)
    return {_iso(start + i * bucket): counts[i] for i in sorted(counts)}


def _range_from_hist(hist: dict, start, end) -> list:
    """Approximate [first, last] activity from the populated histogram buckets;
    falls back to the requested window when empty. (Server-side aggregation
    doesn't pull individual rows, so this is bucket-granular, not exact.)"""
    if not hist:
        return [_iso(start), _iso(end)]
    keys = sorted(hist)
    return [keys[0], keys[-1]]


def _safe_q(url, headers, sql, start, end, label) -> list | None:
    """Run one aggregate query, tolerating a transient failure (the analytics
    backend occasionally returns a 499 'Job timed out'). One retry, then give
    up on just this metric so a single flaky query can't sink the whole run."""
    for attempt in (1, 2):
        try:
            return _supabase_sql(url, headers, sql, start, end, pace=False)
        except Exception as exc:  # noqa: BLE001 — degrade this metric, keep the rest
            _log(f"    agg query {label} attempt {attempt} failed: "
                 f"{type(exc).__name__}: {exc}")
    return None


def _run_queries(url, headers, queries, start, end) -> dict:
    """Run a {name: sql} map of independent aggregate queries concurrently and
    return {name: rows}. Each query spends ~10s in the BigQuery backend, so
    firing them in parallel (rather than one-at-a-time) is what keeps the whole
    run inside the cron's terminal timeout. Pool size bounds the in-flight
    request count under the 30 req/min API cap."""
    with ThreadPoolExecutor(max_workers=SUPABASE_MAX_WORKERS) as pool:
        futures = {
            name: pool.submit(_safe_q, url, headers, sql, start, end, name)
            for name, sql in queries.items()
        }
        rows: dict = {}
        failed: set[str] = set()
        for name, fut in futures.items():
            result = fut.result()
            if result is None:
                failed.add(name)
                rows[name] = []
            else:
                rows[name] = result
        return rows, failed


def _chunks(start, end, max_hours):
    step = end - start
    max_step = step if step.total_seconds() <= max_hours * 3600 else None
    if max_step is not None:
        yield start, end
        return

    cursor = start
    while cursor < end:
        nxt = min(end, cursor + type(step)(hours=max_hours))
        yield cursor, nxt
        cursor = nxt


def _top_rows(counter: Counter, key: str, limit: int) -> list[dict]:
    return [{key: value, "c": count} for value, count in counter.most_common(limit)]


def _merge_histograms(parts: list[dict]) -> dict:
    counts: Counter = Counter()
    for hist in parts:
        for ts, count in hist.items():
            counts[ts] += int(count or 0)
    return {ts: counts[ts] for ts in sorted(counts)}


def _edge_digest_window(url, headers, query_start, query_end, hist_start, hist_end,
                        bucket, limit_multiplier=1) -> tuple[dict, set[str]]:
    """Compute edge digest rows for one query window.

    ``hist_start`` is deliberately separate from ``query_start`` so chunked
    24h collection still produces one global 24-bucket histogram.
    """
    res, failed = _run_queries(url, headers, {
        "edge.status":
            "select split(event_message,' | ')[safe_offset(1)] as status, "
            "count(*) c from edge_logs group by status order by c desc limit 50",
        "edge.endpoints":
            f"select concat(split(event_message,' | ')[safe_offset(0)], ' ', "
            f"{_PATH_NORM}) as endpoint, count(*) c from edge_logs "
            f"group by endpoint order by c desc limit "
            f"{TOP_ENDPOINTS * limit_multiplier}",
        "edge.agents":
            "select split(event_message,' | ')[safe_offset(3)] as ua, count(*) c "
            f"from edge_logs group by ua order by c desc limit "
            f"{TOP_USER_AGENTS * limit_multiplier}",
        "edge.countries":
            "select cf.country as country, count(*) c from edge_logs "
            "cross join unnest(metadata) m cross join unnest(m.request) request "
            f"cross join unnest(request.cf) cf group by country order by c desc "
            f"limit {TOP_COUNTRIES * limit_multiplier}",
        "edge.samples":
            "select event_message from edge_logs where "
            "safe_cast(split(event_message,' | ')[safe_offset(1)] as int64) >= 400 "
            f"order by timestamp desc limit {SAMPLE_CAP}",
        "edge.histogram":
            f"select {_hist_expr(hist_start, bucket)} as b, count(*) c from edge_logs "
            "group by b order by b",
    }, query_start, query_end)

    by_status: Counter = Counter()
    by_class: Counter = Counter()
    total = 0
    for r in res["edge.status"]:
        c = int(r.get("c") or 0)
        total += c
        try:
            si = int(r.get("status"))
        except (TypeError, ValueError):
            continue
        by_status[si] += c
        by_class[_status_class(si)] += c

    digest = {
        "rows": total,
        "time_range": _range_from_hist(
            _histogram(res["edge.histogram"], hist_start, bucket),
            hist_start,
            hist_end,
        ),
        "by_status_class": dict(sorted(by_class.items())),
        "by_status": {str(k): v for k, v in sorted(by_status.items())},
        "top_endpoints": [{"endpoint": r["endpoint"], "count": int(r["c"])}
                          for r in res["edge.endpoints"] if r.get("endpoint")],
        "top_countries": [{"country": r["country"], "count": int(r["c"])}
                          for r in res["edge.countries"] if r.get("country")],
        "top_user_agents": [{"user_agent": r.get("ua") or "unknown",
                             "count": int(r["c"])} for r in res["edge.agents"]],
        "error_samples": [_sample(r.get("event_message", ""))
                          for r in res["edge.samples"]],
        "histogram": _histogram(res["edge.histogram"], hist_start, bucket),
    }
    return digest, failed


def _merge_edge_digests(parts: list[dict], start, end, truncated: bool) -> dict:
    by_class: Counter = Counter()
    by_status: Counter = Counter()
    endpoints: Counter = Counter()
    countries: Counter = Counter()
    agents: Counter = Counter()
    samples = []

    for part in parts:
        by_class.update({k: int(v) for k, v in part.get("by_status_class", {}).items()})
        by_status.update({k: int(v) for k, v in part.get("by_status", {}).items()})
        endpoints.update({
            row["endpoint"]: int(row["count"])
            for row in part.get("top_endpoints", [])
            if row.get("endpoint")
        })
        countries.update({
            row["country"]: int(row["count"])
            for row in part.get("top_countries", [])
            if row.get("country")
        })
        agents.update({
            row["user_agent"]: int(row["count"])
            for row in part.get("top_user_agents", [])
            if row.get("user_agent")
        })

    # Chunks are collected oldest -> newest; take newest samples first.
    for part in reversed(parts):
        for sample in part.get("error_samples", []):
            if len(samples) >= SAMPLE_CAP:
                break
            samples.append(sample)
        if len(samples) >= SAMPLE_CAP:
            break

    histogram = _merge_histograms([part.get("histogram", {}) for part in parts])
    out = {
        "rows": sum(int(part.get("rows") or 0) for part in parts),
        "time_range": _range_from_hist(histogram, start, end),
        "by_status_class": dict(sorted(by_class.items())),
        "by_status": dict(sorted(by_status.items(), key=lambda item: int(item[0]))),
        "top_endpoints": [
            {"endpoint": endpoint, "count": count}
            for endpoint, count in endpoints.most_common(TOP_ENDPOINTS)
        ],
        "top_countries": [
            {"country": country, "count": count}
            for country, count in countries.most_common(TOP_COUNTRIES)
        ],
        "top_user_agents": [
            {"user_agent": ua, "count": count}
            for ua, count in agents.most_common(TOP_USER_AGENTS)
        ],
        "error_samples": samples,
        "histogram": histogram,
    }
    if truncated:
        out["truncated"] = True
    return out


def edge_digest(url, headers, start, end, bucket, deadline=None) -> dict:
    """Same shape as log_digest._edge_digest, computed server-side."""
    total_hours = (end - start).total_seconds() / 3600
    if total_hours <= EDGE_CHUNK_HOURS:
        digest, failed = _edge_digest_window(url, headers, start, end, start, end, bucket)
        if failed:
            digest["truncated"] = True
        return digest

    parts = []
    failed: set[str] = set()
    truncated = False
    chunks = list(_chunks(start, end, EDGE_CHUNK_HOURS))
    _log(f"    edge_logs: chunking into {len(chunks)}x <= {EDGE_CHUNK_HOURS}h windows")
    for idx, (chunk_start, chunk_end) in enumerate(chunks, start=1):
        if deadline is not None and time.monotonic() > deadline:
            _log(f"    edge_logs chunk {idx}/{len(chunks)} skipped: budget exceeded")
            truncated = True
            break
        _log(f"    edge_logs chunk {idx}/{len(chunks)}: "
             f"{_iso(chunk_start)}..{_iso(chunk_end)}")
        part, part_failed = _edge_digest_window(
            url,
            headers,
            chunk_start,
            chunk_end,
            start,
            end,
            bucket,
            limit_multiplier=EDGE_CHUNK_TOP_MULTIPLIER,
        )
        parts.append(part)
        failed.update(part_failed)

    if failed:
        _log("    edge_logs aggregate metrics degraded: " + ", ".join(sorted(failed)))
        truncated = True
    return _merge_edge_digests(parts, start, end, truncated)


def auth_digest(url, headers, start, end, bucket, deadline=None) -> dict:
    """Same shape as log_digest._auth_digest, computed server-side."""
    res, failed = _run_queries(url, headers, {
        "auth.status":
            "select json_value(event_message,'$.status') as status, count(*) c "
            "from auth_logs group by status order by c desc limit 50",
        "auth.paths":
            "select json_value(event_message,'$.path') as path, count(*) c "
            f"from auth_logs group by path order by c desc limit {TOP_PATHS}",
        "auth.ips":
            "select json_value(event_message,'$.remote_addr') as ip, count(*) c "
            f"from auth_logs group by ip order by c desc limit {TOP_IPS}",
        "auth.samples":
            "select event_message from auth_logs where "
            "safe_cast(json_value(event_message,'$.status') as int64) >= 400 "
            f"order by timestamp desc limit {SAMPLE_CAP}",
        "auth.histogram":
            f"select {_hist_expr(start, bucket)} as b, count(*) c from auth_logs "
            "group by b order by b",
    }, start, end)

    by_status: dict = {}
    total = 0
    failures = 0
    for r in res["auth.status"]:
        c = int(r.get("c") or 0)
        total += c
        try:
            si = int(r.get("status"))
        except (TypeError, ValueError):
            continue
        by_status[si] = by_status.get(si, 0) + c
        if si >= 400:
            failures += c

    paths = res["auth.paths"]
    ips = res["auth.ips"]
    samples = res["auth.samples"]
    histogram = _histogram(res["auth.histogram"], start, bucket)

    out = {
        "rows": total,
        "time_range": _range_from_hist(histogram, start, end),
        "by_status": {str(k): v for k, v in sorted(by_status.items())},
        "top_paths": [{"path": r["path"], "count": int(r["c"])}
                      for r in paths if r.get("path")],
        "top_ips": [{"ip": r["ip"], "count": int(r["c"])}
                    for r in ips if r.get("ip")],
        "failures": failures,
        "failure_samples": [_sample(r.get("event_message", "")) for r in samples],
        "histogram": histogram,
    }
    if failed:
        _log("    auth_logs aggregate metrics degraded: " + ", ".join(sorted(failed)))
        out["truncated"] = True
    return out
