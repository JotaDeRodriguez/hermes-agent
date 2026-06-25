"""Collect Railway + Supabase logs over a time window and emit normalized JSON.

Usage:
    python fetch_logs.py [hours]   # default 24

Railway logs: GraphQL API (`environmentLogs`), authenticated with the project
token via the `Project-Access-Token` header, paginated backward by time.
Supabase logs: Management API, recursively time-bisected so the per-query
1000-row cap never silently drops data.

Read-only; nothing is modified on either platform.
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

# When this file is executed as a script, log_aggregate imports "fetch_logs".
# Alias __main__ so that import reuses this module instead of loading a second
# copy with its own timers/constants.
if __name__ == "__main__":
    sys.modules.setdefault("fetch_logs", sys.modules[__name__])

# Load .env sitting next to this script.
load_dotenv(Path(__file__).with_name(".env"))


# --- Diagnostics -------------------------------------------------------------
# All diagnostics go to STDERR on purpose: stdout carries the JSON digest that
# the Hermes agent ingests, so anything printed there would corrupt it. stderr
# is what surfaces in the console / Railway logs. Silence with LOG_QUIET=1.
_T0 = time.monotonic()


def _log(msg: str) -> None:
    if os.environ.get("LOG_QUIET"):
        return
    print(f"[fetch_logs +{time.monotonic() - _T0:6.1f}s] {msg}",
          file=sys.stderr, flush=True)


def _check_env(names: list[str]) -> None:
    """Report presence of required env vars — names and lengths only, never
    the values (these are secrets)."""
    for name in names:
        value = os.environ.get(name)
        _log(f"env {name}: {'set (len=%d)' % len(value) if value else 'MISSING'}")


# --- Railway -----------------------------------------------------------------
RAILWAY_GRAPHQL = "https://backboard.railway.com/graphql/v2"
RAILWAY_BATCH = 5000      # logs requested per environmentLogs page
RAILWAY_MAX_PAGES = 500   # safety cap on backward pagination

# --- Supabase ----------------------------------------------------------------
# Analytics/logs endpoints live under /v0 (see supabase_experimental_api.yaml).
SUPABASE_API = "https://api.supabase.com/v0"
SUPABASE_ROW_CAP = 1000   # Management API caps each query at 1000 rows
# High-volume datasets are aggregated server-side (log_aggregate) — pulling
# their rows and bisecting the 1000-row cap never finished within the cron
# window. The rest are low-volume: raw rows + client-side digest in one query.
SUPABASE_AGG_DATASETS = ("edge_logs", "auth_logs")
SUPABASE_RAW_DATASETS = (
    "postgres_logs",
    "function_logs",
    "storage_logs",
    "realtime_logs",
)
# Wall-clock budget for the whole Supabase phase. The cron runs the script via
# a terminal tool with a ~120s timeout, and a timeout yields NO output at all
# (the run + its tokens are wasted). This budget guarantees we stop and emit
# whatever we have — with a per-dataset `truncated` marker — well inside that
# window. Override with SUPABASE_BUDGET_S.
SUPABASE_BUDGET_S = float(os.environ.get("SUPABASE_BUDGET_S", "90"))
# Log endpoint is limited to 30 req/min; pace requests to stay well under it.
RATE_LIMIT_SLEEP_S = 2.5
# Aggregation fires several independent GROUP BY queries per dataset, each of
# which spends most of its wall-clock time in the BigQuery backend (~10s), so
# running them concurrently is what actually keeps the run inside the cron's
# terminal timeout. Kept small so the in-flight request count stays well under
# the 30 req/min cap.
SUPABASE_MAX_WORKERS = 6


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_ts(value) -> datetime | None:
    """Parse an ISO-8601 timestamp; None if absent/unparseable."""
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    # fromisoformat (<3.11) rejects nanosecond precision; trim to microseconds.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


# --- Railway -----------------------------------------------------------------
def _railway_gql(query: str, variables: dict) -> dict:
    token = os.environ["RAILWAY_AGENT_TOKEN"]
    resp = requests.post(
        RAILWAY_GRAPHQL,
        headers={"Project-Access-Token": token, "Content-Type": "application/json"},
        json={"query": query, "variables": variables},
        timeout=60,
    )
    if resp.status_code != 200:
        _log(f"Railway HTTP {resp.status_code}: {resp.text[:200]}")
    resp.raise_for_status()
    body = resp.json()
    if body.get("errors"):
        raise RuntimeError(f"Railway GraphQL error: {body['errors']}")
    return body["data"]


def _railway_context(service_name: str) -> tuple[str, str]:
    """Resolve (environmentId, serviceId) from the project token + service name."""
    env_id = _railway_gql("query{projectToken{environmentId}}", {})["projectToken"][
        "environmentId"
    ]
    data = _railway_gql(
        "query($id:String!){environment(id:$id){serviceInstances{edges{node"
        "{serviceId serviceName}}}}}",
        {"id": env_id},
    )
    for edge in data["environment"]["serviceInstances"]["edges"]:
        node = edge["node"]
        if node["serviceName"] == service_name:
            return env_id, node["serviceId"]
    raise RuntimeError(f"Service {service_name!r} not found in environment {env_id}")


def railway_logs(hours: int) -> list[dict]:
    env_id, service_id = _railway_context(os.environ["RAILWAY_SERVICE"])
    _log(f"Railway context: env={env_id} service={service_id}")
    cutoff = _utcnow() - timedelta(hours=hours)

    query = (
        "query($e:String!,$a:String!,$n:Int!,$f:String!){"
        "environmentLogs(environmentId:$e,anchorDate:$a,beforeLimit:$n,filter:$f)"
        "{timestamp severity message}}"
    )
    flt = f"@service:{service_id}"

    anchor = _iso(_utcnow())
    seen: set[tuple] = set()
    out: list[dict] = []

    for page_num in range(RAILWAY_MAX_PAGES):
        page = _railway_gql(
            query, {"e": env_id, "a": anchor, "n": RAILWAY_BATCH, "f": flt}
        )["environmentLogs"]
        if not page:
            _log(f"  railway page {page_num + 1}: empty, stopping")
            break

        new = 0
        for rec in page:
            key = (rec["timestamp"], rec["message"])
            if key in seen:
                continue
            seen.add(key)
            new += 1
            ts = _parse_ts(rec["timestamp"])
            if ts is None or ts >= cutoff:
                out.append(rec)

        # ISO-8601 UTC strings sort chronologically; oldest = min.
        oldest = min(rec["timestamp"] for rec in page)
        oldest_ts = _parse_ts(oldest)
        _log(f"  railway page {page_num + 1}: got {len(page)}, new {new}, "
             f"kept {len(out)}, oldest {oldest}")
        if new == 0 or oldest_ts is None or oldest_ts <= cutoff:
            break
        anchor = oldest  # page further back

    return out


# --- Supabase ----------------------------------------------------------------
def _supabase_sql(url, headers, sql, start, end, pace=True) -> list[dict]:
    """Run one analytics SQL query over [start, end) and return its result rows.
    The shared low-level runner for both the raw row-pull and the server-side
    aggregation in log_aggregate. ``pace`` adds the sequential rate-limit sleep;
    the parallel aggregation path sets pace=False and bounds its request rate
    with a small thread pool instead."""
    if pace:
        time.sleep(RATE_LIMIT_SLEEP_S)
    resp = requests.get(
        url,
        headers=headers,
        params={
            "sql": sql,
            "iso_timestamp_start": _iso(start),
            "iso_timestamp_end": _iso(end),
        },
        timeout=120,
    )
    if resp.status_code != 200:
        _log(f"Supabase HTTP {resp.status_code}: {resp.text[:200]}")
    resp.raise_for_status()
    body = resp.json()  # AnalyticsResponse = {"result": [...], "error": str|object}
    # The backend can return HTTP 200 with an error payload (e.g. a 499 "Job
    # timed out" from BigQuery), so check the body too.
    if body.get("error"):
        raise RuntimeError(f"Supabase logs error: {body['error']}")
    return body.get("result", [])


def _supabase_query(url, headers, dataset, start, end) -> list[dict]:
    return _supabase_sql(
        url, headers,
        f"select timestamp, event_message, metadata "
        f"from {dataset} order by timestamp desc limit {SUPABASE_ROW_CAP}",
        start, end,
    )


def _supabase_collect(url, headers, dataset, start, end, out, deadline) -> bool:
    """Query [start, end); bisect the window whenever the row cap is hit.

    Returns True if collection was cut short by the wall-clock ``deadline``
    (so the caller can flag the dataset as truncated rather than complete)."""
    if time.monotonic() > deadline:
        return True
    rows = _supabase_query(url, headers, dataset, start, end)
    if len(rows) >= SUPABASE_ROW_CAP and (end - start) > timedelta(seconds=1):
        _log(f"    {dataset} hit {SUPABASE_ROW_CAP}-row cap, bisecting "
             f"{_iso(start)}..{_iso(end)}")
        mid = start + (end - start) / 2
        t1 = _supabase_collect(url, headers, dataset, start, mid, out, deadline)
        t2 = _supabase_collect(url, headers, dataset, mid, end, out, deadline)
        return t1 or t2
    if len(rows) >= SUPABASE_ROW_CAP:
        print(
            f"WARNING: {dataset} hit the {SUPABASE_ROW_CAP}-row cap in a <=1s window "
            f"at {_iso(start)}; some rows may be dropped.",
            file=sys.stderr,
        )
    out.extend(rows)
    return False


def _supabase_collect_raw(url, headers, dataset, start, now, deadline) -> list[dict]:
    """Raw row pull for one dataset, bisecting on the cap, then deduped."""
    _log(f"  supabase {dataset}: querying {_iso(start)}..{_iso(now)}...")
    rows: list[dict] = []
    truncated = _supabase_collect(url, headers, dataset, start, now, rows, deadline)
    seen: set[tuple] = set()
    deduped = []
    for r in rows:
        key = (r.get("timestamp"), r.get("event_message"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)
    _log(f"  supabase {dataset}: {len(rows)} rows -> {len(deduped)} after dedup"
         + (" [TRUNCATED by budget]" if truncated else ""))
    return deduped


def supabase_logs(hours: int, raw: bool = False) -> dict:
    """Collect Supabase logs as a per-dataset map. By default the high-volume
    datasets are returned as already-built digest dicts (server-side
    aggregation) and low-volume ones as raw row lists for build_digest to
    aggregate. With ``raw=True`` every dataset is returned as raw rows (the
    --raw debug path). The whole phase is bounded by SUPABASE_BUDGET_S so the
    cron never times out empty-handed."""
    # Lazy imports: log_digest / log_aggregate import from this module, so
    # importing them here (after everything above is defined) avoids a cycle.
    from log_aggregate import auth_digest, edge_digest
    from log_digest import HISTOGRAM_BUCKETS

    now = _utcnow()
    start = now - timedelta(hours=hours)
    bucket = (now - start) / HISTOGRAM_BUCKETS
    ref = os.environ["SUPABASE_PROJECT_REF"]
    url = f"{SUPABASE_API}/projects/{ref}/analytics/endpoints/logs.all"
    headers = {"Authorization": f"Bearer {os.environ['SUPABASE_ACCESS_TOKEN']}"}
    deadline = time.monotonic() + SUPABASE_BUDGET_S

    out: dict = {}

    # --raw: every dataset as raw rows (debugging). Bounded by the deadline.
    if raw:
        for dataset in (*SUPABASE_AGG_DATASETS, *SUPABASE_RAW_DATASETS):
            if time.monotonic() > deadline:
                _log(f"  supabase {dataset}: SKIPPED (budget exceeded)")
                out[dataset] = []
                continue
            out[dataset] = _supabase_collect_raw(url, headers, dataset, start, now, deadline)
        return out

    # High-volume: server-side GROUP BY aggregation (bounded, no bisection).
    aggregators = {"edge_logs": edge_digest, "auth_logs": auth_digest}
    for dataset in SUPABASE_AGG_DATASETS:
        if time.monotonic() > deadline:
            _log(f"  supabase {dataset}: SKIPPED (budget "
                 f"{SUPABASE_BUDGET_S:.0f}s exceeded)")
            out[dataset] = {"rows": 0, "truncated": True, "histogram": {}}
            continue
        _log(f"  supabase {dataset}: aggregating server-side ({hours}h)...")
        out[dataset] = aggregators[dataset](url, headers, start, now, bucket, deadline)
        _log(f"  supabase {dataset}: rows={out[dataset].get('rows')}")

    # Low-volume: raw rows + client digest, bounded by the same deadline.
    for dataset in SUPABASE_RAW_DATASETS:
        if time.monotonic() > deadline:
            _log(f"  supabase {dataset}: SKIPPED (budget exceeded)")
            out[dataset] = []
            continue
        out[dataset] = _supabase_collect_raw(url, headers, dataset, start, now, deadline)
    return out


def main() -> None:
    # Logs contain non-ASCII; force UTF-8 so neither stream chokes on Windows.
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    args = [a for a in sys.argv[1:] if a != "--raw"]
    raw = "--raw" in sys.argv
    hours = int(args[0]) if args else 24

    _log(f"start: hours={hours} raw={raw} python={sys.executable}")
    _check_env([
        "RAILWAY_AGENT_TOKEN", "RAILWAY_SERVICE",
        "SUPABASE_ACCESS_TOKEN", "SUPABASE_PROJECT_REF",
    ])

    _log("fetching Railway logs...")
    railway = railway_logs(hours)
    _log(f"Railway: {len(railway)} rows in window")

    _log("fetching Supabase logs...")
    supabase = supabase_logs(hours, raw=raw)
    _log("Supabase totals: " + ", ".join(
        f"{k}={v.get('rows') if isinstance(v, dict) else len(v)}"
        for k, v in supabase.items()))

    if raw:
        # Full unaggregated rows — for debugging only; can be millions of lines.
        output = {
            "generated_at": _iso(_utcnow()),
            "period_hours": hours,
            "railway": railway,
            "supabase": supabase,
        }
        _log("emitting raw rows to stdout")
        print(json.dumps(output, ensure_ascii=False))
        return

    # Default: bounded digest (see log_digest.build_digest).
    from log_digest import build_digest

    _log("building digest...")
    digest = build_digest(railway, supabase, hours)
    _log("emitting digest to stdout")
    print(json.dumps(digest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 — log a clean line, then re-raise
        _log(f"FATAL: {type(exc).__name__}: {exc}")
        raise
