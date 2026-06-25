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
RAILWAY_BATCH = 1000      # logs requested per environmentLogs page
RAILWAY_MAX_PAGES = 500   # safety cap on backward pagination

# --- Supabase ----------------------------------------------------------------
# Analytics/logs endpoints live under /v0 (see supabase_experimental_api.yaml).
SUPABASE_API = "https://api.supabase.com/v0"
SUPABASE_ROW_CAP = 1000   # Management API caps each query at 1000 rows
SUPABASE_DATASETS = [
    "edge_logs",
    "auth_logs",
    "postgres_logs",
    "function_logs",
    "storage_logs",
    "realtime_logs",
]
# Log endpoint is limited to 30 req/min; pace requests to stay well under it.
RATE_LIMIT_SLEEP_S = 2.5


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
def _supabase_query(url, headers, dataset, start, end) -> list[dict]:
    sql = (
        f"select timestamp, event_message, metadata "
        f"from {dataset} order by timestamp desc limit {SUPABASE_ROW_CAP}"
    )
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
        _log(f"Supabase {dataset} HTTP {resp.status_code}: {resp.text[:200]}")
    resp.raise_for_status()
    body = resp.json()  # AnalyticsResponse = {"result": [...], "error": str|object}
    if body.get("error"):
        raise RuntimeError(f"Supabase logs error for {dataset}: {body['error']}")
    return body.get("result", [])


def _supabase_collect(url, headers, dataset, start, end, out) -> None:
    """Query [start, end); bisect the window whenever the row cap is hit."""
    rows = _supabase_query(url, headers, dataset, start, end)
    if len(rows) >= SUPABASE_ROW_CAP and (end - start) > timedelta(seconds=1):
        _log(f"    {dataset} hit {SUPABASE_ROW_CAP}-row cap, bisecting "
             f"{_iso(start)}..{_iso(end)}")
        mid = start + (end - start) / 2
        _supabase_collect(url, headers, dataset, start, mid, out)
        _supabase_collect(url, headers, dataset, mid, end, out)
        return
    if len(rows) >= SUPABASE_ROW_CAP:
        print(
            f"WARNING: {dataset} hit the {SUPABASE_ROW_CAP}-row cap in a <=1s window "
            f"at {_iso(start)}; some rows may be dropped.",
            file=sys.stderr,
        )
    out.extend(rows)


def supabase_logs(hours: int) -> dict[str, list[dict]]:
    now = _utcnow()
    start = now - timedelta(hours=hours)
    ref = os.environ["SUPABASE_PROJECT_REF"]
    url = f"{SUPABASE_API}/projects/{ref}/analytics/endpoints/logs.all"
    headers = {"Authorization": f"Bearer {os.environ['SUPABASE_ACCESS_TOKEN']}"}

    out: dict[str, list[dict]] = {}
    for dataset in SUPABASE_DATASETS:
        _log(f"  supabase {dataset}: querying {hours}h window...")
        rows: list[dict] = []
        _supabase_collect(url, headers, dataset, start, now, rows)
        # Dedup any rows double-counted at bisection boundaries.
        seen: set[tuple] = set()
        deduped = []
        for r in rows:
            key = (r.get("timestamp"), r.get("event_message"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(r)
        out[dataset] = deduped
        _log(f"  supabase {dataset}: {len(rows)} rows -> {len(deduped)} after dedup")
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
    supabase = supabase_logs(hours)
    _log("Supabase totals: "
         + ", ".join(f"{k}={len(v)}" for k, v in supabase.items()))

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
