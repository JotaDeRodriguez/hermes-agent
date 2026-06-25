"""Deterministic suspicious-activity check over a short recent window.

Usage:
    python check_suspicious.py [minutes]   # default 35

Collects the last N minutes of Railway + Supabase logs (via fetch_logs),
applies cheap deterministic rules, and emits one compact JSON payload to
stdout. The Hermes monitor job only spends model tokens when alert=true.

Pipeline order: collect -> redact -> detect -> summarize. Read-only;
nothing is modified on either platform, and no remediation is performed.
"""

import json
import re
import sys

from fetch_logs import _iso, _utcnow, railway_logs, supabase_logs
from log_common import (
    _auth_parse,
    _edge_parse,
    _first,
    _pg_parsed,
    _redact,
    _sample,
)

DEFAULT_WINDOW_MIN = 35

# --- Thresholds (deterministic signals, not proof) ---------------------------
AUTH_FAILURES_PER_IP = 20        # >N failed auth requests from one IP -> flag
BLOCKED_STATUS_SPIKE = 25        # combined 401/403/429 across edge+auth
SERVER_ERROR_SPIKE = 10          # 5xx across edge+auth
PG_ERROR_SPIKE = 15              # postgres ERROR/FATAL/PANIC lines

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Path probes / sensitive-resource access (case-insensitive substring match).
SUSPICIOUS_PATHS = [
    ".env", "/wp-admin", "/wp-login", "/phpmyadmin", "/.git",
    "/.aws", "/config.json", "..%2f", "../",
]
# Higher severity if these specific patterns appear.
PATH_HIGH = ("../", "..%2f", ".env", "/.git", "/.aws")

# Secret-shaped tokens leaking into logs. Targeted to limit false positives.
SECRET_PATTERNS = [
    re.compile(r"service_role", re.I),
    re.compile(r"\bsbp_[A-Za-z0-9_]{8,}"),                 # Supabase mgmt token
    re.compile(r"password=\S+", re.I),
    re.compile(r"api[_-]?key=\S+", re.I),
    re.compile(r"\bsecret=\S+", re.I),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]

# DB activity worth surfacing regardless of error severity.
DB_SENSITIVE = re.compile(
    r"\b(CREATE|ALTER|DROP)\s+(ROLE|USER|SCHEMA|EXTENSION|POLICY)\b", re.I
)

# Railway crash / instability markers.
RAILWAY_CRASH = re.compile(
    r"OOMKilled|out of memory|\bpanic\b|segfault|core dumped|"
    r"\bcrashed\b|fatal error|npm ERR!|Traceback \(most recent call last\)",
    re.I,
)


SAMPLES_PER_RULE = 3  # so noisy rules can't starve high-severity samples


# --- Rules -------------------------------------------------------------------
def _rule_auth_failures(supabase, samples):
    """Failed auth requests grouped by client IP."""
    by_ip: dict[str, int] = {}
    examples: dict[str, str] = {}
    for row in supabase.get("auth_logs", []):
        rec = _auth_parse(row)
        if not rec:
            continue
        status = rec.get("status")
        if not isinstance(status, int) or status < 400:
            continue
        ip = rec.get("remote_addr") or "unknown"
        by_ip[ip] = by_ip.get(ip, 0) + 1
        examples.setdefault(ip, row.get("event_message", ""))

    hits = []
    for ip, count in by_ip.items():
        if count > AUTH_FAILURES_PER_IP:
            hits.append({"ip": ip, "count": count})
            samples.append(_sample(examples[ip]))
    if not hits:
        return None
    hits.sort(key=lambda h: h["count"], reverse=True)
    return {"name": "auth_failures_by_ip", "severity": "HIGH",
            "window_minutes": None, "offenders": hits[:10]}


def _rule_status_spikes(supabase, samples):
    """Spike in blocked (401/403/429) or server-error (5xx) responses."""
    blocked = 0
    server_err = 0
    sample_seen = 0
    for row in supabase.get("edge_logs", []):
        rec = _edge_parse(row)
        if not rec:
            continue
        s = rec["status"]
        if s in (401, 403, 429):
            blocked += 1
        elif s >= 500:
            server_err += 1
            if sample_seen < 3:
                samples.append(_sample(row.get("event_message", "")))
                sample_seen += 1
    for row in supabase.get("auth_logs", []):
        rec = _auth_parse(row)
        if not rec or not isinstance(rec.get("status"), int):
            continue
        s = rec["status"]
        if s in (401, 403, 429):
            blocked += 1
        elif s >= 500:
            server_err += 1

    rules = []
    if blocked > BLOCKED_STATUS_SPIKE:
        rules.append({"name": "blocked_status_spike", "severity": "MEDIUM",
                      "count": blocked, "statuses": "401/403/429"})
    if server_err > SERVER_ERROR_SPIKE:
        rules.append({"name": "server_error_spike", "severity": "MEDIUM",
                      "count": server_err, "statuses": "5xx"})
    return rules


def _rule_suspicious_paths(railway, supabase, samples):
    """Probes for sensitive paths / path traversal across all request URLs."""
    urls = []
    for row in supabase.get("edge_logs", []):
        rec = _edge_parse(row)
        if rec:
            urls.append(rec["url"])
    for row in supabase.get("auth_logs", []):
        rec = _auth_parse(row)
        if rec and rec.get("path"):
            urls.append(rec["path"])
    for row in railway:
        urls.append(row.get("message", ""))

    matched: dict[str, int] = {}
    high = False
    taken = 0
    for url in urls:
        low = url.lower()
        for needle in SUSPICIOUS_PATHS:
            if needle in low:
                matched[needle] = matched.get(needle, 0) + 1
                if needle in PATH_HIGH:
                    high = True
                if taken < SAMPLES_PER_RULE:
                    samples.append(_sample(url))
                    taken += 1
    if not matched:
        return None
    return {"name": "suspicious_paths", "severity": "HIGH" if high else "MEDIUM",
            "patterns": matched}


def _rule_secret_exposure(railway, supabase, samples):
    """Secret-shaped tokens printed into any log stream."""
    hits: dict[str, int] = {}
    taken = 0

    def scan(text):
        nonlocal taken
        for pat in SECRET_PATTERNS:
            if pat.search(text):
                hits[pat.pattern] = hits.get(pat.pattern, 0) + 1
                if taken < SAMPLES_PER_RULE:
                    samples.append(_sample(text))
                    taken += 1

    for row in railway:
        scan(str(row.get("message", "")))
    for ds_rows in supabase.values():
        for row in ds_rows:
            scan(str(row.get("event_message", "")))
    if not hits:
        return None
    return {"name": "secret_exposure", "severity": "CRITICAL", "patterns": hits}


def _rule_railway_instability(railway, samples):
    """Crashes / OOM / panics and a spike of error-severity log lines."""
    crashes = 0
    errors = 0
    taken = 0
    for row in railway:
        msg = str(row.get("message", ""))
        if RAILWAY_CRASH.search(msg):
            crashes += 1
            if taken < SAMPLES_PER_RULE:
                samples.append(_sample(msg))
                taken += 1
        if str(row.get("severity", "")).lower() == "error":
            errors += 1

    rules = []
    if crashes:
        rules.append({"name": "railway_crash", "severity": "HIGH",
                      "count": crashes})
    if errors > SERVER_ERROR_SPIKE:
        rules.append({"name": "railway_error_spike", "severity": "MEDIUM",
                      "count": errors})
    return rules


def _rule_db_anomaly(supabase, samples):
    """Postgres errors and sensitive role/schema/policy DDL."""
    pg_errors = 0
    sensitive = []
    for row in supabase.get("postgres_logs", []):
        parsed = _pg_parsed(row)
        sev = str(parsed.get("error_severity", "")).upper()
        if sev in ("ERROR", "FATAL", "PANIC"):
            pg_errors += 1
        msg = str(row.get("event_message", ""))
        if DB_SENSITIVE.search(msg):
            sensitive.append(_sample(msg))

    rules = []
    if sensitive:
        samples.extend(sensitive[:5])
        rules.append({"name": "db_sensitive_ddl", "severity": "HIGH",
                      "count": len(sensitive)})
    if pg_errors > PG_ERROR_SPIKE:
        rules.append({"name": "db_error_spike", "severity": "MEDIUM",
                      "count": pg_errors})
    return rules


def detect(railway, supabase, window_min: int) -> dict:
    samples: list[str] = []
    rules: list[dict] = []

    auth = _rule_auth_failures(supabase, samples)
    if auth:
        auth["window_minutes"] = window_min
        rules.append(auth)

    rules.extend(_rule_status_spikes(supabase, samples))

    paths = _rule_suspicious_paths(railway, supabase, samples)
    if paths:
        rules.append(paths)

    secrets = _rule_secret_exposure(railway, supabase, samples)
    if secrets:
        rules.append(secrets)

    rules.extend(_rule_railway_instability(railway, samples))
    rules.extend(_rule_db_anomaly(supabase, samples))

    alert = bool(rules)
    severity = "LOW"
    if rules:
        severity = max((r["severity"] for r in rules),
                       key=lambda s: SEVERITY_RANK.get(s, 0))

    # Dedup samples, keep order, cap payload size.
    seen = set()
    sample_events = []
    for s in samples:
        if s in seen:
            continue
        seen.add(s)
        sample_events.append(s)

    return {
        "alert": alert,
        "severity": severity,
        "window_minutes": window_min,
        "generated_at": _iso(_utcnow()),
        "rules": rules,
        "sample_events": sample_events[:20],
    }


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    window_min = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_WINDOW_MIN
    hours = window_min / 60
    railway = railway_logs(hours)
    supabase = supabase_logs(hours)
    print(json.dumps(detect(railway, supabase, window_min), ensure_ascii=False))


if __name__ == "__main__":
    main()
