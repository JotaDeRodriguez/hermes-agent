# Hermes Infrastructure Monitoring

Log monitoring for the LPS 360 stack (Railway + Supabase) driven by the
[Hermes Agent](https://hermes-agent.nousresearch.com/docs/) scheduler.

Two independent jobs:

1. **Daily report** — collect the last 24h of Railway + Supabase logs, let Hermes summarize.
2. **Suspicious-activity monitor** — run every 15–60 min, apply deterministic rules first, only invoke Hermes when a threshold is crossed.

This split avoids spending model tokens on thousands of routine log lines.

## Architecture

```text
Railway logs ───────┐
                    ├─> collector script ─> normalized JSON ─> Hermes analysis
Supabase logs ──────┘                              │
                                                   ├─ daily report
                                                   └─ immediate alert when suspicious
```

Run the collector inside the same Railway service as Hermes, or (preferred) as a small dedicated Railway worker service.

Pipeline order is always: **collect → redact → detect → summarize → notify**. Never **detect → autonomously modify production**.

## 1. Credentials (Railway variables)

```env
RAILWAY_AGENT_TOKEN=...           # project token (scoped to ONE environment)
RAILWAY_SERVICE=LPS 360           # service name to collect (quote if it has a space)

SUPABASE_ACCESS_TOKEN=sbp_...
SUPABASE_PROJECT_REF=dxzdlmzvbrcvbrkwrxyg

LOG_REPORT_TIMEZONE=Europe/Madrid
TZ=Europe/Madrid
```

The script reads `.env` from its own directory (via `python-dotenv`).

- **Railway project token** (`RAILWAY_AGENT_TOKEN`): scoped to a *single environment within a project* — the most restrictive option, ideal for unattended jobs. The script calls the GraphQL API directly with the `Project-Access-Token` header (not `Bearer`). It resolves `environmentId` from the token (`projectToken` query) and maps `RAILWAY_SERVICE` → `serviceId` automatically, so no `RAILWAY_PROJECT_ID` / `RAILWAY_ENVIRONMENT` / service-id config is needed. **No Railway CLI required.**
- For Supabase, use a personal / fine-grained Management API token with **log-reading permission only**. Do **NOT** use the `service_role` key.
- The Supabase Management API needs HTTPS bearer auth. The log endpoint is limited to **30 req/min**, and each request covers at most a **24h window**.

## 2. Dependencies

Install with uv (no Railway CLI needed — the script uses the GraphQL API):

```bash
uv pip install requests python-dotenv
```

## 3. Collector script

`fetch_logs.py` collects the logs and, **by default, emits a bounded digest**
(pretty-printed JSON) to stdout — never the raw rows. Raw 24h output is millions
of lines; the digest is ~700–1300 lines no matter the volume, so the daily
Hermes job can actually ingest it.

```bash
cd hermes_agent_scripts
python fetch_logs.py 24            # digest (default) — feed this to Hermes
python fetch_logs.py 24 --raw      # full unaggregated rows — debugging only
```

`[hours]` defaults to 24. `--raw` returns `{ generated_at, period_hours,
railway: [...], supabase: { <dataset>: [...] } }`.

### Collection

**Railway** — GraphQL `environmentLogs` query, filtered to the service (`@service:<id>`), **paginated backward** from now via `anchorDate`/`beforeLimit` until the requested window is covered (the CLI has no time-window flag, so GraphQL is the only way to page by time).

**Supabase** — Management API `GET /v0/projects/{ref}/analytics/endpoints/logs.all`, queried per dataset (`edge_logs`, `auth_logs`, `postgres_logs`, `function_logs`, `storage_logs`, `realtime_logs`):
- Base URL `https://api.supabase.com`, path under `/v0`, **bearer** auth (per `supabase_experimental_api.yaml`).
- Params: `sql`, `iso_timestamp_start`, `iso_timestamp_end`. Response `{ "result": [...], "error": str|object }` — the script fails fast on a non-empty `error`.
- Each query caps at **1000 rows**, so the window is **recursively time-bisected**: any chunk that hits the cap is split in half until it fits. Nothing is silently dropped. Paced ~2.5s/request to respect the 30 req/min limit (a 24h run therefore takes a few minutes).

### Digest (`log_digest.py`)

`build_digest()` aggregates the collected rows into a fixed-size summary. Every
list is capped (`TOP_*` / `SAMPLE_CAP` / `HISTOGRAM_BUCKETS` constants), so the
output is bounded regardless of input size. Schema:

- **`railway`** — `rows`, `time_range`, `by_severity`, `crash_markers`, `top_messages` (normalized templates), `error_samples`, `histogram`.
- **`supabase.edge_logs`** — `rows`, `by_status_class` (2xx/3xx/4xx/5xx), `by_status`, `top_endpoints` (METHOD + normalized path), `top_countries`, `top_user_agents`, `error_samples` (4xx/5xx), `histogram`.
- **`supabase.auth_logs`** — `rows`, `by_status`, `top_paths`, `top_ips`, `failures`, `failure_samples`, `histogram`.
- **`supabase.postgres_logs`** — `rows`, `by_severity`, `top_statements` (normalized), `error_samples`, `histogram`.
- Other datasets — `rows`, `top_messages`, `histogram`.

Normalization (`log_common.normalize_message` / `url_path`) strips UUIDs, hex
ids, numbers, timestamps and URL query strings so similar lines collapse to one
template with a count. **Secrets are redacted** (`log_common._redact`, shared
with `check_suspicious.py`) before any sample is emitted. Histograms bucket each
source into ≤24 time slots so spikes/trends stay visible.

> Measured: a real 2h window (965k raw lines / 42 MB) compresses to **689 lines
> / 26 KB**. A fully-saturated digest tops out around ~1,300 lines, so 24h stays
> well under the 1000–2000 line target.

## 4. Deterministic detection (`check_suspicious.py`)

```bash
cd hermes_agent_scripts
python check_suspicious.py 35   # window in MINUTES (default 35)
```

Collects the last N minutes via `fetch_logs` (calls `railway_logs`/`supabase_logs`
with `minutes/60` hours), then applies cheap deterministic rules so the Hermes
monitor only spends model tokens when `alert=true`. Read-only; no remediation.

Parsers are written against the **verified** live row shapes: edge_logs
`event_message = "METHOD | STATUS | URL | ua"`; auth_logs `event_message` is JSON
(`status`/`remote_addr`/`path`); postgres `metadata[0].parsed[0].error_severity`;
edge geo at `metadata[0].request[0].cf[0].country`.

Implemented rules (thresholds are constants at the top of the script):

| Rule                    | Trigger                                            | Severity        |
|-------------------------|----------------------------------------------------|-----------------|
| `auth_failures_by_ip`   | >20 auth requests with status ≥400 from one IP     | HIGH            |
| `blocked_status_spike`  | >25 combined `401/403/429` (edge+auth)             | MEDIUM          |
| `server_error_spike`    | >10 `5xx` (edge+auth)                               | MEDIUM          |
| `suspicious_paths`      | probes for `.env`, `/wp-admin`, `../`, `/.git`, …  | HIGH if `.env`/`../`/`.git`, else MEDIUM |
| `secret_exposure`       | `service_role`, `sbp_…`, `password=`, `api_key=`, private key in any log | CRITICAL |
| `railway_crash`         | OOMKilled / panic / traceback / crashed in Railway | HIGH            |
| `railway_error_spike`   | >10 Railway lines with `severity=error`            | MEDIUM          |
| `db_sensitive_ddl`      | `CREATE/ALTER/DROP ROLE/USER/SCHEMA/POLICY/…`      | HIGH            |
| `db_error_spike`        | >15 postgres `ERROR/FATAL/PANIC` lines             | MEDIUM          |

Treat these as **signals, not proof**. Secrets are redacted before any sample
is emitted. Overall `severity` = highest triggered rule. Output payload:

```json
{
  "alert": true,
  "severity": "HIGH",
  "window_minutes": 35,
  "generated_at": "2026-06-25T08:25:37Z",
  "rules": [
    { "name": "auth_failures_by_ip", "severity": "HIGH", "window_minutes": 35,
      "offenders": [ { "ip": "203.0.113.50", "count": 84 } ] }
  ],
  "sample_events": ["{\"status\": 403, \"remote_addr\": \"203.0.113.50\", \"path\": \"/token\"}"]
}
```

Baseline-dependent ideas from the original plan (new-country detection,
7-day request-volume deviation) are **not** implemented — they need a stored
baseline this stateless check doesn't have. Add them when a baseline store exists.

## 5. Daily Hermes job

```bash
hermes cron create "0 9 * * *" \
  "Run python /app/hermes_agent_scripts/fetch_logs.py 24. The output is a pre-aggregated digest (counts, top-N tables, time-bucketed histograms, redacted samples) — not raw logs. Analyze it and produce a concise operations and security report: service availability, deployments and restarts, error counts, repeated failures, unusual authentication activity, suspicious IP or endpoint patterns, possible secret exposure, and recommended actions. Clearly separate confirmed events from hypotheses. Never modify Railway or Supabase resources." \
  --workdir /app/hermes_agent_scripts \
  --name "Daily infrastructure report"
```

`0 9 * * *` runs daily at 09:00 in the scheduler's timezone. `fetch_logs.py 24` emits the bounded digest by default (~700–1300 lines), which is what keeps the daily job within the model's context. **Pin the provider and model** for unattended jobs — current Hermes versions fail closed if the global default model changes.

## 6. Suspicious-activity job

```bash
hermes cron create "*/30 * * * *" \
  "Run python /app/hermes_agent_scripts/check_suspicious.py 35. If JSON output has alert=false, respond only with NO_ALERT. If alert=true, explain what triggered it, include supporting counts and timestamps, assign severity LOW/MEDIUM/HIGH/CRITICAL, and recommend immediate non-destructive actions. Never redeploy, delete, block, rotate credentials, or change configuration automatically." \
  --workdir /app/hermes_agent_scripts \
  --name "Infrastructure security watch"
```

> For real-time Supabase alerts, **Log Drains** (paid) stream logs to an external HTTP/observability endpoint and avoid polling. Management API polling is the cheaper starting point.

## Railway deployment notes

- Attach a **Railway Volume** to Hermes' home/config dir. Cron jobs live in `~/.hermes/cron/jobs.json` — without persistent storage they vanish on redeploy.
- Set `TZ=Europe/Madrid`.
- Smoke test:
  ```bash
  date
  hermes cron list
  hermes cron trigger "Daily infrastructure report"
  ```

## Security boundaries

- Read-only log credentials.
- Dedicated Railway token + fine-grained Supabase token.
- Redact secrets before logs reach the LLM.
- Max log sizes and timeouts.
- No automatic blocking or credential rotation initially.
- Alerts via Telegram / Discord / Slack / email.
- Any remediation goes through a separate approval-required workflow.

## Status

- [x] `fetch_logs.py` — Railway (GraphQL, backward-paginated) + Supabase (time-bisected) collector, tested
- [x] `check_suspicious.py` — deterministic detection + redacted alert payload, tested
- [ ] Railway variables set in the Hermes service
- [ ] Hermes cron jobs created
```
