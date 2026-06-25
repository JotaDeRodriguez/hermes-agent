"""Shared helpers for the Hermes log pipeline: redaction, row parsing, and
message normalization. Imported by both fetch_logs (digest) and
check_suspicious so the redaction and parsing logic exists in exactly one place.

Row shapes are verified against live Railway + Supabase logs:
  - edge_logs    event_message = "METHOD | STATUS | URL | user-agent"
  - auth_logs    event_message = JSON (status / path / remote_addr / ...)
  - postgres     metadata[0].parsed[0].error_severity / command_tag
  - edge geo     metadata[0].request[0].cf[0].country
  - timestamps   Railway = ISO-8601 string; Supabase = epoch microseconds (int)
"""

import json
import re
from datetime import datetime, timezone


# --- Redaction ---------------------------------------------------------------
def _redact(text: str) -> str:
    """Mask secret-shaped substrings before any sample reaches output/LLM."""
    out = str(text)
    out = re.sub(r"\bsbp_[A-Za-z0-9_]{8,}", "sbp_***REDACTED***", out)
    out = re.sub(r"(password=)\S+", r"\1***", out, flags=re.I)
    out = re.sub(r"(api[_-]?key=)\S+", r"\1***", out, flags=re.I)
    out = re.sub(r"(secret=)\S+", r"\1***", out, flags=re.I)
    # Long bearer/JWT-ish blobs.
    out = re.sub(r"\b(eyJ[A-Za-z0-9_\-]{10,})\.[A-Za-z0-9_\-.]+", "eyJ***REDACTED***", out)
    return out


def _sample(text: str, limit: int = 240) -> str:
    return _redact(text)[:limit]


# --- Timestamp parsing -------------------------------------------------------
def to_datetime(value):
    """Parse a log timestamp to aware UTC datetime; None if unparseable.

    Railway emits ISO-8601 strings (nanosecond precision); the Supabase
    analytics API emits epoch microseconds as an integer.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    # fromisoformat (<3.11) rejects nanosecond precision; trim to microseconds.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


# --- Row parsers -------------------------------------------------------------
def _first(meta) -> dict:
    """Supabase rows wrap metadata as a 1-element list; unwrap safely."""
    if isinstance(meta, list):
        return meta[0] if meta else {}
    return meta if isinstance(meta, dict) else {}


def _edge_parse(row: dict):
    """edge_logs event_message: 'METHOD | STATUS | URL | user-agent'."""
    parts = [p.strip() for p in str(row.get("event_message", "")).split("|")]
    if len(parts) < 3:
        return None
    try:
        status = int(parts[1])
    except ValueError:
        return None
    return {"method": parts[0], "status": status, "url": parts[2],
            "ua": parts[3] if len(parts) > 3 else ""}


def _edge_country(row: dict):
    try:
        return _first(_first(_first(row.get("metadata")).get("request")).get("cf")).get("country")
    except AttributeError:
        return None


def _auth_parse(row: dict):
    """auth_logs event_message is a JSON string."""
    try:
        return json.loads(row.get("event_message", ""))
    except (json.JSONDecodeError, TypeError):
        return None


def _pg_parsed(row: dict) -> dict:
    return _first(_first(row.get("metadata")).get("parsed"))


# --- Normalization (collapses volatile ids so similar lines group) -----------
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?")
_HEX = re.compile(r"\b[0-9a-f]{12,}\b", re.I)
_NUM = re.compile(r"\b\d+\b")
_QUERY = re.compile(r'(https?://[^\s"\'?]+)\?\S*')


def normalize_message(text: str) -> str:
    """Replace volatile tokens with placeholders so log lines group by shape."""
    t = str(text)
    t = _QUERY.sub(r"\1", t)   # drop URL query strings (ids live there)
    t = _ISO.sub("<TS>", t)
    t = _UUID.sub("<UUID>", t)
    t = _HEX.sub("<HEX>", t)
    t = _NUM.sub("<N>", t)
    return t


def url_path(url: str) -> str:
    """Reduce a full URL to METHOD-able path, collapsing numeric/uuid ids."""
    m = re.match(r"https?://[^/]+(/[^?\s]*)", url or "")
    path = m.group(1) if m else (url or "")
    path = re.sub(r"/\d+", "/<N>", path)
    path = _UUID.sub("<UUID>", path)
    return path
