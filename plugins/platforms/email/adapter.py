"""
Email platform adapter for the Hermes gateway.

Allows users to interact with Hermes by sending emails.
Uses IMAP to receive and SMTP to send messages. When OAuth2/Microsoft Graph is
configured (EMAIL_OAUTH_* set) and no IMAP host is given, the adapter receives
*and* sends over Graph instead — required where M365 Conditional Access blocks
SMTP/IMAP basic auth from the deployment location but permits OAuth2. If neither
IMAP nor OAuth is configured, the adapter runs in SMTP-only mode for outbound
delivery (no polling).

Environment variables:
    EMAIL_IMAP_HOST     — Optional IMAP server host (e.g., imap.gmail.com)
    EMAIL_IMAP_PORT     — IMAP server port (default: 993)
    EMAIL_SMTP_HOST     — SMTP server host (e.g., smtp.gmail.com)
    EMAIL_SMTP_PORT     — SMTP server port (default: 587)
    EMAIL_ADDRESS       — Email address for the agent
    EMAIL_PASSWORD      — Email password or app-specific password
    EMAIL_SMTP_USERNAME — Optional SMTP auth username (defaults to EMAIL_ADDRESS)
    EMAIL_SMTP_PASSWORD — Optional SMTP auth password (defaults to EMAIL_PASSWORD)
    EMAIL_FROM          — Optional From address (defaults to EMAIL_ADDRESS)
    EMAIL_SMTP_USE_SSL  — Use implicit SMTP SSL even when port is not 465
    EMAIL_POLL_INTERVAL — Seconds between mailbox checks (default: 15)
    EMAIL_ALLOWED_USERS — Comma-separated list of allowed sender addresses

    OAuth2 / Microsoft Graph (outbound send + inbound polling):
    EMAIL_OAUTH_TENANT_ID     — Azure AD tenant id
    EMAIL_OAUTH_CLIENT_ID     — Azure app registration client id
    EMAIL_OAUTH_CLIENT_SECRET — Azure app client secret
    EMAIL_OAUTH_REFRESH_TOKEN — Optional. Delegated refresh token for the
                                mailbox owner (scope: offline_access Mail.Send).
                                When set, sends use the delegated refresh-token
                                grant (no admin consent needed); when absent,
                                the app-only client-credentials grant is used
                                (needs admin-consented application Mail.Send).

    When the three required EMAIL_OAUTH_* vars are set, every outbound message
    is sent via the Microsoft Graph ``sendMail`` API instead of SMTP basic auth.
    This is required where the mailbox provider (M365 Conditional Access) blocks
    legacy/basic SMTP auth from the deployment location but permits OAuth2. SMTP
    basic auth remains the fallback when the OAuth vars are absent. IMAP
    receiving still uses basic auth.
"""

import asyncio
import base64
import email as email_lib
import imaplib
import logging
import os
import re
import smtplib
import socket
import ssl
import threading
import time
import uuid
from urllib.parse import quote
from email.header import decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.utils import formatdate
from email import encoders
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
    cache_document_from_bytes,
    cache_image_from_bytes,
)
from gateway.config import Platform, PlatformConfig
from utils import env_int

logger = logging.getLogger(__name__)
# Automated sender patterns — emails from these are silently ignored
_NOREPLY_PATTERNS = (
    "noreply", "no-reply", "no_reply", "donotreply", "do-not-reply",
    "mailer-daemon", "postmaster", "bounce", "notifications@",
    "automated@", "auto-confirm", "auto-reply", "automailer",
)

# RFC headers that indicate bulk/automated mail
_AUTOMATED_HEADERS = {
    "Auto-Submitted": lambda v: v.lower() != "no",
    "Precedence": lambda v: v.lower() in {"bulk", "list", "junk"},
    "X-Auto-Response-Suppress": lambda v: bool(v),
    "List-Unsubscribe": lambda v: bool(v),
}

# Gmail-safe max length per email body
MAX_MESSAGE_LENGTH = 50_000

SMTP_CONNECT_TIMEOUT = 30


def _create_ipv4_connection(
    host: str,
    port: int,
    timeout: float,
    source_address: Any = None,
) -> socket.socket:
    """Create a TCP connection using only IPv4 addresses.

    This mirrors ``socket.create_connection`` but constrains DNS resolution to
    ``AF_INET``.  It avoids mutating process-global socket functions, which
    matters because email sends run in executor threads.
    """
    last_error: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in socket.getaddrinfo(
        host, port, socket.AF_INET, socket.SOCK_STREAM
    ):
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    if last_error is not None:
        raise last_error
    raise OSError(f"No IPv4 address found for {host}:{port}")


class _IPv4SMTP(smtplib.SMTP):
    def _get_socket(self, host, port, timeout):  # type: ignore[override]
        return _create_ipv4_connection(
            host,
            port,
            timeout,
            source_address=self.source_address,
        )


class _IPv4SMTP_SSL(smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):  # type: ignore[override]
        raw_sock = _create_ipv4_connection(
            host,
            port,
            timeout,
            source_address=self.source_address,
        )
        return self.context.wrap_socket(
            raw_sock,
            server_hostname=getattr(self, "_host", host),
        )

# Supported image extensions for inline detection
_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}

def _send_imap_id(imap: "imaplib.IMAP4") -> None:
    """Send RFC 2971 IMAP ID command identifying this client.

    Required by 163/NetEase mailbox after LOGIN: without it, every UID
    SEARCH/FETCH returns ``BYE Unsafe Login`` and disconnects.  Other
    IMAP servers either honor it silently or reject the unknown command;
    we swallow failures so non-supporting servers keep working.
    """
    try:
        try:
            from hermes_cli import __version__ as _hermes_version
        except Exception:  # noqa: BLE001 — keep ID best-effort if import fails
            _hermes_version = "0"
        imap.xatom(
            "ID",
            f'("name" "hermes-agent" "version" "{_hermes_version}" '
            '"vendor" "NousResearch" '
            '"support-email" "noreply@nousresearch.com")',
        )
    except Exception as e:  # noqa: BLE001 — best-effort, never fatal
        logger.debug("[Email] IMAP ID command not accepted: %s", e)


def _is_automated_sender(address: str, headers: dict) -> bool:
    """Return True if this email is from an automated/noreply source."""
    addr = address.lower()
    if any(pattern in addr for pattern in _NOREPLY_PATTERNS):
        return True
    for header, check in _AUTOMATED_HEADERS.items():
        value = headers.get(header, "")
        if value and check(value):
            return True
    return False


def _env_first(*names: str) -> str:
    """Return the first non-empty environment value from *names*."""
    for name in names:
        value = os.getenv(name, "")
        if value:
            return value
    return ""


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# ──────────────────────────────────────────────────────────────────────────
# OAuth2 / Microsoft Graph outbound. Two flows, auto-selected:
#
#   1. Delegated (preferred where admin consent is unavailable): set
#      EMAIL_OAUTH_REFRESH_TOKEN to a refresh token minted for the mailbox
#      owner (scope: offline_access + Mail.Send). We redeem it for short-lived
#      access tokens. Needs only the *delegated* Mail.Send + offline_access
#      grants, which a user can self-consent — no Global Admin required.
#   2. App-only client-credentials (no refresh token set): requires the
#      *application* Mail.Send permission with admin consent.
#
# Why this exists: M365 Conditional Access blocks SMTP *basic auth* from some
# deployment locations (e.g. cloud datacenters) with "535 5.7.139 ...basic
# authentication is disabled", even when the password is correct. OAuth2 is not
# blocked. When EMAIL_OAUTH_* are configured we send via Graph instead of SMTP.
# ──────────────────────────────────────────────────────────────────────────

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_HTTP_TIMEOUT = 30

# access_token cache keyed by "tenant:client_id" -> (token, expiry_epoch).
# Tokens last ~1h; caching avoids a token round-trip on every send. Guarded by
# a lock because sends run in executor threads.
_GRAPH_TOKEN_CACHE: Dict[str, Tuple[str, float]] = {}
# Latest rotated refresh token (Azure returns a fresh one on each redemption),
# keyed by "tenant:client_id". In-memory only: survives within a process so
# rotation doesn't break long-running sends; on restart we fall back to the
# EMAIL_OAUTH_REFRESH_TOKEN env value (valid for ~90 days of inactivity).
_GRAPH_REFRESH_OVERRIDE: Dict[str, str] = {}
_GRAPH_TOKEN_LOCK = threading.Lock()


def _oauth_credentials() -> Optional[Tuple[str, str, str]]:
    """Return (tenant_id, client_id, client_secret) when all three OAuth env
    vars are set and non-blank, else None (signals SMTP basic-auth fallback)."""
    tenant = os.getenv("EMAIL_OAUTH_TENANT_ID", "").strip()
    client_id = os.getenv("EMAIL_OAUTH_CLIENT_ID", "").strip()
    client_secret = os.getenv("EMAIL_OAUTH_CLIENT_SECRET", "").strip()
    if tenant and client_id and client_secret:
        return tenant, client_id, client_secret
    return None


def _graph_access_token(tenant: str, client_id: str, client_secret: str) -> str:
    """Fetch (and cache) a Graph access token.

    Uses the delegated refresh-token grant when EMAIL_OAUTH_REFRESH_TOKEN is
    set, else the app-only client-credentials grant.
    """
    import requests  # core dep; imported lazily so module import never hard-fails

    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    cache_key = f"{tenant}:{client_id}"
    now = time.time()
    with _GRAPH_TOKEN_LOCK:
        cached = _GRAPH_TOKEN_CACHE.get(cache_key)
        if cached and cached[1] - 60 > now:
            return cached[0]
        refresh_token = (
            _GRAPH_REFRESH_OVERRIDE.get(cache_key)
            or os.getenv("EMAIL_OAUTH_REFRESH_TOKEN", "").strip()
        )

    if refresh_token:
        base = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
            "scope": GRAPH_SCOPE,
        }
        # Try as a confidential client (with secret) first — matches tokens
        # minted via ROPC/auth-code. If the app is registered as a public
        # client the secret is rejected (AADSTS700025); retry without it.
        resp = requests.post(
            token_url, data={**base, "client_secret": client_secret},
            timeout=GRAPH_HTTP_TIMEOUT,
        )
        if resp.status_code != 200 and "AADSTS700025" in resp.text:
            resp = requests.post(token_url, data=base, timeout=GRAPH_HTTP_TIMEOUT)
    else:
        resp = requests.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": GRAPH_SCOPE,
            },
            timeout=GRAPH_HTTP_TIMEOUT,
        )

    if resp.status_code != 200:
        raise RuntimeError(
            f"OAuth token request failed ({resp.status_code}): {resp.text[:300]}"
        )
    payload = resp.json()
    token = payload.get("access_token")
    if not token:
        raise RuntimeError(f"OAuth token response missing access_token: {payload}")
    expires_in = int(payload.get("expires_in", 3600))
    rotated = payload.get("refresh_token")
    with _GRAPH_TOKEN_LOCK:
        _GRAPH_TOKEN_CACHE[cache_key] = (token, now + expires_in)
        if rotated:
            _GRAPH_REFRESH_OVERRIDE[cache_key] = rotated
    return token


def _graph_file_attachment(
    filename: str, content: bytes, content_type: str = "application/octet-stream"
) -> Dict[str, Any]:
    """Build a Graph fileAttachment object (base64-encoded content)."""
    return {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "name": filename,
        "contentType": content_type,
        "contentBytes": base64.b64encode(content).decode("ascii"),
    }


def _graph_send_mail(
    oauth: Tuple[str, str, str],
    *,
    sender: str,
    to_addr: str,
    subject: str,
    body: str,
    attachments: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Send a message via Graph ``POST /users/{sender}/sendMail``.

    ``sender`` is the mailbox the app sends as (app-only requires the Mail.Send
    application permission on that mailbox). Threading: app-only sendMail only
    permits custom ``x-*`` internetMessageHeaders, so standard
    In-Reply-To/References can't be set here — replies thread by the ``Re:``
    subject instead. Raises RuntimeError on a non-2xx response.
    """
    import requests  # core dep; lazy import keeps module import resilient

    tenant, client_id, client_secret = oauth
    token = _graph_access_token(tenant, client_id, client_secret)

    message: Dict[str, Any] = {
        "subject": subject,
        "body": {"contentType": "Text", "content": body},
        "toRecipients": [{"emailAddress": {"address": to_addr}}],
    }
    if attachments:
        message["attachments"] = attachments

    resp = requests.post(
        f"{GRAPH_BASE_URL}/users/{quote(sender)}/sendMail",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"message": message, "saveToSentItems": True},
        timeout=GRAPH_HTTP_TIMEOUT,
    )
    # Graph returns 202 Accepted on success.
    if resp.status_code not in (200, 202):
        raise RuntimeError(
            f"Graph sendMail failed ({resp.status_code}): {resp.text[:300]}"
        )


def check_email_requirements() -> bool:
    """Check if email platform settings are available and non-blank.

    Treats blank/whitespace-only values as missing so an abandoned setup that
    left empty ``EMAIL_*`` keys in ``.env`` does not enable the platform (#40715).
    IMAP is optional: when omitted, the adapter can still run in SMTP-only mode
    for cron notifications and explicit outbound sends.

    OAuth2/Graph mode only needs EMAIL_ADDRESS plus the three EMAIL_OAUTH_* vars
    (no SMTP host/password), since outbound goes over Graph rather than SMTP.
    """
    addr = os.getenv("EMAIL_ADDRESS", "").strip()
    if addr and _oauth_credentials():
        return True
    pwd = _env_first("EMAIL_SMTP_PASSWORD", "SMTP_PASSWORD", "EMAIL_PASSWORD").strip()
    smtp = os.getenv("EMAIL_SMTP_HOST", "").strip()
    return all([addr, pwd, smtp])


def _decode_header_value(raw: str) -> str:
    """Decode an RFC 2047 encoded email header into a plain string."""
    parts = decode_header(raw)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded)


def _extract_text_body(msg: email_lib.message.Message) -> str:
    """Extract the plain-text body from a potentially multipart email."""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            # Skip attachments
            if "attachment" in disposition:
                continue
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace")
        # Fallback: try text/html and strip tags
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                continue
            if content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    html = payload.decode(charset, errors="replace")
                    return _strip_html(html)
        return ""
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if msg.get_content_type() == "text/html":
                return _strip_html(text)
            return text
        return ""


def _strip_html(html: str) -> str:
    """Naive HTML tag stripper for fallback text extraction."""
    text = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)
    text = re.sub(r"<p[^>]*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</p>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _extract_email_address(raw: str) -> str:
    """Extract bare email address from 'Name <addr>' format."""
    match = re.search(r"<([^>]+)>", raw)
    if match:
        return match.group(1).strip().lower()
    return raw.strip().lower()


def _extract_attachments(
    msg: email_lib.message.Message,
    skip_attachments: bool = False,
) -> List[Dict[str, Any]]:
    """Extract attachment metadata and cache files locally.

    When *skip_attachments* is True, all attachment/inline parts are ignored
    (useful for malware protection or bandwidth savings).
    """
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if skip_attachments and ("attachment" in disposition or "inline" in disposition):
            continue
        if "attachment" not in disposition and "inline" not in disposition:
            continue
        # Skip text/plain and text/html body parts
        content_type = part.get_content_type()
        if content_type in {"text/plain", "text/html"} and "attachment" not in disposition:
            continue

        filename = part.get_filename()
        if filename:
            filename = _decode_header_value(filename)
        else:
            ext = part.get_content_subtype() or "bin"
            filename = f"attachment.{ext}"

        payload = part.get_payload(decode=True)
        if not payload:
            continue

        ext = Path(filename).suffix.lower()
        if ext in _IMAGE_EXTS:
            try:
                cached_path = cache_image_from_bytes(payload, ext)
            except ValueError:
                logger.debug("Skipping non-image attachment %s (invalid magic bytes)", filename)
                continue
            attachments.append({
                "path": cached_path,
                "filename": filename,
                "type": "image",
                "media_type": content_type,
            })
        else:
            cached_path = cache_document_from_bytes(payload, filename)
            attachments.append({
                "path": cached_path,
                "filename": filename,
                "type": "document",
                "media_type": content_type,
            })

    return attachments


class EmailAdapter(BasePlatformAdapter):
    """Email gateway adapter using IMAP (receive) and SMTP (send).

    When no IMAP host is configured, the adapter starts in SMTP-only mode. That
    supports deployments where a provider allows SMTP basic auth for outbound
    delivery but requires OAuth2 for IMAP.
    """

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.EMAIL)

        # Resolve connection settings from the env vars first, then fall back to
        # PlatformConfig.extra (address/imap_host/smtp_host) — the canonical dict
        # gateway.config populates and that the "connected" check, the
        # send-helper, and `hermes config show` already read. Without the
        # fallback a config.yaml-only setup left these empty. Host/address values
        # are stripped: a stray space or newline made IMAP4_SSL raise the
        # misleading ``[Errno 8] nodename nor servname`` (an unresolvable name)
        # instead of an obvious "host not set" error.
        extra = config.extra or {}
        self._address = (os.getenv("EMAIL_ADDRESS", "") or extra.get("address", "")).strip()
        self._password = os.getenv("EMAIL_PASSWORD", "")
        self._smtp_username = (
            os.getenv("EMAIL_SMTP_USERNAME", "")
            or os.getenv("SMTP_USERNAME", "")
            or extra.get("smtp_username", "")
            or self._address
        ).strip()
        self._smtp_password = _env_first("EMAIL_SMTP_PASSWORD", "SMTP_PASSWORD", "EMAIL_PASSWORD")
        self._from_address = (
            os.getenv("EMAIL_FROM", "")
            or os.getenv("MAIL_FROM", "")
            or extra.get("from_address", "")
            or self._address
        ).strip()
        self._imap_host = (os.getenv("EMAIL_IMAP_HOST", "") or extra.get("imap_host", "")).strip()
        self._imap_port = env_int("EMAIL_IMAP_PORT", 993)
        self._smtp_host = (os.getenv("EMAIL_SMTP_HOST", "") or extra.get("smtp_host", "")).strip()
        self._smtp_port = env_int("EMAIL_SMTP_PORT", 587)
        self._smtp_use_ssl = _env_bool(
            "EMAIL_SMTP_USE_SSL",
            _env_bool("SMTP_USE_SSL", self._smtp_port == 465),
        )
        self._poll_interval = env_int("EMAIL_POLL_INTERVAL", 15)

        # OAuth2/Graph outbound: when configured, all sends go via Microsoft
        # Graph (app-only) instead of SMTP basic auth. None => SMTP fallback.
        self._oauth = _oauth_credentials()

        # Skip attachments — configured via config.yaml:
        #   platforms:
        #     email:
        #       skip_attachments: true
        self._skip_attachments = extra.get("skip_attachments", False)

        # Track message IDs we've already processed to avoid duplicates
        self._seen_uids: set = set()
        self._seen_uids_max: int = 2000   # cap to prevent unbounded memory growth
        self._poll_task: Optional[asyncio.Task] = None

        # Map chat_id (sender email) -> last subject + message-id for threading
        self._thread_context: Dict[str, Dict[str, str]] = {}

        logger.info("[Email] Adapter initialized for %s", self._address)

    def _trim_seen_uids(self) -> None:
        """Keep only the most recent UIDs to prevent unbounded memory growth.

        IMAP UIDs are monotonically increasing integers. When the set grows
        beyond the cap, we keep only the highest half — old UIDs are safe to
        drop because new messages always have higher UIDs and IMAP's UNSEEN
        flag prevents re-delivery regardless.
        """
        if len(self._seen_uids) <= self._seen_uids_max:
            return
        try:
            # UIDs are bytes like b'1234' — sort numerically and keep top half
            sorted_uids = sorted(self._seen_uids, key=lambda u: int(u))
            keep = self._seen_uids_max // 2
            self._seen_uids = set(sorted_uids[-keep:])
            logger.debug("[Email] Trimmed seen UIDs to %d entries", len(self._seen_uids))
        except (ValueError, TypeError):
            # Fallback: just clear old entries if sort fails
            self._seen_uids = set(list(self._seen_uids)[-self._seen_uids_max // 2:])

    def _connect_smtp(self) -> smtplib.SMTP:
        """Create an SMTP connection, selecting the correct protocol for the port.

        Port 465 or ``EMAIL_SMTP_USE_SSL=true`` uses implicit TLS
        (``SMTP_SSL``). All other connections use ``SMTP`` + ``STARTTLS``.

        When the host resolves to an IPv6 address that is unreachable
        (common on networks without IPv6 routing), the default connection can
        hang until the socket timeout expires.  We retry connection-level
        failures through an IPv4-only socket path, without mutating global
        resolver state.  TLS verification errors are not retried.

        Returns a connected SMTP object with TLS established — callers
        can proceed directly to ``login()``.
        """
        ctx = ssl.create_default_context()
        host = self._smtp_host
        port = self._smtp_port

        def _connect(*, ipv4_only: bool = False) -> smtplib.SMTP:
            """Attempt one SMTP connection."""
            smtp_cls = _IPv4SMTP if ipv4_only else smtplib.SMTP
            smtp_ssl_cls = _IPv4SMTP_SSL if ipv4_only else smtplib.SMTP_SSL
            if self._smtp_use_ssl:
                return smtp_ssl_cls(host, port, timeout=SMTP_CONNECT_TIMEOUT, context=ctx)
            smtp = smtp_cls(host, port, timeout=SMTP_CONNECT_TIMEOUT)
            try:
                smtp.starttls(context=ctx)
            except Exception:
                smtp.close()
                raise
            return smtp

        try:
            return _connect()
        except (socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            if isinstance(exc, ssl.SSLError):
                raise
            # Connection-level failure (may be unreachable IPv6).
            # Retry with IPv4 only.
            return _connect(ipv4_only=True)

    async def connect(self) -> bool:
        """Connect to email services and start polling when IMAP is configured."""
        # In OAuth/Graph mode, outbound goes over Graph — SMTP host/username/
        # password are not required, only EMAIL_ADDRESS (the mailbox to send as)
        # plus the three EMAIL_OAUTH_* vars (validated when building self._oauth).
        if self._oauth:
            required = (("EMAIL_ADDRESS", self._address),)
        else:
            required = (
                ("EMAIL_ADDRESS", self._address),
                ("EMAIL_SMTP_USERNAME", self._smtp_username),
                ("EMAIL_SMTP_PASSWORD or EMAIL_PASSWORD", self._smtp_password),
                ("EMAIL_SMTP_HOST", self._smtp_host),
            )
        missing = [name for name, value in required if not value]
        if missing:
            message = (
                "Not configured — missing "
                + ", ".join(missing)
                + ". Set it via `hermes gateway setup` (env) or platforms.email "
                "in config.yaml."
            )
            logger.error("[Email] %s", message)
            # Mark non-retryable so the gateway does NOT keep reconnecting
            # against empty required settings. Blank-but-present env vars used
            # to slip past the startup gate and drive an indefinite retry loop
            # that leaked memory until the host OOM-killed (#40715).
            self._set_fatal_error(
                "email_missing_configuration", message, retryable=False
            )
            return False

        if self._imap_host:
            try:
                # Test IMAP connection
                imap = imaplib.IMAP4_SSL(self._imap_host, self._imap_port, timeout=30)
                imap.login(self._address, self._password)
                _send_imap_id(imap)
                # Mark all existing messages as seen so we only process new ones
                imap.select("INBOX")
                status, data = imap.uid("search", None, "ALL")
                if status == "OK" and data and data[0]:
                    for uid in data[0].split():
                        self._seen_uids.add(uid)
                # Keep only the most recent UIDs to prevent unbounded growth
                self._trim_seen_uids()
                imap.logout()
                logger.info("[Email] IMAP connection test passed. %d existing messages skipped.", len(self._seen_uids))
            except Exception as e:
                logger.error("[Email] IMAP connection failed: %s", e)
                return False
        elif self._oauth:
            logger.info(
                "[Email] IMAP host not configured; receiving via Microsoft Graph polling."
            )
        else:
            logger.info(
                "[Email] IMAP host not configured; starting in SMTP-only mode (no polling)."
            )

        if self._oauth:
            # Validate the OAuth path by acquiring a Graph token (basic-auth SMTP
            # would fail here on locations where it's blocked — the very reason
            # OAuth mode exists).
            try:
                _graph_access_token(*self._oauth)
                logger.info("[Email] OAuth2/Graph token acquired — outbound via Graph.")
            except Exception as e:
                logger.error("[Email] OAuth2/Graph token request failed: %s", e)
                return False
            # Graph inbound: skip the existing unread backlog so a freshly
            # started gateway only replies to mail that arrives afterwards
            # (mirrors the IMAP branch above marking existing messages seen).
            # Only when Graph is the receive path — if IMAP is configured it
            # owns receiving and already pre-seeded seen_uids above.
            if not self._imap_host:
                try:
                    loop = asyncio.get_running_loop()
                    skipped = await loop.run_in_executor(
                        None, self._graph_skip_existing_unread
                    )
                    logger.info(
                        "[Email] Graph inbox poll enabled. %d existing unread "
                        "messages skipped.", skipped,
                    )
                except Exception as e:
                    logger.warning(
                        "[Email] Could not pre-skip existing unread via Graph: %s", e
                    )
        else:
            try:
                # Test SMTP connection
                smtp = self._connect_smtp()
                try:
                    smtp.login(self._smtp_username, self._smtp_password)
                finally:
                    smtp.quit()
                logger.info("[Email] SMTP connection test passed.")
            except Exception as e:
                logger.error("[Email] SMTP connection failed: %s", e)
                return False

        self._running = True
        # Poll for inbound when a receive path exists: IMAP, or Graph (OAuth
        # without IMAP). SMTP-only with no OAuth has no inbox to read.
        if self._imap_host or self._oauth:
            self._poll_task = asyncio.create_task(self._poll_loop())
            print(f"[Email] Connected as {self._address}")
        else:
            self._poll_task = None
            print(f"[Email] Connected as {self._address} (SMTP-only)")
        return True

    async def disconnect(self) -> None:
        """Stop polling and disconnect."""
        self._running = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None
        logger.info("[Email] Disconnected.")

    async def _poll_loop(self) -> None:
        """Poll the inbox (IMAP or Graph) for new messages at regular intervals."""
        while self._running:
            try:
                await self._check_inbox()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("[Email] Poll error: %s", e)
            await asyncio.sleep(self._poll_interval)

    async def _check_inbox(self) -> None:
        """Check INBOX for unseen messages and dispatch them.

        Receive transport is chosen by config: Microsoft Graph when OAuth is
        configured and no IMAP host is set (the M365/Railway case where basic
        auth is blocked), otherwise IMAP basic auth.
        """
        # Run the (blocking) fetch in a thread to avoid blocking the event loop
        loop = asyncio.get_running_loop()
        fetch = (
            self._fetch_new_messages_graph
            if self._oauth and not self._imap_host
            else self._fetch_new_messages
        )
        messages = await loop.run_in_executor(None, fetch)
        for msg_data in messages:
            await self._dispatch_message(msg_data)

    # ──────────────────────────────────────────────────────────────────────
    # Microsoft Graph inbound (used when OAuth is configured and IMAP is not).
    # Mirrors the IMAP receive path: unread inbox messages are read, recorded in
    # seen_uids, and marked read on the server (the Graph analog of IMAP setting
    # \Seen on an RFC822 fetch) so they are not processed twice. The same
    # delegated refresh-token grant that authorizes sendMail also grants inbox
    # read access (Mail.ReadWrite), so no extra consent is needed.
    # ──────────────────────────────────────────────────────────────────────

    def _graph_get(
        self, url: str, params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Authenticated Graph GET returning parsed JSON. Runs in executor
        thread. Raises RuntimeError on a non-200 response."""
        import requests  # core dep; lazy import keeps module import resilient

        token = _graph_access_token(*self._oauth)
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=GRAPH_HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Graph GET failed ({resp.status_code}): {resp.text[:300]}"
            )
        return resp.json()

    def _graph_mark_read(self, msg_id: str) -> None:
        """Best-effort: mark a Graph message read so the next poll skips it.

        A failure is non-fatal — ``seen_uids`` still guards against in-process
        repeats, and connect() re-skips any still-unread backlog on restart.
        """
        import requests

        try:
            token = _graph_access_token(*self._oauth)
            resp = requests.patch(
                f"{GRAPH_BASE_URL}/users/{quote(self._address)}/messages/{msg_id}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json={"isRead": True},
                timeout=GRAPH_HTTP_TIMEOUT,
            )
            if resp.status_code != 200:
                logger.warning(
                    "[Email] Graph mark-read failed (%s): %s",
                    resp.status_code, resp.text[:200],
                )
        except Exception as e:  # noqa: BLE001 — best-effort, never fatal
            logger.warning("[Email] Graph mark-read error for %s: %s", msg_id, e)

    def _graph_attachments(self, msg_id: str) -> List[Dict[str, Any]]:
        """Fetch and cache a Graph message's file attachments.

        Returns the same ``{path, filename, type, media_type}`` dicts as
        ``_extract_attachments`` (so _dispatch_message needs no changes), using
        the same image/document caching logic. Honors ``self._skip_attachments``.
        Best-effort: any failure yields no attachments rather than dropping the
        whole message.
        """
        if self._skip_attachments:
            return []
        attachments: List[Dict[str, Any]] = []
        try:
            url = (
                f"{GRAPH_BASE_URL}/users/{quote(self._address)}"
                f"/messages/{msg_id}/attachments"
            )
            data = self._graph_get(url)
            for att in data.get("value", []):
                if att.get("@odata.type") != "#microsoft.graph.fileAttachment":
                    continue
                content_b64 = att.get("contentBytes")
                if not content_b64:
                    continue
                try:
                    payload = base64.b64decode(content_b64)
                except Exception:
                    logger.debug("[Email] Skipping attachment with bad base64")
                    continue

                filename = att.get("name") or "attachment.bin"
                content_type = att.get("contentType") or "application/octet-stream"
                ext = Path(filename).suffix.lower()
                if ext in _IMAGE_EXTS:
                    try:
                        cached_path = cache_image_from_bytes(payload, ext)
                    except ValueError:
                        logger.debug(
                            "Skipping non-image attachment %s (invalid magic bytes)",
                            filename,
                        )
                        continue
                    attachments.append({
                        "path": cached_path,
                        "filename": filename,
                        "type": "image",
                        "media_type": content_type,
                    })
                else:
                    cached_path = cache_document_from_bytes(payload, filename)
                    attachments.append({
                        "path": cached_path,
                        "filename": filename,
                        "type": "document",
                        "media_type": content_type,
                    })
        except Exception as e:  # noqa: BLE001 — attachments are best-effort
            logger.warning(
                "[Email] Failed to fetch Graph attachments for %s: %s", msg_id, e
            )
        return attachments

    def _fetch_new_messages_graph(self) -> List[Dict[str, Any]]:
        """Fetch new (unread) inbox messages via Microsoft Graph.

        Returns the SAME list-of-dicts shape as ``_fetch_new_messages`` so
        ``_dispatch_message`` needs no changes. Runs in an executor thread.
        """
        results: List[Dict[str, Any]] = []
        try:
            base = (
                f"{GRAPH_BASE_URL}/users/{quote(self._address)}"
                f"/mailFolders/inbox/messages"
            )
            params = {
                "$filter": "isRead eq false",
                "$top": "25",
                "$orderby": "receivedDateTime asc",
                "$select": (
                    "id,subject,from,receivedDateTime,internetMessageId,"
                    "bodyPreview,body,hasAttachments,conversationId"
                ),
            }
            data = self._graph_get(base, params=params)
            for message in data.get("value", []):
                msg_id = message.get("id")
                if not msg_id or msg_id in self._seen_uids:
                    continue
                self._seen_uids.add(msg_id)
                if len(self._seen_uids) > self._seen_uids_max:
                    self._trim_seen_uids()

                sender = (message.get("from") or {}).get("emailAddress") or {}
                sender_addr = (sender.get("address") or "").strip().lower()
                sender_name = sender.get("name") or ""

                # Skip automated/noreply senders before any heavier work
                # (parity with the IMAP path's _is_automated_sender gate).
                if sender_addr and _is_automated_sender(sender_addr, {}):
                    logger.debug("[Email] Skipping automated sender: %s", sender_addr)
                    self._graph_mark_read(msg_id)
                    continue

                subject = message.get("subject") or "(no subject)"
                body_obj = message.get("body") or {}
                body = body_obj.get("content", "") or ""
                if (body_obj.get("contentType") or "").lower() == "html":
                    body = _strip_html(body)
                if not body:
                    body = message.get("bodyPreview", "") or ""

                attachments = (
                    self._graph_attachments(msg_id)
                    if message.get("hasAttachments")
                    else []
                )

                results.append({
                    "uid": msg_id,
                    "sender_addr": sender_addr,
                    "sender_name": sender_name,
                    "subject": subject,
                    "message_id": message.get("internetMessageId", ""),
                    # in_reply_to needs internetMessageHeaders to populate;
                    # replies thread by the Re: subject instead (see _graph_send).
                    "in_reply_to": "",
                    "body": body,
                    "attachments": attachments,
                    "date": message.get("receivedDateTime", ""),
                })
                # Mark read so the next poll's isRead-eq-false query skips it.
                # seen_uids is the in-process guard; this is the durable one.
                self._graph_mark_read(msg_id)
        except Exception as e:
            logger.error("[Email] Graph fetch error: %s", e)
        return results

    def _graph_skip_existing_unread(self) -> int:
        """Mark all currently-unread inbox messages read (recording their ids),
        so a freshly-started gateway only replies to mail that arrives after it
        comes up. The Graph analog of connect()'s IMAP path adding existing UIDs
        to ``seen_uids``. Runs synchronously in an executor thread; pagination is
        bounded to avoid a pathological loop on a huge backlog.
        """
        count = 0
        url: Optional[str] = (
            f"{GRAPH_BASE_URL}/users/{quote(self._address)}"
            f"/mailFolders/inbox/messages"
        )
        params: Optional[Dict[str, str]] = {
            "$filter": "isRead eq false",
            "$top": "50",
            "$select": "id",
        }
        for _ in range(40):  # cap at ~2000 messages
            data = self._graph_get(url, params=params)
            for message in data.get("value", []):
                mid = message.get("id")
                if not mid:
                    continue
                self._seen_uids.add(mid)
                self._graph_mark_read(mid)
                count += 1
            url = data.get("@odata.nextLink")
            params = None  # nextLink already encodes the query
            if not url:
                break
        return count

    def _fetch_new_messages(self) -> List[Dict[str, Any]]:
        """Fetch new (unseen) messages from IMAP. Runs in executor thread."""
        results = []
        try:
            imap = imaplib.IMAP4_SSL(self._imap_host, self._imap_port, timeout=30)
            try:
                imap.login(self._address, self._password)
                _send_imap_id(imap)
                imap.select("INBOX")

                status, data = imap.uid("search", None, "UNSEEN")
                if status != "OK" or not data or not data[0]:
                    return results

                for uid in data[0].split():
                    if uid in self._seen_uids:
                        continue
                    self._seen_uids.add(uid)
                    # Trim periodically to prevent unbounded memory growth
                    if len(self._seen_uids) > self._seen_uids_max:
                        self._trim_seen_uids()

                    status, msg_data = imap.uid("fetch", uid, "(RFC822)")
                    if status != "OK":
                        continue

                    raw_email = msg_data[0][1]
                    msg = email_lib.message_from_bytes(raw_email)

                    sender_raw = msg.get("From", "")
                    sender_addr = _extract_email_address(sender_raw)
                    sender_name = _decode_header_value(sender_raw)
                    # Remove email from name if present
                    if "<" in sender_name:
                        sender_name = sender_name.split("<")[0].strip().strip('"')

                    subject = _decode_header_value(msg.get("Subject", "(no subject)"))
                    message_id = msg.get("Message-ID", "")
                    in_reply_to = msg.get("In-Reply-To", "")
                    # Skip automated/noreply senders before any processing
                    msg_headers = dict(msg.items())
                    if _is_automated_sender(sender_addr, msg_headers):
                        logger.debug("[Email] Skipping automated sender: %s", sender_addr)
                        continue
                    body = _extract_text_body(msg)
                    attachments = _extract_attachments(msg, skip_attachments=self._skip_attachments)

                    results.append({
                        "uid": uid,
                        "sender_addr": sender_addr,
                        "sender_name": sender_name,
                        "subject": subject,
                        "message_id": message_id,
                        "in_reply_to": in_reply_to,
                        "body": body,
                        "attachments": attachments,
                        "date": msg.get("Date", ""),
                    })
            finally:
                try:
                    imap.logout()
                except Exception:
                    pass
        except Exception as e:
            logger.error("[Email] IMAP fetch error: %s", e)
        return results

    async def _dispatch_message(self, msg_data: Dict[str, Any]) -> None:
        """Convert a fetched email into a MessageEvent and dispatch it."""
        sender_addr = msg_data["sender_addr"]

        # Skip self-messages
        if sender_addr == self._address.lower():
            return

        # Never reply to automated senders
        if _is_automated_sender(sender_addr, {}):
            logger.debug("[Email] Dropping automated sender at dispatch: %s", sender_addr)
            return

        # Skip senders not in EMAIL_ALLOWED_USERS — prevents the adapter
        # from creating a MessageEvent (and thus thread context) for senders
        # that the gateway will never authorize.  Without this early guard,
        # a race between dispatch and authorization can result in the adapter
        # sending a reply even though the handler returned None.
        allowed_raw = os.getenv("EMAIL_ALLOWED_USERS", "").strip()
        if allowed_raw:
            allowed = {addr.strip().lower() for addr in allowed_raw.split(",") if addr.strip()}
            if sender_addr.lower() not in allowed:
                logger.debug("[Email] Dropping non-allowlisted sender at dispatch: %s", sender_addr)
                return

        subject = msg_data["subject"]
        body = msg_data["body"].strip()
        attachments = msg_data["attachments"]

        # Build message text: include subject as context
        text = body
        if subject and not subject.startswith("Re:"):
            text = f"[Subject: {subject}]\n\n{body}"

        # Determine message type and media
        media_urls = []
        media_types = []
        msg_type = MessageType.TEXT

        for att in attachments:
            media_urls.append(att["path"])
            media_types.append(att["media_type"])
            if att["type"] == "image" and msg_type == MessageType.TEXT:
                msg_type = MessageType.PHOTO
            elif att["type"] == "document":
                # Document wins over PHOTO for mixed attachments: run.py's
                # image handling keys off the per-path image/* mime type
                # regardless of message_type, but document-context injection
                # gates strictly on MessageType.DOCUMENT — so DOCUMENT is the
                # only classification that surfaces both.
                msg_type = MessageType.DOCUMENT

        # Store thread context for reply threading
        self._thread_context[sender_addr] = {
            "subject": subject,
            "message_id": msg_data["message_id"],
        }

        source = self.build_source(
            chat_id=sender_addr,
            chat_name=msg_data["sender_name"] or sender_addr,
            chat_type="dm",
            user_id=sender_addr,
            user_name=msg_data["sender_name"] or sender_addr,
        )

        event = MessageEvent(
            text=text or "(empty email)",
            message_type=msg_type,
            source=source,
            message_id=msg_data["message_id"],
            media_urls=media_urls,
            media_types=media_types,
            reply_to_message_id=msg_data["in_reply_to"] or None,
        )

        logger.info("[Email] New message from %s: %s", sender_addr, subject)
        await self.handle_message(event)

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send an email reply to the given address."""
        try:
            loop = asyncio.get_running_loop()
            message_id = await loop.run_in_executor(
                None, self._send_email, chat_id, content, reply_to
            )
            return SendResult(success=True, message_id=message_id)
        except Exception as e:
            logger.error("[Email] Send failed to %s: %s", chat_id, e)
            return SendResult(success=False, error=str(e))

    def _reply_subject(self, to_addr: str) -> str:
        """Compute the (Re:-prefixed) reply subject from stored thread context."""
        subject = self._thread_context.get(to_addr, {}).get("subject", "Hermes Agent")
        if not subject.startswith("Re:"):
            subject = f"Re: {subject}"
        return subject

    def _graph_send(
        self,
        to_addr: str,
        subject: str,
        body: str,
        attachments: Optional[List[Tuple[str, bytes, str]]] = None,
    ) -> str:
        """Send via Microsoft Graph. ``attachments`` is a list of
        (filename, content_bytes, content_type). Returns a synthetic Message-ID
        (Graph assigns the real one server-side). Runs in executor thread."""
        graph_attachments = [
            _graph_file_attachment(name, content, ctype)
            for (name, content, ctype) in (attachments or [])
        ]
        _graph_send_mail(
            self._oauth,
            sender=self._address,
            to_addr=to_addr,
            subject=subject,
            body=body,
            attachments=graph_attachments,
        )
        msg_id = f"<hermes-{uuid.uuid4().hex[:12]}@{self._address.split('@')[1]}>"
        logger.info("[Email] Sent via Graph to %s (subject: %s)", to_addr, subject)
        return msg_id

    def _send_email(
        self,
        to_addr: str,
        body: str,
        reply_to_msg_id: Optional[str] = None,
    ) -> str:
        """Send an email. Uses Graph when OAuth is configured, else SMTP.
        Runs in executor thread."""
        subject = self._reply_subject(to_addr)

        if self._oauth:
            return self._graph_send(to_addr, subject, body)

        msg = MIMEMultipart()
        msg["From"] = self._from_address
        msg["To"] = to_addr
        msg["Subject"] = subject

        # Threading headers
        ctx = self._thread_context.get(to_addr, {})
        original_msg_id = reply_to_msg_id or ctx.get("message_id")
        if original_msg_id:
            msg["In-Reply-To"] = original_msg_id
            msg["References"] = original_msg_id

        msg["Date"] = formatdate(localtime=True)
        msg_id = f"<hermes-{uuid.uuid4().hex[:12]}@{self._address.split('@')[1]}>"
        msg["Message-ID"] = msg_id

        msg.attach(MIMEText(body, "plain", "utf-8"))

        smtp = self._connect_smtp()
        try:
            smtp.login(self._smtp_username, self._smtp_password)
            smtp.send_message(msg)
        finally:
            try:
                smtp.quit()
            except Exception:
                smtp.close()

        logger.info("[Email] Sent reply to %s (subject: %s)", to_addr, subject)
        return msg_id

    async def send_typing(self, chat_id: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Email has no typing indicator — no-op."""

    async def send_image(
        self,
        chat_id: str,
        image_url: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send an image URL as part of an email body.

        ``metadata`` is accepted to honor the base-class contract; the
        email body send doesn't use it.
        """
        text = caption or ""
        text += f"\n\nImage: {image_url}"
        return await self.send(chat_id, text.strip(), reply_to)

    async def send_multiple_images(
        self,
        chat_id: str,
        images: List[Tuple[str, str]],
        metadata: Optional[Dict[str, Any]] = None,
        human_delay: float = 0.0,
    ) -> None:
        """Send a batch of images as a single email with multiple MIME attachments.

        Local files are attached directly. URL images have their URL
        appended to the body (email adapter does not download remote
        images). No hard cap — email clients handle dozens of
        attachments fine, subject to SMTP message size limits.
        """
        if not images:
            return

        from urllib.parse import unquote as _unquote

        body_parts: List[str] = []
        local_paths: List[str] = []
        for image_url, alt_text in images:
            if alt_text:
                body_parts.append(alt_text)
            if image_url.startswith("file://"):
                local_path = _unquote(image_url[7:])
                if Path(local_path).exists():
                    local_paths.append(local_path)
                else:
                    logger.warning("[Email] Skipping missing image: %s", local_path)
            else:
                # Remote URLs just get linked in the body (parity with send_image)
                body_parts.append(f"Image: {image_url}")

        if not local_paths and not body_parts:
            return

        body = "\n\n".join(body_parts)

        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                self._send_email_with_attachments,
                chat_id,
                body,
                local_paths,
            )
        except Exception as e:
            logger.error("[Email] Multi-image send failed, falling back: %s", e, exc_info=True)
            await super().send_multiple_images(chat_id, images, metadata, human_delay)

    def _send_email_with_attachments(
        self,
        to_addr: str,
        body: str,
        file_paths: List[str],
    ) -> str:
        """Send an email with multiple file attachments. Graph when OAuth is
        configured, else SMTP."""
        subject = self._reply_subject(to_addr)

        if self._oauth:
            attachments: List[Tuple[str, bytes, str]] = []
            for file_path in file_paths:
                p = Path(file_path)
                try:
                    attachments.append((p.name, p.read_bytes(), "application/octet-stream"))
                except Exception as e:
                    logger.warning("[Email] Failed to attach %s: %s", file_path, e)
            return self._graph_send(to_addr, subject, body, attachments)

        msg = MIMEMultipart()
        msg["From"] = self._from_address
        msg["To"] = to_addr
        msg["Subject"] = subject

        ctx = self._thread_context.get(to_addr, {})
        original_msg_id = ctx.get("message_id")
        if original_msg_id:
            msg["In-Reply-To"] = original_msg_id
            msg["References"] = original_msg_id

        msg["Date"] = formatdate(localtime=True)
        msg_id = f"<hermes-{uuid.uuid4().hex[:12]}@{self._address.split('@')[1]}>"
        msg["Message-ID"] = msg_id

        if body:
            msg.attach(MIMEText(body, "plain", "utf-8"))

        for file_path in file_paths:
            p = Path(file_path)
            try:
                with open(p, "rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", f"attachment; filename={p.name}")
                    msg.attach(part)
            except Exception as e:
                logger.warning("[Email] Failed to attach %s: %s", file_path, e)

        smtp = self._connect_smtp()
        try:
            smtp.login(self._smtp_username, self._smtp_password)
            smtp.send_message(msg)
        finally:
            try:
                smtp.quit()
            except Exception:
                smtp.close()

        logger.info("[Email] Sent multi-attachment email to %s (%d files)", to_addr, len(file_paths))
        return msg_id

    async def send_document(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        file_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        **kwargs,
    ) -> SendResult:
        """Send a file as an email attachment."""
        try:
            loop = asyncio.get_running_loop()
            message_id = await loop.run_in_executor(
                None,
                self._send_email_with_attachment,
                chat_id,
                caption or "",
                file_path,
                file_name,
            )
            return SendResult(success=True, message_id=message_id)
        except Exception as e:
            logger.error("[Email] Send document failed: %s", e)
            return SendResult(success=False, error=str(e))

    def _send_email_with_attachment(
        self,
        to_addr: str,
        body: str,
        file_path: str,
        file_name: Optional[str] = None,
    ) -> str:
        """Send an email with a file attachment. Graph when OAuth is
        configured, else SMTP."""
        subject = self._reply_subject(to_addr)
        p = Path(file_path)
        fname = file_name or p.name

        if self._oauth:
            attachments = [(fname, p.read_bytes(), "application/octet-stream")]
            return self._graph_send(to_addr, subject, body, attachments)

        msg = MIMEMultipart()
        msg["From"] = self._from_address
        msg["To"] = to_addr
        msg["Subject"] = subject

        ctx = self._thread_context.get(to_addr, {})
        original_msg_id = ctx.get("message_id")
        if original_msg_id:
            msg["In-Reply-To"] = original_msg_id
            msg["References"] = original_msg_id

        msg["Date"] = formatdate(localtime=True)
        msg_id = f"<hermes-{uuid.uuid4().hex[:12]}@{self._address.split('@')[1]}>"
        msg["Message-ID"] = msg_id

        if body:
            msg.attach(MIMEText(body, "plain", "utf-8"))

        # Attach file
        with open(p, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={fname}")
            msg.attach(part)

        smtp = self._connect_smtp()
        try:
            smtp.login(self._smtp_username, self._smtp_password)
            smtp.send_message(msg)
        finally:
            try:
                smtp.quit()
            except Exception:
                smtp.close()

        return msg_id

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        """Return basic info about the email chat."""
        ctx = self._thread_context.get(chat_id, {})
        return {
            "name": chat_id,
            "type": "dm",
            "chat_id": chat_id,
            "subject": ctx.get("subject", ""),
        }


# ──────────────────────────────────────────────────────────────────────────
# Plugin migration glue (#41112 / #3823)
#
# Added when the Email adapter moved from gateway/platforms/email.py into this
# bundled plugin. register() exposes the platform via the registry, replacing
# the Platform.EMAIL elif in gateway/run.py, the _PLATFORM_CONNECTED_CHECKERS
# entry in gateway/config.py, the _PLATFORMS["email"] static dict in
# hermes_cli/gateway.py, and the _send_email dispatch in
# tools/send_message_tool.py. EMAIL_* env→PlatformConfig seeding stays in core.
# ──────────────────────────────────────────────────────────────────────────


async def _standalone_send(
    pconfig,
    chat_id,
    message,
    *,
    thread_id=None,
    media_files=None,
    force_document=False,
):
    """Out-of-process Email delivery (one-shot). Implements the
    standalone_sender_fn contract; replaces the legacy _send_email helper.

    Uses Microsoft Graph (OAuth2) when EMAIL_OAUTH_* are configured, else SMTP
    basic auth."""
    import smtplib
    import ssl as _ssl
    from email.mime.text import MIMEText
    from email.utils import formatdate

    extra = getattr(pconfig, "extra", {}) or {}
    address = extra.get("address") or os.getenv("EMAIL_ADDRESS", "")

    # OAuth2/Graph path — preferred when configured (mirrors the adapter).
    oauth = _oauth_credentials()
    if oauth and address:
        try:
            attachments = []
            for fpath in (media_files or []):
                try:
                    p = Path(fpath)
                    attachments.append((p.name, p.read_bytes(), "application/octet-stream"))
                except Exception as e:
                    logger.warning("[Email] Failed to attach %s: %s", fpath, e)
            await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: _graph_send_mail(
                    oauth,
                    sender=address,
                    to_addr=chat_id,
                    subject="Hermes Agent",
                    body=message,
                    attachments=[
                        _graph_file_attachment(n, c, t) for (n, c, t) in attachments
                    ],
                ),
            )
            return {"success": True, "platform": "email", "chat_id": chat_id}
        except Exception as e:
            try:
                from tools.send_message_tool import _error as _e
                return _e(f"Email send failed: {e}")
            except Exception:
                return {"error": f"Email send failed: {e}"}

    smtp_username = (
        os.getenv("EMAIL_SMTP_USERNAME", "")
        or os.getenv("SMTP_USERNAME", "")
        or extra.get("smtp_username", "")
        or address
    )
    password = _env_first("EMAIL_SMTP_PASSWORD", "SMTP_PASSWORD", "EMAIL_PASSWORD")
    from_address = (
        os.getenv("EMAIL_FROM", "")
        or os.getenv("MAIL_FROM", "")
        or extra.get("from_address", "")
        or address
    )
    smtp_host = extra.get("smtp_host") or os.getenv("EMAIL_SMTP_HOST", "")
    try:
        smtp_port = int(os.getenv("EMAIL_SMTP_PORT", "587"))
    except (ValueError, TypeError):
        smtp_port = 587
    smtp_use_ssl = _env_bool("EMAIL_SMTP_USE_SSL", _env_bool("SMTP_USE_SSL", smtp_port == 465))

    if not all([address, smtp_username, password, smtp_host]):
        return {
            "error": (
                "Email not configured (EMAIL_ADDRESS, EMAIL_SMTP_HOST, and "
                "EMAIL_SMTP_PASSWORD or EMAIL_PASSWORD required)"
            )
        }

    try:
        msg = MIMEText(message, "plain", "utf-8")
        msg["From"] = from_address
        msg["To"] = chat_id
        msg["Subject"] = "Hermes Agent"
        msg["Date"] = formatdate(localtime=True)

        ctx = _ssl.create_default_context()
        if smtp_use_ssl:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls(context=ctx)
        server.login(smtp_username, password)
        server.send_message(msg)
        server.quit()
        return {"success": True, "platform": "email", "chat_id": chat_id}
    except Exception as e:
        try:
            from tools.send_message_tool import _error as _e
            return _e(f"Email send failed: {e}")
        except Exception:
            return {"error": f"Email send failed: {e}"}


def _is_connected(config) -> bool:
    """Email is connected when an address is configured (in PlatformConfig.extra
    or via EMAIL_ADDRESS). Mirrors the legacy
    _PLATFORM_CONNECTED_CHECKERS[Platform.EMAIL] = bool(extra.get('address'))."""
    extra = getattr(config, "extra", {}) or {}
    if extra.get("address"):
        return True
    import hermes_cli.gateway as gateway_mod
    return bool((gateway_mod.get_env_value("EMAIL_ADDRESS") or "").strip())


def _build_adapter(config):
    """Factory wrapper that constructs EmailAdapter from a PlatformConfig."""
    return EmailAdapter(config)


def register(ctx) -> None:
    """Plugin entry point — called by the Hermes plugin system."""
    ctx.register_platform(
        name="email",
        label="Email",
        adapter_factory=_build_adapter,
        check_fn=check_email_requirements,
        is_connected=_is_connected,
        required_env=["EMAIL_ADDRESS", "EMAIL_PASSWORD", "EMAIL_SMTP_HOST"],
        install_hint="Email uses the Python stdlib (smtplib/imaplib) — no extra deps",
        allowed_users_env="EMAIL_ALLOWED_USERS",
        allow_all_env="EMAIL_ALLOW_ALL_USERS",
        cron_deliver_env_var="EMAIL_HOME_ADDRESS",
        standalone_sender_fn=_standalone_send,
        max_message_length=50_000,
        pii_safe=True,
        emoji="📧",
        allow_update_command=True,
    )
