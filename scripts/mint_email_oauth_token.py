"""One-time helper: mint a delegated Microsoft Graph refresh token for the
email adapter, so outbound mail can use the delegated `Mail.Send` permission
(no Global-Admin consent required — unlike the app-only flow).

Run this LOCALLY, from a trusted machine (not the Railway container). It uses
the OAuth2 device-code flow: it prints a URL + short code, you open the URL in
a browser and sign in as the MAILBOX OWNER (e.g. innovacion@lpsgrupo.com) and
approve. The script then prints the value to put in EMAIL_OAUTH_REFRESH_TOKEN.

Prerequisites:
  * The three app vars in your environment (or a local .env you load first):
      EMAIL_OAUTH_TENANT_ID, EMAIL_OAUTH_CLIENT_ID, EMAIL_OAUTH_CLIENT_SECRET
    (the secret is included in the token exchange because the app is registered
    as a confidential client — no "Allow public client flows" toggle needed).
  * The app must already have the delegated `Mail.Send` + `offline_access`
    permissions consented (your screenshot showed both are already granted).

Usage:
    python scripts/mint_email_oauth_token.py

Then paste the printed line into /opt/data/.env on Railway (and your local .env)
and redeploy. The adapter auto-detects EMAIL_OAUTH_REFRESH_TOKEN and switches to
the delegated refresh-token grant.
"""

import os
import sys
import time

import requests

# Scopes: offline_access is what makes Azure return a refresh_token; Mail.Send
# is the delegated permission we actually need. openid/profile keep the
# sign-in well-formed.
SCOPE = "offline_access openid profile https://graph.microsoft.com/Mail.Send"


def _require(name: str) -> str:
    val = os.getenv(name, "").strip()
    if not val:
        sys.exit(
            f"Missing {name}. Set it in your environment (or load a local .env "
            f"first), then re-run. See this script's docstring."
        )
    return val


def main() -> None:
    tenant = _require("EMAIL_OAUTH_TENANT_ID")
    client_id = _require("EMAIL_OAUTH_CLIENT_ID")
    client_secret = _require("EMAIL_OAUTH_CLIENT_SECRET")

    base = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"

    # 1) Ask Azure for a device code.
    dc = requests.post(
        f"{base}/devicecode",
        data={"client_id": client_id, "scope": SCOPE},
        timeout=30,
    )
    if dc.status_code != 200:
        sys.exit(f"devicecode request failed ({dc.status_code}): {dc.text[:500]}")
    dc = dc.json()

    print("\n" + "=" * 70)
    print(dc["message"])  # "To sign in, use a web browser to open ... and enter code ..."
    print("=" * 70 + "\n")
    print("Sign in as the MAILBOX OWNER (the address you send from).")
    print("Waiting for you to complete sign-in...\n")

    interval = int(dc.get("interval", 5))
    device_code = dc["device_code"]
    deadline = time.time() + int(dc.get("expires_in", 900))

    # 2) Poll the token endpoint until the user finishes (or it expires).
    while time.time() < deadline:
        time.sleep(interval)
        tok = requests.post(
            f"{base}/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "device_code": device_code,
            },
            timeout=30,
        ).json()

        if "access_token" in tok:
            refresh = tok.get("refresh_token")
            if not refresh:
                sys.exit(
                    "Got an access token but NO refresh token. Ensure the app "
                    "has 'offline_access' consented and SCOPE includes it."
                )
            print("\n✅ Success! Add this line to /opt/data/.env (and your local .env):\n")
            print(f"EMAIL_OAUTH_REFRESH_TOKEN={refresh}\n")
            return

        err = tok.get("error")
        if err == "authorization_pending":
            continue  # user hasn't finished yet
        if err == "slow_down":
            interval += 5
            continue
        # Real error (expired_token, authorization_declined, bad_verification, etc.)
        sys.exit(f"\n❌ Sign-in failed: {err} — {tok.get('error_description', '')[:500]}")

    sys.exit("\n❌ Timed out waiting for sign-in. Re-run and finish faster.")


if __name__ == "__main__":
    main()
