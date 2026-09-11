# Google Drive Integration Setup Guide

**Updated:** September 11, 2026
**Version:** 1.0.0

Complete step-by-step guide for setting up Google Drive (Cloud) monitoring in SeceoKnight DLP.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Google Cloud Project Setup](#google-cloud-project-setup)
3. [Configure OAuth Consent Screen](#configure-oauth-consent-screen)
4. [Create OAuth Client Credentials](#create-oauth-client-credentials)
5. [Environment Configuration](#environment-configuration)
6. [Verify Setup](#verify-setup)
7. [Create Google Drive Policy](#create-google-drive-policy)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- A Google account (personal Gmail or Google Workspace)
- Google Cloud Console access ([console.cloud.google.com](https://console.cloud.google.com/))
- SeceoKnight DLP server running and accessible
- Admin access to configure environment variables (`.env`) and restart the deployment

**Important Notes:**
- This is server-side polling, not an endpoint agent — there's nothing to install on any Windows/Mac machine.
  It works by connecting a Google account via OAuth and polling the Drive Activity API on a schedule.
- The account you connect needs read access to whatever Drive folders you want monitored — connect the
  account that actually owns/has access to those folders, not a throwaway test account with nothing in it.
- Cloud monitoring is currently **log-only** (see `server/app/utils/policy_transformer.py`'s
  `_transform_google_drive_cloud_config` — actions are hardcoded to `{"log": {}}`). It records and alerts on
  activity; it cannot block or quarantine a cloud file the way the endpoint agent can for local files.

---

## Google Cloud Project Setup

### Step 1: Create or Select a Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click the project dropdown at the top → **New Project**
3. Name it something recognizable, e.g. `SeceoKnight DLP`
4. Click **Create**, then make sure the new project is selected in the dropdown

### Step 2: Enable Required APIs

SeceoKnight needs **two** APIs enabled — missing either one causes OAuth or polling failures later.

1. Go to **APIs & Services → Library**
2. Search for **Google Drive API** → click it → **Enable**
3. Search for **Drive Activity API** → click it → **Enable**
   - This is the one that's easy to miss. `server/app/services/google_drive_polling.py` calls
     `build("driveactivity", "v2", ...)` — without this API enabled, every poll fails.

---

## Configure OAuth Consent Screen

1. Go to **APIs & Services → OAuth consent screen**
2. **User Type**:
   - **External** — if you're using a personal Gmail account or don't have a Google Workspace org. Select
     this in almost all cases.
   - **Internal** — only available if your account belongs to a Google Workspace organization.
3. Fill in the required fields: App name (e.g. `SeceoKnight DLP`), User support email, Developer contact email
4. **Scopes**: skip this — SeceoKnight requests its scopes at runtime (see `GoogleDriveOAuthService.SCOPES`
   in `server/app/services/google_drive_oauth.py`: `drive.readonly`, `drive.metadata.readonly`,
   `drive.activity.readonly`, plus basic profile/email). Nothing to configure here.
5. **Test users** (External + Testing publish status, which is the default): add the Google account
   email(s) you'll actually use to connect. Without this, Google blocks the OAuth flow for anyone not listed.
6. Save.

---

## Create OAuth Client Credentials

### Step 1: Create the OAuth Client ID

1. Go to **APIs & Services → Credentials**
2. Click **+ Create Credentials → OAuth client ID**
3. **Application type**: **Web application**
4. **Name**: anything recognizable, e.g. `SeceoKnight DLP Server`
5. **Authorized redirect URIs** → **+ Add URI**:
   ```
   http://YOUR_SERVER_IP:55000/api/v1/google-drive/callback
   ```
   Replace `YOUR_SERVER_IP` with your actual server's IP or domain. This must match
   `GOOGLE_REDIRECT_URI` in your `.env` **exactly** — protocol, port, and path all have to line up, or the
   OAuth flow fails with a redirect URI mismatch.

   **Example URIs:**
   ```
   http://192.168.1.67:55000/api/v1/google-drive/callback
   http://localhost:55000/api/v1/google-drive/callback
   https://dlp.example.com/api/v1/google-drive/callback
   ```
6. Click **Create**

### Step 2: Save Your Credentials

A dialog shows your **Client ID** and **Client Secret** — copy both now.

- **Client ID** looks like: `123456789-abc123def456.apps.googleusercontent.com`
- **Client Secret** looks like: `GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz`

**Security Note**: never commit these to version control. Store them in `.env` (already gitignored) or a
secrets manager.

---

## Environment Configuration

### Step 1: Locate the `.env` File

```bash
cd /path/to/Seceoknight-DLP
```

The `.env` file is in the project root (copy `.env.example` to `.env` if you haven't already).

### Step 2: Add Google Drive Configuration

```bash
# Google Drive OAuth Configuration
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=http://YOUR_SERVER_IP:55000/api/v1/google-drive/callback
```

### Step 3: Complete Example

```bash
# Google Drive OAuth Configuration
GOOGLE_CLIENT_ID=123456789-abc123def456.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz
GOOGLE_REDIRECT_URI=http://192.168.1.67:55000/api/v1/google-drive/callback
```

### Step 4: Verify Configuration

- No extra quotes or spaces around values
- `GOOGLE_REDIRECT_URI` matches the OAuth client's Authorized redirect URI **exactly**
- Client ID ends in `.apps.googleusercontent.com`

**Alternative — credentials.json file**: instead of the three env vars above, you can point
`GOOGLE_OAUTH_CREDENTIALS_PATH` at a Google-downloaded OAuth client JSON file (the same "Download JSON"
button on the Credentials page). See `GoogleDriveOAuthService._load_config_from_file()` in
`server/app/services/google_drive_oauth.py` for the exact shape it expects. The env-var approach above is
simpler for most deployments.

---

## Verify Setup

### Step 1: Deploy the New Configuration

```bash
cd /opt/seceoknight && sudo bash update.sh
```

`update.sh` force-recreates the `manager`, `celery-worker`, and `celery-beat` containers, which is what
actually picks up new `.env` values — editing `.env` alone does nothing until those containers restart.

### Step 2: Check Logs for Configuration Errors

```bash
docker compose -f docker-compose.prod.yml logs manager | grep -i "google"
docker compose -f docker-compose.prod.yml logs celery-beat | grep -i "google"
```

### Step 3: Test the OAuth Endpoint Directly

```bash
TOKEN=$(curl -s -X POST http://YOUR_SERVER_IP:55000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

curl -X POST http://YOUR_SERVER_IP:55000/api/v1/google-drive/connect \
  -H "Authorization: Bearer $TOKEN"
```

Expected response:
```json
{
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "state": "..."
}
```

If instead you get a 503 with `"Google OAuth is not configured..."`, the env vars weren't picked up — double
check they're in `.env` and that you actually ran `update.sh` (or restarted the `manager` container) after
adding them.

---

## Create Google Drive Policy

### Step 1: Access the Dashboard

```
http://YOUR_SERVER_IP:3000
```
(or wherever your dashboard is served — through nginx it may just be `https://YOUR_SERVER_IP`)

### Step 2: Navigate to Policies

1. Click **Policies** in the left sidebar
2. Click **Create Policy**

### Step 3: Select Policy Type

Find and select **Google Drive (Cloud)**.

### Step 4: Connect a Google Drive Account

1. Under **Google Drive Account**, click **Connect Account**
2. A popup opens with the Google sign-in flow
3. Sign in with the account you added as a Test user earlier
4. Review and accept the requested permissions (Drive read access, Drive Activity read access)
5. The popup closes automatically once authorized — the account now appears in the connection list

### Step 5: Select Protected Folders

1. Once a connection is selected, the folder browser appears
2. Navigate into the Drive folders you want monitored and select them
3. Selected folders show up in the "Selected Folders" list at the bottom, each with its own baseline
   timestamp — only activity **after** that baseline is picked up, so you won't get flooded with the
   folder's entire history on first connect

### Step 6: Configure Polling Interval

Pick 5/10/15/30/60 minutes, or a custom value. This is honored per-connection (the shortest interval across
all policies sharing that connection wins) — see the CHANGELOG entry "Google Drive (Cloud): audit + two
fixes" for how this is implemented.

### Step 7: Fill In Policy Details and Save

Name, description, severity, priority — same as any other policy. Save.

### Step 8: Verify

The policy should appear in the Active Policies list. Drop or edit a file in one of the selected Drive
folders, wait up to one polling interval, then check the Events tab for a `google_drive_cloud`-sourced
event, or trigger a poll immediately:

```bash
curl -X POST http://YOUR_SERVER_IP:55000/api/v1/google-drive/poll \
  -H "Authorization: Bearer $TOKEN"
```

---

## Troubleshooting

### OAuth Flow Issues

**Problem**: "redirect_uri_mismatch" error from Google

**Solution**: The URI in your OAuth client's "Authorized redirect URIs" must match `GOOGLE_REDIRECT_URI`
character-for-character — check `http` vs `https`, the port, and trailing slashes.

**Problem**: "Access blocked: this app's request is invalid" or "app hasn't completed verification"

**Solution**: If the OAuth consent screen is in Testing mode (the default for External apps), only accounts
listed as Test users can complete the flow. Add the account's email under OAuth consent screen → Test users.

**Problem**: Clicking "Connect Account" in the dashboard shows a generic "Failed to initiate connection" or
now shows the real reason (e.g. "Google OAuth is not configured...")

**Solution**: That real reason means `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`/`GOOGLE_REDIRECT_URI` aren't
set, or the deployment hasn't been restarted since they were added. Re-check `.env` and re-run `update.sh`.

### Configuration Issues

**Problem**: Server fails to start Google Drive polling, or `/google-drive/connect` always 503s

**Solution**: Verify all three env vars are set with no typos, then confirm the `manager` and `celery-beat`
containers were actually recreated (`update.sh` does this; a plain `docker compose restart` does NOT pick up
new `.env` values for some Compose configurations — force-recreate is safer).

### Polling Issues

**Problem**: No Google Drive events appearing after connecting and selecting folders

**Solution**:
1. Confirm Celery Beat is running: `docker compose -f docker-compose.prod.yml ps celery-beat`
2. Check its logs for the `google-drive-polling` task firing every 5 minutes:
   `docker compose -f docker-compose.prod.yml logs celery-beat | grep google_drive`
3. Confirm the folder's baseline isn't set to a future timestamp — use "Reset Selected Baseline" in the
   policy form to reset it to now, then generate new activity after that.
4. Remember: cloud events only get stored if they match at least one enabled policy's conditions
   (`GoogleDrivePollingService._persist_event` silently drops non-matching activity) — double-check the
   policy is enabled and the folder you're testing in is actually one of its protected folders.
5. Trigger a manual poll instead of waiting for the schedule:
   ```bash
   curl -X POST http://YOUR_SERVER_IP:55000/api/v1/google-drive/poll -H "Authorization: Bearer $TOKEN"
   ```

**Problem**: Changing "Polling Interval" in the UI doesn't seem to speed things up

**Solution**: The underlying Celery Beat tick is still every 5 minutes — a connection configured for, say,
30 minutes will still get *checked* every 5 minutes, but skips the actual Drive API call until 30 minutes
have actually elapsed since its last poll. So the effective cadence is right, but nothing will ever poll
*more often* than every 5 minutes even if you set a custom interval below that.

### Token / Permission Issues

**Problem**: "Connection lacks refresh token" or repeated re-authorization prompts

**Solution**: Google only issues a refresh token on the *first* consent with `prompt=consent` (which this
flow always requests) — if you previously revoked SeceoKnight's access from your Google Account's
[third-party access settings](https://myaccount.google.com/permissions) and reconnect without fully
disconnecting the old connection in SeceoKnight first, delete the stale connection
(`DELETE /api/v1/google-drive/connections/{id}`) and reconnect from scratch.

**Problem**: Polling fails with an auth/401 error partway through

**Solution**: The service auto-refreshes an expired access token using the stored refresh token
(`GoogleDrivePollingService.poll_connection` calls `is_token_expired()` / `refresh_access_token()`
automatically). If refresh itself fails, the refresh token was likely revoked externally — reconnect the
account.

---

## Quick Reference

### Environment Variables

```bash
GOOGLE_CLIENT_ID=<OAuth Client ID>
GOOGLE_CLIENT_SECRET=<OAuth Client Secret>
GOOGLE_REDIRECT_URI=http://YOUR_SERVER_IP:55000/api/v1/google-drive/callback
```

### API Endpoints

- **Connect**: `POST /api/v1/google-drive/connect`
- **Callback**: `GET /api/v1/google-drive/callback`
- **List Connections**: `GET /api/v1/google-drive/connections`
- **List Folders**: `GET /api/v1/google-drive/connections/{id}/folders`
- **Protected Folders**: `GET /api/v1/google-drive/connections/{id}/protected-folders`
- **Delete Connection**: `DELETE /api/v1/google-drive/connections/{id}`
- **Connection Status**: `GET /api/v1/google-drive/connections/{id}/status`
- **Update Baseline**: `POST /api/v1/google-drive/connections/{id}/baseline`
- **Manual Poll**: `POST /api/v1/google-drive/poll`

### Required OAuth Scopes

- `https://www.googleapis.com/auth/drive.readonly`
- `https://www.googleapis.com/auth/drive.metadata.readonly`
- `https://www.googleapis.com/auth/drive.activity.readonly`
- `https://www.googleapis.com/auth/userinfo.email`
- `https://www.googleapis.com/auth/userinfo.profile`
- `openid`

### Supported Operations

- ✅ File creation, modification, deletion, trash, restore
- ✅ File move, copy, download, share, comment
- ✅ Log + alert (severity determined by activity type, see `ACTION_MAP` in
  `server/app/services/google_drive_event_normalizer.py`)
- ❌ Block or quarantine (log-only — see Prerequisites above)

---

## Additional Resources

- [Google Drive API Documentation](https://developers.google.com/drive/api/guides/about-sdk)
- [Drive Activity API Documentation](https://developers.google.com/drive/activity/v2)
- [Google OAuth 2.0 for Web Server Applications](https://developers.google.com/identity/protocols/oauth2/web-server)

---

## Support

If you encounter issues not covered in this guide:

1. Review service logs: `docker compose -f docker-compose.prod.yml logs manager celery-beat`
2. Check `CHANGELOG.md` for known limitations and recent fixes to this integration
3. Verify your Google Cloud project has both Drive API and Drive Activity API enabled

---

**Last Updated**: September 11, 2026
**Version**: 1.0.0
