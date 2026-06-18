# OneDrive Integration Setup Guide

**Updated:** December 2024  
**Version:** 1.0.0

Complete step-by-step guide for setting up OneDrive cloud monitoring in SeceoKnight DLP.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Azure App Registration](#azure-app-registration)
3. [Configure API Permissions](#configure-api-permissions)
4. [Create Client Secret](#create-client-secret)
5. [Environment Configuration](#environment-configuration)
6. [Verify Setup](#verify-setup)
7. [Create OneDrive Policy](#create-onedrive-policy)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Microsoft account (Personal or Microsoft 365)
- Azure Portal access ([portal.azure.com](https://portal.azure.com))
- SeceoKnight DLP server running and accessible
- Admin access to configure environment variables

**Important Notes:**
- File download detection requires a Microsoft 365 subscription
- Personal OneDrive accounts can monitor: file creation, modification, deletion, and movement
- Free Microsoft accounts work for basic monitoring

---

## Azure App Registration

### Step 1: Access Azure Portal

1. Go to [Azure Portal](https://portal.azure.com/)
2. Sign in with your Microsoft account
3. If you don't have an Azure account, you can create one for free

### Step 2: Navigate to App Registrations

1. In the Azure Portal, search for **"Azure Active Directory"** or **"Microsoft Entra ID"** in the top search bar
2. Click on **Azure Active Directory** (or **Microsoft Entra ID**)
3. In the left sidebar, click **App registrations**
4. Click **+ New registration** button at the top

### Step 3: Register New Application

Fill in the registration form:

1. **Name**: 
   - Enter: `SeceoKnight DLP` (or any name you prefer)
   - This is for your reference only

2. **Supported account types**:
   - **Recommended**: Select **"Accounts in any organizational directory and personal Microsoft accounts"**
     - This allows both personal and work/school accounts
   - **Alternative options**:
     - **"Personal Microsoft accounts only"** - Only personal accounts
     - **"Accounts in this organizational directory only"** - Only your organization's accounts

3. **Redirect URI**:
   - Platform: Select **Web**
   - URI: `http://YOUR_SERVER_IP:55000/api/v1/onedrive/callback`
   - **Replace `YOUR_SERVER_IP`** with:
     - Your server's IP address (e.g., `YOUR_SERVER_IP`)
     - Or `localhost` if testing locally
     - Or your domain name if using a domain
   
   **Example URIs:**
   ```
   http://YOUR_SERVER_IP:55000/api/v1/onedrive/callback
   http://localhost:55000/api/v1/onedrive/callback
   http://dlp.example.com:55000/api/v1/onedrive/callback
   ```

4. Click **Register**

### Step 4: Save Application Details

After registration, you'll see the **Overview** page:

1. **Copy the Application (client) ID**:
   - This is your `ONEDRIVE_CLIENT_ID`
   - Format: `12345678-abcd-1234-abcd-123456789abc`
   - Save this somewhere safe

2. **Copy the Directory (tenant) ID**:
   - This is your `ONEDRIVE_TENANT_ID`
   - Usually `common` for multi-tenant apps
   - Or a GUID like `12345678-abcd-1234-abcd-123456789abc`
   - Save this as well

---

## Configure API Permissions

### Step 1: Add Microsoft Graph Permissions

1. In your app registration, click **API permissions** in the left sidebar
2. You'll see default permissions (usually just `User.Read`)
3. Click **+ Add a permission**

### Step 2: Select Microsoft Graph

1. In the "Request API permissions" panel:
   - Select **Microsoft Graph**
   - Choose **Delegated permissions** (not Application permissions)

### Step 3: Add Required Permissions

Add the following permissions one by one:

1. **Files.Read**
   - Description: "Read user files"
   - Click **Add permissions**

2. **Files.Read.All**
   - Description: "Read all files that the user can access"
   - Click **Add permissions**

3. **User.Read**
   - Description: "Sign in and read user profile"
   - Usually already added by default

4. **Sites.Read.All** (Optional, for SharePoint)
   - Description: "Read items in all site collections"
   - Only needed if monitoring SharePoint sites

### Step 4: Grant Admin Consent

**Important**: Admin consent may be required depending on your account type.

1. Click **Grant admin consent for [Your Organization]**
   - If you see this button, click it
   - This grants permissions for all users in your organization
   - For personal accounts, this step may not be required

2. Verify permissions show **"Granted for [Your Organization]"** or **"Granted for [Your Name]"**

**Note**: If admin consent is not available:
- Users will be prompted to consent during the OAuth flow
- This is normal for personal Microsoft accounts

---

## Create Client Secret

### Step 1: Navigate to Certificates & Secrets

1. In your app registration, click **Certificates & secrets** in the left sidebar
2. Click **+ New client secret**

### Step 2: Create Secret

1. **Description**: 
   - Enter: `SeceoKnight DLP Secret` (or any description)
   - This is for your reference

2. **Expires**:
   - **Recommended**: 24 months (for production)
   - **Testing**: Never (expires in 2 years, but easier for testing)
   - **Production**: 12 or 24 months (follow your security policy)

3. Click **Add**

### Step 3: Copy Secret Value

**CRITICAL**: Copy the secret **Value** immediately!

1. The secret value will be displayed only once
2. **Copy the entire value** (looks like: `abc~DEF123ghi456JKL789mno012PQR345stu678`)
3. Save it securely - you'll need it for the `.env` file
4. If you lose it, you'll need to create a new secret

**Security Note**: 
- Never commit secrets to version control
- Store secrets securely (password manager, secure notes, etc.)
- Rotate secrets periodically

---

## Environment Configuration

### Step 1: Locate .env File

Navigate to your SeceoKnight DLP project directory:

```bash
cd /path/to/Data-Loss-Prevention
```

The `.env` file should be in the root directory.

### Step 2: Add OneDrive Configuration

Open `.env` file and add the following variables:

```bash
# OneDrive OAuth Configuration
ONEDRIVE_CLIENT_ID=your-application-client-id-here
ONEDRIVE_CLIENT_SECRET=your-client-secret-value-here
ONEDRIVE_TENANT_ID=consumers  # Use "consumers" for personal accounts, "common" for both, or tenant ID for org accounts
ONEDRIVE_REDIRECT_URI=http://YOUR_SERVER_IP:55000/api/v1/onedrive/callback
```

### Step 3: Replace Placeholder Values

Replace the following:

1. **`your-application-client-id-here`**:
   - Replace with your **Application (client) ID** from Azure Portal
   - Example: `12345678-abcd-1234-abcd-123456789abc`

2. **`your-client-secret-value-here`**:
   - Replace with your **Client Secret Value** from Azure Portal
   - Example: `abc~DEF123ghi456JKL789mno012PQR345stu678`

3. **`YOUR_SERVER_IP`**:
   - Replace with your server IP address or domain
   - Must match the redirect URI in Azure app registration exactly
   - Examples:
     - `YOUR_SERVER_IP` (local network)
     - `localhost` (local testing)
     - `dlp.example.com` (domain)

4. **`ONEDRIVE_TENANT_ID`**:
   - **For Personal Microsoft Accounts**: Use `consumers` (required to avoid SPO license errors)
   - **For Work/School Accounts**: Use `organizations` or your specific tenant ID
   - **For Both Types**: Use `common` (may cause SPO license errors with personal accounts)
   
   **Important**: If you're using a free personal Microsoft account, you MUST use `consumers` as the tenant ID to avoid "Tenant does not have a SPO license" errors.

### Step 4: Complete Example

Here's a complete example `.env` configuration:

```bash
# OneDrive OAuth Configuration (Personal Account Example)
ONEDRIVE_CLIENT_ID=12345678-abcd-1234-abcd-123456789abc
ONEDRIVE_CLIENT_SECRET=abc~DEF123ghi456JKL789mno012PQR345stu678
ONEDRIVE_TENANT_ID=consumers  # Required for personal accounts to avoid SPO license errors
ONEDRIVE_REDIRECT_URI=http://YOUR_SERVER_IP:55000/api/v1/onedrive/callback
```

### Step 5: Verify Configuration

Double-check:
- ✅ No extra spaces or quotes around values
- ✅ Redirect URI matches Azure app registration exactly
- ✅ Client ID and Secret are correct
- ✅ Tenant ID is appropriate for your use case

---

## Verify Setup

### Step 1: Restart Services

Restart the SeceoKnight DLP services to load new environment variables:

```bash
docker-compose restart manager celery-worker celery-beat
```

Or if using docker compose (v2):

```bash
docker compose restart manager celery-worker celery-beat
```

### Step 2: Check Service Logs

Verify services started without errors:

```bash
# Check manager logs
docker-compose logs manager | tail -20

# Check for OneDrive configuration errors
docker-compose logs manager | grep -i onedrive
```

### Step 3: Test OAuth Endpoint

Test that the OAuth endpoint is accessible:

```bash
# Get auth token first (if needed)
TOKEN=$(curl -s -X POST http://localhost:55000/api/v1/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

# Test OneDrive connect endpoint
curl -X POST http://localhost:55000/api/v1/onedrive/connect \
  -H "Authorization: Bearer $TOKEN"
```

Expected response:
```json
{
  "auth_url": "https://login.microsoftonline.com/...",
  "state": "..."
}
```

If you see an error, check:
- Environment variables are set correctly
- Services are restarted
- No typos in `.env` file

---

## Create OneDrive Policy

### Step 1: Access Dashboard

1. Open your browser and navigate to:
   ```
   http://YOUR_SERVER_IP:3000
   ```

2. Log in with your credentials (default: `admin`/`admin`)

### Step 2: Navigate to Policies

1. Click **Policies** in the left sidebar
2. Click **Create Policy** button

### Step 3: Select Policy Type

1. In Step 1 (Select Policy Type):
   - Find and click **"OneDrive (Cloud)"**
   - Click **Next**

### Step 4: Connect OneDrive Account

1. In Step 2 (Configure Policy):
   - Scroll to **"OneDrive Account"** section
   - Click **"Connect Account"** button
   - A popup window will open

2. **Complete OAuth Flow**:
   - Sign in with your Microsoft account
   - Review permissions requested by SeceoKnight DLP
   - Click **Accept** or **Allow** to grant permissions
   - The popup will close automatically after successful authentication

3. **Verify Connection**:
   - You should see your Microsoft account email displayed
   - Connection status should show as active

### Step 5: Select Protected Folders

1. Scroll to **"Protected Folders"** section
2. Use the folder browser to navigate your OneDrive:
   - Click folder names to navigate into them
   - Use breadcrumbs to navigate back
   - Check boxes to select folders to protect

3. **Select Folders**:
   - Click the checkbox next to folders you want to monitor
   - Or click **"Select This Folder"** button for the current folder
   - Selected folders will appear in the summary below

### Step 6: Configure Policy Settings

1. **Basic Information**:
   - **Policy Name**: Enter a descriptive name (e.g., "OneDrive Sensitive Files")
   - **Description**: Optional description
   - **Severity**: Choose severity level (Low, Medium, High, Critical)
   - **Priority**: Set priority number (lower = higher priority)

2. **Polling Interval**:
   - Select how often to check for changes (default: 10 minutes)
   - Options: 5, 10, 15, 30, 60 minutes, or Custom

3. **Status**:
   - **Enabled**: Toggle to enable/disable the policy

### Step 7: Review and Save

1. Click **Next** to go to Step 3 (Review)
2. Review your policy configuration
3. Click **Save Policy**

### Step 8: Verify Policy Created

1. You should see the policy in the **Active Policies** table
2. Status should show as **Enabled**
3. Connection should show your Microsoft account email

---

## Troubleshooting

### OAuth Flow Issues

**Problem**: "Redirect URI mismatch" error

**Solution**:
- Verify redirect URI in `.env` exactly matches Azure app registration
- Check for:
  - Protocol mismatch (`http://` vs `https://`)
  - Port number differences
  - Trailing slashes
  - IP address vs domain name mismatch

**Problem**: "Application not found" error

**Solution**:
- Verify `ONEDRIVE_CLIENT_ID` is correct
- Check tenant ID matches your account type
- Ensure app registration exists in the correct Azure AD tenant

**Problem**: OAuth popup doesn't open

**Solution**:
- Check browser popup blocker settings
- Verify `auth_url` is returned from `/onedrive/connect` endpoint
- Check browser console for JavaScript errors

### Configuration Issues

**Problem**: Services fail to start

**Solution**:
- Check `.env` file syntax (no extra quotes, correct format)
- Verify all required variables are set:
  - `ONEDRIVE_CLIENT_ID`
  - `ONEDRIVE_CLIENT_SECRET`
  - `ONEDRIVE_TENANT_ID`
  - `ONEDRIVE_REDIRECT_URI`
- Check logs: `docker-compose logs manager`

**Problem**: "No access token available" error

**Solution**:
- Verify OAuth flow completed successfully
- Check connection exists in database
- Try disconnecting and reconnecting the account

### Polling Issues

**Problem**: No events appearing

**Solution**:
1. Check Celery worker logs:
   ```bash
   docker-compose logs celery-worker | grep -i onedrive
   ```

2. Verify protected folders are configured:
   - Check policy has selected folders
   - Verify folders exist in OneDrive

3. Check baseline timestamps:
   - Reset baseline if too old
   - Ensure baseline is set correctly

4. Trigger manual poll:
   ```bash
   curl -X POST http://localhost:55000/api/v1/onedrive/poll \
     -H "Authorization: Bearer $TOKEN"
   ```

**Problem**: Duplicate events

**Solution**:
- Reset baseline for affected folders
- Verify delta tokens are being stored correctly
- Check event IDs are deterministic

**Problem**: Polling not running

**Solution**:
1. Verify Celery Beat is running:
   ```bash
   docker-compose ps celery-beat
   ```

2. Check Celery Beat logs:
   ```bash
   docker-compose logs celery-beat
   ```

3. Verify schedule configuration:
   - Default: every 5 minutes
   - Check `server/app/tasks/reporting_tasks.py`

### API Permission Issues

**Problem**: "Insufficient privileges" error

**Solution**:
- Verify API permissions are granted in Azure Portal
- Check admin consent is granted (if required)
- Ensure permissions include:
  - `Files.Read`
  - `Files.Read.All`
  - `User.Read`

**Problem**: "Access denied" when listing folders

**Solution**:
- Verify user has access to the folders
- Check API permissions are correct
- Try refreshing the access token

### Token Refresh Issues

**Problem**: Token refresh fails

**Solution**:
- Verify client secret hasn't expired
- Check refresh token is stored correctly
- Ensure MSAL library is properly configured
- Check network connectivity to Microsoft endpoints

### Graph API Issues

**Problem**: Rate limiting errors (429)

**Solution**:
- Reduce polling frequency
- Check for excessive API calls
- Implement exponential backoff (already handled in code)

**Problem**: Invalid folder ID errors

**Solution**:
- Verify folder IDs are correct
- Check folders haven't been deleted
- Re-select folders in policy configuration

### Hybrid Detection Issues

**Problem**: File modifications still showing as create+delete

**Solution**:
1. Verify Redis is running:
   ```bash
   docker-compose ps redis
   docker-compose logs redis | tail -20
   ```

2. Check Redis connectivity:
   ```bash
   docker-compose exec redis redis-cli ping
   # Should return: PONG
   ```

3. Check file state storage:
   ```bash
   docker-compose exec redis redis-cli
   KEYS onedrive:file_state:*
   # Should show stored file states
   ```

4. Verify Redis configuration in `.env`:
   ```bash
   REDIS_HOST=localhost
   REDIS_PORT=6379
   REDIS_PASSWORD=your_password
   REDIS_DB=0
   ```

5. Check manager logs for Redis warnings:
   ```bash
   docker-compose logs manager | grep -i "redis\|file_state"
   ```

**Problem**: "Redis not available" warnings in logs

**Solution**:
- System will fall back to delta-only mode (still functional)
- Fix Redis connectivity to enable hybrid detection:
  - Check Redis container is running
  - Verify Redis password in `.env` matches container
  - Check network connectivity between manager and Redis
  - Restart manager after fixing Redis: `docker-compose restart manager`

**Problem**: Modifications not detected for old files

**Solution**:
- File state is only stored after first poll
- Old files modified before first poll may not have state in Redis
- System will still detect modifications, but may need to fetch metadata
- Subsequent modifications will be accurately detected

---

## Quick Reference

### Environment Variables

```bash
ONEDRIVE_CLIENT_ID=<Azure Application (client) ID>
ONEDRIVE_CLIENT_SECRET=<Azure Client Secret Value>
ONEDRIVE_TENANT_ID=common
ONEDRIVE_REDIRECT_URI=http://YOUR_SERVER_IP:55000/api/v1/onedrive/callback
```

### API Endpoints

- **Connect**: `POST /api/v1/onedrive/connect`
- **Callback**: `GET /api/v1/onedrive/callback`
- **List Connections**: `GET /api/v1/onedrive/connections`
- **List Folders**: `GET /api/v1/onedrive/connections/{id}/folders`
- **Protected Folders**: `GET /api/v1/onedrive/connections/{id}/protected-folders`
- **Update Baseline**: `POST /api/v1/onedrive/connections/{id}/baseline`
- **Manual Poll**: `POST /api/v1/onedrive/poll`

### How Hybrid Modification Detection Works

**Problem:** Microsoft Graph API delta queries sometimes report file modifications as "created" + "deleted" events instead of a single "updated" event. This causes the system to show file creation and deletion instead of file modification when a user adds text to an existing file.

**Solution:** Hybrid approach combining delta API with file metadata comparison:

1. **Delta API for Deletions & Creations:**
   - Uses delta API as-is for reliable `changeType="deleted"` and `changeType="created"` events
   - These change types are accurate and don't need verification

2. **Metadata Comparison for Modifications:**
   - When delta reports `changeType="updated"`: Fetches current file metadata (ETag, version, lastModifiedDateTime) from Graph API
   - Compares current ETag with stored ETag in Redis
   - If ETag changed → Real modification (logs as `file_modified`)
   - If ETag same but timestamp changed → Metadata-only change (still logs as `file_modified`)

3. **Suspected Modification Detection:**
   - When delta reports `changeType="created"` but file_id exists in Redis → Treats as suspected modification
   - Fetches current metadata and compares with stored state
   - If ETag changed → Confirmed modification (logs as `file_modified`)
   - If ETag same → Treats as creation (might be re-upload)

4. **File State Storage:**
   - Stores file state in Redis: `onedrive:file_state:{connection_id}:{file_id}`
   - State includes: ETag, lastModifiedDateTime, version
   - 90-day TTL for automatic cleanup
   - State removed when file is deleted

5. **Graceful Fallback:**
   - If Redis is unavailable, falls back to delta-only mode
   - Logs warning but continues operation
   - No data loss, just reduced modification detection accuracy

**Benefits:**
- ✅ Accurately detects file modifications instead of showing create+delete pairs
- ✅ Handles historical modifications correctly
- ✅ No performance degradation in normal operation
- ✅ Gracefully handles Redis unavailability

### Required Azure Permissions

- `Files.Read` (Delegated)
- `Files.Read.All` (Delegated)
- `User.Read` (Delegated)

### Supported Operations

- ✅ File creation
- ✅ File modification (with hybrid detection - uses Redis + ETag comparison)
- ✅ File deletion
- ✅ File movement/renaming
- ❌ File downloads (requires M365 subscription)

### Hybrid Modification Detection

**Problem:** Microsoft Graph API delta queries sometimes report file modifications as "created" + "deleted" events instead of a single "updated" event. This causes the system to show file creation and deletion instead of file modification when a user adds text to an existing file.

**Solution:** Hybrid approach combining delta API with file metadata comparison:

1. **Delta API for Deletions & Creations:** Uses delta API as-is for reliable `changeType="deleted"` and `changeType="created"` events
2. **Metadata Comparison for Modifications:** 
   - When delta reports "updated" OR when a file previously seen appears as "created", verifies by comparing file state
   - Stores file state in Redis: `onedrive:file_state:{connection_id}:{file_id}` with ETag, version, lastModifiedDateTime
   - Compares current ETag with stored ETag to detect real modifications
   - If ETag changed → Real modification
   - If ETag same but timestamp changed → Metadata-only change (still logged as modification)

**Benefits:**
- Accurately detects file modifications instead of showing create+delete pairs
- Handles historical modifications correctly
- Gracefully falls back to delta-only mode if Redis is unavailable
- No performance degradation in normal operation

**Requirements:**
- Redis must be running (for file state storage)
- If Redis is unavailable, system falls back to delta-only mode (logs warning)

---

## Additional Resources

- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/overview)
- [Azure App Registration Guide](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- [MSAL Python Documentation](https://msal-python.readthedocs.io/)
- [OneDrive API Reference](https://docs.microsoft.com/en-us/onedrive/developer/rest-api/)

---

## Support

If you encounter issues not covered in this guide:

1. Check the main [INSTALLATION_GUIDE.md](./INSTALLATION_GUIDE.md)
2. Review service logs: `docker-compose logs`
3. Verify Azure app registration configuration
4. Check Microsoft Graph API status

---

**Last Updated**: December 25, 2025  
**Version**: 1.1.0

**Recent Updates:**
- Added hybrid modification detection using Redis + ETag comparison (December 25, 2025)
- Fixes issue where file modifications were shown as create+delete pairs


