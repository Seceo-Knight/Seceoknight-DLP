# SeceoKnight DLP — Email DLP (SMTP relay)

Blocks outbound email carrying sensitive data. Every attachment (**pdf, docx,
xlsx, pptx, csv, txt, …**) *and* the message body is extracted to text,
classified by the existing DLP engine, and the message is **rejected before it
leaves** if it contains Confidential/Restricted content.

Because enforcement happens in the **mail flow** (not in a client), it covers
**every** sender — Gmail web, mobile, Thunderbird, Outlook — with one hook, and
**it works the same way regardless of which mail platform your organization
runs**. The relay is a plain SMTP server; it doesn't know or care whether the
mail arrived via Google Workspace or Microsoft 365 — it only needs to sit in
the outbound path. See the routing section below for whichever platform
applies: [Google Workspace](#google-workspace-routing-the-deployment-step) or
[Microsoft 365 / Exchange Online](#microsoft-365--exchange-online-routing-the-deployment-step).

| Classification | Outcome | Events |
|---|---|---|
| Public | forwarded | `email_send_allowed` (log) |
| Internal | forwarded | `email_send_internal` (alert) |
| Confidential / Restricted | **`550` rejected** | `email_send_attempt` + `email_send_prevented` |

## How it works
```
any client ──> your mail platform ──(outbound connector/gateway)──> DLP SMTP relay
  (Gmail web,     (Google Workspace                                  │ parse MIME
   Outlook,        or Microsoft 365 /                                │ extract text (pdf/docx/xlsx/csv/txt)
   Thunderbird,    Exchange Online)                                  │ POST /policy/evaluate  (existing classifier+policy)
   mobile, ...)                                       reject 550 ◀───┤ Confidential/Restricted
                                                                      └──> next hop ──> recipient
```
A `550` at DATA is a **true block**: the sending MTA never receives a `250`, so
the message is not delivered and the sender gets a bounce.

The relay holds **no** classification logic — it calls the same
`/agents/{id}/policy/evaluate` every other channel uses, so policy stays in one
place. It's a small standalone image (no ML stack).

## Configuration (env)
| Var | Purpose |
|---|---|
| `DLP_SERVER_URL` | Manager API, e.g. `http://manager:55000/api/v1` |
| `RELAY_AGENT_ID` / `RELAY_AGENT_KEY` | A registered agent's id + `X-Agent-Key` (the relay authenticates as an agent) |
| `RELAY_NEXT_HOP_HOST/_PORT/_USER/_PASS/_STARTTLS` | Where clean mail goes next (e.g. `smtp-relay.gmail.com:587`). **Unset = accept but don't deliver (test mode only).** |
| `RELAY_HOST_PORT` | Host port to publish (default `10025`) |
| `RELAY_BLOCK_UNEXTRACTABLE` | `true` = reject mail whose attachments can't be read (encrypted zip, scanned-image PDF, legacy `.doc`). Safer, but bounces some legit mail. Default `false`. |
| `RELAY_BLOCK_ON_DLP_ERROR` | `true` = fail **closed** if the DLP server is unreachable. Default `false` (a DLP outage must not stop company mail). |
| `RELAY_SCAN_BODY` | Scan the message body too (default `true`). |

Add to `.env`:
```
RELAY_AGENT_ID=<a registered agent id>
RELAY_AGENT_KEY=<that agent's X-Agent-Key>
RELAY_NEXT_HOP_HOST=smtp-relay.gmail.com
RELAY_NEXT_HOP_PORT=587
```
Then: `docker compose up -d smtp-relay`

## Google Workspace routing (the deployment step)
1. **Make the relay reachable from Google.** Google's outbound gateway connects
   *to* your relay over the internet — it needs a public DNS name/IP, the SMTP
   port open, and (strongly recommended) TLS. ⚠️ This is the main infra
   prerequisite; an internal-only host will not work.
2. **Admin console** → *Apps → Google Workspace → Gmail → Hosts* → add your
   relay host (name/IP + port).
3. *Gmail → Routing* → **Outbound gateway** (or a Routing rule scoped to
   outbound) → select the host you added.
4. **SPF**: because mail now egresses via the relay/next hop, include it in the
   domain's SPF record or downstream MTAs will mark it as a forgery.
5. Set `RELAY_NEXT_HOP_HOST` so accepted mail is actually delivered
   (`smtp-relay.gmail.com` is the usual choice; it requires the sending IP to be
   allow-listed under *Gmail → Routing → SMTP relay service*).

## Microsoft 365 / Exchange Online routing (the deployment step)
Same idea as Google Workspace above — Exchange calls this a **Connector**
routed through a **smart host** instead of an "outbound gateway," and needs a
mail flow rule to actually apply it to outbound internet mail (Exchange Online
otherwise sends external mail directly).

1. **Make the relay reachable from Microsoft 365.** Same prerequisite as
   Google: a public DNS name/IP, the SMTP port open, and TLS strongly
   recommended. ⚠️ An internal-only host will not work.
2. **Exchange admin center** → *Mail flow → Connectors* → **Add a connector**.
   - **Connection from**: `Office 365`
   - **Connection to**: `Partner organization`
3. On the routing page, choose **Route email through these smart hosts** and
   enter the relay's FQDN or IP (same value as the Google `Hosts` entry above).
4. Set the connector's scope to your outbound internet traffic — either
   **all accepted domains** for a blanket policy, or scope it with a **mail
   flow rule** (transport rule) matching "the recipient is located → Outside
   the organization" so only mail actually leaving your org routes through
   the relay (internal mail between your own users doesn't need DLP-relay
   inspection the same way).
5. Under **Security restrictions**, enable **Always use TLS** if the relay
   presents a certificate (recommended).
6. **SPF**: same as Google — once mail egresses via the relay/next hop,
   include it in the domain's SPF record or downstream MTAs will flag it as a
   forgery.
7. Set `RELAY_NEXT_HOP_HOST` so accepted mail is actually delivered onward —
   for Microsoft 365 environments this is typically your tenant's own inbound
   endpoint (`<tenant>-com.mail.protection.outlook.com`) if mail is looping
   back through Exchange Online, or your real next-hop smarthost otherwise.

Exact menu labels shift between Microsoft's "new" and "classic" Exchange admin
center — if a step doesn't match what you see, search Exchange admin center
help for "connectors" and "mail flow rules"; the underlying two settings
(smart host + scope-to-outbound-mail rule) are what matter.

## Test
```bash
# from a shell that can reach the relay
python3 - <<'EOF'
import smtplib
from email.message import EmailMessage
m = EmailMessage()
m["From"]="you@company.com"; m["To"]="outsider@example.com"; m["Subject"]="test"
m.set_content("Card: 4111 1111 1111 1111  SSN: 456-78-1234")   # sensitive
with smtplib.SMTP("<relay-host>", 10025) as s: s.send_message(m)
EOF
# expect: smtplib.SMTPDataError 550 ... blocked by SeceoKnight DLP
```
Clean mail returns `250`. Blocked mail produces `email_send_attempt` +
`email_send_prevented` events in the dashboard.

## Limitations
- **Encrypted / password-protected attachments** can't be read. Default is to
  allow them; set `RELAY_BLOCK_UNEXTRACTABLE=true` to reject instead.
- **Scanned-image PDFs** have no text layer (no OCR here) → not classifiable.
- **Legacy `.doc`/`.xls`/`.ppt`** (OLE) aren't parsed — flagged unreadable.
- **Archives (zip/7z)** aren't expanded yet.
- Only mail that actually **routes through this relay** is inspected — mail
  sent by a client or path that bypasses the outbound gateway/connector
  (Google Workspace) or connector/mail-flow-rule (Microsoft 365) is not.
