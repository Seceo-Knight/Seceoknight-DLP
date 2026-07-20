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
| `RELAY_TLS_CERT_FILE` / `RELAY_TLS_KEY_FILE` | PEM cert + key for **inbound** STARTTLS (in-container paths, e.g. `/certs/fullchain.pem`). Unset = plaintext listener only. See [TLS](#tls-inbound-starttls) below — needed before exposing this relay to the public internet. |
| `RELAY_REQUIRE_STARTTLS` | `true` = reject any command before STARTTLS is negotiated. Only meaningful with the cert/key above set. Default `false`. |

## TLS (inbound STARTTLS)
Whoever connects to this relay from the public internet (Google's outbound
gateway, Microsoft's connector) should not do so in cleartext — the whole
point of this relay is protecting sensitive mail, so the mail itself
shouldn't cross the internet unencrypted to reach it.

1. Get a certificate for the relay's public hostname. The standard free
   option is [Let's Encrypt](https://letsencrypt.org/) via `certbot`:
   ```bash
   sudo certbot certonly --standalone -d relay.yourdomain.com
   # produces /etc/letsencrypt/live/relay.yourdomain.com/{fullchain.pem,privkey.pem}
   ```
   `--standalone` needs port 80 reachable from the internet during issuance
   (and renewal) — if that's not possible on your network, use certbot's
   `--dns-<provider>` plugin (DNS-01 challenge) instead, which doesn't need
   any inbound port open at all.
2. Point the compose volume at that directory and set the env vars in `.env`:
   ```
   RELAY_TLS_CERT_DIR=/etc/letsencrypt/live/relay.yourdomain.com
   RELAY_TLS_CERT_FILE=/certs/fullchain.pem
   RELAY_TLS_KEY_FILE=/certs/privkey.pem
   RELAY_REQUIRE_STARTTLS=true
   ```
3. `docker compose -f docker-compose.prod.yml up -d smtp-relay` and check the
   logs for `STARTTLS enabled (cert=..., required=True)`.
4. Let's Encrypt certs expire every 90 days — `certbot renew` (cron/systemd
   timer) handles renewal; the relay picks up the renewed file on its next
   restart (it doesn't hot-reload the cert while running).

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
   - **If the server is on-prem / behind a firewall** (not a cloud VM with its
     own public IP): you need a static public IP from your ISP (or Dynamic
     DNS if not), a NAT/port-forward or Virtual IP rule on your firewall
     mapping an external port to the relay container's port (`10025` by
     default, or `RELAY_HOST_PORT`), and a firewall policy permitting that
     inbound traffic. Google lets you specify **any port** in the Hosts
     config below — if your ISP blocks inbound port 25 (common), forward a
     different external port (e.g. `2525`) instead; Google will still
     connect to it fine.
   - Check whether port 25 inbound is actually reachable before relying on
     it: [mxtoolbox.com/SuperTool.aspx](https://mxtoolbox.com/SuperTool.aspx)
     (SMTP test) from outside your network, or ask your ISP directly.
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
