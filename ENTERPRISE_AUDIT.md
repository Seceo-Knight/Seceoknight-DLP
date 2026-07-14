# SeceoKnight DLP — Enterprise-Grade Audit Report
_Audited against Symantec DLP 16 / Microsoft Purview DLP benchmark_
_Date: June 2026 — updated July 14, 2026_

> **Update (July 14, 2026):** A re-verification pass found this report was stale on
> three points. MFA (TOTP) was already fully implemented and wired end-to-end
> (backend + dashboard) — it was never actually missing. Native browser
> file-upload detection also already existed (`network_exfil_monitor.cpp`'s
> `BrowserDetectorThread`, backed by the `Detect Browser Upload` policy) and
> was miscategorized as absent. ML/NLP classification (spaCy NER + TF-IDF/SGD
> classifier) had been fully built as `app/services/ml_classification.py` and
> `app/services/context_analyzer.py`, with the Docker image already installing
> spaCy — but the integration into `ClassificationEngine.classify_content()`
> had only ever been left as an unapplied "how to integrate" instructions file
> (`classification_engine_ml_patch.py`) with no real caller. That wiring has
> now been completed (gated behind `FEATURE_ML_CLASSIFICATION`, with a 200ms
> timeout fallback to rule-only scoring). Email DLP was re-verified and
> confirmed still genuinely absent — that finding below stands.

> **Correction (same day, July 14, 2026):** The "No OCR" finding above was
> also wrong, and this report repeated the mistake in its own first
> revision — the earlier re-verification pass only grepped the Python
> server (`server/app`) and missed the C++ Windows agent entirely. Real,
> working Tesseract OCR already existed there: `agent.cpp`'s screen-capture
> classifier captures the foreground window's pixels, shells out to
> `tesseract.exe`, and blocks the screenshot in real time if the recognized
> text is sensitive — with `install-agent.ps1` Step 4 already auto-installing
> Chocolatey + Tesseract on every endpoint. What genuinely *was* missing was
> that this OCR path only covered screen captures — file writes/saves, USB
> transfers, and clipboard image paste had no OCR coverage. That gap has now
> been closed (see Agent Platform below); OCR is removed from the gaps list
> entirely. **Caveat:** the new file/USB/clipboard OCR code has not been
> compiled or run on a real Windows machine — verify on an actual endpoint
> before shipping to production.

---

## Summary Score

| Domain | Score | Grade |
|---|---|---|
| Authentication & Authorization | 9 / 10 | A− |
| Network Security | 9 / 10 | A |
| Detection Engine | 7 / 10 | B |
| Agent Platform | 8 / 10 | B+ |
| Audit & Compliance | 7 / 10 | B |
| Incident Response | 7 / 10 | B |
| High Availability | 4 / 10 | D |
| SIEM & Observability | 8 / 10 | A− |
| **OVERALL** | **7.4 / 10** | **B+** |

**Verdict: Mid-market enterprise ready, and closer to Fortune-500 / regulated-industry ready than previously assessed. HA and SSO remain the main blockers.**

---

## ✅ What Is Already Enterprise-Grade

### Authentication & Authorization
- **JWT with refresh tokens** — short-lived access tokens (1h) + long-lived refresh tokens with Redis blacklisting on logout. This is the correct pattern.
- **bcrypt password hashing** — `CryptContext(schemes=["bcrypt"])`. Industry standard.
- **MFA (TOTP)** — full `pyotp`-based two-factor flow: QR-code enrollment (`/auth/mfa/setup`), verified activation (`/auth/mfa/verify-setup`), a short-lived single-use bridge token gating login until the 6-digit code is validated (`/auth/mfa/validate`), Fernet-encrypted secret at rest, and a dashboard Settings tab for setup/disable. Wired end-to-end, not a stub.
- **RBAC** — role hierarchy `ADMIN (3) > MANAGER/ANALYST/THREAT_ADMIN/DATA_PROTECTION_ADMIN/ACCESS_CONTROL_ADMIN (2) > VIEWER (1)`, plus domain-scoped admin roles (Threat, Data Protection, Access Control) so each admin only sees policies/events/incidents tagged to their domain. Enforced via `require_role()` on every sensitive endpoint.
- **ABAC** — department + clearance level predicate, emitted in both SQL and MongoDB dialects so they stay in sync. Spec-compliant null-deny behavior.
- **IP allowlisting** — admin-managed CIDR allowlist middleware on the portal (fail-open when empty; agent/health endpoints always exempt).
- **Rate limiting** — per-IP Redis-backed middleware, 100 req/60s default. Prevents API abuse.
- **Token blacklisting** — refresh tokens are invalidated on logout with correct TTL. Prevents session reuse after sign-out.
- **CORS strict allowlist** — `CORS_ORIGINS` must be set explicitly; no wildcard default.

### Network Security
- **TLS everywhere** — Nginx terminates TLS (Let's Encrypt). Manager and databases are internal-only; zero host ports exposed.
- **`no-new-privileges` on all containers** — prevents privilege escalation via setuid binaries.
- **No database ports exposed to host** — PostgreSQL, MongoDB, Redis, OpenSearch all on internal Docker network only.
- **Resource limits on every container** — CPU and memory caps prevent runaway containers from taking down the host.

### Detection Engine (Server-side)
- **Multi-signal classification** — keyword matching + regex + entropy + fingerprinting with weighted scoring.
- **ML/NLP classification** — spaCy NER + TF-IDF/SGD sensitivity classifier now wired into `ClassificationEngine.classify_content()` (`FEATURE_ML_CLASSIFICATION`, 200ms timeout with graceful fallback to rule-only). Blended 50% rule / 30% ML / 20% context-adjustment, with a false-positive hard-cap so context-flagged content (test files, documentation, known example values) doesn't trigger blocking actions.
- **Context-aware false-positive reduction** — `ContextAnalyzer` distinguishes "SSN format: XXX-XX-XXXX" (documentation) from "My SSN is 123-45-6789" (real violation) using phrase-window analysis, known-test-value matching, and test-file path detection.
- **Shannon entropy analysis** — detects encrypted/compressed data (≥7.5 bits → Restricted), base64/obfuscated (≥6.5 → Confidential). Cannot be bypassed by renaming a file.
- **SHA-256 file fingerprinting** — exact-match document identification via `FingerprintService`. Admins can register known sensitive documents and any copy is flagged.
- **Celery async processing** — events are processed off the request path; API stays responsive under load.
- **Data retention / cleanup** — dashboard-managed retention policy (event + index retention) with a hard 90-day compliance floor enforced at both API and DB (CHECK constraint) levels; scheduled Celery task purges accordingly.
- **Threat intelligence (STIX 2.1 / TAXII 2.1)** — poll external IOC feeds, manual/CSV/STIX import, and an outbound TAXII sharing server for publishing DLP-derived indicators to partners.

### Agent Platform (Windows)
- **Kernel minifilter architecture** — `csfilter.sys` at altitude 370100 intercepts file I/O, USB events, clipboard, print, and screen capture at kernel level. Cannot be bypassed by user-mode software.
- **Multi-channel coverage** — file operations, USB device lifecycle, clipboard, screen capture, print jobs, network exfiltration, and browser file-upload selection (see below).
- **Browser upload detection** — `NetworkExfilMonitor::BrowserDetectorThread` (UI Automation hooks on Chrome/Edge/Firefox) detects file-selection in browser upload dialogs, classifies the selected file, and emits `channel=BROWSER` / `event_subtype=browser_file_selection` events; backed by the seeded `Detect Browser Upload` policy. Detection + alert only (cannot inspect the HTTPS payload itself — TLS terminates in the browser — that would require a browser extension; see minor gaps below).
- **Real-time Tesseract OCR** — the foreground-window screen-capture classifier OCRs on-screen content and blocks the screenshot before it happens if sensitive data is detected (`install-agent.ps1` auto-installs Chocolatey + Tesseract on every endpoint). As of July 14, 2026 the same OCR path also covers file writes/saves, USB file transfers, and clipboard image paste (raster images only — `.png/.jpg/.jpeg/.bmp/.tiff/.gif`; multi-page scanned PDFs would need a bundled PDF rasterizer and remain unconverted). *Not yet compiled/tested on a real Windows machine — verify before production use.*
- **Sub-10ms policy evaluation** — `PolicyEngine::Evaluate()` tracks atomic `evalCount_`, `evalTotalUs_`, `evalMaxUs_` with microsecond precision. Performance is measurable.
- **Agent auto-update** — binary checks GitHub SHA-256 every 5 minutes; downloads, verifies, and restarts automatically. No manual updates needed after initial deployment.
- **Fail-open kernel integration** — if `csfilter.sys` is not loaded, the agent continues in user-mode-only mode rather than crashing.
- **Linux agent exists** — `/agents/endpoint/linux/` with systemd service unit (note: no self-update loop — Windows-only capability today).

### Audit & Observability
- **Immutable audit log** — admin-only endpoint, date/user/action filterable. Every admin action and login is recorded.
- **Structured JSON logging** — `structlog` with ISO timestamps, stack traces, Unicode safety.
- **Prometheus metrics** — `http_requests_total`, histograms, gauges. Ready for Grafana dashboard.
- **SIEM connectors** — Splunk HEC and ELK/OpenSearch connectors with full event schema mapping.
- **Export** — CSV and PDF export of events/analytics for compliance reporting.

### Cloud Storage Scanning
- **OneDrive + Google Drive** — OAuth-integrated polling with Celery tasks. Detects sensitive content in cloud storage, not just endpoint activity.

### Incident Management
- **Incident lifecycle** — create → investigate → resolve → close with severity (0–4), assignment, and comment thread.
- **Automated incident creation** — policy violations auto-create incidents.

---

## ❌ Gaps — What Needs Work Before Claiming "Enterprise"

### 🔴 Critical Gaps

#### 1. No SAML/SSO / LDAP Integration
**What's missing:** Users are managed in local PostgreSQL only. No Active Directory, no Azure AD (Entra ID), no Okta. (There is a narrow `/auth/sso/exchange` endpoint, but it's a shared-secret HMAC token exchange scoped to SIEM integration — not a general enterprise IdP integration.)

**Enterprise standard:** Enterprises will not accept a tool that requires separate user management outside their IdP. This is a deal-breaker for mid-size and large organizations.

**Fix:** Add `python-saml` or `authlib` OIDC client. Map AD groups to RBAC roles. Approximately 1 week of work.

---

#### 2. Single-Node OpenSearch (No HA for Event Store)
**What's missing:** `docker-compose.prod.yml` sets `discovery.type=single-node`. If OpenSearch goes down, all event ingestion and querying stops. There is no replica, no failover.

**Enterprise standard:** Production deployments require at minimum a 3-node OpenSearch cluster with 1 replica shard.

**Fix:** Add two more OpenSearch nodes to docker-compose, set `discovery.seed_hosts`, `cluster.initial_cluster_manager_nodes`. Alternatively, use a managed OpenSearch service (AWS OpenSearch, Elastic Cloud).

---

#### 3. Single Manager Instance (No API HA)
**What's missing:** One `manager` container. If it crashes, all agents lose connection until Docker restarts it (up to 30s).

**Enterprise standard:** At least 2 manager replicas behind a load balancer.

**Fix:** `deploy: replicas: 2` in docker-compose + sticky sessions in Nginx for WebSocket connections, or use Kubernetes with a Deployment of 2+ replicas.

---

### 🟡 Important Gaps

#### 4. JWT Uses HS256 (Symmetric, Not RS256)
**What's missing:** `JWT_ALGORITHM=HS256` means the signing secret must be shared with every service that validates tokens. In a distributed setup this is a security risk — any compromised service can forge tokens.

**Enterprise standard:** RS256 (asymmetric) — private key signs, public key verifies. Services only need the public key.

**Fix:** Generate RSA key pair, switch `jwt.encode`/`jwt.decode` to RS256. Low risk, 1 day of work.

---

#### 5. No Email DLP (Content Inspection)
**What's missing:** `app/api/v1/email_settings.py` exists but is SMTP configuration for *outbound alert notifications* only (e.g., emailing an admin when a policy fires) — it does not inspect the content of users' outbound email. There is no Exchange Online / Gmail API integration comparable to the existing OneDrive/Google Drive cloud-storage scanners. Confirmed genuinely absent on re-audit.

**Enterprise standard:** Symantec DLP and Purview both scan outbound email content (subject, body, attachments) before send.

**Fix:** Add a Microsoft Graph (Exchange Online) and Gmail API connector following the same OAuth-polling pattern as `onedrive_polling.py` / `google_drive_polling.py`, running attachments and body text through `ClassificationEngine`. Roughly the same scope as the OneDrive integration, ~1–2 weeks.

---

#### 6. Fingerprinting Is Exact Match Only (No Fuzzy/Partial)
**What's missing:** `FingerprintService` only does exact SHA-256 match. If a user copies 3 paragraphs from a sensitive document into a new file, the hash won't match.

**Enterprise standard:** Symantec DLP's IDM (Indexed Document Matching) does partial-match fingerprinting on document chunks.

**Fix:** Implement chunk-based fingerprinting — split documents into 500-byte overlapping windows, hash each chunk, store chunk hashes. Match if ≥30% of chunks in a candidate file appear in the fingerprint database. About 3–5 days.

---

#### 7. No Field-Level Encryption at Rest
**What's missing:** PII in PostgreSQL (user emails, SIDs, device IDs) and event content in MongoDB is stored in plaintext (at the application level). Database-level encryption is not configured in docker-compose.

**Enterprise standard:** HIPAA and PCI-DSS require encryption of PII/cardholder data at rest.

**Fix (quick):** Enable MongoDB Encrypted Storage Engine or PostgreSQL `pgcrypto` for sensitive columns. Enable OpenSearch index encryption. These are configuration changes, not code changes.

---

#### 8. No Compliance Report Templates
**What's missing:** The export endpoint produces raw event CSVs. There are no pre-built GDPR Article 30 records-of-processing reports, HIPAA breach notification templates, or PCI DSS scope reports.

**Enterprise standard:** Purview ships 150+ compliance templates out of the box.

**Fix:** Add a `reporting_service` that assembles events, policies, and users into named compliance report formats. About 1 week.

---

### 🟢 Minor Gaps

#### 9. No macOS Agent
The Linux agent exists but macOS (which many enterprise users run) has no agent. macOS requires `EndpointSecurity` framework (replaces deprecated `kauth`).

#### 10. No Browser Extension (Content-Level)
Native file-selection detection for browser uploads already exists (see Agent Platform above) and alerts on which file a user picked in a Chrome/Edge/Firefox upload dialog. What's still missing is inspecting the actual upload *payload* — TLS terminates inside the browser process, so the kernel driver can't see it. A browser extension (WebExtensions API, intercepting `fetch`/`XMLHttpRequest`/`FormData` before encryption) would close that remaining gap, e.g. redacting/blocking based on content rather than just filename.

#### 11. Kernel Driver Not Production-Code-Signed
`csfilter.sys` currently runs in test-signing mode only. For production deployment it must be EV code-signed and submitted to Microsoft for attestation signing (WHCP). This is a process step, not a code change, but costs ~$300/year for an EV certificate.

---

## Priority Action Plan

| Priority | Item | Effort | Impact |
|---|---|---|---|
| P0 | Add SSO/SAML / Azure AD | 1 week | Required by most enterprises |
| P0 | OpenSearch HA (3-node cluster) | 1 day config | Eliminates single point of failure |
| P1 | Manager replica (2 instances) | 1 day | API HA |
| P1 | Switch JWT to RS256 | 1 day | Distributed security |
| P1 | Chunk-based fingerprinting | 1 week | Catches partial document copies |
| P1 | Build + test new agent OCR code on real Windows | 1–2 days | Verifies the July 14 file/USB/clipboard OCR wiring before production |
| P2 | Scanned-PDF OCR (needs a bundled PDF rasterizer) | 3–5 days | Extends OCR beyond raster images to multi-page PDF scans |
| P2 | Email DLP (Exchange/Gmail content scan) | 1–2 weeks | Closes email exfiltration channel |
| P2 | Field-level DB encryption | 2 days | HIPAA/PCI-DSS compliance |
| P2 | Compliance report templates | 1 week | Enterprise compliance reporting |
| P3 | macOS agent | 3–4 weeks | macOS endpoint coverage |
| P3 | Browser extension (content-level) | 2–3 weeks | Payload-level web upload coverage |
| P3 | EV code signing for driver | Process | Production kernel driver deployment |

~~Add MFA (TOTP)~~ and ~~Add NLP/ML classifier~~ — both already done; see the July 14, 2026 update note above.

---

## Bottom Line

SeceoKnight DLP is a solid, well-architected product, and stronger than the June 2026 version of this report gave it credit for. The core infrastructure (TLS, RBAC/ABAC with domain scoping, MFA, IP allowlisting, audit logs, SIEM integration, kernel minifilter, multi-channel detection including browser upload detection, ML-assisted classification, threat-intel sharing) is genuinely well-built and significantly ahead of most open-source DLP tools. The security posture of the server deployment (no exposed ports, resource limits, token blacklisting) is better than many commercial SMB products.

The main remaining gap is concentrated in two areas: **identity federation** (no enterprise SSO/SAML/LDAP — MFA is already solved) and **high availability** (single-node event store, single manager instance). Fixing the two P0 items (SSO + OpenSearch HA) would make this enterprise-deployable for organizations without strict regulated-industry requirements. Completing the P1 items (RS256, HA manager, chunk-based fingerprinting, and verifying the new agent OCR code on real Windows hardware) would bring it to the level of mid-market commercial DLP (Forcepoint, Digital Guardian). Scanned-PDF OCR, Email DLP content inspection, content-level browser extension coverage, and macOS support are what separates Symantec/Purview-tier from mid-market.
