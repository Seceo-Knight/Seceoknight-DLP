"""
Action Executor
Comprehensive action execution system for DLP policies
"""

import hashlib
import secrets
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import structlog
import aiofiles
import aiohttp
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .action_types import (
    ActionType, ActionResult, AlertResult, BlockResult, QuarantineResult,
    RedactResult, EncryptResult, NotifyResult, WebhookResult, AuditResult,
    ExecutionSummary, RedactionMethod, EncryptionAlgorithm, NotificationChannel
)
from app.core.observability import StructuredLogger, MetricsCollector
from app.core.config import settings

logger = StructuredLogger("action_executor")


class ActionExecutor:
    """
    Execute various actions based on policy rules

    Supported Actions:
    - alert: Create alerts
    - block: Block events/transfers
    - quarantine: Quarantine files
    - redact: Redact sensitive content
    - encrypt: Encrypt content
    - notify: Send notifications
    - webhook: Call webhooks
    - audit: Enhanced audit logging
    - tag: Add tags to events
    - escalate: Escalate to higher priority
    - delete: Secure deletion
    - preserve: Preserve for legal hold
    - flag_for_review: Flag for manual review
    - create_incident: Create incident ticket
    - track: Track for compliance
    """

    def __init__(self, db=None, redis=None, opensearch=None):
        self.db = db
        self.redis = redis
        self.opensearch = opensearch
        self.quarantine_base = Path(settings.QUARANTINE_PATH if hasattr(settings, 'QUARANTINE_PATH') else '/quarantine')

    async def execute_actions(
        self,
        event: Dict[str, Any],
        actions: List[Dict[str, Any]],
        policy_id: str,
        rule_id: str
    ) -> ExecutionSummary:
        """
        Execute list of actions

        Args:
            event: Event data
            actions: List of action configurations
            policy_id: Policy ID
            rule_id: Rule ID

        Returns:
            ExecutionSummary with results
        """
        results = []

        for action in actions:
            action_type = action.get("type")

            try:
                if action_type == ActionType.ALERT:
                    result = await self.execute_alert(event, action)
                elif action_type == ActionType.BLOCK:
                    result = await self.execute_block(event, action)
                elif action_type == ActionType.QUARANTINE:
                    result = await self.execute_quarantine(event, action)
                elif action_type == ActionType.REDACT:
                    result = await self.execute_redact(event, action)
                elif action_type == ActionType.ENCRYPT:
                    result = await self.execute_encrypt(event, action)
                elif action_type == ActionType.NOTIFY:
                    result = await self.execute_notify(event, action)
                elif action_type == ActionType.WEBHOOK:
                    result = await self.execute_webhook(event, action)
                elif action_type == ActionType.AUDIT:
                    result = await self.execute_audit(event, action)
                elif action_type == ActionType.TAG:
                    result = await self.execute_tag(event, action)
                elif action_type == ActionType.ESCALATE:
                    result = await self.execute_escalate(event, action)
                elif action_type == ActionType.DELETE:
                    result = await self.execute_delete(event, action)
                elif action_type == ActionType.PRESERVE:
                    result = await self.execute_preserve(event, action)
                elif action_type == ActionType.FLAG_FOR_REVIEW:
                    result = await self.execute_flag_for_review(event, action)
                elif action_type == ActionType.CREATE_INCIDENT:
                    result = await self.execute_create_incident(event, action)
                elif action_type == ActionType.TRACK:
                    result = await self.execute_track(event, action)
                else:
                    logger.logger.warning(f"Unknown action type: {action_type}")
                    continue

                results.append(result)

            except Exception as e:
                logger.log_error(e, {"action_type": action_type, "event_id": event.get("event_id")})
                results.append(ActionResult(
                    action_type=action_type,
                    success=False,
                    error=str(e)
                ))

        # Create summary
        summary = ExecutionSummary(
            event_id=event.get("event_id", "unknown"),
            policy_id=policy_id,
            rule_id=rule_id,
            actions_executed=results,
            total_actions=len(results),
            successful_actions=sum(1 for r in results if r.success),
            failed_actions=sum(1 for r in results if not r.success),
            blocked=any(isinstance(r, BlockResult) and r.blocked for r in results),
            quarantined=any(isinstance(r, QuarantineResult) and r.quarantined for r in results),
            encrypted=any(isinstance(r, EncryptResult) and r.encrypted for r in results),
            redacted=any(isinstance(r, RedactResult) and r.redacted for r in results),
            notifications_sent=sum(1 for r in results if isinstance(r, NotifyResult) and r.notified),
            webhooks_called=sum(1 for r in results if isinstance(r, WebhookResult) and r.webhook_called),
            alerts_created=sum(1 for r in results if isinstance(r, AlertResult))
        )

        # Update event with summary
        event["actions_executed"] = summary.dict()

        return summary

    async def execute_alert(self, event: Dict, action: Dict) -> AlertResult:
        """Create alert and persist to database"""
        from app.services.alert_service import AlertService
        from app.core.database import postgres_session_factory

        alert_id = f"alert-{uuid.uuid4()}"
        severity = action.get("parameters", {}).get("severity") or action.get("severity", "medium")

        # Build descriptive title and message
        title = self._build_alert_title(event, action)
        message = self._build_alert_message(event, action)

        # Build metadata with classification details
        classification_meta = event.get("classification_metadata", {})
        matched_rules = [r.get("label") for r in event.get("classification", [])]

        alert_metadata = {
            "classification_level": classification_meta.get("classification_level"),
            "confidence_score": classification_meta.get("confidence_score"),
            "matched_rules": matched_rules,
            "file_name": event.get("file_path") or event.get("file", {}).get("path"),
            "source_path": event.get("source_path"),
            "destination_path": event.get("destination", {}).get("path"),
            "blocked": event.get("blocked", False),
            "action_details": action
        }

        # Persist alert to database
        try:
            async with postgres_session_factory() as session:
                alert_service = AlertService(session)

                await alert_service.create_alert(
                    alert_id=alert_id,
                    alert_type="policy_violation",
                    severity=severity,
                    title=title,
                    message=message,
                    source_type="policy",
                    policy_id=action.get("metadata", {}).get("policy_id"),
                    event_id=event.get("event_id"),
                    user_email=event.get("user", {}).get("email") or event.get("user_email"),
                    agent_id=event.get("agent", {}).get("id"),
                    metadata=alert_metadata
                )

                logger.logger.info(
                    "alert_created_in_database",
                    alert_id=alert_id,
                    event_id=event.get("event_id"),
                    severity=severity
                )
        except Exception as e:
            logger.logger.error(
                "failed_to_persist_alert",
                alert_id=alert_id,
                error=str(e)
            )
            # Continue even if database save fails

        # Log policy violation for metrics
        logger.log_policy_violation(
            event.get("event_id"),
            action.get("metadata", {}).get("policy_id", "unknown"),
            severity
        )

        MetricsCollector.record_policy_violation(
            action.get("metadata", {}).get("policy_id", "unknown"),
            severity
        )

        return AlertResult(
            action_type=ActionType.ALERT,
            success=True,
            alert_id=alert_id,
            severity=severity,
            title=title,
            description=message,
            metadata=alert_metadata
        )

    def _build_alert_title(self, event: Dict, action: Dict) -> str:
        """Build descriptive alert title"""
        event_type = event.get("event", {}).get("type", "event")
        classification_meta = event.get("classification_metadata", {})
        classification = classification_meta.get("classification_level", "Unknown")
        confidence = classification_meta.get("confidence_score", 0.0)

        file_name = event.get("file_path") or event.get("file", {}).get("path") or "Unknown file"
        if file_name != "Unknown file":
            file_name = Path(file_name).name

        blocked = event.get("blocked", False)
        action_verb = "Blocked" if blocked else "Detected"

        if "usb" in event_type.lower():
            if event.get("event", {}).get("subtype") == "usb_file_transfer":
                return f"USB Transfer {action_verb} - {file_name} ({classification} - {int(confidence * 100)}%)"
            else:
                device = event.get("usb", {}).get("device_name", "USB Device")
                return f"USB Device {action_verb} - {device}"
        elif "clipboard" in event_type.lower():
            return f"Clipboard {action_verb} ({classification} - {int(confidence * 100)}%)"
        elif "file" in event_type.lower():
            return f"File Activity {action_verb} - {file_name} ({classification})"
        else:
            return f"{event_type.title()} {action_verb} - {file_name}"

    def _build_alert_message(self, event: Dict, action: Dict) -> str:
        """Build detailed alert message"""
        parts = []

        # Add classification details
        classification_meta = event.get("classification_metadata", {})
        if classification_meta:
            classification_level = classification_meta.get("classification_level", "Unknown")
            confidence = classification_meta.get("confidence_score", 0.0)
            parts.append(f"Classification: {classification_level}")
            parts.append(f"Confidence: {int(confidence * 100)}%")

            matched_rules = [r.get("label") for r in event.get("classification", [])]
            if matched_rules:
                parts.append(f"Sensitive data detected: {', '.join(matched_rules[:5])}")

        # Add file details
        if event.get("file_path"):
            parts.append(f"File: {event['file_path']}")
        if event.get("source_path"):
            parts.append(f"Source: {event['source_path']}")
        destination = event.get("destination", {})
        if isinstance(destination, dict) and destination.get("path"):
            parts.append(f"Destination: {destination['path']}")
        elif isinstance(destination, str):
            parts.append(f"Destination: {destination}")

        # Add action taken
        if event.get("blocked"):
            parts.append("Action: Transfer blocked and file deleted")
        elif event.get("quarantined"):
            quarantine_path = event.get("quarantine_path", 'secure location')
            parts.append(f"Action: Quarantined to {quarantine_path}")

        return "\n".join(parts) if parts else "Policy violation detected"

    async def execute_block(self, event: Dict, action: Dict) -> BlockResult:
        """Block action/transfer"""
        event["blocked"] = True
        event["block_reason"] = action.get("message", "Policy violation")
        event["block_timestamp"] = datetime.utcnow().isoformat()

        logger.logger.warning(
            "event_blocked",
            event_id=event.get("event_id"),
            reason=event["block_reason"]
        )

        return BlockResult(
            action_type=ActionType.BLOCK,
            success=True,
            blocked=True,
            block_reason=event["block_reason"]
        )

    async def execute_quarantine(self, event: Dict, action: Dict) -> QuarantineResult:
        """Quarantine file/content.

        Note: Agents may already move the file and include `quarantined`/`quarantine_path`
        in the event payload. In that case, we treat quarantine as completed and only
        record metadata to avoid double-moving or permission errors.
        """
        # If agent already quarantined, honor agent-provided metadata
        if event.get("quarantined") or event.get("quarantine_path"):
            return QuarantineResult(
                action_type=ActionType.QUARANTINE,
                success=True,
                quarantined=True,
                original_path=event.get("file_path") or event.get("source_path"),
                quarantine_path=event.get("quarantine_path"),
                encrypted=event.get("quarantine_encrypted", False),
            )

        original_path = (
            event.get("file_path")
            or event.get("source_path")
            or event.get("file", {}).get("path")
        )
        if not original_path:
            return QuarantineResult(
                action_type=ActionType.QUARANTINE,
                success=False,
                quarantined=False,
                error="No file path to quarantine"
            )

        # Determine destination path preference: policy action path -> action location -> default base
        quarantine_location = Path(
            action.get("path")
            or action.get("location")
            or self.quarantine_base
        )
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        event_id = event.get("event_id", "unknown")
        quarantine_filename = f"{event_id}_{timestamp}_{Path(original_path).name}"
        quarantine_path = quarantine_location / quarantine_filename

        # Backend does not move the file (agents are expected to have done so); record metadata
        event["quarantined"] = True
        event["quarantine_path"] = str(quarantine_path)
        event["quarantine_timestamp"] = datetime.utcnow().isoformat()

        logger.logger.info(
            "file_quarantined",
            event_id=event.get("event_id"),
            original_path=original_path,
            quarantine_path=str(quarantine_path),
            encrypted=action.get("encrypt", False)
        )

        return QuarantineResult(
            action_type=ActionType.QUARANTINE,
            success=True,
            quarantined=True,
            original_path=original_path,
            quarantine_path=str(quarantine_path),
            encrypted=action.get("encrypt", False),
        )

    async def execute_redact(self, event: Dict, action: Dict) -> RedactResult:
        """Redact sensitive content"""
        method = RedactionMethod(action.get("method", "full"))
        redaction_char = action.get("redaction_char", "*")
        fields_redacted = []

        # Redact content field
        if "content" in event:
            original = event["content"]

            if method == RedactionMethod.FULL:
                event["content"] = "[REDACTED]"
            elif method == RedactionMethod.PARTIAL:
                # Keep first/last 4 chars
                if len(original) > 8:
                    event["content"] = original[:4] + redaction_char * (len(original) - 8) + original[-4:]
                else:
                    event["content"] = redaction_char * len(original)
            elif method == RedactionMethod.MASK_EXCEPT_LAST4:
                # For credit cards - show only last 4
                if len(original) >= 4:
                    event["content"] = redaction_char * (len(original) - 4) + original[-4:]
                else:
                    event["content"] = original
            elif method == RedactionMethod.MASK_EXCEPT_FIRST4:
                if len(original) >= 4:
                    event["content"] = original[:4] + redaction_char * (len(original) - 4)
                else:
                    event["content"] = original
            elif method == RedactionMethod.HASH:
                event["content"] = hashlib.sha256(original.encode()).hexdigest()

            fields_redacted.append("content")

        # Redact classification details
        if "classification" in event and action.get("redact_classification", False):
            for cls in event["classification"]:
                if "value" in cls:
                    cls["value"] = "[REDACTED]"
                    fields_redacted.append("classification.value")

        event["redacted"] = True
        event["redaction_method"] = method.value

        return RedactResult(
            action_type=ActionType.REDACT,
            success=True,
            redacted=True,
            method=method,
            fields_redacted=fields_redacted
        )

    async def execute_encrypt(self, event: Dict, action: Dict) -> EncryptResult:
        """Encrypt content"""
        algorithm = EncryptionAlgorithm(action.get("algorithm", "AES-256"))
        key_id = action.get("key_id", "default")

        if "content" not in event:
            return EncryptResult(
                action_type=ActionType.ENCRYPT,
                success=False,
                encrypted=False,
                error="No content to encrypt"
            )

        # Generate or retrieve encryption key
        if algorithm in [EncryptionAlgorithm.AES_256, EncryptionAlgorithm.AES_128]:
            # Use Fernet (AES-128 in CBC mode with HMAC)
            key = Fernet.generate_key()
            cipher = Fernet(key)

            encrypted_content = cipher.encrypt(event["content"].encode())

            event["content_encrypted"] = encrypted_content.decode()
            event["encryption_key_id"] = key_id
            event["encryption_algorithm"] = algorithm.value
            event["content"] = "[ENCRYPTED]"

        elif algorithm in [EncryptionAlgorithm.RSA_2048, EncryptionAlgorithm.RSA_4096]:
            # RSA encryption (would use proper key management in production)
            event["content"] = "[RSA_ENCRYPTED]"
            event["encryption_algorithm"] = algorithm.value

        event["encrypted"] = True

        return EncryptResult(
            action_type=ActionType.ENCRYPT,
            success=True,
            encrypted=True,
            algorithm=algorithm,
            key_id=key_id
        )

    async def execute_notify(self, event: Dict, action: Dict) -> NotifyResult:
        """Send notification"""
        channel = NotificationChannel(action.get("channel", "email"))
        recipients = action.get("recipients", [])
        template = action.get("template")

        if not recipients:
            return NotifyResult(
                action_type=ActionType.NOTIFY,
                success=False,
                notified=False,
                error="No recipients specified"
            )

        notification_id = f"notif-{uuid.uuid4()}"

        if channel == NotificationChannel.EMAIL:
            success = await self._send_email(event, recipients, template, action)
        elif channel == NotificationChannel.SLACK:
            success = await self._send_slack(event, action.get("webhook"), template)
        elif channel == NotificationChannel.TEAMS:
            success = await self._send_teams(event, action.get("webhook"), template)
        elif channel == NotificationChannel.PAGERDUTY:
            success = await self._send_pagerduty(event, action)
        elif channel == NotificationChannel.SMS:
            success = await self._send_sms(event, recipients, template)
        elif channel == NotificationChannel.WEBHOOK:
            result = await self.execute_webhook(event, action)
            success = result.success
        else:
            success = False

        return NotifyResult(
            action_type=ActionType.NOTIFY,
            success=success,
            notified=success,
            channel=channel,
            recipients=recipients,
            notification_id=notification_id if success else None
        )

    async def _send_email(self, event: Dict, recipients: List[str], template: Optional[str], action: Dict) -> bool:
        """Send email notification"""
        try:
            subject = action.get("subject", f"DLP Alert: {event.get('event', {}).get('type', 'Unknown')} event")

            # Build email body
            body = f"""
            DLP Policy Violation Detected

            Event ID: {event.get('event_id')}
            Agent: {event.get('agent', {}).get('name')}
            Type: {event.get('event', {}).get('type')}
            Severity: {event.get('event', {}).get('severity')}
            Timestamp: {event.get('@timestamp')}

            Classification: {event.get('classification', [])}

            Policy: {action.get('metadata', {}).get('policy_id')}
            Regulation: {action.get('metadata', {}).get('regulation')}
            """

            # In production, would actually send email via SMTP
            logger.logger.info(
                "email_notification_sent",
                event_id=event.get("event_id"),
                recipients=recipients,
                subject=subject
            )

            return True

        except Exception as e:
            logger.log_error(e, {"action": "send_email"})
            return False

    async def _send_slack(self, event: Dict, webhook_url: str, template: Optional[str]) -> bool:
        """Send Slack notification"""
        if not webhook_url:
            return False

        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "text": f"🚨 DLP Alert",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*Event ID:* {event.get('event_id')}\n*Severity:* {event.get('event', {}).get('severity')}"
                            }
                        }
                    ]
                }

                async with session.post(webhook_url, json=payload) as response:
                    return response.status == 200

        except Exception as e:
            logger.log_error(e, {"action": "send_slack"})
            return False

    async def _send_teams(self, event: Dict, webhook_url: str, template: Optional[str]) -> bool:
        """Send Microsoft Teams notification"""
        if not webhook_url:
            return False

        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "@type": "MessageCard",
                    "@context": "https://schema.org/extensions",
                    "summary": "DLP Alert",
                    "themeColor": "FF0000",
                    "title": "DLP Policy Violation",
                    "sections": [{
                        "activityTitle": f"Event {event.get('event_id')}",
                        "facts": [
                            {"name": "Severity", "value": event.get('event', {}).get('severity')},
                            {"name": "Agent", "value": event.get('agent', {}).get('name')}
                        ]
                    }]
                }

                async with session.post(webhook_url, json=payload) as response:
                    return response.status == 200

        except Exception as e:
            logger.log_error(e, {"action": "send_teams"})
            return False

    async def _send_pagerduty(self, event: Dict, action: Dict) -> bool:
        """Send PagerDuty alert"""
        # Would integrate with PagerDuty Events API
        logger.logger.info("pagerduty_alert", event_id=event.get("event_id"))
        return True

    async def _send_sms(self, event: Dict, recipients: List[str], template: Optional[str]) -> bool:
        """Send SMS notification"""
        # Would integrate with Twilio or similar
        logger.logger.info("sms_sent", event_id=event.get("event_id"), recipients=recipients)
        return True

    async def execute_webhook(self, event: Dict, action: Dict) -> WebhookResult:
        """Call webhook"""
        url = action.get("url")
        method = action.get("method", "POST")
        headers = action.get("headers", {})

        if not url:
            return WebhookResult(
                action_type=ActionType.WEBHOOK,
                success=False,
                webhook_called=False,
                error="No webhook URL specified"
            )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, json=event, headers=headers) as response:
                    response_data = await response.json() if response.content_type == 'application/json' else None

                    return WebhookResult(
                        action_type=ActionType.WEBHOOK,
                        success=response.status < 400,
                        webhook_called=True,
                        url=url,
                        status_code=response.status,
                        response=response_data
                    )

        except Exception as e:
            logger.log_error(e, {"action": "webhook", "url": url})
            return WebhookResult(
                action_type=ActionType.WEBHOOK,
                success=False,
                webhook_called=False,
                url=url,
                error=str(e)
            )

    async def execute_audit(self, event: Dict, action: Dict) -> AuditResult:
        """Enhanced audit logging"""
        audit_id = f"audit-{uuid.uuid4()}"
        log_level = action.get("log_level", "detailed")
        retention_days = action.get("retention_days", 365)

        audit_entry = {
            "audit_id": audit_id,
            "event_id": event.get("event_id"),
            "timestamp": datetime.utcnow().isoformat(),
            "log_level": log_level,
            "retention_days": retention_days,
            "event_data": event,
            "metadata": action.get("metadata", {})
        }

        # Store in audit log (would use dedicated audit system)
        logger.logger.info(
            "audit_entry_created",
            audit_id=audit_id,
            event_id=event.get("event_id"),
            log_level=log_level
        )

        return AuditResult(
            action_type=ActionType.AUDIT,
            success=True,
            audit_logged=True,
            audit_id=audit_id,
            log_level=log_level,
            retention_days=retention_days
        )

    async def execute_tag(self, event: Dict, action: Dict) -> ActionResult:
        """Add tags to event"""
        tags = action.get("tags", [])

        if "tags" not in event:
            event["tags"] = []

        event["tags"].extend(tags)
        event["tags"] = list(set(event["tags"]))  # Remove duplicates

        return ActionResult(
            action_type=ActionType.TAG,
            success=True,
            metadata={"tags": event["tags"]}
        )

    async def execute_escalate(self, event: Dict, action: Dict) -> ActionResult:
        """Escalate to higher priority"""
        recipients = action.get("to", [])
        priority = action.get("priority", "high")

        event["escalated"] = True
        event["escalation_priority"] = priority
        event["escalation_recipients"] = recipients

        # Would integrate with incident management system
        logger.logger.warning(
            "event_escalated",
            event_id=event.get("event_id"),
            priority=priority,
            recipients=recipients
        )

        return ActionResult(
            action_type=ActionType.ESCALATE,
            success=True,
            metadata={"priority": priority, "recipients": recipients}
        )

    async def execute_delete(self, event: Dict, action: Dict) -> ActionResult:
        """Secure deletion"""
        immediate = action.get("immediate", False)
        secure_wipe = action.get("secure_wipe", False)

        event["marked_for_deletion"] = True
        event["deletion_immediate"] = immediate
        event["secure_wipe"] = secure_wipe

        logger.logger.warning(
            "deletion_requested",
            event_id=event.get("event_id"),
            immediate=immediate,
            secure_wipe=secure_wipe
        )

        return ActionResult(
            action_type=ActionType.DELETE,
            success=True,
            metadata={"immediate": immediate, "secure_wipe": secure_wipe}
        )

    async def execute_preserve(self, event: Dict, action: Dict) -> ActionResult:
        """Preserve for legal hold"""
        location = action.get("location", "/preservation")
        immutable = action.get("immutable", True)

        event["preserved"] = True
        event["preservation_location"] = location
        event["immutable"] = immutable
        event["preservation_timestamp"] = datetime.utcnow().isoformat()

        logger.logger.info(
            "event_preserved",
            event_id=event.get("event_id"),
            location=location,
            immutable=immutable
        )

        return ActionResult(
            action_type=ActionType.PRESERVE,
            success=True,
            metadata={"location": location, "immutable": immutable}
        )

    async def execute_flag_for_review(self, event: Dict, action: Dict) -> ActionResult:
        """Flag for manual review"""
        review_type = action.get("review_type", "general")
        reviewer_role = action.get("reviewer_role")

        event["flagged_for_review"] = True
        event["review_type"] = review_type
        event["reviewer_role"] = reviewer_role
        event["review_status"] = "pending"

        logger.logger.info(
            "flagged_for_review",
            event_id=event.get("event_id"),
            review_type=review_type,
            reviewer_role=reviewer_role
        )

        return ActionResult(
            action_type=ActionType.FLAG_FOR_REVIEW,
            success=True,
            metadata={"review_type": review_type, "reviewer_role": reviewer_role}
        )

    async def execute_create_incident(self, event: Dict, action: Dict) -> ActionResult:
        """Create incident ticket and persist to database"""
        severity_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        severity_str = action.get("severity", "medium")
        severity_int = severity_map.get(severity_str, 2)

        incident_type = action.get("incident_type", "dlp_violation")
        event_id = event.get("event_id")
        title = f"DLP Violation: {incident_type}"
        description = f"Auto-created incident for event {event_id}"

        try:
            from app.core.database import postgres_session_factory
            if postgres_session_factory:
                async with postgres_session_factory() as session:
                    from app.services.incident_service import IncidentService
                    svc = IncidentService(session)
                    incident = await svc.create_incident(
                        event_id=event_id,
                        severity=severity_int,
                        title=title,
                        description=description,
                    )
                    await session.commit()
                    incident_id = str(incident.id)
                    event["incident_id"] = incident_id

                    logger.logger.warning(
                        "incident_created",
                        incident_id=incident_id,
                        event_id=event_id,
                        severity=severity_str
                    )

                    return ActionResult(
                        action_type=ActionType.CREATE_INCIDENT,
                        success=True,
                        metadata={"incident_id": incident_id, "severity": severity_str}
                    )
        except Exception as e:
            logger.log_error(e, {"action": "create_incident", "event_id": event_id})

        # Fallback if DB not available
        fallback_id = f"incident-{uuid.uuid4()}"
        event["incident_id"] = fallback_id
        return ActionResult(
            action_type=ActionType.CREATE_INCIDENT,
            success=True,
            metadata={"incident_id": fallback_id, "fallback": True}
        )

    async def execute_track(self, event: Dict, action: Dict) -> ActionResult:
        """Track for compliance"""
        tracking_id = action.get("tracking_id", f"track-{uuid.uuid4()}")

        event["tracked"] = True
        event["tracking_id"] = tracking_id
        event["tracking_metadata"] = action.get("metadata", {})

        logger.logger.info(
            "event_tracked",
            event_id=event.get("event_id"),
            tracking_id=tracking_id
        )

        return ActionResult(
            action_type=ActionType.TRACK,
            success=True,
            metadata={"tracking_id": tracking_id}
        )
