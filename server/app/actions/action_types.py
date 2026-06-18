"""
Action Type Definitions and Result Models
"""

from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from datetime import datetime


class ActionType(str, Enum):
    """Supported action types"""
    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    REDACT = "redact"
    ENCRYPT = "encrypt"
    NOTIFY = "notify"
    WEBHOOK = "webhook"
    AUDIT = "audit"
    TAG = "tag"
    ESCALATE = "escalate"
    DELETE = "delete"
    PRESERVE = "preserve"
    FLAG_FOR_REVIEW = "flag_for_review"
    CREATE_INCIDENT = "create_incident"
    TRACK = "track"


class RedactionMethod(str, Enum):
    """Redaction methods"""
    FULL = "full"
    PARTIAL = "partial"
    MASK_EXCEPT_LAST4 = "mask_except_last4"
    MASK_EXCEPT_FIRST4 = "mask_except_first4"
    HASH = "hash"


class EncryptionAlgorithm(str, Enum):
    """Supported encryption algorithms"""
    AES_256 = "AES-256"
    AES_128 = "AES-128"
    RSA_2048 = "RSA-2048"
    RSA_4096 = "RSA-4096"


class NotificationChannel(str, Enum):
    """Notification channels"""
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    SMS = "sms"
    WEBHOOK = "webhook"
    SIEM = "siem"


class ActionResult(BaseModel):
    """Result of action execution"""
    action_type: ActionType
    success: bool
    message: Optional[str] = None
    metadata: Dict[str, Any] = {}
    timestamp: datetime = datetime.utcnow()
    error: Optional[str] = None


class AlertResult(ActionResult):
    """Alert action result"""
    alert_id: Optional[str] = None
    severity: str = "medium"
    title: Optional[str] = None
    description: Optional[str] = None


class BlockResult(ActionResult):
    """Block action result"""
    blocked: bool = True
    block_reason: Optional[str] = None


class QuarantineResult(ActionResult):
    """Quarantine action result"""
    quarantined: bool = False
    original_path: Optional[str] = None
    quarantine_path: Optional[str] = None
    encrypted: bool = False


class RedactResult(ActionResult):
    """Redaction action result"""
    redacted: bool = False
    method: RedactionMethod = RedactionMethod.FULL
    fields_redacted: List[str] = []


class EncryptResult(ActionResult):
    """Encryption action result"""
    encrypted: bool = False
    algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256
    key_id: Optional[str] = None


class NotifyResult(ActionResult):
    """Notification action result"""
    notified: bool = False
    channel: NotificationChannel = NotificationChannel.EMAIL
    recipients: List[str] = []
    notification_id: Optional[str] = None


class WebhookResult(ActionResult):
    """Webhook action result"""
    webhook_called: bool = False
    url: Optional[str] = None
    status_code: Optional[int] = None
    response: Optional[Dict[str, Any]] = None


class AuditResult(ActionResult):
    """Audit logging result"""
    audit_logged: bool = False
    audit_id: Optional[str] = None
    log_level: str = "detailed"
    retention_days: int = 365


class ExecutionSummary(BaseModel):
    """Summary of all actions executed"""
    event_id: str
    policy_id: str
    rule_id: str
    timestamp: datetime = datetime.utcnow()
    actions_executed: List[ActionResult] = []
    total_actions: int = 0
    successful_actions: int = 0
    failed_actions: int = 0
    blocked: bool = False
    quarantined: bool = False
    encrypted: bool = False
    redacted: bool = False
    notifications_sent: int = 0
    webhooks_called: int = 0
    alerts_created: int = 0
