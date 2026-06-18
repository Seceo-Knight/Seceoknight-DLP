"""
MongoDB Collection Schemas for DLP Events
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ClassificationResult(BaseModel):
    """Classification result for an event"""
    score: float = Field(..., ge=0.0, le=1.0)
    labels: List[str]
    method: str
    confidence: float = Field(..., ge=0.0, le=1.0)


class PolicyMatch(BaseModel):
    """Policy match information"""
    policy_id: str
    policy_name: str
    action: str
    severity: str


class DLPEventDocument(BaseModel):
    """Main DLP Event document structure"""
    id: str = Field(default_factory=lambda: f"evt-{datetime.utcnow().timestamp()}")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str  # file_access, network_transfer, clipboard, etc.
    source: str  # endpoint, network, cloud

    # User context
    user_id: Optional[str] = None
    user_email: str
    device_id: Optional[str] = None
    device_name: Optional[str] = None

    # Classification
    classification: ClassificationResult

    # Policy matching
    policy_matches: List[PolicyMatch] = []

    # Action taken
    action_taken: str  # allow, block, alert, quarantine
    blocked: bool = False

    # Event details
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    file_size: Optional[int] = None
    destination: Optional[str] = None
    protocol: Optional[str] = None

    # Content metadata
    content_type: Optional[str] = None
    entropy: Optional[float] = None

    # Audit trail
    processed_at: datetime = Field(default_factory=datetime.utcnow)
    wazuh_forwarded: bool = False

    class Config:
        json_schema_extra = {
            "example": {
                "id": "evt-1234567890",
                "timestamp": "2024-01-15T10:30:45Z",
                "event_type": "file_transfer",
                "source": "endpoint",
                "user_email": "john.doe@company.com",
                "classification": {
                    "score": 0.92,
                    "labels": ["PAN", "HIGH_ENTROPY"],
                    "method": "regex+ml",
                    "confidence": 0.88
                },
                "policy_matches": [
                    {
                        "policy_id": "pol-001",
                        "policy_name": "Block Credit Card",
                        "action": "block",
                        "severity": "critical"
                    }
                ],
                "action_taken": "block",
                "blocked": True,
                "file_path": "/home/user/export.csv",
                "destination": "external-server.com"
            }
        }


# MongoDB Indexes
EVENT_INDEXES = [
    [("timestamp", -1)],
    [("user_email", 1)],
    [("source", 1)],
    [("blocked", 1)],
    [("classification.labels", 1)],
    [("policy_matches.policy_id", 1)],
    [("wazuh_forwarded", 1)],
]
