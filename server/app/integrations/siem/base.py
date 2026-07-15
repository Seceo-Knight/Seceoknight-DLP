"""
Base SIEM Connector
Abstract base class for all SIEM integrations
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum

from app.core.observability import StructuredLogger

logger = StructuredLogger(__name__)


class SIEMType(str, Enum):
    """Supported SIEM types"""
    ELK = "elk"
    SPLUNK = "splunk"
    QRADAR = "qradar"
    SENTINEL = "sentinel"
    WAZUH = "wazuh"
    SYSLOG = "syslog"
    CUSTOM = "custom"


class EventSeverity(str, Enum):
    """SIEM event severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SIEMConnector(ABC):
    """
    Abstract base class for SIEM connectors

    All SIEM integrations must implement these methods
    """

    def __init__(
        self,
        name: str,
        siem_type: SIEMType,
        host: str,
        port: int,
        use_ssl: bool = True,
        verify_certs: bool = True,
        **kwargs
    ):
        """
        Initialize SIEM connector

        Args:
            name: Human-readable name for this connector
            siem_type: Type of SIEM system
            host: SIEM hostname or IP
            port: SIEM port
            use_ssl: Use SSL/TLS connection
            verify_certs: Verify SSL certificates
            **kwargs: Additional connector-specific parameters
        """
        self.name = name
        self.siem_type = siem_type
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.verify_certs = verify_certs
        self.config = kwargs
        self.connected = False

    @abstractmethod
    async def connect(self) -> bool:
        """
        Establish connection to SIEM

        Returns:
            True if connection successful, False otherwise
        """
        pass

    @abstractmethod
    async def disconnect(self) -> bool:
        """
        Close connection to SIEM

        Returns:
            True if disconnect successful, False otherwise
        """
        pass

    @abstractmethod
    async def test_connection(self) -> Dict[str, Any]:
        """
        Test connectivity to SIEM

        Returns:
            Dictionary with test results
        """
        pass

    @abstractmethod
    async def send_event(
        self,
        event: Dict[str, Any],
        index: Optional[str] = None
    ) -> bool:
        """
        Send single event to SIEM

        Args:
            event: Event data dictionary
            index: Optional index/sourcetype

        Returns:
            True if sent successfully, False otherwise
        """
        pass

    @abstractmethod
    async def send_batch(
        self,
        events: List[Dict[str, Any]],
        index: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send batch of events to SIEM

        Args:
            events: List of event dictionaries
            index: Optional index/sourcetype

        Returns:
            Dictionary with batch results (success count, failures, etc.)
        """
        pass

    @abstractmethod
    async def query_events(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query events from SIEM

        Args:
            query: SIEM-specific query string
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum results to return

        Returns:
            List of matching events
        """
        pass

    @abstractmethod
    async def create_alert(
        self,
        alert_name: str,
        description: str,
        severity: EventSeverity,
        query: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create alert/rule in SIEM

        Args:
            alert_name: Name of the alert
            description: Alert description
            severity: Alert severity level
            query: Query that triggers alert
            **kwargs: Additional SIEM-specific parameters

        Returns:
            Dictionary with alert creation result
        """
        pass

    def format_dlp_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format DLP event for SIEM ingestion

        Args:
            event: Raw DLP event

        Returns:
            Formatted event dictionary
        """
        # Common event format (CEF-like structure)
        formatted = {
            "timestamp": event.get("timestamp", datetime.utcnow().isoformat()),
            "event_id": event.get("event_id"),
            "event_type": "dlp_incident",
            "source": "seceoknight_dlp",
            "severity": event.get("severity", "medium"),

            # Agent information
            "agent": {
                "id": event.get("agent_id"),
                "name": event.get("agent_name"),
                "hostname": event.get("hostname"),
                "ip": event.get("agent_ip"),
                "os": event.get("os")
            },

            # Event details
            "dlp": {
                "classification_type": event.get("classification_type"),
                "confidence": event.get("confidence"),
                "blocked": event.get("blocked", False),
                "policy_id": event.get("policy_id"),
                "policy_name": event.get("policy_name"),
                "rule_id": event.get("rule_id")
            },

            # User information
            "user": {
                "username": event.get("username"),
                "domain": event.get("domain"),
                "email": event.get("user_email")
            },

            # Network information
            "network": {
                "source_ip": event.get("source_ip"),
                "destination_ip": event.get("destination_ip"),
                "destination_host": event.get("destination_host"),
                "destination_country": event.get("destination_country")
            },

            # File information (if applicable)
            "file": {
                "name": event.get("file_name"),
                "path": event.get("file_path"),
                "size": event.get("file_size"),
                "hash": event.get("file_hash"),
                "type": event.get("file_type")
            },

            # Actions taken
            "actions": event.get("actions", []),

            # Additional metadata
            "metadata": event.get("metadata", {})
        }

        # Remove empty nested dictionaries
        formatted = self._remove_empty_dicts(formatted)

        return formatted

    def _remove_empty_dicts(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """Remove nested dictionaries that are empty or contain only None values"""
        if not isinstance(d, dict):
            return d

        cleaned = {}
        for key, value in d.items():
            if isinstance(value, dict):
                nested = self._remove_empty_dicts(value)
                if nested and any(v is not None for v in nested.values()):
                    cleaned[key] = nested
            elif value is not None:
                cleaned[key] = value

        return cleaned

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on SIEM connection

        Returns:
            Health check results
        """
        try:
            test_result = await self.test_connection()

            return {
                "name": self.name,
                "siem_type": self.siem_type.value,
                "status": "healthy" if test_result.get("success") else "unhealthy",
                "connected": self.connected,
                "host": self.host,
                "port": self.port,
                "test_result": test_result,
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.log_error(e, {
                "operation": "health_check",
                "siem": self.name
            })

            return {
                "name": self.name,
                "siem_type": self.siem_type.value,
                "status": "error",
                "connected": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    def get_info(self) -> Dict[str, Any]:
        """
        Get connector information

        Returns:
            Connector details
        """
        return {
            "name": self.name,
            "siem_type": self.siem_type.value,
            "host": self.host,
            "port": self.port,
            "use_ssl": self.use_ssl,
            "connected": self.connected,
            "config_keys": list(self.config.keys())
        }
