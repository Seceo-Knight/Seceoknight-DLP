"""
SIEM Integration Service
Manages multiple SIEM connectors and provides unified interface
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import asyncio

from .base import SIEMConnector, SIEMType
from .elk_connector import ELKConnector
from .splunk_connector import SplunkConnector
from app.core.observability import StructuredLogger

logger = StructuredLogger(__name__)


class SIEMIntegrationService:
    """
    Service for managing multiple SIEM integrations

    Provides:
    - Multi-SIEM event forwarding
    - Health monitoring
    - Failover support
    - Batch processing
    """

    def __init__(self):
        """Initialize SIEM integration service"""
        self.connectors: Dict[str, SIEMConnector] = {}
        self.active_connectors: List[str] = []

    def register_connector(self, connector: SIEMConnector) -> bool:
        """
        Register a SIEM connector

        Args:
            connector: SIEM connector instance

        Returns:
            True if registered successfully
        """
        try:
            self.connectors[connector.name] = connector
            logger.logger.info("siem_connector_registered",
                              name=connector.name,
                              siem_type=connector.siem_type.value)
            return True

        except Exception as e:
            logger.log_error(e, {"operation": "register_connector"})
            return False

    def unregister_connector(self, name: str) -> bool:
        """
        Unregister a SIEM connector

        Args:
            name: Connector name

        Returns:
            True if unregistered successfully
        """
        try:
            if name in self.connectors:
                del self.connectors[name]
                if name in self.active_connectors:
                    self.active_connectors.remove(name)

                logger.logger.info("siem_connector_unregistered", name=name)
                return True

            return False

        except Exception as e:
            logger.log_error(e, {"operation": "unregister_connector"})
            return False

    async def connect_all(self) -> Dict[str, bool]:
        """
        Connect to all registered SIEM systems

        Returns:
            Dictionary mapping connector names to connection status
        """
        results = {}

        for name, connector in self.connectors.items():
            try:
                success = await connector.connect()
                results[name] = success

                if success:
                    if name not in self.active_connectors:
                        self.active_connectors.append(name)
                else:
                    if name in self.active_connectors:
                        self.active_connectors.remove(name)

            except Exception as e:
                logger.log_error(e, {
                    "operation": "connect_all",
                    "connector": name
                })
                results[name] = False

        logger.logger.info("siem_connect_all_completed",
                          total=len(self.connectors),
                          successful=sum(results.values()))

        return results

    async def send_event_to_all(
        self,
        event: Dict[str, Any],
        index: Optional[str] = None
    ) -> Dict[str, bool]:
        """
        Send event to all active SIEM connectors

        Args:
            event: Event dictionary
            index: Optional index/sourcetype

        Returns:
            Dictionary mapping connector names to send status
        """
        tasks = []
        connector_names = []

        for name in self.active_connectors:
            connector = self.connectors.get(name)
            if connector:
                tasks.append(connector.send_event(event, index))
                connector_names.append(name)

        # Execute in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Map results
        status_map = {}
        for name, result in zip(connector_names, results):
            if isinstance(result, Exception):
                logger.log_error(result, {
                    "operation": "send_event_to_all",
                    "connector": name
                })
                status_map[name] = False
            else:
                status_map[name] = result

        return status_map

    async def send_batch_to_all(
        self,
        events: List[Dict[str, Any]],
        index: Optional[str] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Send batch of events to all active SIEM connectors

        Args:
            events: List of events
            index: Optional index/sourcetype

        Returns:
            Dictionary mapping connector names to batch results
        """
        tasks = []
        connector_names = []

        for name in self.active_connectors:
            connector = self.connectors.get(name)
            if connector:
                tasks.append(connector.send_batch(events, index))
                connector_names.append(name)

        # Execute in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Map results
        results_map = {}
        for name, result in zip(connector_names, results):
            if isinstance(result, Exception):
                logger.log_error(result, {
                    "operation": "send_batch_to_all",
                    "connector": name
                })
                results_map[name] = {
                    "success": False,
                    "error": str(result)
                }
            else:
                results_map[name] = result

        return results_map

    async def health_check_all(self) -> Dict[str, Dict[str, Any]]:
        """
        Perform health check on all connectors

        Returns:
            Dictionary mapping connector names to health status
        """
        tasks = []
        connector_names = []

        for name, connector in self.connectors.items():
            tasks.append(connector.health_check())
            connector_names.append(name)

        # Execute in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Map results
        health_map = {}
        for name, result in zip(connector_names, results):
            if isinstance(result, Exception):
                health_map[name] = {
                    "status": "error",
                    "error": str(result)
                }
            else:
                health_map[name] = result

        return health_map

    def get_connector(self, name: str) -> Optional[SIEMConnector]:
        """Get connector by name"""
        return self.connectors.get(name)

    def list_connectors(self) -> List[Dict[str, Any]]:
        """List all registered connectors"""
        return [
            {
                "name": name,
                "siem_type": connector.siem_type.value,
                "connected": connector.connected,
                "active": name in self.active_connectors
            }
            for name, connector in self.connectors.items()
        ]

    async def disconnect_all(self) -> Dict[str, bool]:
        """Disconnect from all SIEM systems"""
        results = {}

        for name, connector in self.connectors.items():
            try:
                success = await connector.disconnect()
                results[name] = success

                if name in self.active_connectors:
                    self.active_connectors.remove(name)

            except Exception as e:
                logger.log_error(e, {
                    "operation": "disconnect_all",
                    "connector": name
                })
                results[name] = False

        return results


# Global SIEM integration service instance
siem_service = SIEMIntegrationService()
