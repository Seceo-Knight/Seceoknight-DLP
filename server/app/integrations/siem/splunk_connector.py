"""
Splunk SIEM Connector
Integration with Splunk Enterprise and Splunk Cloud
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import asyncio
import aiohttp
from urllib.parse import urljoin

from .base import SIEMConnector, SIEMType, EventSeverity
from app.core.observability import StructuredLogger

logger = StructuredLogger(__name__)


class SplunkConnector(SIEMConnector):
    """
    Splunk connector for SIEM integration

    Supports:
    - Event ingestion via HTTP Event Collector (HEC)
    - Search via REST API
    - Alert creation via REST API
    - Both Splunk Enterprise and Splunk Cloud
    """

    def __init__(
        self,
        name: str = "Splunk",
        host: str = "localhost",
        port: int = 8088,  # HEC port
        hec_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_ssl: bool = True,
        verify_certs: bool = True,
        source: str = "seceoknight_dlp",
        sourcetype: str = "dlp:event",
        index: str = "dlp",
        **kwargs
    ):
        """
        Initialize Splunk connector

        Args:
            name: Connector name
            host: Splunk host
            port: Splunk HEC port (default 8088)
            hec_token: HTTP Event Collector token
            username: Splunk username (for REST API)
            password: Splunk password (for REST API)
            use_ssl: Use HTTPS
            verify_certs: Verify SSL certificates
            source: Event source
            sourcetype: Event sourcetype
            index: Target index
            **kwargs: Additional parameters
        """
        super().__init__(name, SIEMType.SPLUNK, host, port, use_ssl, verify_certs, **kwargs)

        self.hec_token = hec_token
        self.username = username
        self.password = password
        self.source = source
        self.sourcetype = sourcetype
        self.index = index

        # Build URLs
        scheme = "https" if self.use_ssl else "http"
        self.base_url = f"{scheme}://{self.host}:{self.port}"
        self.hec_url = urljoin(self.base_url, "/services/collector")
        self.api_url = urljoin(self.base_url, "/services")

        self.session: Optional[aiohttp.ClientSession] = None
        self.session_key: Optional[str] = None

    async def connect(self) -> bool:
        """Establish connection to Splunk"""
        try:
            # Create HTTP session
            connector = aiohttp.TCPConnector(
                ssl=self.verify_certs if self.use_ssl else False
            )

            self.session = aiohttp.ClientSession(
                connector=connector,
                headers={
                    "Content-Type": "application/json"
                }
            )

            # Authenticate with REST API (if credentials provided)
            if self.username and self.password:
                auth_url = urljoin(self.api_url, "/auth/login")

                async with self.session.post(
                    auth_url,
                    data={
                        "username": self.username,
                        "password": self.password,
                        "output_mode": "json"
                    },
                    ssl=self.verify_certs if self.use_ssl else False
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.session_key = data.get("sessionKey")

            self.connected = True
            logger.logger.info("splunk_connected", host=self.host)

            return True

        except Exception as e:
            self.connected = False
            logger.log_error(e, {"operation": "splunk_connect"})
            return False

    async def disconnect(self) -> bool:
        """Close Splunk connection"""
        try:
            if self.session:
                await self.session.close()
                self.session = None
                self.session_key = None
                self.connected = False
                logger.logger.info("splunk_disconnected")

            return True

        except Exception as e:
            logger.log_error(e, {"operation": "splunk_disconnect"})
            return False

    async def test_connection(self) -> Dict[str, Any]:
        """Test Splunk connectivity"""
        try:
            if not self.session:
                await self.connect()

            # Test HEC endpoint
            test_url = urljoin(self.hec_url, "/health")

            async with self.session.get(
                test_url,
                headers={"Authorization": f"Splunk {self.hec_token}"},
                ssl=self.verify_certs if self.use_ssl else False
            ) as response:
                if response.status == 200:
                    return {
                        "success": True,
                        "message": "Connected to Splunk HEC",
                        "hec_status": "healthy"
                    }
                else:
                    text = await response.text()
                    return {
                        "success": False,
                        "message": f"HEC test failed: {response.status}",
                        "detail": text
                    }

        except Exception as e:
            logger.log_error(e, {"operation": "splunk_test_connection"})
            return {
                "success": False,
                "message": f"Connection test failed: {str(e)}"
            }

    async def send_event(
        self,
        event: Dict[str, Any],
        index: Optional[str] = None
    ) -> bool:
        """
        Send single event to Splunk via HEC

        Args:
            event: Event dictionary
            index: Optional index name (defaults to configured index)

        Returns:
            True if sent successfully
        """
        try:
            if not self.session or not self.connected:
                await self.connect()

            # Format event for Splunk HEC
            formatted_event = self.format_dlp_event(event)

            # Build HEC payload
            hec_payload = {
                "time": int(datetime.fromisoformat(
                    formatted_event.get("timestamp", datetime.utcnow().isoformat())
                ).timestamp()),
                "host": formatted_event.get("agent", {}).get("hostname", "unknown"),
                "source": self.source,
                "sourcetype": self.sourcetype,
                "index": index or self.index,
                "event": formatted_event
            }

            # Send to HEC
            async with self.session.post(
                self.hec_url,
                headers={"Authorization": f"Splunk {self.hec_token}"},
                json=hec_payload,
                ssl=self.verify_certs if self.use_ssl else False
            ) as response:
                if response.status == 200:
                    logger.logger.info("event_sent_to_splunk",
                                      event_id=event.get("event_id"))
                    return True
                else:
                    text = await response.text()
                    logger.logger.warning("splunk_send_failed",
                                        status=response.status,
                                        detail=text)
                    return False

        except Exception as e:
            logger.log_error(e, {
                "operation": "splunk_send_event",
                "event_id": event.get("event_id")
            })
            return False

    async def send_batch(
        self,
        events: List[Dict[str, Any]],
        index: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send batch of events to Splunk HEC

        Args:
            events: List of events
            index: Optional index name

        Returns:
            Batch result summary
        """
        try:
            if not self.session or not self.connected:
                await self.connect()

            # Build batch payload (newline-delimited JSON)
            batch_payloads = []

            for event in events:
                formatted_event = self.format_dlp_event(event)

                hec_payload = {
                    "time": int(datetime.fromisoformat(
                        formatted_event.get("timestamp", datetime.utcnow().isoformat())
                    ).timestamp()),
                    "host": formatted_event.get("agent", {}).get("hostname", "unknown"),
                    "source": self.source,
                    "sourcetype": self.sourcetype,
                    "index": index or self.index,
                    "event": formatted_event
                }

                batch_payloads.append(json.dumps(hec_payload))

            # Join with newlines
            batch_data = "\n".join(batch_payloads)

            # Send batch
            async with self.session.post(
                self.hec_url,
                headers={"Authorization": f"Splunk {self.hec_token}"},
                data=batch_data,
                ssl=self.verify_certs if self.use_ssl else False
            ) as response:
                if response.status == 200:
                    result = await response.json()

                    logger.logger.info("batch_sent_to_splunk",
                                      total=len(events),
                                      index=index or self.index)

                    return {
                        "success": True,
                        "total": len(events),
                        "indexed": len(events),
                        "failed": 0,
                        "index": index or self.index
                    }
                else:
                    text = await response.text()
                    logger.logger.warning("splunk_batch_failed",
                                        status=response.status,
                                        detail=text)

                    return {
                        "success": False,
                        "error": text,
                        "total": len(events),
                        "indexed": 0,
                        "failed": len(events)
                    }

        except Exception as e:
            logger.log_error(e, {"operation": "splunk_send_batch"})
            return {
                "success": False,
                "error": str(e),
                "total": len(events),
                "indexed": 0,
                "failed": len(events)
            }

    async def query_events(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query events using Splunk Search Processing Language (SPL)

        Args:
            query: SPL query string
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum results

        Returns:
            List of matching events
        """
        try:
            if not self.session or not self.connected:
                await self.connect()

            if not self.session_key:
                logger.logger.warning("splunk_query_no_auth",
                                    message="Session key required for search API")
                return []

            # Build search query
            search_query = f"search {query} earliest={start_time.isoformat()} latest={end_time.isoformat()} | head {limit}"

            # Create search job
            search_url = urljoin(self.api_url, "/search/jobs")

            async with self.session.post(
                search_url,
                headers={"Authorization": f"Splunk {self.session_key}"},
                data={
                    "search": search_query,
                    "output_mode": "json"
                },
                ssl=self.verify_certs if self.use_ssl else False
            ) as response:
                if response.status != 201:
                    return []

                data = await response.json()
                job_id = data.get("sid")

            # Poll for job completion
            job_url = urljoin(self.api_url, f"/search/jobs/{job_id}")

            for _ in range(30):  # Poll for up to 30 seconds
                async with self.session.get(
                    job_url,
                    headers={"Authorization": f"Splunk {self.session_key}"},
                    params={"output_mode": "json"},
                    ssl=self.verify_certs if self.use_ssl else False
                ) as response:
                    if response.status == 200:
                        job_status = await response.json()
                        if job_status.get("entry", [{}])[0].get("content", {}).get("isDone"):
                            break

                await asyncio.sleep(1)

            # Get results
            results_url = urljoin(self.api_url, f"/search/jobs/{job_id}/results")

            async with self.session.get(
                results_url,
                headers={"Authorization": f"Splunk {self.session_key}"},
                params={"output_mode": "json"},
                ssl=self.verify_certs if self.use_ssl else False
            ) as response:
                if response.status == 200:
                    results = await response.json()
                    events = results.get("results", [])

                    logger.logger.info("splunk_query_executed",
                                      query=query,
                                      results=len(events))

                    return events
                else:
                    return []

        except Exception as e:
            logger.log_error(e, {"operation": "splunk_query_events"})
            return []

    async def create_alert(
        self,
        alert_name: str,
        description: str,
        severity: EventSeverity,
        query: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create saved search (alert) in Splunk

        Args:
            alert_name: Alert name
            description: Alert description
            severity: Alert severity
            query: SPL query that triggers alert
            **kwargs: Additional alert parameters

        Returns:
            Alert creation result
        """
        try:
            if not self.session or not self.connected:
                await self.connect()

            if not self.session_key:
                return {
                    "success": False,
                    "error": "Session key required for alert creation"
                }

            # Build saved search
            alert_url = urljoin(self.api_url, "/saved/searches")

            alert_data = {
                "name": alert_name,
                "search": query,
                "description": description,
                "alert_type": "always",
                "alert_severity": severity.value,
                "alert.track": "1",
                "alert.expires": kwargs.get("expires", "24h"),
                "cron_schedule": kwargs.get("cron", "*/5 * * * *"),  # Every 5 minutes
                "is_scheduled": "1",
                "actions": kwargs.get("actions", "email"),
                "output_mode": "json"
            }

            # Add email action if configured
            if kwargs.get("email_to"):
                alert_data["action.email.to"] = kwargs["email_to"]
                alert_data["action.email.subject"] = f"DLP Alert: {alert_name}"

            async with self.session.post(
                alert_url,
                headers={"Authorization": f"Splunk {self.session_key}"},
                data=alert_data,
                ssl=self.verify_certs if self.use_ssl else False
            ) as response:
                if response.status == 201:
                    logger.logger.info("splunk_alert_created",
                                      alert_name=alert_name)

                    return {
                        "success": True,
                        "alert_name": alert_name,
                        "message": "Alert created successfully"
                    }
                else:
                    text = await response.text()
                    return {
                        "success": False,
                        "error": text
                    }

        except Exception as e:
            logger.log_error(e, {"operation": "splunk_create_alert"})
            return {
                "success": False,
                "error": str(e)
            }
