"""
ELK Stack (Elasticsearch) SIEM Connector
Integration with Elasticsearch/Logstash/Kibana
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from elasticsearch import AsyncElasticsearch, helpers
from elasticsearch.exceptions import ConnectionError, NotFoundError

from .base import SIEMConnector, SIEMType, EventSeverity
from app.core.observability import StructuredLogger

logger = StructuredLogger(__name__)


class ELKConnector(SIEMConnector):
    """
    Elasticsearch/ELK Stack connector for SIEM integration

    Supports:
    - Event ingestion via Elasticsearch API
    - Bulk indexing for performance
    - Query via Elasticsearch DSL
    - Alert creation via Kibana/Watcher
    """

    def __init__(
        self,
        name: str = "ELK Stack",
        host: str = "localhost",
        port: int = 9200,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        cloud_id: Optional[str] = None,
        use_ssl: bool = True,
        verify_certs: bool = True,
        index_prefix: str = "dlp-events",
        **kwargs
    ):
        """
        Initialize ELK connector

        Args:
            name: Connector name
            host: Elasticsearch host
            port: Elasticsearch port
            username: Basic auth username
            password: Basic auth password
            api_key: Elasticsearch API key (alternative to basic auth)
            cloud_id: Elastic Cloud ID (for cloud deployments)
            use_ssl: Use HTTPS
            verify_certs: Verify SSL certificates
            index_prefix: Prefix for indices
            **kwargs: Additional Elasticsearch client parameters
        """
        super().__init__(name, SIEMType.ELK, host, port, use_ssl, verify_certs, **kwargs)

        self.username = username
        self.password = password
        self.api_key = api_key
        self.cloud_id = cloud_id
        self.index_prefix = index_prefix
        self.client: Optional[AsyncElasticsearch] = None

    async def connect(self) -> bool:
        """Establish connection to Elasticsearch"""
        try:
            # Build connection parameters
            if self.cloud_id:
                # Elastic Cloud connection
                self.client = AsyncElasticsearch(
                    cloud_id=self.cloud_id,
                    api_key=self.api_key if self.api_key else None,
                    basic_auth=(self.username, self.password) if self.username else None
                )
            else:
                # Self-hosted Elasticsearch
                scheme = "https" if self.use_ssl else "http"
                hosts = [f"{scheme}://{self.host}:{self.port}"]

                self.client = AsyncElasticsearch(
                    hosts=hosts,
                    api_key=self.api_key if self.api_key else None,
                    basic_auth=(self.username, self.password) if self.username else None,
                    verify_certs=self.verify_certs,
                    **self.config
                )

            # Test connection
            info = await self.client.info()
            self.connected = True

            logger.logger.info("elk_connected",
                              cluster_name=info.get("cluster_name"),
                              version=info.get("version", {}).get("number"))

            return True

        except Exception as e:
            self.connected = False
            logger.log_error(e, {"operation": "elk_connect"})
            return False

    async def disconnect(self) -> bool:
        """Close Elasticsearch connection"""
        try:
            if self.client:
                await self.client.close()
                self.connected = False
                logger.logger.info("elk_disconnected")
            return True

        except Exception as e:
            logger.log_error(e, {"operation": "elk_disconnect"})
            return False

    async def test_connection(self) -> Dict[str, Any]:
        """Test Elasticsearch connectivity"""
        try:
            if not self.client:
                await self.connect()

            # Ping cluster
            ping_result = await self.client.ping()

            if not ping_result:
                return {
                    "success": False,
                    "message": "Elasticsearch cluster unreachable"
                }

            # Get cluster info
            info = await self.client.info()
            health = await self.client.cluster.health()

            return {
                "success": True,
                "message": "Connected to Elasticsearch",
                "cluster_name": info.get("cluster_name"),
                "version": info.get("version", {}).get("number"),
                "cluster_health": health.get("status"),
                "number_of_nodes": health.get("number_of_nodes"),
                "active_shards": health.get("active_shards")
            }

        except Exception as e:
            logger.log_error(e, {"operation": "elk_test_connection"})
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
        Send single event to Elasticsearch

        Args:
            event: Event dictionary
            index: Optional index name (defaults to dlp-events-YYYY.MM.DD)

        Returns:
            True if indexed successfully
        """
        try:
            if not self.client or not self.connected:
                await self.connect()

            # Format event
            formatted_event = self.format_dlp_event(event)

            # Generate index name (daily indices)
            if not index:
                date_suffix = datetime.utcnow().strftime("%Y.%m.%d")
                index = f"{self.index_prefix}-{date_suffix}"

            # Index document
            result = await self.client.index(
                index=index,
                document=formatted_event
            )

            logger.logger.info("event_sent_to_elk",
                              index=index,
                              event_id=event.get("event_id"),
                              result=result.get("result"))

            return result.get("result") in ["created", "updated"]

        except Exception as e:
            logger.log_error(e, {
                "operation": "elk_send_event",
                "event_id": event.get("event_id")
            })
            return False

    async def send_batch(
        self,
        events: List[Dict[str, Any]],
        index: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send batch of events using bulk API

        Args:
            events: List of events
            index: Optional index name

        Returns:
            Batch result summary
        """
        try:
            if not self.client or not self.connected:
                await self.connect()

            # Prepare bulk actions
            date_suffix = datetime.utcnow().strftime("%Y.%m.%d")
            target_index = index or f"{self.index_prefix}-{date_suffix}"

            actions = []
            for event in events:
                formatted_event = self.format_dlp_event(event)
                actions.append({
                    "_index": target_index,
                    "_source": formatted_event
                })

            # Execute bulk request
            success_count = 0
            error_count = 0

            async for ok, result in helpers.async_streaming_bulk(
                self.client,
                actions,
                chunk_size=500,
                raise_on_error=False
            ):
                if ok:
                    success_count += 1
                else:
                    error_count += 1
                    logger.logger.warning("bulk_index_error", result=result)

            logger.logger.info("batch_sent_to_elk",
                              total=len(events),
                              success=success_count,
                              errors=error_count,
                              index=target_index)

            return {
                "success": True,
                "total": len(events),
                "indexed": success_count,
                "failed": error_count,
                "index": target_index
            }

        except Exception as e:
            logger.log_error(e, {"operation": "elk_send_batch"})
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
        Query events using Elasticsearch DSL

        Args:
            query: Elasticsearch query string or dict
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum results

        Returns:
            List of matching events
        """
        try:
            if not self.client or not self.connected:
                await self.connect()

            # Build search query
            if isinstance(query, str):
                # Simple query string
                search_body = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "query_string": {
                                        "query": query
                                    }
                                },
                                {
                                    "range": {
                                        "timestamp": {
                                            "gte": start_time.isoformat(),
                                            "lte": end_time.isoformat()
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    "size": limit,
                    "sort": [{"timestamp": "desc"}]
                }
            else:
                # Advanced query dict
                search_body = query
                search_body["size"] = limit

            # Execute search across indices
            index_pattern = f"{self.index_prefix}-*"

            result = await self.client.search(
                index=index_pattern,
                body=search_body
            )

            # Extract hits
            hits = result.get("hits", {}).get("hits", [])
            events = [hit["_source"] for hit in hits]

            logger.logger.info("elk_query_executed",
                              query=query,
                              results=len(events))

            return events

        except Exception as e:
            logger.log_error(e, {"operation": "elk_query_events"})
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
        Create alert using Elasticsearch Watcher

        Args:
            alert_name: Alert name
            description: Alert description
            severity: Alert severity
            query: Query that triggers alert
            **kwargs: Additional watcher parameters

        Returns:
            Alert creation result
        """
        try:
            if not self.client or not self.connected:
                await self.connect()

            # Build watcher definition
            watcher_id = alert_name.lower().replace(" ", "_")

            watcher_body = {
                "trigger": {
                    "schedule": {
                        "interval": kwargs.get("interval", "5m")
                    }
                },
                "input": {
                    "search": {
                        "request": {
                            "indices": [f"{self.index_prefix}-*"],
                            "body": {
                                "query": {
                                    "query_string": {
                                        "query": query
                                    }
                                }
                            }
                        }
                    }
                },
                "condition": {
                    "compare": {
                        "ctx.payload.hits.total": {
                            "gt": kwargs.get("threshold", 0)
                        }
                    }
                },
                "actions": {
                    "log_alert": {
                        "logging": {
                            "text": f"{description} - {{{{ctx.payload.hits.total}}}} events matched"
                        }
                    }
                }
            }

            # Add email action if configured
            if kwargs.get("email_to"):
                watcher_body["actions"]["email_alert"] = {
                    "email": {
                        "to": kwargs["email_to"],
                        "subject": f"DLP Alert: {alert_name}",
                        "body": {
                            "text": description
                        }
                    }
                }

            # Create watcher
            result = await self.client.watcher.put_watch(
                id=watcher_id,
                body=watcher_body
            )

            logger.logger.info("elk_alert_created",
                              alert_name=alert_name,
                              watcher_id=watcher_id)

            return {
                "success": True,
                "alert_id": watcher_id,
                "message": "Alert created successfully"
            }

        except Exception as e:
            logger.log_error(e, {"operation": "elk_create_alert"})
            return {
                "success": False,
                "error": str(e)
            }

    async def create_index_template(self) -> bool:
        """
        Create index template for DLP events

        Returns:
            True if template created successfully
        """
        try:
            if not self.client or not self.connected:
                await self.connect()

            template_body = {
                "index_patterns": [f"{self.index_prefix}-*"],
                "template": {
                    "settings": {
                        "number_of_shards": 3,
                        "number_of_replicas": 1,
                        "index.refresh_interval": "5s"
                    },
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "event_id": {"type": "keyword"},
                            "event_type": {"type": "keyword"},
                            "source": {"type": "keyword"},
                            "severity": {"type": "keyword"},

                            "agent": {
                                "properties": {
                                    "id": {"type": "keyword"},
                                    "name": {"type": "keyword"},
                                    "hostname": {"type": "keyword"},
                                    "ip": {"type": "ip"},
                                    "os": {"type": "keyword"}
                                }
                            },

                            "dlp": {
                                "properties": {
                                    "classification_type": {"type": "keyword"},
                                    "confidence": {"type": "float"},
                                    "blocked": {"type": "boolean"},
                                    "policy_id": {"type": "keyword"},
                                    "policy_name": {"type": "text"},
                                    "rule_id": {"type": "keyword"}
                                }
                            },

                            "user": {
                                "properties": {
                                    "username": {"type": "keyword"},
                                    "domain": {"type": "keyword"},
                                    "email": {"type": "keyword"}
                                }
                            },

                            "network": {
                                "properties": {
                                    "source_ip": {"type": "ip"},
                                    "destination_ip": {"type": "ip"},
                                    "destination_host": {"type": "keyword"},
                                    "destination_country": {"type": "keyword"}
                                }
                            },

                            "file": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "path": {"type": "text"},
                                    "size": {"type": "long"},
                                    "hash": {"type": "keyword"},
                                    "type": {"type": "keyword"}
                                }
                            },

                            "actions": {"type": "keyword"},
                            "metadata": {"type": "object", "enabled": False}
                        }
                    }
                }
            }

            result = await self.client.indices.put_index_template(
                name=f"{self.index_prefix}-template",
                body=template_body
            )

            logger.logger.info("elk_template_created",
                              template=f"{self.index_prefix}-template")

            return result.get("acknowledged", False)

        except Exception as e:
            logger.log_error(e, {"operation": "elk_create_template"})
            return False
