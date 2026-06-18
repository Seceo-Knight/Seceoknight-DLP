"""
OpenSearch Client for Event Storage and Search
Wazuh-style event indexing with daily rolling indices
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import structlog
from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import NotFoundError, RequestError

from app.core.config import settings

logger = structlog.get_logger()

# Global OpenSearch client instance
opensearch_client: Optional[AsyncOpenSearch] = None


# Index Mappings for Events
EVENT_INDEX_MAPPINGS = {
    "dynamic": "strict",
    "properties": {
        "@timestamp": {
            "type": "date",
            "format": "strict_date_optional_time||epoch_millis"
        },
        "event_id": {
            "type": "keyword"
        },
        "agent": {
            "properties": {
                "id": {"type": "keyword"},
                "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "ip": {"type": "ip"},
                "os": {"type": "keyword"},
                "version": {"type": "keyword"}
            }
        },
        "event": {
            "properties": {
                "type": {"type": "keyword"},
                "subtype": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "action": {"type": "keyword"},
                "outcome": {"type": "keyword"}
            }
        },
        "user": {
            "properties": {
                "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "email": {"type": "keyword"},
                "id": {"type": "keyword"}
            }
        },
        "file": {
            "properties": {
                "path": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "name": {"type": "keyword"},
                "extension": {"type": "keyword"},
                "size": {"type": "long"},
                "hash": {
                    "properties": {
                        "md5": {"type": "keyword"},
                        "sha1": {"type": "keyword"},
                        "sha256": {"type": "keyword"}
                    }
                }
            }
        },
        "process": {
            "properties": {
                "name": {"type": "keyword"},
                "pid": {"type": "long"},
                "executable": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}
            }
        },
        "network": {
            "properties": {
                "protocol": {"type": "keyword"},
                "direction": {"type": "keyword"},
                "source_ip": {"type": "ip"},
                "destination_ip": {"type": "ip"},
                "source_port": {"type": "integer"},
                "destination_port": {"type": "integer"},
                "bytes_sent": {"type": "long"},
                "bytes_received": {"type": "long"}
            }
        },
        "classification": {
            "type": "nested",
            "properties": {
                "type": {"type": "keyword"},
                "label": {"type": "keyword"},
                "confidence": {"type": "float"},
                "patterns_matched": {"type": "keyword"},
                "sensitive_data": {
                    "properties": {
                        "type": {"type": "keyword"},
                        "count": {"type": "integer"},
                        "redacted": {"type": "boolean"}
                    }
                }
            }
        },
        "policy": {
            "properties": {
                "id": {"type": "keyword"},
                "name": {"type": "keyword"},
                "rule_id": {"type": "keyword"},
                "action": {"type": "keyword"},
                "severity": {"type": "keyword"}
            }
        },
        "alert": {
            "properties": {
                "id": {"type": "keyword"},
                "title": {"type": "text"},
                "description": {"type": "text"},
                "severity": {"type": "keyword"},
                "status": {"type": "keyword"},
                "acknowledged": {"type": "boolean"}
            }
        },
        "usb": {
            "properties": {
                "device_id": {"type": "keyword"},
                "vendor": {"type": "keyword"},
                "product": {"type": "keyword"},
                "serial_number": {"type": "keyword"},
                "action": {"type": "keyword"}
            }
        },
        "clipboard": {
            "properties": {
                "content_type": {"type": "keyword"},
                "content_hash": {"type": "keyword"},
                "content_size": {"type": "long"}
            }
        },
        "content": {
            "type": "text",
            "analyzer": "standard"
        },
        "content_redacted": {
            "type": "text",
            "analyzer": "standard"
        },
        "metadata": {
            "type": "object",
            "enabled": True
        },
        "tags": {
            "type": "keyword"
        },
        "quarantined": {
            "type": "boolean"
        },
        "quarantine_path": {
            "type": "keyword"
        },
        "blocked": {
            "type": "boolean"
        }
    }
}

# Index Settings
EVENT_INDEX_SETTINGS = {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "refresh_interval": "5s",
    "max_result_window": 10000
}


async def init_opensearch() -> None:
    """
    Initialize OpenSearch connection and create index templates
    OpenSearch is optional - server will start even if OpenSearch is unavailable
    """
    global opensearch_client

    import asyncio
    
    max_retries = 5
    retry_delay = 5  # seconds
    
    for attempt in range(max_retries):
        try:
            # Create OpenSearch client
            client_kwargs = {
                'hosts': [{
                    'host': settings.OPENSEARCH_HOST,
                    'port': settings.OPENSEARCH_PORT
                }],
                'use_ssl': settings.OPENSEARCH_USE_SSL,
                'verify_certs': settings.OPENSEARCH_VERIFY_CERTS,
                'ssl_show_warn': False,
                'timeout': 30,
                'max_retries': 3,
                'retry_on_timeout': True
            }
            
            # Only add auth if SSL is enabled (security plugin active)
            if settings.OPENSEARCH_USE_SSL:
                client_kwargs['http_auth'] = (settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD)
            
            opensearch_client = AsyncOpenSearch(**client_kwargs)

            # Test connection
            info = await opensearch_client.info()
            logger.info(
                "OpenSearch connection established",
                cluster_name=info.get('cluster_name'),
                version=info.get('version', {}).get('number'),
                host=settings.OPENSEARCH_HOST,
                attempt=attempt + 1
            )

            # Create index template for events
            await create_index_template()

            # Create today's index
            await ensure_daily_index()

            logger.info("OpenSearch initialization complete")
            return  # Success - exit function

        except Exception as e:
            if attempt < max_retries - 1:
                logger.debug(
                    "OpenSearch connection attempt failed, retrying",
                    attempt=attempt + 1,
                    max_retries=max_retries,
                    error=str(e),
                    host=settings.OPENSEARCH_HOST
                )
                await asyncio.sleep(retry_delay)
            else:
                # Final attempt failed
                logger.warning(
                    "Failed to connect to OpenSearch after all retries - continuing without it",
                    error=str(e),
                    host=settings.OPENSEARCH_HOST,
                    attempts=max_retries
                )
                # Set client to None to indicate OpenSearch is unavailable
                opensearch_client = None
                # DO NOT raise - allow server to start without OpenSearch


async def close_opensearch() -> None:
    """
    Close OpenSearch connection
    """
    global opensearch_client

    if opensearch_client is not None:
        try:
            await opensearch_client.close()
            logger.info("OpenSearch connection closed")
        except Exception as e:
            logger.warning(f"Error closing OpenSearch connection: {e}")
        finally:
            opensearch_client = None


async def create_index_template() -> None:
    """
    Create index template for event indices
    """
    if opensearch_client is None:
        raise RuntimeError("OpenSearch not initialized")

    template_name = f"{settings.OPENSEARCH_INDEX_PREFIX}-events-template"
    index_pattern = f"{settings.OPENSEARCH_INDEX_PREFIX}-events-*"

    template_body = {
        "index_patterns": [index_pattern],
        "template": {
            "settings": EVENT_INDEX_SETTINGS,
            "mappings": EVENT_INDEX_MAPPINGS
        },
        "priority": 100
    }

    try:
        # Check if template exists
        try:
            result = await opensearch_client.indices.get_index_template(name=template_name)
            exists = True
        except NotFoundError:
            exists = False

        if exists:
            # Update existing template
            await opensearch_client.indices.put_index_template(
                name=template_name,
                body=template_body
            )
            logger.info("Updated OpenSearch index template", template=template_name)
        else:
            # Create new template
            await opensearch_client.indices.put_index_template(
                name=template_name,
                body=template_body
            )
            logger.info("Created OpenSearch index template", template=template_name)

    except Exception as e:
        logger.error("Failed to create index template", error=str(e))
        raise


def get_daily_index_name(date: Optional[datetime] = None) -> str:
    """
    Get index name for a specific date
    """
    if date is None:
        date = datetime.utcnow()

    date_str = date.strftime("%Y.%m.%d")
    return f"{settings.OPENSEARCH_INDEX_PREFIX}-events-{date_str}"


async def ensure_daily_index(date: Optional[datetime] = None) -> str:
    """
    Ensure that the daily index exists, create if not
    """
    if opensearch_client is None:
        raise RuntimeError("OpenSearch not initialized")

    index_name = get_daily_index_name(date)

    try:
        exists = await opensearch_client.indices.exists(index=index_name)

        if not exists:
            # Create index (will use template)
            await opensearch_client.indices.create(index=index_name)
            logger.info("Created daily index", index=index_name)

        return index_name

    except RequestError as e:
        # Index might have been created by another process
        if 'resource_already_exists_exception' in str(e):
            logger.debug("Index already exists", index=index_name)
            return index_name
        raise


async def index_event(event: Dict[str, Any]) -> str:
    """
    Index a single event to OpenSearch
    """
    if opensearch_client is None:
        logger.debug("OpenSearch unavailable - skipping event indexing", event_id=event.get('event_id'))
        return "opensearch_unavailable"

    # Ensure today's index exists
    index_name = await ensure_daily_index()

    # Add timestamp if not present
    if '@timestamp' not in event:
        event['@timestamp'] = datetime.utcnow().isoformat()

    try:
        # Index document
        response = await opensearch_client.index(
            index=index_name,
            body=event,
            refresh='wait_for'  # Wait for index refresh
        )

        logger.debug(
            "Event indexed to OpenSearch",
            index=index_name,
            event_id=event.get('event_id'),
            doc_id=response.get('_id')
        )

        return response['_id']

    except Exception as e:
        logger.error(
            "Failed to index event",
            error=str(e),
            event_id=event.get('event_id')
        )
        raise


async def bulk_index_events(events: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Bulk index multiple events to OpenSearch
    """
    if opensearch_client is None:
        logger.debug("OpenSearch unavailable - skipping bulk indexing", event_count=len(events))
        return {"indexed": 0, "errors": 0, "skipped": len(events)}

    if not events:
        return {"indexed": 0, "errors": 0}

    # Ensure today's index exists
    index_name = await ensure_daily_index()

    # Prepare bulk operations
    operations = []
    for event in events:
        # Add timestamp if not present
        if '@timestamp' not in event:
            event['@timestamp'] = datetime.utcnow().isoformat()

        operations.append({
            "index": {
                "_index": index_name
            }
        })
        operations.append(event)

    try:
        # Execute bulk operation
        response = await opensearch_client.bulk(
            body=operations,
            refresh='wait_for'
        )

        # Count successes and errors
        errors = 0
        if response.get('errors'):
            for item in response.get('items', []):
                if 'error' in item.get('index', {}):
                    errors += 1

        indexed = len(events) - errors

        logger.info(
            "Bulk indexed events",
            total=len(events),
            indexed=indexed,
            errors=errors
        )

        return {"indexed": indexed, "errors": errors}

    except Exception as e:
        logger.error("Failed to bulk index events", error=str(e))
        raise


async def search_events(
    query: Optional[Dict[str, Any]] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    size: int = 100,
    from_: int = 0,
    sort: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Search events in OpenSearch
    """
    if opensearch_client is None:
        logger.debug("OpenSearch unavailable - returning empty search results")
        return {"total": 0, "hits": [], "took": 0}

    # Determine indices to search
    if start_date and end_date:
        # Generate list of indices for date range
        indices = []
        current_date = start_date
        while current_date <= end_date:
            indices.append(get_daily_index_name(current_date))
            current_date += timedelta(days=1)
        index_pattern = ",".join(indices)
    else:
        # Search all event indices
        index_pattern = f"{settings.OPENSEARCH_INDEX_PREFIX}-events-*"

    # Default query (match all)
    if query is None:
        query = {"match_all": {}}

    # Default sort (by timestamp descending)
    if sort is None:
        sort = [{"@timestamp": {"order": "desc"}}]

    # Build search body
    search_body = {
        "query": query,
        "size": size,
        "from": from_,
        "sort": sort
    }

    try:
        response = await opensearch_client.search(
            index=index_pattern,
            body=search_body
        )

        return {
            "total": response['hits']['total']['value'],
            "hits": [hit['_source'] for hit in response['hits']['hits']],
            "took": response['took']
        }

    except NotFoundError:
        logger.warning("No indices found for search", index_pattern=index_pattern)
        return {"total": 0, "hits": [], "took": 0}

    except Exception as e:
        logger.error("Search failed", error=str(e))
        raise


async def delete_old_indices(retention_days: int = 90) -> int:
    """
    Delete indices older than retention period
    """
    if opensearch_client is None:
        raise RuntimeError("OpenSearch not initialized")

    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    deleted_count = 0

    try:
        # Get all event indices
        pattern = f"{settings.OPENSEARCH_INDEX_PREFIX}-events-*"
        indices = await opensearch_client.indices.get(index=pattern)

        for index_name in indices.keys():
            # Extract date from index name
            try:
                date_str = index_name.split('-')[-1]  # Get last part (date)
                index_date = datetime.strptime(date_str, "%Y.%m.%d")

                if index_date < cutoff_date:
                    # Delete old index
                    await opensearch_client.indices.delete(index=index_name)
                    logger.info("Deleted old index", index=index_name, date=date_str)
                    deleted_count += 1

            except (ValueError, IndexError):
                logger.warning("Could not parse date from index", index=index_name)
                continue

        logger.info(
            "Completed index cleanup",
            deleted=deleted_count,
            retention_days=retention_days
        )

        return deleted_count

    except Exception as e:
        logger.error("Failed to delete old indices", error=str(e))
        raise


def get_opensearch_client() -> AsyncOpenSearch:
    """
    Get OpenSearch client for dependency injection
    """
    if opensearch_client is None:
        raise RuntimeError("OpenSearch not initialized")
    return opensearch_client
