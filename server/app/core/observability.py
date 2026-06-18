"""
Centralized Logging and Metrics
Structured logging, Prometheus metrics, and monitoring
"""

import time
from typing import Any, Dict, Optional, Callable
from functools import wraps
from contextlib import contextmanager
import structlog
from prometheus_client import Counter, Histogram, Gauge, Info
from fastapi import Request
import logging

# Configure structlog
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


# Prometheus Metrics

# API Metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

# Event Processing Metrics
events_processed_total = Counter(
    'events_processed_total',
    'Total events processed',
    ['event_type', 'status']
)

events_processing_duration_seconds = Histogram(
    'events_processing_duration_seconds',
    'Event processing duration in seconds',
    ['stage']
)

# Classification Metrics
pii_detected_total = Counter(
    'pii_detected_total',
    'Total PII detections',
    ['pii_type']
)

classification_accuracy = Gauge(
    'classification_accuracy',
    'Classification accuracy score',
    ['pii_type']
)

# Policy Metrics
policy_violations_total = Counter(
    'policy_violations_total',
    'Total policy violations',
    ['policy_id', 'severity']
)

policy_evaluation_duration_seconds = Histogram(
    'policy_evaluation_duration_seconds',
    'Policy evaluation duration in seconds'
)

# Agent Metrics
agents_connected_total = Gauge(
    'agents_connected_total',
    'Number of connected agents'
)

agent_heartbeats_total = Counter(
    'agent_heartbeats_total',
    'Total agent heartbeats received',
    ['agent_id']
)

agent_events_submitted_total = Counter(
    'agent_events_submitted_total',
    'Total events submitted by agents',
    ['agent_id', 'event_type']
)

# Database Metrics
database_queries_total = Counter(
    'database_queries_total',
    'Total database queries',
    ['database', 'operation']
)

database_query_duration_seconds = Histogram(
    'database_query_duration_seconds',
    'Database query duration in seconds',
    ['database', 'operation']
)

# Cache Metrics
cache_hits_total = Counter(
    'cache_hits_total',
    'Total cache hits',
    ['cache_type']
)

cache_misses_total = Counter(
    'cache_misses_total',
    'Total cache misses',
    ['cache_type']
)

# System Info
system_info = Info('system', 'System information')


class MetricsCollector:
    """
    Centralized metrics collection
    """

    @staticmethod
    def record_http_request(method: str, endpoint: str, status: int, duration: float):
        """Record HTTP request metrics"""
        http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
        http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

    @staticmethod
    def record_event_processed(event_type: str, status: str):
        """Record event processing"""
        events_processed_total.labels(event_type=event_type, status=status).inc()

    @staticmethod
    def record_processing_stage(stage: str, duration: float):
        """Record processing stage duration"""
        events_processing_duration_seconds.labels(stage=stage).observe(duration)

    @staticmethod
    def record_pii_detection(pii_type: str):
        """Record PII detection"""
        pii_detected_total.labels(pii_type=pii_type).inc()

    @staticmethod
    def record_policy_violation(policy_id: str, severity: str):
        """Record policy violation"""
        policy_violations_total.labels(policy_id=policy_id, severity=severity).inc()

    @staticmethod
    def record_agent_heartbeat(agent_id: str):
        """Record agent heartbeat"""
        agent_heartbeats_total.labels(agent_id=agent_id).inc()

    @staticmethod
    def record_agent_event(agent_id: str, event_type: str):
        """Record agent event submission"""
        agent_events_submitted_total.labels(agent_id=agent_id, event_type=event_type).inc()

    @staticmethod
    def update_connected_agents(count: int):
        """Update connected agents count"""
        agents_connected_total.set(count)

    @staticmethod
    def record_database_query(database: str, operation: str, duration: float):
        """Record database query"""
        database_queries_total.labels(database=database, operation=operation).inc()
        database_query_duration_seconds.labels(database=database, operation=operation).observe(duration)

    @staticmethod
    def record_cache_hit(cache_type: str):
        """Record cache hit"""
        cache_hits_total.labels(cache_type=cache_type).inc()

    @staticmethod
    def record_cache_miss(cache_type: str):
        """Record cache miss"""
        cache_misses_total.labels(cache_type=cache_type).inc()


# Decorators for automatic metrics collection

def track_time(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """
    Decorator to track function execution time
    """
    def decorator(func: Callable):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start
                logger.info(
                    f"{func.__name__} completed",
                    duration=duration,
                    metric=metric_name,
                    labels=labels
                )

                # Record to appropriate metric
                if "processing" in metric_name:
                    stage = labels.get("stage", func.__name__) if labels else func.__name__
                    MetricsCollector.record_processing_stage(stage, duration)
                elif "database" in metric_name:
                    db = labels.get("database", "unknown") if labels else "unknown"
                    op = labels.get("operation", "query") if labels else "query"
                    MetricsCollector.record_database_query(db, op, duration)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start
                logger.info(
                    f"{func.__name__} completed",
                    duration=duration,
                    metric=metric_name,
                    labels=labels
                )

        # Return appropriate wrapper based on function type
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


@contextmanager
def measure_time(operation: str, **labels):
    """
    Context manager to measure operation time

    Usage:
        with measure_time("database_query", database="postgres", operation="select"):
            # your code here
            pass
    """
    start = time.time()
    try:
        yield
    finally:
        duration = time.time() - start
        logger.info(
            f"{operation} completed",
            duration=duration,
            **labels
        )


class StructuredLogger:
    """
    Structured logger with consistent formatting
    """

    def __init__(self, name: str):
        self.logger = structlog.get_logger(name)

    def log_event_received(self, event_id: str, agent_id: str, event_type: str):
        """Log event received"""
        self.logger.info(
            "event_received",
            event_id=event_id,
            agent_id=agent_id,
            event_type=event_type
        )

    def log_event_processed(self, event_id: str, status: str, duration: float, **kwargs):
        """Log event processed"""
        self.logger.info(
            "event_processed",
            event_id=event_id,
            status=status,
            duration=duration,
            **kwargs
        )

    def log_pii_detected(self, event_id: str, pii_type: str, confidence: float):
        """Log PII detection"""
        self.logger.info(
            "pii_detected",
            event_id=event_id,
            pii_type=pii_type,
            confidence=confidence
        )
        MetricsCollector.record_pii_detection(pii_type)

    def log_policy_violation(self, event_id: str, policy_id: str, severity: str, **kwargs):
        """Log policy violation"""
        self.logger.warning(
            "policy_violation",
            event_id=event_id,
            policy_id=policy_id,
            severity=severity,
            **kwargs
        )
        MetricsCollector.record_policy_violation(policy_id, severity)

    def log_agent_registered(self, agent_id: str, name: str, ip: str):
        """Log agent registration"""
        self.logger.info(
            "agent_registered",
            agent_id=agent_id,
            agent_name=name,
            agent_ip=ip
        )

    def log_agent_heartbeat(self, agent_id: str):
        """Log agent heartbeat"""
        self.logger.debug(
            "agent_heartbeat",
            agent_id=agent_id
        )
        MetricsCollector.record_agent_heartbeat(agent_id)

    def log_error(self, error: Exception, context: Dict[str, Any]):
        """Log error with context"""
        self.logger.error(
            "error_occurred",
            error=str(error),
            error_type=type(error).__name__,
            **context
        )

    def log_security_event(self, event_type: str, severity: str, **kwargs):
        """Log security-related event"""
        self.logger.warning(
            "security_event",
            event_type=event_type,
            severity=severity,
            **kwargs
        )

    def log_performance_warning(self, operation: str, duration: float, threshold: float):
        """Log performance warning"""
        if duration > threshold:
            self.logger.warning(
                "performance_warning",
                operation=operation,
                duration=duration,
                threshold=threshold,
                exceeded_by=duration - threshold
            )


# Middleware for FastAPI

async def metrics_middleware(request: Request, call_next):
    """
    Middleware to collect HTTP metrics
    """
    start = time.time()

    # Process request
    response = await call_next(request)

    # Record metrics
    duration = time.time() - start
    MetricsCollector.record_http_request(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code,
        duration=duration
    )

    # Add custom headers
    response.headers["X-Process-Time"] = str(duration)

    return response


async def logging_middleware(request: Request, call_next):
    """
    Middleware for request/response logging
    """
    request_id = request.headers.get("X-Request-ID", str(time.time()))

    # Bind request context to logger
    with structlog.contextvars.bound_contextvars(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else None
    ):
        logger.info("request_started")

        start = time.time()
        try:
            response = await call_next(request)
            duration = time.time() - start

            logger.info(
                "request_completed",
                status_code=response.status_code,
                duration=duration
            )

            response.headers["X-Request-ID"] = request_id
            return response

        except Exception as e:
            duration = time.time() - start
            logger.error(
                "request_failed",
                error=str(e),
                error_type=type(e).__name__,
                duration=duration
            )
            raise


# Health check helpers

class HealthCheck:
    """
    System health checks
    """

    @staticmethod
    async def check_database(db_session) -> Dict[str, Any]:
        """Check database connectivity"""
        try:
            start = time.time()
            # Execute simple query
            await db_session.execute("SELECT 1")
            duration = time.time() - start

            return {
                "status": "healthy",
                "latency_ms": duration * 1000
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }

    @staticmethod
    async def check_redis(redis_client) -> Dict[str, Any]:
        """Check Redis connectivity"""
        try:
            start = time.time()
            await redis_client.ping()
            duration = time.time() - start

            return {
                "status": "healthy",
                "latency_ms": duration * 1000
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }

    @staticmethod
    async def check_opensearch(opensearch_client) -> Dict[str, Any]:
        """Check OpenSearch connectivity"""
        try:
            start = time.time()
            info = await opensearch_client.info()
            duration = time.time() - start

            return {
                "status": "healthy",
                "version": info.get("version", {}).get("number"),
                "latency_ms": duration * 1000
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }

    @staticmethod
    def get_system_metrics() -> Dict[str, Any]:
        """Get system metrics"""
        import psutil

        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "process_count": len(psutil.pids())
        }


# Alert helpers

class AlertManager:
    """
    Manage alerts and notifications
    """

    def __init__(self):
        self.logger = StructuredLogger("alert_manager")

    async def send_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Send alert (implement with email, Slack, PagerDuty, etc.)
        """
        self.logger.logger.warning(
            "alert_triggered",
            alert_type=alert_type,
            severity=severity,
            message=message,
            metadata=metadata or {}
        )

        # TODO: Implement actual alert sending
        # - Email (SMTP)
        # - Slack webhook
        # - PagerDuty API
        # - SMS (Twilio)
        # - Microsoft Teams webhook

    async def send_policy_violation_alert(
        self,
        event_id: str,
        policy_id: str,
        agent_id: str,
        severity: str,
        details: Dict[str, Any]
    ):
        """Send policy violation alert"""
        message = f"Policy violation detected: {policy_id} on agent {agent_id}"

        await self.send_alert(
            alert_type="policy_violation",
            severity=severity,
            message=message,
            metadata={
                "event_id": event_id,
                "policy_id": policy_id,
                "agent_id": agent_id,
                **details
            }
        )

    async def send_system_alert(
        self,
        component: str,
        status: str,
        message: str
    ):
        """Send system health alert"""
        severity = "critical" if status == "down" else "warning"

        await self.send_alert(
            alert_type="system_health",
            severity=severity,
            message=f"{component}: {message}",
            metadata={"component": component, "status": status}
        )
