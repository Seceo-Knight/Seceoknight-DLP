"""
Structured Logging Configuration
Using structlog for JSON-formatted logs
"""

import logging
import re
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor

from app.core.config import settings

# Patterns for PII redaction
_PII_PATTERNS = [
    (re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'), '[EMAIL_REDACTED]'),
    (re.compile(r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b'), '[SSN_REDACTED]'),
    (re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'), '[CC_REDACTED]'),
]

# Keys whose values should always be fully redacted
_SENSITIVE_KEYS = frozenset({
    'password', 'hashed_password', 'secret', 'token', 'api_key',
    'credit_card', 'ssn', 'secret_key', 'refresh_token', 'access_token',
})

# Keys whose values should be PII-scrubbed (regex replacement)
_PII_KEYS = frozenset({
    'email', 'user_email', 'username', 'file_path', 'source_path',
    'destination', 'ip_address', 'filters', 'query_filter',
})


def _redact_value(value: Any) -> Any:
    """Apply PII regex patterns to a string value."""
    if not isinstance(value, str):
        return value
    for pattern, replacement in _PII_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def redact_pii(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Structlog processor that redacts PII from log event fields."""
    for key in list(event_dict.keys()):
        lower_key = key.lower()
        if lower_key in _SENSITIVE_KEYS:
            event_dict[key] = '[REDACTED]'
        elif lower_key in _PII_KEYS:
            event_dict[key] = _redact_value(str(event_dict[key]))
    return event_dict


def add_app_context(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """
    Add application context to log events
    """
    event_dict["service"] = settings.PROJECT_NAME
    event_dict["environment"] = settings.ENVIRONMENT
    event_dict["version"] = settings.VERSION
    return event_dict


def setup_logging() -> None:
    """
    Configure structured logging with JSON output
    """
    # Determine log level
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    # Configure processors
    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        add_app_context,
        redact_pii,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # Add appropriate renderer based on format
    if settings.LOG_FORMAT == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    # Set log level for third-party libraries
    logging.getLogger("uvicorn").setLevel(log_level)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> Any:
    """
    Get a logger instance with the given name
    """
    return structlog.get_logger(name)
