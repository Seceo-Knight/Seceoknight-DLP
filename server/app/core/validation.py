"""
Input Validation and Sanitization
Comprehensive validation for all API inputs to prevent injection attacks
"""

import re
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from pydantic import BaseModel, validator, Field
from fastapi import HTTPException, status
import html
import bleach
import structlog

logger = structlog.get_logger()


class ValidationError(HTTPException):
    """Custom validation error exception"""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail
        )


class InputValidator:
    """
    Comprehensive input validation and sanitization
    """

    # Regex patterns for common inputs
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    AGENT_ID_PATTERN = re.compile(r'^AGENT-\d{4,}$')
    EVENT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{8,64}$')
    HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')

    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(\bunion\b.*\bselect\b)",
        r"(\bselect\b.*\bfrom\b)",
        r"(\binsert\b.*\binto\b)",
        r"(\bupdate\b.*\bset\b)",
        r"(\bdelete\b.*\bfrom\b)",
        r"(\bdrop\b.*\btable\b)",
        r"(\bexec\b.*\()",
        r"(\bscript\b.*>)",
        r"(<.*script.*>)",
        r"(javascript:)",
        r"(on\w+\s*=)",  # Event handlers
    ]

    @staticmethod
    def validate_email(email: str) -> str:
        """
        Validate and sanitize email address
        """
        if not email:
            raise ValidationError("Email is required")

        email = email.strip().lower()

        if len(email) > 254:
            raise ValidationError("Email too long")

        if not InputValidator.EMAIL_PATTERN.match(email):
            raise ValidationError("Invalid email format")

        # Check for common email injection patterns
        if any(char in email for char in ['<', '>', '"', "'"]):
            raise ValidationError("Email contains invalid characters")

        return email

    @staticmethod
    def validate_ip_address(ip: str) -> str:
        """
        Validate IP address
        """
        if not ip:
            raise ValidationError("IP address is required")

        ip = ip.strip()

        if not InputValidator.IP_PATTERN.match(ip):
            raise ValidationError("Invalid IP address format")

        # Validate each octet
        octets = ip.split('.')
        for octet in octets:
            num = int(octet)
            if num < 0 or num > 255:
                raise ValidationError(f"Invalid IP octet: {octet}")

        return ip

    @staticmethod
    def validate_hostname(hostname: str) -> str:
        """
        Validate hostname
        """
        if not hostname:
            raise ValidationError("Hostname is required")

        hostname = hostname.strip().lower()

        if len(hostname) > 253:
            raise ValidationError("Hostname too long")

        if not InputValidator.HOSTNAME_PATTERN.match(hostname):
            raise ValidationError("Invalid hostname format")

        return hostname

    @staticmethod
    def validate_agent_id(agent_id: str) -> str:
        """
        Validate agent ID format
        """
        if not agent_id:
            raise ValidationError("Agent ID is required")

        agent_id = agent_id.strip().upper()

        if not InputValidator.AGENT_ID_PATTERN.match(agent_id):
            raise ValidationError("Invalid agent ID format (expected: AGENT-XXXX)")

        return agent_id

    @staticmethod
    def validate_event_id(event_id: str) -> str:
        """
        Validate event ID format
        """
        if not event_id:
            raise ValidationError("Event ID is required")

        event_id = event_id.strip()

        if not InputValidator.EVENT_ID_PATTERN.match(event_id):
            raise ValidationError("Invalid event ID format")

        return event_id

    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000, allow_html: bool = False) -> str:
        """
        Sanitize string input
        """
        if not isinstance(value, str):
            raise ValidationError("Value must be a string")

        # Strip whitespace
        value = value.strip()

        # Check length
        if len(value) > max_length:
            raise ValidationError(f"String too long (max: {max_length})")

        # Check for SQL injection patterns
        value_lower = value.lower()
        for pattern in InputValidator.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                logger.warning("Potential SQL injection detected", value=value[:100])
                raise ValidationError("Input contains potentially malicious content")

        # Sanitize HTML if not allowed
        if not allow_html:
            # Escape HTML entities
            value = html.escape(value)

            # Remove any script tags
            value = re.sub(r'<script[^>]*>.*?</script>', '', value, flags=re.IGNORECASE | re.DOTALL)

            # Remove event handlers
            value = re.sub(r'on\w+\s*=\s*["\']?[^"\']*["\']?', '', value, flags=re.IGNORECASE)

        else:
            # If HTML allowed, use bleach to sanitize
            allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li']
            allowed_attrs = {'a': ['href', 'title']}
            value = bleach.clean(value, tags=allowed_tags, attributes=allowed_attrs, strip=True)

        return value

    @staticmethod
    def validate_json_field(value: Any, field_name: str, required_keys: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Validate JSON/dict field
        """
        if not isinstance(value, dict):
            raise ValidationError(f"{field_name} must be a JSON object")

        # Check required keys
        if required_keys:
            missing = set(required_keys) - set(value.keys())
            if missing:
                raise ValidationError(f"{field_name} missing required keys: {missing}")

        # Recursively sanitize string values
        sanitized = {}
        for k, v in value.items():
            if isinstance(v, str):
                sanitized[k] = InputValidator.sanitize_string(v)
            elif isinstance(v, dict):
                sanitized[k] = InputValidator.validate_json_field(v, f"{field_name}.{k}")
            elif isinstance(v, list):
                sanitized[k] = [
                    InputValidator.sanitize_string(item) if isinstance(item, str) else item
                    for item in v
                ]
            else:
                sanitized[k] = v

        return sanitized

    @staticmethod
    def validate_integer(value: Any, min_value: Optional[int] = None, max_value: Optional[int] = None) -> int:
        """
        Validate integer with range check
        """
        try:
            value = int(value)
        except (ValueError, TypeError):
            raise ValidationError("Value must be an integer")

        if min_value is not None and value < min_value:
            raise ValidationError(f"Value must be >= {min_value}")

        if max_value is not None and value > max_value:
            raise ValidationError(f"Value must be <= {max_value}")

        return value

    @staticmethod
    def validate_timestamp(value: str) -> str:
        """
        Validate ISO 8601 timestamp
        """
        try:
            datetime.fromisoformat(value.replace('Z', '+00:00'))
            return value
        except (ValueError, AttributeError):
            raise ValidationError("Invalid timestamp format (expected ISO 8601)")

    @staticmethod
    def validate_kql_query(query: str) -> str:
        """
        Validate KQL query (basic validation)
        """
        if not query:
            return "*"

        query = query.strip()

        # Length check
        if len(query) > 10000:
            raise ValidationError("KQL query too long")

        # Basic syntax check (allow alphanumeric, operators, quotes, parentheses)
        if not re.match(r'^[a-zA-Z0-9\s\.\:\*\(\)\"\'\-\>\<\=\!\&\|\,\[\]]+$', query):
            raise ValidationError("KQL query contains invalid characters")

        return query

    @staticmethod
    def validate_file_path(path: str, allow_absolute: bool = False) -> str:
        """
        Validate file path (prevent directory traversal)
        """
        if not path:
            raise ValidationError("File path is required")

        path = path.strip()

        # Check for directory traversal patterns
        if '..' in path or path.startswith('/') or path.startswith('\\'):
            if not allow_absolute:
                raise ValidationError("Invalid file path (directory traversal not allowed)")

        # Check for null bytes
        if '\x00' in path:
            raise ValidationError("File path contains null bytes")

        # Length check
        if len(path) > 4096:
            raise ValidationError("File path too long")

        return path

    @staticmethod
    def validate_severity(severity: str) -> str:
        """
        Validate severity level
        """
        valid_severities = ['low', 'medium', 'high', 'critical']

        severity = severity.strip().lower()

        if severity not in valid_severities:
            raise ValidationError(f"Invalid severity (must be one of: {', '.join(valid_severities)})")

        return severity

    @staticmethod
    def validate_event_type(event_type: str) -> str:
        """
        Validate event type
        """
        valid_types = ['file', 'clipboard', 'usb', 'network', 'email', 'upload']

        event_type = event_type.strip().lower()

        if event_type not in valid_types:
            raise ValidationError(f"Invalid event type (must be one of: {', '.join(valid_types)})")

        return event_type

    @staticmethod
    def validate_classification_type(classification_type: str) -> str:
        """
        Validate classification type
        """
        valid_types = [
            'credit_card', 'ssn', 'email', 'phone', 'api_key',
            'password', 'private_key', 'aws_key', 'azure_key',
            'ip_address', 'medical_record', 'drivers_license'
        ]

        classification_type = classification_type.strip().lower()

        if classification_type not in valid_types:
            raise ValidationError(f"Invalid classification type")

        return classification_type

    @staticmethod
    def validate_action_type(action_type: str) -> str:
        """
        Validate policy action type
        """
        valid_actions = ['alert', 'block', 'quarantine', 'notify', 'redact', 'audit']

        action_type = action_type.strip().lower()

        if action_type not in valid_actions:
            raise ValidationError(f"Invalid action type (must be one of: {', '.join(valid_actions)})")

        return action_type


# Pydantic models with comprehensive validation

class ValidatedAgentRegistration(BaseModel):
    """Validated agent registration request"""
    name: str = Field(..., min_length=3, max_length=100)
    hostname: str = Field(..., min_length=1, max_length=253)
    ip: str
    os: str = Field(..., min_length=1, max_length=50)
    version: str = Field(..., min_length=1, max_length=50)

    @validator('name')
    def validate_name(cls, v):
        return InputValidator.sanitize_string(v, max_length=100)

    @validator('hostname')
    def validate_hostname(cls, v):
        return InputValidator.validate_hostname(v)

    @validator('ip')
    def validate_ip(cls, v):
        return InputValidator.validate_ip_address(v)

    @validator('os')
    def validate_os(cls, v):
        allowed_os = ['windows', 'linux', 'macos', 'unix']
        v_lower = v.lower()
        if not any(os in v_lower for os in allowed_os):
            raise ValueError(f"Invalid OS (expected: {', '.join(allowed_os)})")
        return v

    @validator('version')
    def validate_version(cls, v):
        # Basic semver validation
        if not re.match(r'^\d+\.\d+\.\d+', v):
            raise ValueError("Invalid version format (expected semver)")
        return v


class ValidatedEventSubmission(BaseModel):
    """Validated event submission"""
    event_id: str = Field(..., min_length=8, max_length=64)
    event_type: str
    severity: str
    timestamp: str
    agent_id: str
    content: Optional[str] = Field(None, max_length=1000000)  # 1MB max
    file: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

    @validator('event_id')
    def validate_event_id(cls, v):
        return InputValidator.validate_event_id(v)

    @validator('event_type')
    def validate_event_type(cls, v):
        return InputValidator.validate_event_type(v)

    @validator('severity')
    def validate_severity(cls, v):
        return InputValidator.validate_severity(v)

    @validator('timestamp')
    def validate_timestamp(cls, v):
        return InputValidator.validate_timestamp(v)

    @validator('agent_id')
    def validate_agent_id(cls, v):
        return InputValidator.validate_agent_id(v)

    @validator('content')
    def validate_content(cls, v):
        if v:
            return InputValidator.sanitize_string(v, max_length=1000000, allow_html=False)
        return v

    @validator('file')
    def validate_file(cls, v):
        if v:
            return InputValidator.validate_json_field(v, 'file', required_keys=['path'])
        return v

    @validator('metadata')
    def validate_metadata(cls, v):
        if v:
            return InputValidator.validate_json_field(v, 'metadata')
        return v


class ValidatedKQLQuery(BaseModel):
    """Validated KQL query"""
    query: str = Field(default="*", max_length=10000)
    size: Optional[int] = Field(default=100, ge=1, le=10000)
    start_date: Optional[str] = None
    end_date: Optional[str] = None

    @validator('query')
    def validate_query(cls, v):
        return InputValidator.validate_kql_query(v)

    @validator('start_date', 'end_date')
    def validate_dates(cls, v):
        if v:
            return InputValidator.validate_timestamp(v)
        return v


class ValidatedUserRegistration(BaseModel):
    """Validated user registration"""
    email: str
    password: str = Field(..., min_length=8, max_length=128)
    full_name: Optional[str] = Field(None, max_length=200)
    role: Optional[str] = Field(default="VIEWER")

    @validator('email')
    def validate_email(cls, v):
        return InputValidator.validate_email(v)

    @validator('password')
    def validate_password(cls, v):
        # Password strength validation
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")

        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain uppercase letters")

        if not any(c.islower() for c in v):
            raise ValueError("Password must contain lowercase letters")

        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain digits")

        if not any(not c.isalnum() for c in v):
            raise ValueError("Password must contain special characters")

        return v

    @validator('full_name')
    def validate_full_name(cls, v):
        if v:
            return InputValidator.sanitize_string(v, max_length=200)
        return v

    @validator('role')
    def validate_role(cls, v):
        valid_roles = ['ADMIN', 'ANALYST', 'VIEWER']
        if v not in valid_roles:
            raise ValueError(f"Invalid role (must be: {', '.join(valid_roles)})")
        return v


# Rate limiting helpers

class RateLimiter:
    """
    Simple rate limiter using Redis
    """

    def __init__(self, redis_client):
        self.redis = redis_client

    async def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int
    ) -> bool:
        """
        Check if rate limit is exceeded
        Returns True if within limit, False if exceeded
        """
        try:
            # Increment counter
            count = await self.redis.incr(key)

            # Set expiry on first request
            if count == 1:
                await self.redis.expire(key, window_seconds)

            # Check limit
            if count > max_requests:
                logger.warning(
                    "Rate limit exceeded",
                    key=key,
                    count=count,
                    limit=max_requests
                )
                return False

            return True

        except Exception as e:
            logger.error("Rate limit check failed", error=str(e))
            # Fail open (allow request if Redis is down)
            return True

    async def get_remaining(self, key: str, max_requests: int) -> int:
        """Get remaining requests in window"""
        try:
            count = await self.redis.get(key)
            if count is None:
                return max_requests
            return max(0, max_requests - int(count))
        except Exception:
            return max_requests
