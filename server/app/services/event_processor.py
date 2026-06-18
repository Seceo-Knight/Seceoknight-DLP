"""
Event Processor Service
Handles event validation, normalization, enrichment, classification, and policy evaluation
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import structlog
import re
import hashlib

from app.policies.database_policy_evaluator import DatabasePolicyEvaluator
from app.actions.action_executor import ActionExecutor
from app.actions.action_types import ExecutionSummary
from app.services.classification_engine import ClassificationEngine
import app.core.database as _db

logger = structlog.get_logger()


class EventProcessor:
    """
    Processes DLP events through multiple stages:
    1. Validation
    2. Normalization
    3. Enrichment
    4. Classification
    5. Policy Evaluation
    6. Action Execution
    """

    def __init__(
        self,
        policy_evaluator: Optional[DatabasePolicyEvaluator] = None,
        action_executor: Optional[ActionExecutor] = None,
    ):
        self.validators = []
        self.enrichers = []
        self.classifiers = []
        self.policy_evaluator = policy_evaluator or DatabasePolicyEvaluator()
        self.action_executor = action_executor or ActionExecutor()

    async def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single event through the pipeline

        Args:
            event: Raw event data

        Returns:
            Processed event data
        """
        try:
            # Stage 1: Validate
            validated_event = await self.validate_event(event)

            # Stage 2: Normalize
            normalized_event = await self.normalize_event(validated_event)

            # Stage 3: Enrich
            enriched_event = await self.enrich_event(normalized_event)

            # Stage 4: Classify
            classified_event = await self.classify_event(enriched_event)

            # Stage 5: Evaluate Policies (will be implemented with policy engine)
            evaluated_event = await self.evaluate_policies(classified_event)

            # Stage 6: Execute Actions (will be implemented with action executor)
            final_event = await self.execute_actions(evaluated_event)

            logger.info(
                "Event processed successfully",
                event_id=event.get("event_id"),
                stages_completed=6
            )

            return final_event

        except Exception as e:
            logger.error(
                "Event processing failed",
                event_id=event.get("event_id"),
                error=str(e)
            )
            raise

    async def validate_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate event structure and required fields

        Required fields:
        - event_id
        - agent (with id)
        - event (with type and severity)
        """
        # Check required fields
        if "event_id" not in event:
            raise ValueError("Missing required field: event_id")

        if "agent" not in event:
            raise ValueError("Missing required field: agent")

        if "id" not in event.get("agent", {}):
            raise ValueError("Missing required field: agent.id")

        if "event" not in event:
            raise ValueError("Missing required field: event")

        if "type" not in event.get("event", {}):
            raise ValueError("Missing required field: event.type")

        if "severity" not in event.get("event", {}):
            raise ValueError("Missing required field: event.severity")

        # Validate severity
        valid_severities = ["low", "medium", "high", "critical"]
        severity = event["event"]["severity"]
        if severity not in valid_severities:
            logger.warning(
                "Invalid severity, defaulting to medium",
                provided=severity,
                event_id=event.get("event_id")
            )
            event["event"]["severity"] = "medium"

        logger.debug("Event validated", event_id=event.get("event_id"))
        return event

    async def normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize event data to standard format

        - Ensure @timestamp is present
        - Normalize field names
        - Convert data types
        - Add default values
        """
        # Add timestamp if not present
        if "@timestamp" not in event:
            event["@timestamp"] = datetime.utcnow().isoformat()

        # Normalize status fields
        if "blocked" not in event:
            event["blocked"] = False

        if "quarantined" not in event:
            event["quarantined"] = False

        # Normalize agent fields
        if "agent" in event:
            agent = event["agent"]

            # Ensure all agent fields exist
            if "name" not in agent:
                agent["name"] = agent.get("id", "unknown")

            if "os" not in agent:
                agent["os"] = "unknown"

        # Normalize event fields
        if "event" in event:
            evt = event["event"]

            # Ensure outcome
            if "outcome" not in evt:
                evt["outcome"] = "success"

            # Ensure action
            if "action" not in evt:
                evt["action"] = "logged"

        # Preserve clipboard content field for clipboard events
        if event.get("event", {}).get("type") == "clipboard":
            if "clipboard_content" not in event and event.get("content"):
                event["clipboard_content"] = event["content"]

        # Add tags if not present
        if "tags" not in event:
            event["tags"] = []

        # Add metadata if not present
        if "metadata" not in event:
            event["metadata"] = {}

        logger.debug("Event normalized", event_id=event.get("event_id"))
        return event

    async def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich event with additional context

        - GeoIP lookup (if enabled)
        - User lookup (if available)
        - Threat intelligence (if enabled)
        - Historical context
        """
        # Add processing metadata
        event["metadata"]["processed_at"] = datetime.utcnow().isoformat()
        event["metadata"]["processor_version"] = "2.0.0"

        # Enrich with event type specific data
        event_type = event.get("event", {}).get("type")

        if event_type == "file":
            event = await self._enrich_file_event(event)
        elif event_type == "network":
            event = await self._enrich_network_event(event)
        elif event_type == "usb":
            event = await self._enrich_usb_event(event)

        # Add event type to tags
        if event_type and event_type not in event.get("tags", []):
            event.setdefault("tags", []).append(event_type)

        # Add OS to tags
        os_name = event.get("agent", {}).get("os")
        if os_name and os_name not in event.get("tags", []):
            event.setdefault("tags", []).append(os_name)

        logger.debug("Event enriched", event_id=event.get("event_id"))
        return event

    async def _enrich_file_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich file-specific events"""
        if "file" in event:
            file_info = event["file"]

            # Extract extension if path is present
            if "path" in file_info and "extension" not in file_info:
                path = file_info["path"]
                if "." in path:
                    extension = path.rsplit(".", 1)[-1].lower()
                    file_info["extension"] = f".{extension}"

            # Extract filename if path is present
            if "path" in file_info and "name" not in file_info:
                path = file_info["path"]
                # Handle both Windows and Unix paths
                if "\\" in path:
                    file_info["name"] = path.rsplit("\\", 1)[-1]
                else:
                    file_info["name"] = path.rsplit("/", 1)[-1]

            # Generate file hash if content is available
            if "content" in event and "hash" not in file_info:
                content = event["content"]
                if isinstance(content, str):
                    content_bytes = content.encode()
                    file_info.setdefault("hash", {})["sha256"] = hashlib.sha256(content_bytes).hexdigest()

        return event

    async def _enrich_network_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich network-specific events"""
        if "network" in event:
            network_info = event["network"]

            # Add direction if not present
            if "direction" not in network_info:
                # Try to infer from source/destination
                source_ip = network_info.get("source_ip", "")
                if source_ip.startswith("10.") or source_ip.startswith("192.168.") or source_ip.startswith("172."):
                    network_info["direction"] = "outbound"
                else:
                    network_info["direction"] = "inbound"

        return event

    async def _enrich_usb_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich USB-specific events"""
        if "usb" in event:
            usb_info = event["usb"]

            # Tag USB events
            if "usb" not in event.get("tags", []):
                event.setdefault("tags", []).append("usb")

            # Add device type tag if available
            if "vendor" in usb_info:
                vendor_tag = f"usb_vendor_{usb_info['vendor'].lower().replace(' ', '_')}"
                if vendor_tag not in event.get("tags", []):
                    event.setdefault("tags", []).append(vendor_tag)

        return event

    async def classify_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify event content for sensitive data using dynamic rule-based classification.

        Uses the ClassificationEngine with database rules for:
        - Credit card numbers (PAN)
        - Social Security Numbers (SSN)
        - Email addresses
        - Phone numbers
        - API keys
        - And many more patterns based on configured rules
        """
        # Get content to classify
        content = event.get("content") or event.get("content_redacted")

        if not content:
            # No content to classify
            return event

        if not isinstance(content, str):
            content = str(content)

        # Try to use ClassificationEngine with database rules
        try:
            if _db.postgres_session_factory:
                async with _db.postgres_session_factory() as session:
                    classification_engine = ClassificationEngine(session)

                    # Build context from event
                    context = {
                        "event_type": event.get("event", {}).get("type"),
                        "event_id": event.get("event_id"),
                        "agent_id": event.get("agent", {}).get("id"),
                        "file_extension": event.get("file", {}).get("extension"),
                        "source_type": event.get("source_type"),
                    }

                    # Classify content using database rules
                    result = await classification_engine.classify_content(content, context)

                    # Convert ClassificationEngine result to event format
                    if result.matched_rules:
                        classifications = []

                        for matched_rule in result.matched_rules:
                            classification = {
                                "type": matched_rule["rule_type"],
                                "label": matched_rule["rule_name"],
                                "confidence": result.confidence_score,
                                "patterns_matched": [matched_rule["rule_id"]],
                                "sensitive_data": {
                                    "type": matched_rule["rule_type"],
                                    "count": matched_rule["match_count"],
                                    "severity": matched_rule["severity"],
                                    "category": matched_rule["category"],
                                    "redacted": False
                                }
                            }
                            classifications.append(classification)

                            # Add classification tag
                            tag = f"contains_{matched_rule['rule_type']}"
                            if tag not in event.get("tags", []):
                                event.setdefault("tags", []).append(tag)

                            # Add category tag if available
                            if matched_rule["category"]:
                                category_tag = f"category_{matched_rule['category'].lower().replace(' ', '_')}"
                                if category_tag not in event.get("tags", []):
                                    event.setdefault("tags", []).append(category_tag)

                            # Increase severity based on classification level
                            if result.classification == "Restricted":
                                event["event"]["severity"] = "critical"
                            elif result.classification == "Confidential" and event["event"]["severity"] not in ["critical"]:
                                event["event"]["severity"] = "high"
                            elif result.classification == "Internal" and event["event"]["severity"] not in ["critical", "high"]:
                                event["event"]["severity"] = "medium"

                        # Add classifications to event
                        event["classification"] = classifications

                        # Add classification metadata
                        event["classification_metadata"] = {
                            "classification_level": result.classification,
                            "confidence_score": result.confidence_score,
                            "total_matches": result.total_matches,
                            "matched_rules_count": len(result.matched_rules),
                            "engine": "rule_based"
                        }

                        # Redact content if sensitive data found (Confidential or above)
                        if result.classification in ["Confidential", "Restricted"]:
                            event["content_redacted"] = "[REDACTED - Sensitive content detected]"
                            event.pop("content", None)

                            if event.get("event", {}).get("type") == "clipboard":
                                event.setdefault("clipboard_content", content)

                        logger.info(
                            "Content classified using rule engine",
                            event_id=event.get("event_id"),
                            classification=result.classification,
                            confidence=result.confidence_score,
                            matched_rules=len(result.matched_rules)
                        )

                        logger.debug("Event classified", event_id=event.get("event_id"), classifications_count=len(classifications))
                        return event
                    else:
                        # No rules matched
                        logger.debug("No rules matched for event", event_id=event.get("event_id"))
                        return event
            else:
                logger.warning("PostgreSQL session factory not available, skipping classification")
                return event

        except Exception as e:
            logger.error(
                "Failed to classify using rule engine, falling back to legacy patterns",
                event_id=event.get("event_id"),
                error=str(e)
            )
            # Fall through to legacy classification below

        # Legacy fallback: Use hardcoded patterns if rule engine fails
        classifications = []

        # Pattern-based classification
        patterns = {
            "credit_card": {
                "pattern": r'\b(?:\d{4}[\s-]?){3}\d{4}\b',
                "label": "PAN",
                "severity": "critical"
            },
            "ssn": {
                "pattern": r'\b\d{3}-\d{2}-\d{4}\b',
                "label": "SSN",
                "severity": "critical"
            },
            "email": {
                "pattern": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "label": "EMAIL",
                "severity": "medium"
            },
            "phone": {
                "pattern": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                "label": "PHONE",
                "severity": "low"
            },
            "api_key": {
                "pattern": r'\b[A-Za-z0-9_-]{32,}\b',
                "label": "API_KEY",
                "severity": "high"
            },
            # Indian identifiers
            "aadhaar": {
                "pattern": r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                "label": "AADHAAR",
                "severity": "critical"
            },
            "pan": {
                "pattern": r'\b[A-Z]{5}\d{4}[A-Z]{1}\b',
                "label": "PAN",
                "severity": "critical"
            },
            "ifsc": {
                "pattern": r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
                "label": "IFSC",
                "severity": "high"
            },
            "indian_bank_account": {
                "pattern": r'\b\d{9,18}\b',
                "label": "INDIAN_BANK_ACCOUNT",
                "severity": "high"
            },
            "indian_phone": {
                "pattern": r'\b(\+91|91|0)?[6-9]\d{9}\b',
                "label": "INDIAN_PHONE",
                "severity": "medium"
            },
            "upi_id": {
                "pattern": r'\b[\w.-]+@(paytm|phonepe|ybl|okaxis|okhdfcbank|oksbi|okicici)\b',
                "label": "UPI_ID",
                "severity": "high"
            },
            "micr": {
                "pattern": r'\b\d{9}\b',
                "label": "MICR",
                "severity": "medium"
            },
            "indian_dob": {
                "pattern": r'\b(0[1-9]|[12][0-9]|3[01])[/-](0[1-9]|1[0-2])[/-](19|20)\d{2}\b',
                "label": "INDIAN_DOB",
                "severity": "medium"
            },
            # Source code detection
            "source_code_content": {
                "pattern": r'\b(function|def|class|public|private|protected|static|import|from|require|include|using|package|const|let|var|int|string|float|bool)\s+\w+',
                "label": "SOURCE_CODE",
                "severity": "high"
            },
            "api_key_in_code": {
                "pattern": r'(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{32,}["\']?)',
                "label": "API_KEY_IN_CODE",
                "severity": "critical"
            },
            "database_connection_string": {
                "pattern": r'(jdbc:(mysql|postgresql|oracle|sqlserver)://|mongodb://|mongodb\+srv://|redis://|rediss://)',
                "label": "DATABASE_CONNECTION",
                "severity": "critical"
            }
        }

        for pattern_type, pattern_info in patterns.items():
            matches = re.findall(pattern_info["pattern"], content)

            if matches:
                classification = {
                    "type": pattern_type,
                    "label": pattern_info["label"],
                    "confidence": 1.0,  # Pattern match is 100% confident
                    "patterns_matched": [pattern_type],
                    "sensitive_data": {
                        "type": pattern_type,
                        "count": len(matches),
                        "redacted": False
                    }
                }
                classifications.append(classification)

                # Add classification tag
                tag = f"contains_{pattern_type}"
                if tag not in event.get("tags", []):
                    event.setdefault("tags", []).append(tag)

                # Increase severity if critical data found
                if pattern_info["severity"] == "critical":
                    event["event"]["severity"] = "critical"

                logger.info(
                    "Sensitive data detected",
                    event_id=event.get("event_id"),
                    pattern_type=pattern_type,
                    count=len(matches)
                )

        # Add classifications to event
        if classifications:
            event["classification"] = classifications

            # Redact content if sensitive data found
            event["content_redacted"] = self._redact_content(content, patterns)
            event.pop("content", None)  # Remove original content

            if event.get("event", {}).get("type") == "clipboard":
                event.setdefault("clipboard_content", content)

        logger.debug("Event classified", event_id=event.get("event_id"), classifications_count=len(classifications))
        return event

    def _redact_content(self, content: str, patterns: Dict[str, Any]) -> str:
        """
        Redact sensitive data from content

        Replaces sensitive patterns with [REDACTED]
        """
        redacted = content

        for pattern_info in patterns.values():
            pattern = pattern_info["pattern"]
            redacted = re.sub(pattern, "[REDACTED]", redacted)

        return redacted

    async def evaluate_policies(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate event against database-backed DLP policies.
        """
        matches = await self.policy_evaluator.evaluate_event(event)

        if not matches:
            logger.debug("No policies matched event", event_id=event.get("event_id"))
            return event

        event.setdefault("matched_policies", [])
        event.setdefault("policy_action_summaries", [])

        for match in matches:
            event["matched_policies"].append(
                {
                    "policy_id": match.policy_id,
                    "policy_name": match.policy_name,
                    "severity": match.severity,
                    "priority": match.priority,
                    "matched_rules": match.matched_rules,
                }
            )

            if not match.actions:
                continue

            summary: ExecutionSummary = await self.action_executor.execute_actions(
                event,
                match.actions,
                policy_id=match.policy_id,
                rule_id=match.rule_id,
            )

            event["policy_action_summaries"].append(summary.dict())

            if summary.blocked:
                event["blocked"] = True
            if summary.quarantined:
                event["quarantined"] = True

        # Matched-policy severity is the single source of truth for event
        # severity. Without this, an event that arrived with the default
        # "medium" (e.g. USB connect/disconnect, which has no content for
        # the classification stage to override severity) kept that default
        # even when a matching policy explicitly defined "low" / "high" /
        # etc. When multiple policies match, the highest severity wins so
        # the most serious classification surfaces in alerts/incidents.
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        candidate_severities = [m.severity for m in matches if m.severity]
        if candidate_severities:
            winning_severity = max(
                candidate_severities,
                key=lambda s: severity_rank.get(s, -1),
            )
            event.setdefault("event", {})
            event["event"]["severity"] = winning_severity

        logger.info(
            "Policies evaluated",
            event_id=event.get("event_id"),
            matched=len(matches),
        )
        return event

    async def execute_actions(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute actions based on policy evaluation

        Actions may include:
        - Blocking
        - Quarantining files
        - Sending alerts
        - Logging
        """
        if event.get("policy_action_summaries"):
            # Actions already executed via DatabasePolicyEvaluator
            return event

        # Legacy fallback for events processed without evaluator
        if event.get("blocked"):
            logger.info("Event remains blocked", event_id=event.get("event_id"))
        if event.get("quarantined"):
            logger.info("Event remains quarantined", event_id=event.get("event_id"))

        logger.debug("No additional actions executed", event_id=event.get("event_id"))
        return event

    async def process_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process multiple events in batch

        More efficient than processing one-by-one
        """
        processed_events = []

        for event in events:
            try:
                processed_event = await self.process_event(event)
                processed_events.append(processed_event)
            except Exception as e:
                logger.error(
                    "Failed to process event in batch",
                    event_id=event.get("event_id"),
                    error=str(e)
                )
                # Continue with other events

        logger.info(
            "Batch processing complete",
            total=len(events),
            processed=len(processed_events),
            failed=len(events) - len(processed_events)
        )

        return processed_events


# Singleton instance
_event_processor = None


def get_event_processor() -> EventProcessor:
    """
    Get singleton instance of EventProcessor
    """
    global _event_processor

    if _event_processor is None:
        _event_processor = EventProcessor()

    return _event_processor
