"""
Context Analyzer - False Positive Reduction Engine
===================================================
Analyzes the CONTEXT around detected sensitive patterns to determine
if they are real sensitive data or false positives (examples, docs,
test data, code comments, etc).

This is the KEY differentiator between regex-only DLP and ML-powered DLP.

Examples it catches:
- "SSN format: XXX-XX-XXXX" in documentation = NOT a violation
- "My SSN is 123-45-6789" in an email = REAL violation
- "4111111111111111" in test code = NOT a violation
- "Card: 4532-1234-5678-9012" in a spreadsheet = REAL violation
"""

import re
from typing import Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger()


# --- Context Indicators ---
# Phrases that suggest content is an EXAMPLE, not real sensitive data
FALSE_POSITIVE_INDICATORS = [
    # Documentation / educational context
    r"\bformat\s*(is|:)",
    r"\bexample\s*(:|is|of)",
    r"\bsample\s*(:|is|data)",
    r"\btest\s*(data|case|card|number|value)",
    r"\bplaceholder",
    r"\bdummy\s*(data|value|number)",
    r"\bfake\s*(data|number|card)",
    r"\bfor\s*testing",
    r"\bvalidat(e|ion|ing)",
    r"\btutorial",
    r"\bdocumentat(ion|ing)",
    r"\bhow\s*to",
    r"\bregex\s*(pattern|for|to)",
    r"\bpattern\s*(is|:)",
    r"\blike\s*this",
    r"\bfor\s*instance",
    r"\bsuch\s*as",
    r"\be\.?g\.?",
    r"\bi\.?e\.?",
    r"\blooks?\s*like",

    # Code context
    r"\bassert\b",
    r"\bdef\s+test_",
    r"\bfunction\s+test",
    r"\bdescribe\(",
    r"\bit\(",
    r"\bexpect\(",
    r"\bmock",
    r"\bfixture",
    r"\b(//|#|/\*|\*/)\s*",  # Comment indicators
    r"\bTODO\b",
    r"\bFIXME\b",
    r"\bconsole\.log",
    r"\bprint\(",
    r"\bString\s+(ssn|card|pan)",

    # Training / reference material
    r"\btraining\s*(material|doc|data)",
    r"\breference\s*(guide|doc)",
    r"\bcheat\s*sheet",
    r"\bquick\s*reference",
]

# Phrases that suggest content IS real sensitive data
TRUE_POSITIVE_INDICATORS = [
    # Possessive / personal context
    r"\bmy\s+(ssn|social|card|credit|password|aadhaar|pan)",
    r"\bhis\s+(ssn|social|card|password)",
    r"\bher\s+(ssn|social|card|password)",
    r"\btheir\s+(ssn|social|card|password)",
    r"\byour\s+(ssn|social|card|password)",

    # Action verbs suggesting real data handling
    r"\bsend(ing)?\s*(you|this|the)",
    r"\bhere\s*(is|are)\s*(my|the|your)",
    r"\battach(ed|ing)",
    r"\bplease\s*(find|see|use|note)",
    r"\bfor\s*(your|the)\s*records?",
    r"\bconfidential",
    r"\bdo\s*not\s*(share|forward|distribute)",
    r"\bprivate",
    r"\bsecret",
    r"\bsensitive\s*(info|data|document)",

    # Data transfer context
    r"\bexport(ed|ing)?",
    r"\bdownload(ed|ing)?",
    r"\bcopy(ing|ied)?",
    r"\btransfer(ring|red)?",
    r"\bupload(ed|ing)?",
    r"\bforward(ed|ing)?",

    # Patient / employee / customer context
    r"\bpatient\s*(id|name|record|data|ssn)",
    r"\bemployee\s*(id|ssn|record|data|salary)",
    r"\bcustomer\s*(data|record|info|pii)",
    r"\bpayroll",
    r"\bhr\s*(record|data|file)",
]

# Known test/example values that are always false positives
KNOWN_TEST_VALUES = [
    "123-45-6789",       # Universal test SSN
    "000-00-0000",       # Invalid SSN
    "111-11-1111",       # Repeated digits SSN
    "4111111111111111",  # Visa test card
    "4111-1111-1111-1111",
    "5500000000000004",  # MC test card
    "378282246310005",   # Amex test card
    "6011111111111117",  # Discover test card
    "ABCDE1234F",        # Example PAN
    "0000 0000 0000",    # Example Aadhaar
    "1234 5678 9012",    # Example Aadhaar
    "AKIAIOSFODNN7EXAMPLE",  # AWS example key
    "sk_test_",          # Stripe test key prefix
    "pk_test_",          # Stripe test key prefix
]

# File extensions / paths that indicate test/example context
TEST_FILE_PATTERNS = [
    r"test[_/]",
    r"spec[_/]",
    r"__test__",
    r"fixture",
    r"mock",
    r"example",
    r"sample",
    r"demo",
    r"tutorial",
    r"docs?[_/]",
    r"README",
    r"CHANGELOG",
    r"\.md$",
    r"\.rst$",
    r"\.test\.",
    r"\.spec\.",
]


class ContextAnalysisResult:
    """Result of context analysis."""

    def __init__(
        self,
        is_false_positive: bool,
        confidence_adjustment: float,
        reason: str,
        fp_indicators_found: List[str],
        tp_indicators_found: List[str],
        is_test_value: bool,
        is_test_file: bool,
    ):
        self.is_false_positive = is_false_positive
        self.confidence_adjustment = confidence_adjustment
        self.reason = reason
        self.fp_indicators_found = fp_indicators_found
        self.tp_indicators_found = tp_indicators_found
        self.is_test_value = is_test_value
        self.is_test_file = is_test_file

    def to_dict(self) -> Dict:
        return {
            "is_false_positive": self.is_false_positive,
            "confidence_adjustment": round(self.confidence_adjustment, 3),
            "reason": self.reason,
            "fp_indicators_found": self.fp_indicators_found,
            "tp_indicators_found": self.tp_indicators_found,
            "is_test_value": self.is_test_value,
            "is_test_file": self.is_test_file,
        }


class ContextAnalyzer:
    """
    Analyzes context around detected sensitive patterns to determine
    if they are real violations or false positives.

    Used AFTER regex/ML detection to adjust confidence scores.
    """

    def __init__(self):
        # Pre-compile regex patterns for performance
        self._fp_patterns = [
            re.compile(p, re.IGNORECASE) for p in FALSE_POSITIVE_INDICATORS
        ]
        self._tp_patterns = [
            re.compile(p, re.IGNORECASE) for p in TRUE_POSITIVE_INDICATORS
        ]
        self._test_file_patterns = [
            re.compile(p, re.IGNORECASE) for p in TEST_FILE_PATTERNS
        ]

    def analyze(
        self,
        content: str,
        matched_values: List[str],
        metadata: Optional[Dict] = None,
    ) -> ContextAnalysisResult:
        """
        Analyze context to determine if detection is a false positive.

        Args:
            content: Full content that was scanned.
            matched_values: List of matched sensitive values (e.g. SSN strings).
            metadata: Optional context (filename, source, event_type).

        Returns:
            ContextAnalysisResult with adjustment recommendation.
        """
        fp_indicators = []
        tp_indicators = []
        is_test_value = False
        is_test_file = False

        # Check 1: Is this a known test/example value?
        for value in matched_values:
            clean_value = value.strip().replace(" ", "").replace("-", "")
            for test_val in KNOWN_TEST_VALUES:
                clean_test = test_val.replace(" ", "").replace("-", "")
                if clean_value == clean_test or value.startswith(test_val[:8]):
                    is_test_value = True
                    fp_indicators.append(f"known_test_value:{test_val}")
                    break

        # Check 2: Is this from a test/documentation file?
        if metadata:
            filename = metadata.get("filename", "") or ""
            filepath = metadata.get("filepath", "") or ""
            full_path = f"{filepath}/{filename}"

            for pattern in self._test_file_patterns:
                if pattern.search(full_path):
                    is_test_file = True
                    fp_indicators.append(f"test_file:{pattern.pattern}")
                    break

        # Check 3: Look for false positive context indicators in text
        # Use a window around matched values for context analysis
        context_windows = self._extract_context_windows(content, matched_values)
        analysis_text = " ".join(context_windows) if context_windows else content[:2000]

        for pattern in self._fp_patterns:
            match = pattern.search(analysis_text)
            if match:
                fp_indicators.append(match.group(0).strip())

        # Check 4: Look for true positive indicators
        for pattern in self._tp_patterns:
            match = pattern.search(analysis_text)
            if match:
                tp_indicators.append(match.group(0).strip())

        # Decision logic
        fp_score = len(fp_indicators)
        tp_score = len(tp_indicators)

        # Strong false positive signals
        if is_test_value and not tp_indicators:
            return ContextAnalysisResult(
                is_false_positive=True,
                confidence_adjustment=-0.8,
                reason=f"Known test value detected with no real-data context",
                fp_indicators_found=fp_indicators,
                tp_indicators_found=tp_indicators,
                is_test_value=is_test_value,
                is_test_file=is_test_file,
            )

        if is_test_file and fp_score > 0 and tp_score == 0:
            return ContextAnalysisResult(
                is_false_positive=True,
                confidence_adjustment=-0.7,
                reason="Test/documentation file with example context",
                fp_indicators_found=fp_indicators,
                tp_indicators_found=tp_indicators,
                is_test_value=is_test_value,
                is_test_file=is_test_file,
            )

        if fp_score >= 3 and tp_score == 0:
            return ContextAnalysisResult(
                is_false_positive=True,
                confidence_adjustment=-0.6,
                reason=f"Multiple false positive indicators ({fp_score}) with no real-data signals",
                fp_indicators_found=fp_indicators,
                tp_indicators_found=tp_indicators,
                is_test_value=is_test_value,
                is_test_file=is_test_file,
            )

        # Mixed signals: reduce confidence but don't mark as false positive
        if fp_score > tp_score and fp_score >= 2:
            adjustment = -0.3 * (fp_score / (fp_score + tp_score))
            return ContextAnalysisResult(
                is_false_positive=False,
                confidence_adjustment=adjustment,
                reason=f"Mixed signals: {fp_score} FP vs {tp_score} TP indicators",
                fp_indicators_found=fp_indicators,
                tp_indicators_found=tp_indicators,
                is_test_value=is_test_value,
                is_test_file=is_test_file,
            )

        # Strong true positive signals: boost confidence
        if tp_score >= 2 and fp_score == 0:
            adjustment = min(0.2, tp_score * 0.05)
            return ContextAnalysisResult(
                is_false_positive=False,
                confidence_adjustment=adjustment,
                reason=f"Strong real-data context ({tp_score} indicators)",
                fp_indicators_found=fp_indicators,
                tp_indicators_found=tp_indicators,
                is_test_value=is_test_value,
                is_test_file=is_test_file,
            )

        # Neutral: no strong signals either way
        return ContextAnalysisResult(
            is_false_positive=False,
            confidence_adjustment=0.0,
            reason="No strong context signals",
            fp_indicators_found=fp_indicators,
            tp_indicators_found=tp_indicators,
            is_test_value=is_test_value,
            is_test_file=is_test_file,
        )

    def _extract_context_windows(
        self, content: str, matched_values: List[str], window_size: int = 100
    ) -> List[str]:
        """
        Extract text windows around each matched value for context analysis.
        """
        windows = []
        content_lower = content.lower()

        for value in matched_values:
            idx = content_lower.find(value.lower())
            if idx == -1:
                # Try partial match (first 8 chars)
                idx = content_lower.find(value[:8].lower())

            if idx != -1:
                start = max(0, idx - window_size)
                end = min(len(content), idx + len(value) + window_size)
                windows.append(content[start:end])

        return windows

    def analyze_batch(
        self,
        content: str,
        detections: List[Dict],
        metadata: Optional[Dict] = None,
    ) -> List[Tuple[Dict, ContextAnalysisResult]]:
        """
        Analyze context for multiple detections in the same content.
        More efficient than calling analyze() per detection.

        Args:
            content: Full content.
            detections: List of detection dicts with 'matched_text' key.
            metadata: Optional file/event metadata.

        Returns:
            List of (detection, context_result) tuples.
        """
        results = []
        for detection in detections:
            matched = [detection.get("matched_text", "")]
            result = self.analyze(content, matched, metadata)
            results.append((detection, result))
        return results


# Module-level singleton
_context_analyzer = None


def get_context_analyzer() -> ContextAnalyzer:
    """Get the singleton ContextAnalyzer instance."""
    global _context_analyzer
    if _context_analyzer is None:
        _context_analyzer = ContextAnalyzer()
    return _context_analyzer
