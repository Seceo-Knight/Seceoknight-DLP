"""
Production-Grade Classification Engine (v2)

Multi-technique sensitive data detection:
  1. Pattern-based: Regex with precompilation + validation (Luhn, Verhoeff)
  2. Keyword matching: Case-sensitive and case-insensitive
  3. File fingerprinting: SHA-256 exact hash matching
  4. Entropy analysis: Shannon entropy for detecting encoded/encrypted data
  5. Context-aware: File type and source metadata influence scoring
  6. Dictionary: External wordlist matching with set intersection

Classification levels (by confidence score):
  - 0.0 - 0.3: Public
  - 0.3 - 0.6: Internal
  - 0.6 - 0.8: Confidential
  - 0.8 - 1.0: Restricted
"""

from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import re
import math
import hashlib
import structlog
from pathlib import Path
from collections import Counter

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.rule import Rule
from app.models.data_label import DataLabel

logger = structlog.get_logger()

# Module-level cache — shared across all engine instances within a worker.
# Cleared by the /cache/invalidate endpoint.
_module_cache: Dict[str, Any] = {
    "rules": [],
    "expires_at": None,
    "regex": {},
    "dictionary": {},
}


def clear_module_cache():
    """Called by the cache invalidation endpoint."""
    _module_cache["rules"] = []
    _module_cache["expires_at"] = None
    _module_cache["regex"].clear()
    _module_cache["dictionary"].clear()
    logger.info("Classification module-level caches cleared")


# ────────────────────────────────────────────────────────────────────────────
# Validation helpers (Luhn, Verhoeff, Shannon entropy)
# ────────────────────────────────────────────────────────────────────────────

def luhn_check(number_str: str) -> bool:
    """Validate a number string using the Luhn algorithm (credit cards)."""
    digits = [int(d) for d in number_str if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# Verhoeff algorithm tables for Aadhaar validation
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_check(number_str: str) -> bool:
    """Validate a number string using the Verhoeff algorithm (Aadhaar)."""
    digits = [int(d) for d in number_str if d.isdigit()]
    if len(digits) != 12:
        return False
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][d]]
    return c == 0


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random/compressed/encrypted."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# File types with higher risk multiplier
_HIGH_RISK_EXTENSIONS = frozenset({
    ".xlsx", ".xls", ".csv", ".tsv", ".sql", ".db", ".sqlite",
    ".json", ".xml", ".yaml", ".yml", ".env", ".conf", ".cfg",
    ".pem", ".key", ".p12", ".pfx", ".cer",
})
_MEDIUM_RISK_EXTENSIONS = frozenset({
    ".docx", ".doc", ".pdf", ".txt", ".rtf", ".odt",
    ".pptx", ".ppt",
})

# Sources with higher risk multiplier
_HIGH_RISK_SOURCES = frozenset({"clipboard", "usb", "removable", "email", "cloud"})


@dataclass
class ClassificationResult:
    """Result of classification analysis"""
    classification: str
    confidence_score: float
    matched_rules: List[Dict[str, Any]]
    total_matches: int
    details: Dict[str, Any]
    entropy_score: float = 0.0
    data_types: List[str] = field(default_factory=list)


class ClassificationEngine:
    """
    Production classification engine with multi-technique detection.

    Techniques:
      1. Fingerprint matching (SHA-256, authoritative)
      2. Regex pattern matching (precompiled, cached)
      3. Keyword matching (case-sensitive/insensitive)
      4. Dictionary matching (external wordlists)
      5. Entropy analysis (encoded/encrypted content detection)
      6. Context-aware scoring (file type, source channel)
    """

    # Content size limits to prevent DoS
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB
    MAX_REGEX_TIMEOUT_CHARS = 1_000_000     # Limit regex evaluation to first 1M chars

    def __init__(self, session: AsyncSession, cache_ttl_seconds: int = 60):
        self.session = session
        self._cache_ttl = timedelta(seconds=cache_ttl_seconds)

    async def classify_content(
        self,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ClassificationResult:
        """
        Full classification pipeline:
          1. Fingerprint check (authoritative — stops if matched)
          2. Entropy analysis
          3. Regex pattern matching
          4. Keyword matching
          5. Dictionary matching
          6. Context-aware score adjustment
          7. Determine classification level
        """
        if not content or not isinstance(content, str):
            return ClassificationResult(
                classification="Public",
                confidence_score=0.0,
                matched_rules=[],
                total_matches=0,
                details={"reason": "No content to classify"},
            )

        # Truncate oversized content to prevent DoS
        eval_content = content[:self.MAX_CONTENT_LENGTH]
        ctx = context or {}

        # Step 1: Fingerprint check (authoritative)
        fp_match = None
        try:
            fp_match = await self._check_fingerprint(eval_content)
        except Exception as e:
            logger.warning("Fingerprint check failed", error=str(e))

        if fp_match:
            return ClassificationResult(
                classification="Restricted",
                confidence_score=1.0,
                matched_rules=[fp_match],
                total_matches=1,
                details={
                    "content_length": len(eval_content),
                    "rules_evaluated": 0,
                    "context": ctx,
                    "method": "fingerprint",
                },
            )

        # Step 2: Entropy analysis
        # Use a sample for performance (first 10K chars)
        entropy = shannon_entropy(eval_content[:10000])

        # Step 3-5: Rule evaluation
        rules = await self._get_cached_rules()
        if not rules:
            return ClassificationResult(
                classification="Public",
                confidence_score=0.0,
                matched_rules=[],
                total_matches=0,
                details={"reason": "No rules available"},
            )

        matched_rules: List[Dict[str, Any]] = []
        total_weight = 0.0
        total_matches = 0
        data_types: List[str] = []

        for rule in rules:
            # Context-aware filtering: skip rules that don't apply to this file type
            if rule.file_types and ctx.get("file_type"):
                if ctx["file_type"].lower() not in [ft.lower() for ft in rule.file_types]:
                    continue

            matches, match_count, validated_count = await self._evaluate_rule_with_validation(
                rule, eval_content, ctx
            )

            if matches and validated_count >= rule.threshold:
                rule_result = self._build_rule_result(rule, validated_count)
                matched_rules.append(rule_result)

                # Confidence contribution: scale with match count above threshold
                # but cap at 2x weight for very high match counts
                if rule.threshold > 0:
                    scale = min(2.0, validated_count / rule.threshold)
                else:
                    scale = 1.0
                contribution = rule.weight * scale
                total_weight += contribution
                total_matches += validated_count

                # Track data types
                if rule.classification_labels:
                    for label in rule.classification_labels:
                        if label not in data_types:
                            data_types.append(label)

        # Step 6: Correlation analysis — detect multi-signal patterns
        correlation_result = self._correlate_signals(eval_content, matched_rules, data_types)
        if correlation_result:
            matched_rules.extend(correlation_result["extra_rules"])
            total_weight += correlation_result["bonus_weight"]
            total_matches += correlation_result["extra_matches"]
            for dt in correlation_result.get("extra_types", []):
                if dt not in data_types:
                    data_types.append(dt)

        # Step 7: Context-aware score adjustment
        context_multiplier = self._compute_context_multiplier(ctx)
        adjusted_weight = total_weight * context_multiplier

        # Entropy bonus: high entropy content with pattern matches is more suspicious
        entropy_bonus = 0.0
        if entropy > 5.0 and total_matches > 0:
            entropy_bonus = 0.05

        confidence_score = min(1.0, adjusted_weight + entropy_bonus)
        classification = self._determine_classification(confidence_score)

        return ClassificationResult(
            classification=classification,
            confidence_score=round(confidence_score, 4),
            matched_rules=matched_rules,
            total_matches=total_matches,
            details={
                "content_length": len(eval_content),
                "rules_evaluated": len(rules),
                "context": ctx,
                "context_multiplier": context_multiplier,
                "entropy_score": round(entropy, 4),
                "method": "multi_technique_correlated",
                "correlation": correlation_result.get("signals", []) if correlation_result else [],
            },
            entropy_score=round(entropy, 4),
            data_types=data_types,
        )

    async def _evaluate_rule_with_validation(
        self,
        rule: Rule,
        content: str,
        context: Optional[Dict[str, Any]],
    ) -> Tuple[bool, int, int]:
        """
        Evaluate a rule and apply secondary validation (Luhn, Verhoeff).

        Returns:
            (matched: bool, raw_match_count: int, validated_count: int)
        """
        try:
            if rule.type == "regex":
                return await self._evaluate_regex_with_validation(rule, content)
            elif rule.type == "keyword":
                matched, count = await self._evaluate_keyword_rule(rule, content)
                return matched, count, count
            elif rule.type == "dictionary":
                matched, count = await self._evaluate_dictionary_rule(rule, content)
                return matched, count, count
            else:
                return False, 0, 0
        except Exception as e:
            logger.error("Rule evaluation failed", rule_name=rule.name, error=str(e))
            return False, 0, 0

    async def _evaluate_regex_with_validation(
        self, rule: Rule, content: str
    ) -> Tuple[bool, int, int]:
        """Evaluate regex rule with secondary validation for known patterns."""
        if not rule.pattern:
            return False, 0, 0

        pattern = self._get_compiled_regex(rule)
        if pattern is None:
            return False, 0, 0

        # Limit regex evaluation to prevent ReDoS
        eval_text = content[:self.MAX_REGEX_TIMEOUT_CHARS]
        raw_matches = pattern.findall(eval_text)
        raw_count = len(raw_matches)

        if raw_count == 0:
            return False, 0, 0

        # Apply secondary validation based on rule category
        category = (rule.category or "").lower()
        labels = [l.upper() for l in (rule.classification_labels or [])]

        validated_count = raw_count

        if "CREDIT_CARD" in labels or "PCI" in labels:
            # Luhn validation — ONLY for credit card rules, not all financial rules
            validated = 0
            for match in raw_matches:
                match_str = match if isinstance(match, str) else str(match)
                digits_only = re.sub(r'\D', '', match_str)
                if luhn_check(digits_only):
                    validated += 1
            validated_count = validated

        elif "AADHAAR" in labels:
            # Aadhaar: format match is sufficient for DLP detection.
            # Verhoeff is NOT a gate — real leaked numbers may have typos.
            # All format-matched 12-digit numbers are counted.
            validated_count = raw_count

        # Filter out matches inside code comments (// or # or /* */)
        if validated_count > 0 and ("API" in labels or "CREDENTIALS" in labels):
            # Check if the match is likely in a code comment or example
            comment_pattern = re.compile(
                r'(?:^|\n)\s*(?://|#|/\*|\*|<!--).*$', re.MULTILINE
            )
            non_comment_text = comment_pattern.sub('', eval_text)
            non_comment_matches = pattern.findall(non_comment_text)
            validated_count = len(non_comment_matches)

        return validated_count > 0, raw_count, validated_count

    def _get_compiled_regex(self, rule: Rule) -> Optional[re.Pattern]:
        """Get compiled regex from module-level cache or compile and cache it."""
        pattern_key = f"{rule.id}:{rule.pattern}"
        if pattern_key in _module_cache["regex"]:
            return _module_cache["regex"][pattern_key]

        flags = 0
        if rule.regex_flags:
            for flag_name in rule.regex_flags:
                if hasattr(re, flag_name):
                    flags |= getattr(re, flag_name)
        try:
            compiled = re.compile(rule.pattern, flags)
            _module_cache["regex"][pattern_key] = compiled
            return compiled
        except re.error as e:
            logger.error("Invalid regex pattern", rule_name=rule.name, error=str(e))
            return None

    async def _evaluate_keyword_rule(self, rule: Rule, content: str) -> Tuple[bool, int]:
        """Evaluate keyword matching rule."""
        if not rule.keywords:
            return False, 0

        if rule.case_sensitive:
            search_content = content
            search_keywords = rule.keywords
        else:
            search_content = content.lower()
            search_keywords = [kw.lower() for kw in rule.keywords]

        match_count = 0
        for keyword in search_keywords:
            count = search_content.count(keyword)
            match_count += count

        return match_count > 0, match_count

    async def _evaluate_dictionary_rule(self, rule: Rule, content: str) -> Tuple[bool, int]:
        """Evaluate dictionary-based rule."""
        if not rule.dictionary_path:
            return False, 0

        dict_key = f"{rule.id}:{rule.dictionary_path}"
        if dict_key not in _module_cache["dictionary"]:
            try:
                words = await self._load_dictionary(rule.dictionary_path)
                _module_cache["dictionary"][dict_key] = words
            except Exception as e:
                logger.error("Dictionary load failed", rule_name=rule.name, error=str(e))
                return False, 0

        dictionary = _module_cache["dictionary"][dict_key]
        content_words = set(re.findall(r'\b\w+\b', content.lower()))
        matched_words = content_words & dictionary
        return len(matched_words) > 0, len(matched_words)

    async def _load_dictionary(self, path: str) -> Set[str]:
        """Load dictionary file into a set of lowercase words."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Dictionary file not found: {path}")

        words: Set[str] = set()
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip().lower()
                if word:
                    words.add(word)

        logger.info("Dictionary loaded", path=path, word_count=len(words))
        return words

    async def _check_fingerprint(self, content: str) -> Optional[Dict[str, Any]]:
        """Check content hash against known file fingerprints."""
        from app.models.file_fingerprint import FileFingerprint
        from sqlalchemy.orm import selectinload

        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        stmt = (
            select(FileFingerprint)
            .where(FileFingerprint.hash == content_hash)
            .options(selectinload(FileFingerprint.label))
        )
        result = await self.session.execute(stmt)
        fp = result.scalar_one_or_none()

        if fp:
            rule_result = {
                "rule_id": str(fp.id),
                "rule_name": f"Fingerprint: {fp.file_name or fp.hash[:16]}",
                "rule_type": "fingerprint",
                "match_count": 1,
                "weight": 1.0,
                "priority": 0,
                "classification_labels": [],
                "severity": "critical",
                "category": "Fingerprint Match",
            }
            if fp.label:
                rule_result["label"] = {
                    "id": str(fp.label.id),
                    "name": fp.label.name,
                    "severity": fp.label.severity,
                    "color": fp.label.color,
                }
            return rule_result
        return None

    async def _get_cached_rules(self) -> List[Rule]:
        """Get enabled rules with module-level caching."""
        now = datetime.now(timezone.utc)
        expires = _module_cache.get("expires_at")
        if expires and expires > now and _module_cache["rules"]:
            return _module_cache["rules"]

        from sqlalchemy.orm import selectinload
        stmt = (
            select(Rule)
            .where(Rule.enabled == True)
            .where(Rule.deleted_at == None)  # noqa: E711 — SQLAlchemy requires == None
            .options(selectinload(Rule.label))
            .order_by(Rule.priority.asc(), Rule.weight.desc())
        )
        result = await self.session.execute(stmt)
        rules = list(result.scalars().all())

        _module_cache["rules"] = rules
        _module_cache["expires_at"] = now + self._cache_ttl

        logger.info("Rule cache refreshed", rule_count=len(rules))
        return rules

    # ── Banking context keywords for correlation scoring ────────────────
    _BANKING_KEYWORDS = frozenset({
        "account", "acc", "acct", "a/c", "bank", "beneficiary",
        "saving", "savings", "current", "deposit", "neft", "rtgs",
        "imps", "ifsc", "branch", "cheque", "check", "transfer",
        "wire", "remittance", "balance", "statement", "passbook",
        "micr", "swift", "iban", "routing", "sort code",
    })

    _PII_KEYWORDS = frozenset({
        "name", "dob", "date of birth", "address", "father",
        "mother", "spouse", "gender", "nationality", "passport",
        "voter", "driving", "license", "employee", "salary",
        "compensation", "social security",
    })

    def _correlate_signals(
        self,
        content: str,
        existing_rules: List[Dict[str, Any]],
        existing_types: List[str],
    ) -> Optional[Dict[str, Any]]:
        """
        Multi-signal correlation — detects when multiple weak signals
        combine into a strong indicator of sensitive data.

        Scoring system:
          +50 → IFSC code detected
          +40 → PAN card detected
          +30 → Aadhaar detected
          +20 → Numeric pattern (9-18 digits) near banking keywords
          +20 → Banking keyword context present
          +15 → PII keyword context present
          +10 → Multiple structured IDs in same content

        Thresholds:
          score >= 70 → RESTRICTED (weight 0.95)
          score >= 50 → CONFIDENTIAL (weight 0.7)
          score >= 30 → INTERNAL (weight 0.4)
        """
        content_lower = content.lower()
        score = 0
        signals: List[str] = []
        extra_rules: List[Dict[str, Any]] = []
        extra_types: List[str] = []

        # Already-detected signal types from rule evaluation
        detected_set = set(t.upper() for t in existing_types)

        # Score existing detections
        if "IFSC" in detected_set or "IFSC_CODE" in detected_set:
            score += 50
            signals.append("IFSC_DETECTED(+50)")
        if "PAN" in detected_set or "PAN_CARD" in detected_set or "TAX" in detected_set:
            score += 40
            signals.append("PAN_DETECTED(+40)")
        if "AADHAAR" in detected_set:
            score += 30
            signals.append("AADHAAR_DETECTED(+30)")
        if "CREDIT_CARD" in detected_set or "PCI" in detected_set:
            score += 40
            signals.append("CREDIT_CARD_DETECTED(+40)")
        if "SSN" in detected_set:
            score += 40
            signals.append("SSN_DETECTED(+40)")
        if "BANK_ACCOUNT" in detected_set:
            score += 40
            signals.append("BANK_ACCOUNT_DETECTED(+40)")

        # Stage 1: Detect unstructured numeric candidates (9-18 digits)
        # that weren't caught by specific rules
        candidate_numbers = re.findall(r'(?<!\d)\d{9,18}(?!\d)', content)
        uncaught_candidates = []
        for num in candidate_numbers:
            # Skip if already matched by a specific rule
            already_matched = False
            for rule in existing_rules:
                if num in str(rule.get("match_count", "")):
                    already_matched = True
                    break
            if not already_matched:
                uncaught_candidates.append(num)

        if uncaught_candidates:
            score += 10
            signals.append(f"NUMERIC_CANDIDATES({len(uncaught_candidates)})(+10)")

        # Stage 2: Banking keyword context
        banking_hits = [kw for kw in self._BANKING_KEYWORDS if kw in content_lower]
        if banking_hits:
            score += 20
            signals.append(f"BANKING_CONTEXT({','.join(banking_hits[:3])})(+20)")

            # If we have numeric candidates + banking context = likely account number
            if uncaught_candidates:
                score += 20
                signals.append("NUMERIC+BANKING_CORRELATION(+20)")
                extra_types.append("BANK_ACCOUNT_CANDIDATE")
                extra_rules.append({
                    "rule_id": "correlation-bank",
                    "rule_name": "Correlation: Bank Account (context)",
                    "rule_type": "correlation",
                    "match_count": len(uncaught_candidates),
                    "weight": 0.0,  # Weight handled by correlation score
                    "priority": 0,
                    "classification_labels": ["FINANCIAL", "BANK_ACCOUNT"],
                    "severity": "high",
                    "category": "Correlation",
                    "label": None,
                })

        # Stage 3: PII keyword context
        pii_hits = [kw for kw in self._PII_KEYWORDS if kw in content_lower]
        if pii_hits:
            score += 15
            signals.append(f"PII_CONTEXT({','.join(pii_hits[:3])})(+15)")

        # Stage 4: Multi-signal correlation bonus
        structured_count = sum(1 for t in detected_set if t in {
            "IFSC", "PAN", "PAN_CARD", "TAX", "AADHAAR",
            "CREDIT_CARD", "SSN", "BANK_ACCOUNT",
        })
        if structured_count >= 2:
            score += 10 * (structured_count - 1)
            signals.append(f"MULTI_SIGNAL({structured_count} types)(+{10*(structured_count-1)})")

        # No correlation signals found
        if score == 0:
            return None

        # Convert score to weight bonus
        if score >= 70:
            bonus_weight = 0.95
        elif score >= 50:
            bonus_weight = 0.7
        elif score >= 30:
            bonus_weight = 0.4
        else:
            bonus_weight = 0.1

        # Don't add bonus if rules already gave high confidence
        existing_weight = sum(r.get("weight", 0) for r in existing_rules)
        if existing_weight >= 0.8:
            bonus_weight = max(0, bonus_weight - existing_weight)

        return {
            "score": score,
            "signals": signals,
            "bonus_weight": round(bonus_weight, 4),
            "extra_rules": extra_rules,
            "extra_matches": len(uncaught_candidates),
            "extra_types": extra_types,
        }

    def _compute_context_multiplier(self, ctx: Dict[str, Any]) -> float:
        """
        Compute a score multiplier based on context metadata.

        High-risk file types and channels increase the score.
        """
        multiplier = 1.0

        file_type = (ctx.get("file_type") or "").lower()
        source = (ctx.get("source") or ctx.get("channel") or "").lower()

        if file_type in _HIGH_RISK_EXTENSIONS:
            multiplier *= 1.2
        elif file_type in _MEDIUM_RISK_EXTENSIONS:
            multiplier *= 1.1

        if source in _HIGH_RISK_SOURCES:
            multiplier *= 1.15

        return multiplier

    def _build_rule_result(self, rule: Rule, match_count: int) -> Dict[str, Any]:
        """Build a standardized rule result dictionary."""
        result: Dict[str, Any] = {
            "rule_id": str(rule.id),
            "rule_name": rule.name,
            "rule_type": rule.type,
            "match_count": match_count,
            "weight": rule.weight,
            "priority": rule.priority,
            "classification_labels": rule.classification_labels or [],
            "severity": rule.severity,
            "category": rule.category,
        }
        if rule.label:
            result["label"] = {
                "id": str(rule.label.id),
                "name": rule.label.name,
                "severity": rule.label.severity,
                "color": rule.label.color,
            }
        else:
            result["label"] = None
        return result

    def _determine_classification(self, confidence_score: float) -> str:
        """Map confidence score to classification level."""
        if confidence_score >= 0.8:
            return "Restricted"
        elif confidence_score >= 0.6:
            return "Confidential"
        elif confidence_score >= 0.3:
            return "Internal"
        else:
            return "Public"

    def clear_cache(self):
        """Clear all caches (instance + module level)."""
        clear_module_cache()


async def get_classification_engine(session: AsyncSession) -> ClassificationEngine:
    """Factory function to create classification engine."""
    return ClassificationEngine(session)
