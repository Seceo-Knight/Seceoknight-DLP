"""
Real-time redaction — the "redact" action for Web Activity Control.

New capability, design ported in spirit from CyberSentinel-DLP commit
d3ed5e4 ("redact sensitive values instead of blocking, where a policy says
so"), adapted to SeceoKnight's own classification pipeline.

WHY THIS IS A SEPARATE, SECOND PASS AND NOT PART OF THE CLASSIFIER HOT PATH:
classification_engine.py's rule evaluation uses pattern.findall() (see
_evaluate_regex_with_validation), which returns matched substrings but never
their positions in the source text -- by design, since every existing
caller of classify_content() (clipboard, USB, print, network-share, email,
...) only ever needed a match COUNT to score confidence, never WHERE the
match sat in the string. Teaching that hot path to carry offsets would add
cost to every single event across every channel, to serve a decision only a
"redact" verdict on the new web-activity path actually reaches.

This module re-runs ONLY the rules that already matched (matched_rules from
a completed classify_content() call), re-fetching those specific Rule rows
and using finditer()/substring search instead of findall() to recover match
spans, then substitutes a placeholder per match. It never runs on the
classifier's own hot path -- only when a web_activity_control policy's
matrix cell for the relevant (app_category, activity) resolves to "redact".
"""
from typing import Any, Dict, List, Tuple
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rule import Rule

# Separate from classification_engine.py's own _module_cache -- deliberately
# not shared, so this module has no import-time dependency on the
# classifier's internals beyond the Rule model itself. Same compiled-pattern
# caching idea (rule_id+pattern -> compiled regex), just local to redaction.
_regex_cache: Dict[str, "re.Pattern[str]"] = {}


def _compiled(rule: Rule):
    if not rule.pattern:
        return None
    key = f"{rule.id}:{rule.pattern}"
    cached = _regex_cache.get(key)
    if cached is not None:
        return cached
    flags = 0
    if rule.regex_flags:
        for flag_name in rule.regex_flags:
            if hasattr(re, flag_name):
                flags |= getattr(re, flag_name)
    try:
        compiled = re.compile(rule.pattern, flags)
    except re.error:
        return None
    _regex_cache[key] = compiled
    return compiled


async def redact_content(
    db: AsyncSession,
    content: str,
    matched_rules: List[Dict[str, Any]],
) -> Tuple[str, List[str]]:
    """Redact every span matched by ``matched_rules`` (the same list a
    classify_content() call returns) out of ``content``.

    Returns (redacted_content, labels_redacted). ``labels_redacted`` lists
    which classification label was substituted at each occurrence (e.g.
    ["AADHAAR", "CREDIT_CARD"]) -- for the event record. The actual sensitive
    VALUES are never included in the return value or logged anywhere by this
    function; only the placeholder text is.
    """
    if not content or not matched_rules:
        return content, []

    rule_ids = [
        mr["rule_id"] for mr in matched_rules
        if mr.get("rule_id") and mr.get("rule_type") in ("regex", "keyword")
    ]
    # Dictionary-type rules are deliberately excluded -- see the module
    # docstring note below on why they don't get redacted here.
    if not rule_ids:
        return content, []

    rows = (await db.execute(select(Rule).where(Rule.id.in_(rule_ids)))).scalars().all()
    rules_by_id = {str(r.id): r for r in rows}

    spans: List[Tuple[int, int, str]] = []  # (start, end, label)

    for mr in matched_rules:
        rule = rules_by_id.get(mr.get("rule_id"))
        if not rule:
            continue
        label = (rule.classification_labels or ["SENSITIVE"])[0].upper()

        if rule.type == "regex":
            pattern = _compiled(rule)
            if not pattern:
                continue
            for m in pattern.finditer(content):
                spans.append((m.start(), m.end(), label))
        elif rule.type == "keyword" and rule.keywords:
            haystack = content if rule.case_sensitive else content.lower()
            for kw in rule.keywords:
                needle = kw if rule.case_sensitive else (kw or "").lower()
                if not needle:
                    continue
                start = 0
                while True:
                    idx = haystack.find(needle, start)
                    if idx == -1:
                        break
                    spans.append((idx, idx + len(needle), label))
                    start = idx + len(needle)
        # DICTIONARY rules are matched elsewhere in the engine via a wordlist
        # lookup keyed on whole tokens -- reproducing that here would mean
        # loading the same dictionary file this module doesn't otherwise
        # depend on, just to recover offsets. A dictionary-only match is a
        # documented gap: it contributes to the classification score as
        # normal, but doesn't get its own span redacted. This is disclosed
        # behavior, not a silent failure -- the caller (web-activity
        # evaluation) still applies the configured action to the REST of the
        # content around it; a policy relying entirely on dictionary rules
        # for its sensitive-data detection should use "block" rather than
        # "redact" until this is extended.

    if not spans:
        return content, []

    # Sort by start ascending, longest-match-first on ties, then drop any
    # span that overlaps one already accepted -- two rules tripping on
    # overlapping text (e.g. a broad "16 digits" rule and a stricter
    # Luhn-validated credit-card rule matching the same digits) should
    # produce ONE placeholder, not two overlapping ones that would corrupt
    # the output when spliced back together.
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    merged: List[Tuple[int, int, str]] = []
    for start, end, label in spans:
        if merged and start < merged[-1][1]:
            continue
        merged.append((start, end, label))

    counters: Dict[str, int] = {}
    labels_redacted: List[str] = []
    out: List[str] = []
    cursor = 0
    for start, end, label in merged:
        out.append(content[cursor:start])
        counters[label] = counters.get(label, 0) + 1
        out.append(f"[{label}_{counters[label]}]")
        labels_redacted.append(label)
        cursor = end
    out.append(content[cursor:])
    return "".join(out), labels_redacted
