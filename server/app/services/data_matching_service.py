"""
Exact Data Matching (EDM) + Document Fingerprinting -- one-way, keyed, local.

Ported from a comparable module in CyberSentinel-DLP (a competitor product)
after a deployment-tooling/feature comparison found SeceoKnight had no way to
match real protected data (e.g. a customer SSN+name export) or catch a
partially-copied/edited protected document -- SeceoKnight's existing
"file-identity denylist" (app/services/fingerprint_service.py) only catches
BYTE-IDENTICAL files via whole-file SHA-256, which misses both of the above
entirely.

This is the detection core. It is intentionally PURE (no DB, no I/O, stdlib
only) so it is trivially unit-testable and carries no deployment dependencies.

Design guarantees (the requirement is "one-way hashes, performed locally"):

  * The protected data -- real SSNs / names / account numbers, and the text of
    sensitive documents -- is NEVER stored. An index holds ONLY keyed one-way
    digests (HMAC-SHA256). You cannot reconstruct a record or a document from
    an index.

  * "One-way" alone is not enough for low-entropy PII: plain sha256("123-45-6789")
    is reversible in minutes because there are only ~1e9 SSNs. We therefore key
    every digest with a per-deployment secret (HMAC). A stolen index cannot be
    brute-forced or rainbow-tabled without that key, which never leaves the
    server and is never written into an index.

  * EDM fires on ROW-LEVEL COMBINATIONS (e.g. name AND ssn from the SAME
    record), not single cells. This is what keeps false positives near zero --
    a random SSN-shaped number is not in the index, and even a real lone value
    can be required to co-occur with a corroborating field before it alerts.
    It also means cracking one field's hash does not reconstruct a record.

Two independent matchers share the same keyed-hash primitive:
  * build_edm_index / match_edm            -- structured records
  * build_fingerprint_index / match_fp     -- documents (partial / edited copies)
"""
from __future__ import annotations

import hmac
import hashlib
import re
from typing import Any, Dict, Iterable, List, Sequence, Set

# Digest width. 128 bits (32 hex) is ample against collision for this use and
# halves index size vs. full sha256. It is a truncated HMAC, still keyed.
_DIGEST_HEX = 32

_WS = re.compile(r"\s+")
_WORD = re.compile(r"[^\W_]+", re.UNICODE)          # word tokens (keeps unicode letters/digits)
_NUMERIC_TOKEN = re.compile(r"^[\d\s._\-]+$")       # a value that is only digits + separators
_NONDIGIT = re.compile(r"\D")
# Punctuation stripped from the ENDS of a candidate before hashing. Real prose
# attaches these to values ("Doe,", "123-45-6789.", "(Khan)"); without this the
# token would not equal the clean cell that was indexed. Interior characters
# (name apostrophes, the '-' in an SSN) are kept.
_EDGE_PUNCT = " \t\r\n.,;:!?()[]{}<>\"'`|/\\"
# Field separators turned into spaces before EDM tokenising, so comma/tab/pipe-
# packed records (a raw CSV/TSV export) are split into individual cells.
_FIELD_DELIM = re.compile(r"[,\t\r\n;|]+")


# -----------------------------------------------------------------------
# Keyed one-way primitive
# -----------------------------------------------------------------------
def derive_key(secret: str) -> bytes:
    """Derive the indexing/matching HMAC key from the deployment secret
    (settings.SECRET_KEY). The fixed context label domain-separates it from
    every other use of that secret, so the EDM key is not the JWT key. The
    derived key lives only in server memory and is NEVER written into an index --
    that is what makes a stolen index unusable.
    """
    return hmac.new(
        (secret or "").encode("utf-8"),
        b"seceoknight-dlp-datamatch-v1",
        hashlib.sha256,
    ).digest()


def keyed_digest(value: str, key: bytes) -> str:
    """HMAC-SHA256(value) truncated to 128 bits, hex. One-way and keyed:
    without `key` the output cannot be brute-forced back to `value`."""
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:_DIGEST_HEX]


def normalize_variants(value: str) -> Set[str]:
    """The normalized form(s) of a value that BOTH indexing and matching hash,
    so the same datum is recognised regardless of separators/case.

    - Always: lowercased, whitespace-collapsed, trimmed.
    - Also, for a token that is purely digits+separators of a plausible
      identifier length: a digits-only form, so "123-45-6789", "123 45 6789"
      and "123.45.6789" all collapse to the same digest. The gate (pure
      numeric, 6..19 digits) stops a phrase like "call 5 people" from being
      hashed as a number.
    """
    if value is None:
        return set()
    base = _WS.sub(" ", str(value)).strip().lower().strip(_EDGE_PUNCT)
    if not base:
        return set()
    out = {base}
    if _NUMERIC_TOKEN.match(base):
        digits = _NONDIGIT.sub("", base)
        if 6 <= len(digits) <= 19:
            out.add(digits)
    return out


# -----------------------------------------------------------------------
# EDM -- structured record matching
# -----------------------------------------------------------------------
def build_edm_index(
    rows: Sequence[Dict[str, Any]],
    columns: Sequence[str],
    key: bytes,
) -> Dict[str, Any]:
    """Turn a protected dataset into a keyed-hash index. Plaintext is consumed
    and DISCARDED -- only digests and (row, column) coordinates remain.

    rows:    list of dict records (a CSV/DB export, already parsed)
    columns: which columns are sensitive and should be indexed
    """
    cells: Dict[str, List[List[Any]]] = {}   # digest -> [[row_id, column], ...]
    row_count = 0
    for row_id, row in enumerate(rows):
        any_cell = False
        for col in columns:
            raw = row.get(col)
            if raw is None or str(raw).strip() == "":
                continue
            for norm in normalize_variants(str(raw)):
                dig = keyed_digest(norm, key)
                cells.setdefault(dig, [])
                # de-dup identical (row,col) coordinates for multiple variants
                coord = [row_id, col]
                if coord not in cells[dig]:
                    cells[dig].append(coord)
                any_cell = True
        if any_cell:
            row_count += 1
    return {
        "type": "edm",
        "columns": list(columns),
        "row_count": row_count,
        "cells": cells,
    }


def _ngrams(content: str, max_n: int = 4) -> Iterable[str]:
    """Candidate 1..max_n-grams from the content.

    Splitting on whitespace alone misses FIELD-DELIMITED data: a raw CSV row
    "Jane,Doe,ACCT-19205472,1955-01-14" is one whitespace token, so its cells
    would never be matched and an export of protected records with no regex
    pattern would slip through. We first turn comma / tab / pipe / semicolon /
    newline -- the usual field separators -- into spaces, so each cell becomes
    its own token. Interior value characters (an SSN's '-', a name's
    apostrophe) are kept. max_n=4 lets 4-group values like a spaced card
    number match as one.
    """
    tokens = _FIELD_DELIM.sub(" ", content).split()
    n = len(tokens)
    for i in range(n):
        for size in range(1, max_n + 1):
            if i + size <= n:
                yield " ".join(tokens[i:i + size])


def match_edm(
    content: str,
    index: Dict[str, Any],
    key: bytes,
    min_fields: int = 2,
) -> Dict[str, Any]:
    """Does `content` contain a protected RECORD?

    Fires only when at least `min_fields` DISTINCT columns of the SAME indexed
    row appear in the content -- the combination rule that makes EDM precise.
    min_fields=1 is available for uniquely-identifying single values (e.g. a
    structured account number) but 2 is the safe default.
    """
    cells: Dict[str, List[List[Any]]] = index.get("cells", {})
    if not cells:
        return {"matched": False, "rows": [], "min_fields": min_fields}

    # row_id -> set(columns matched in this content)
    hits: Dict[int, Set[str]] = {}
    for gram in _ngrams(content):
        for norm in normalize_variants(gram):
            coords = cells.get(keyed_digest(norm, key))
            if not coords:
                continue
            for row_id, col in coords:
                hits.setdefault(row_id, set()).add(col)

    matched_rows = [
        {"row_id": rid, "columns": sorted(cols)}
        for rid, cols in hits.items()
        if len(cols) >= min_fields
    ]
    matched_rows.sort(key=lambda r: (-len(r["columns"]), r["row_id"]))
    return {
        "matched": bool(matched_rows),
        "rows": matched_rows,
        "matched_row_count": len(matched_rows),
        "min_fields": min_fields,
    }


# -----------------------------------------------------------------------
# Document fingerprinting -- partial / edited-copy matching (winnowing)
# -----------------------------------------------------------------------
def _shingle_hashes(text: str, key: bytes, k: int) -> List[int]:
    """k-word shingles -> keyed digests as ints (for min-selection)."""
    words = [w.lower() for w in _WORD.findall(text)]
    if len(words) < k:
        if not words:
            return []
        shingles = [" ".join(words)]
    else:
        shingles = [" ".join(words[i:i + k]) for i in range(len(words) - k + 1)]
    return [int(keyed_digest(s, key), 16) for s in shingles]


def _winnow(hashes: Sequence[int], w: int) -> Set[int]:
    """Winnowing: the min hash of every window of `w` shingles. Guarantees any
    shared passage of >= (w + k - 1) words yields at least one common
    fingerprint, so partial copies and edits are still caught -- while keeping
    only a stable subset of hashes rather than all of them."""
    if not hashes:
        return set()
    if len(hashes) <= w:
        return set(hashes)
    selected: Set[int] = set()
    for i in range(len(hashes) - w + 1):
        selected.add(min(hashes[i:i + w]))
    return selected


def build_fingerprint_index(
    text: str,
    key: bytes,
    k: int = 5,
    w: int = 4,
) -> Dict[str, Any]:
    """Register a document. Stores ONLY winnowed keyed shingle digests -- the
    document text is discarded and is not reconstructable from the index."""
    fp = _winnow(_shingle_hashes(text, key, k), w)
    return {
        "type": "fingerprint",
        "k": k,
        "w": w,
        "fp": sorted(format(h, "x") for h in fp),
    }


def match_fp(
    content: str,
    index: Dict[str, Any],
    key: bytes,
    min_shingles: int = 4,
    min_containment: float = 0.25,
) -> Dict[str, Any]:
    """Does `content` contain a substantial passage from a registered document?

    Reports overlap and CONTAINMENT (overlap / smaller fingerprint set), which
    is the right measure for "an excerpt of a big protected doc appears in this
    small email". Fires on either an absolute overlap of `min_shingles` shingles
    or containment >= `min_containment` -- so both "a chunk of a big doc" and
    "most of a small doc" are caught. Both thresholds are policy-tunable.
    """
    registered = set(index.get("fp", []))
    if not registered:
        return {"matched": False, "overlap": 0, "containment": 0.0}
    k = int(index.get("k", 5))
    w = int(index.get("w", 4))
    cand = {format(h, "x") for h in _winnow(_shingle_hashes(content, key, k), w)}
    if not cand:
        return {"matched": False, "overlap": 0, "containment": 0.0}
    overlap = len(registered & cand)
    containment = overlap / min(len(registered), len(cand))
    matched = overlap >= min_shingles or containment >= min_containment
    return {
        "matched": matched,
        "overlap": overlap,
        "containment": round(containment, 4),
        "registered_shingles": len(registered),
        "candidate_shingles": len(cand),
        "min_shingles": min_shingles,
        "min_containment": min_containment,
    }
