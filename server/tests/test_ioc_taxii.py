"""
Tests for the threat-intel IOC store (app.services.ioc_service) — STIX
pattern parsing/building, value normalization, and the upsert path.

Ported alongside the Threat Intel / TAXII feature. CyberSentinel DLP shipped
this with zero test coverage; adding it here so the matcher and STIX parsing
logic don't silently regress.
"""
import uuid

import pytest

from app.services.ioc_service import (
    normalize_value,
    extract_indicators_from_pattern,
    build_stix_pattern,
    upsert_ioc,
)


# ── normalize_value ──────────────────────────────────────────────────────────

def test_normalize_value_lowercases_domain_email_ipv6_and_hashes():
    assert normalize_value("domain", "EVIL.example.COM") == "evil.example.com"
    assert normalize_value("email", "Attacker@Evil.COM") == "attacker@evil.com"
    assert normalize_value("file_sha256", "ABCDEF") == "abcdef"


def test_normalize_value_preserves_url_case_and_ipv4():
    assert normalize_value("url", "https://Evil.example/Path") == "https://Evil.example/Path"
    assert normalize_value("ipv4", "203.0.113.7") == "203.0.113.7"


def test_normalize_value_strips_whitespace():
    assert normalize_value("ipv4", "  203.0.113.7  ") == "203.0.113.7"


def test_normalize_value_empty_string():
    assert normalize_value("domain", "") == ""
    assert normalize_value("domain", "   ") == ""


# ── STIX pattern <-> value ───────────────────────────────────────────────────

def test_build_stix_pattern_known_types():
    assert build_stix_pattern("ipv4", "203.0.113.7") == "[ipv4-addr:value = '203.0.113.7']"
    assert build_stix_pattern("domain", "evil.example.com") == "[domain-name:value = 'evil.example.com']"
    assert build_stix_pattern("file_sha256", "a" * 64) == f"[file:hashes.'SHA-256' = '{'a' * 64}']"


def test_build_stix_pattern_unsupported_type_raises():
    with pytest.raises(ValueError):
        build_stix_pattern("not_a_real_type", "x")


def test_build_stix_pattern_escapes_single_quotes():
    pattern = build_stix_pattern("domain", "evil'example.com")
    assert "\\'" in pattern


def test_extract_indicators_from_pattern_single_comparison():
    pairs = extract_indicators_from_pattern("[ipv4-addr:value = '203.0.113.7']")
    assert pairs == [("ipv4", "203.0.113.7")]


def test_extract_indicators_from_pattern_multi_comparison():
    pattern = "[domain-name:value = 'evil.example.com' OR url:value = 'https://evil.example/x']"
    pairs = extract_indicators_from_pattern(pattern)
    assert ("domain", "evil.example.com") in pairs
    assert ("url", "https://evil.example/x") in pairs


def test_extract_indicators_from_pattern_infers_hash_type_by_length():
    sha256 = "a" * 64
    pattern = f"[file:hashes.'unknown-alg' = '{sha256}']"
    pairs = extract_indicators_from_pattern(pattern)
    assert pairs == [("file_sha256", sha256)]


def test_extract_indicators_from_pattern_empty_or_none():
    assert extract_indicators_from_pattern("") == []
    assert extract_indicators_from_pattern(None) == []


def test_build_then_extract_round_trips():
    pattern = build_stix_pattern("ipv4", "198.51.100.23")
    pairs = extract_indicators_from_pattern(pattern)
    assert pairs == [("ipv4", "198.51.100.23")]


# ── upsert_ioc ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_upsert_ioc_creates_new_row(db_session):
    from app.models.ioc import IOC
    from sqlalchemy import select

    created = await upsert_ioc(
        db_session, ioc_type="ipv4", value="203.0.113.99", source="manual",
        direction="internal", tlp="red", confidence=80,
    )
    await db_session.commit()

    assert created is True
    row = (await db_session.execute(
        select(IOC).where(IOC.ioc_type == "ipv4", IOC.value == "203.0.113.99")
    )).scalar_one()
    assert row.source == "manual"
    assert row.tlp == "red"
    assert row.confidence == 80
    assert row.is_active is True
    # pattern auto-derived when not supplied.
    assert row.pattern == "[ipv4-addr:value = '203.0.113.99']"


@pytest.mark.asyncio
async def test_upsert_ioc_refreshes_existing_row_without_downgrading_shared(db_session):
    from app.models.ioc import IOC
    from sqlalchemy import select

    await upsert_ioc(db_session, ioc_type="domain", value="evil.example.com", source="feed-a")
    await db_session.commit()

    row = (await db_session.execute(
        select(IOC).where(IOC.ioc_type == "domain", IOC.value == "evil.example.com")
    )).scalar_one()
    row.is_shared = True
    await db_session.commit()

    # Second ingest of the same indicator from a different source: refreshes
    # attribution but is NOT a new row, and must not clear is_shared.
    created_again = await upsert_ioc(
        db_session, ioc_type="domain", value="EVIL.example.com", source="feed-b",
    )
    await db_session.commit()

    assert created_again is False
    row2 = (await db_session.execute(
        select(IOC).where(IOC.ioc_type == "domain", IOC.value == "evil.example.com")
    )).scalar_one()
    assert row2.source == "feed-b"
    assert row2.is_shared is True  # never downgraded by a refresh


@pytest.mark.asyncio
async def test_upsert_ioc_rejects_empty_normalized_value(db_session):
    created = await upsert_ioc(db_session, ioc_type="domain", value="   ", source="manual")
    assert created is False
