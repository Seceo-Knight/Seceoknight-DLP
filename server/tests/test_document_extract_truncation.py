"""
Regression tests for the scan-window bypass.

The rule these defend: text we did not scan is NOT clean text. Clipping content
to fit a budget is fine; reporting the clipped result as a complete inspection
is not — that let an 87KB zip (filler ahead of the secret) classify as Public.

Pure-function tests: no DB, no network.
"""
import io
import zipfile

import pytest

from app.services import document_extract as de
from app.services.document_extract import extract_text

SECRET = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
FILLER = "The quarterly team offsite agenda item number seven. "


@pytest.fixture
def small_cap(monkeypatch):
    """Shrink the scan budget so tests stay fast but exercise the real paths."""
    monkeypatch.setattr(de, "MAX_TEXT_CHARS", 1000)
    return 1000


def test_text_within_budget_is_not_truncated():
    ex = extract_text("notes.txt", (FILLER * 10).encode())
    assert ex.ok and not ex.truncated


def test_oversized_text_is_flagged_truncated(small_cap):
    ex = extract_text("big.txt", (FILLER * 500).encode())
    assert ex.ok, "we still classify what we could read"
    assert ex.truncated, "must not claim a complete read"
    assert len(ex.text) == small_cap


def test_secret_past_the_budget_is_reported_truncated(small_cap):
    """THE BYPASS: filler ahead of a secret must never yield a silent clean read."""
    payload = (FILLER * 500 + SECRET).encode()
    ex = extract_text("padded.txt", payload)
    assert SECRET.strip() not in ex.text, "precondition: secret is past the cap"
    # The caller must be able to tell 'clean' from 'did not look'.
    assert ex.truncated is True


def test_secret_within_budget_is_still_found():
    """The fix must not stop at the first megabyte of a normal-sized file."""
    payload = (FILLER * 30000 + SECRET).encode()      # ~1.5M chars, under the 10M budget
    ex = extract_text("padded.txt", payload)
    assert not ex.truncated
    assert "AKIAIOSFODNN7EXAMPLE" in ex.text, "content past 1M chars must be scanned"


def test_archive_member_truncation_propagates(small_cap):
    """A partly-read member makes the whole archive a partial read."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("filler.txt", FILLER * 500)
        z.writestr("secret.txt", SECRET)
    ex = extract_text("bundle.zip", bio.getvalue())
    assert ex.truncated, "archive must inherit its members' incompleteness"


def test_archive_within_budget_finds_secret_behind_filler():
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("aaa-filler.txt", FILLER * 30000)   # sorts/streams first
        z.writestr("zzz-secret.txt", SECRET)
    ex = extract_text("bundle.zip", bio.getvalue())
    assert not ex.truncated
    assert "AKIAIOSFODNN7EXAMPLE" in ex.text


def test_binary_padding_contributes_no_text():
    """Random padding must not spend the text budget (test-sample design)."""
    import secrets as _s
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("00-secret.txt", SECRET)
        z.writestr("zz-pad.bin", _s.token_bytes(200_000))
    ex = extract_text("padded.zip", bio.getvalue())
    assert ex.ok and not ex.truncated
    assert "AKIAIOSFODNN7EXAMPLE" in ex.text
    assert len(ex.text) < 1000, "binary padding must not become text"
