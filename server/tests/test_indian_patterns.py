"""
Test Indian identifier pattern detection
"""
import pytest
import re
from app.services.event_processor import EventProcessor


class TestIndianPatterns:
    """Test Indian identifier detection patterns"""

    @pytest.fixture
    def processor(self):
        """Create EventProcessor instance"""
        return EventProcessor()

    @pytest.mark.asyncio
    async def test_aadhaar_detection_with_spaces(self, processor):
        """Test Aadhaar detection with spaces"""
        event = {
            "event_id": "test-001",
            "content": "My Aadhaar number is 1234 5678 9012",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "AADHAAR" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_aadhaar_detection_without_spaces(self, processor):
        """Test Aadhaar detection without spaces"""
        event = {
            "event_id": "test-002",
            "content": "Aadhaar: 123456789012",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "AADHAAR" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_aadhaar_detection_with_dashes(self, processor):
        """Test Aadhaar detection with dashes"""
        event = {
            "event_id": "test-003",
            "content": "UID: 1234-5678-9012",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "AADHAAR" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_aadhaar_invalid_length(self, processor):
        """Test that invalid Aadhaar length is not detected"""
        event = {
            "event_id": "test-004",
            "content": "Invalid: 1234 5678 901",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        if "classification" in result:
            assert not any(c["label"] == "AADHAAR" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_pan_detection_valid(self, processor):
        """Test PAN detection with valid format"""
        event = {
            "event_id": "test-005",
            "content": "PAN: ABCDE1234F",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "PAN" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_pan_detection_invalid(self, processor):
        """Test that invalid PAN format is not detected"""
        event = {
            "event_id": "test-006",
            "content": "Invalid PAN: ABCD1234F",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        if "classification" in result:
            assert not any(c["label"] == "PAN" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_ifsc_detection(self, processor):
        """Test IFSC code detection"""
        event = {
            "event_id": "test-007",
            "content": "IFSC: SBIN0001234",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "IFSC" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_ifsc_invalid_missing_zero(self, processor):
        """Test that IFSC without required zero is not detected"""
        event = {
            "event_id": "test-008",
            "content": "Invalid IFSC: SBIN001234",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        if "classification" in result:
            assert not any(c["label"] == "IFSC" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_indian_phone_with_prefix(self, processor):
        """Test Indian phone number with +91 prefix"""
        event = {
            "event_id": "test-009",
            "content": "Phone: +91-9876543210",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "INDIAN_PHONE" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_indian_phone_without_prefix(self, processor):
        """Test Indian phone number without prefix"""
        event = {
            "event_id": "test-010",
            "content": "Mobile: 9876543210",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "INDIAN_PHONE" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_indian_phone_with_zero(self, processor):
        """Test Indian phone number with leading zero"""
        event = {
            "event_id": "test-011",
            "content": "Contact: 09876543210",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "INDIAN_PHONE" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_upi_id_detection(self, processor):
        """Test UPI ID detection"""
        event = {
            "event_id": "test-012",
            "content": "UPI: user@paytm",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "UPI_ID" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_upi_id_phonepe(self, processor):
        """Test UPI ID with PhonePe"""
        event = {
            "event_id": "test-013",
            "content": "Payment: merchant@phonepe",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "UPI_ID" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_micr_detection(self, processor):
        """Test MICR code detection"""
        event = {
            "event_id": "test-014",
            "content": "MICR: 123456789",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "MICR" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_indian_dob_detection(self, processor):
        """Test Indian date of birth detection"""
        event = {
            "event_id": "test-015",
            "content": "DOB: 15/08/1990",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "INDIAN_DOB" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_indian_dob_with_dash(self, processor):
        """Test Indian DOB with dash separator"""
        event = {
            "event_id": "test-016",
            "content": "Birth Date: 15-08-1990",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "INDIAN_DOB" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_indian_bank_account_detection(self, processor):
        """Test Indian bank account number detection"""
        event = {
            "event_id": "test-017",
            "content": "Account: 123456789012",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "INDIAN_BANK_ACCOUNT" for c in result["classification"])

