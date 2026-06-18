"""
Comprehensive Test Suite for Detection and Classification
Tests PII detection, classification accuracy, and performance
"""

import pytest
import re
from typing import Dict, Any, List
from datetime import datetime

from app.services.event_processor import EventProcessor


class SyntheticPIIGenerator:
    """
    Generate synthetic PII and confidential data for testing
    Ensures no real data is used in tests
    """

    @staticmethod
    def generate_credit_cards(count: int = 10, valid: bool = True) -> List[str]:
        """Generate synthetic credit card numbers"""
        cards = []

        if valid:
            # Generate valid Luhn algorithm credit cards
            prefixes = [
                "4",      # Visa
                "51",     # Mastercard
                "6011",   # Discover
                "34",     # Amex
                "37",     # Amex
            ]

            for prefix in prefixes[:count]:
                # Pad to 15 digits (16th will be check digit)
                card = prefix + "0" * (15 - len(prefix))
                # Calculate Luhn check digit
                check_digit = SyntheticPIIGenerator._luhn_check_digit(card)
                cards.append(card + str(check_digit))
        else:
            # Generate invalid cards (fail Luhn)
            for i in range(count):
                cards.append(f"4111{'0' * 11}{i % 10}")

        return cards

    @staticmethod
    def _luhn_check_digit(card_number: str) -> int:
        """Calculate Luhn check digit"""
        def digits_of(n):
            return [int(d) for d in str(n)]

        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        return (10 - (checksum % 10)) % 10

    @staticmethod
    def generate_ssns(count: int = 10) -> List[str]:
        """Generate synthetic SSNs"""
        ssns = []
        for i in range(count):
            area = str(100 + i).zfill(3)
            group = str(10 + i).zfill(2)
            serial = str(1000 + i).zfill(4)
            ssns.append(f"{area}-{group}-{serial}")
        return ssns

    @staticmethod
    def generate_emails(count: int = 10) -> List[str]:
        """Generate synthetic email addresses"""
        domains = ["example.com", "test.org", "sample.net", "demo.io"]
        emails = []
        for i in range(count):
            username = f"user{i}"
            domain = domains[i % len(domains)]
            emails.append(f"{username}@{domain}")
        return emails

    @staticmethod
    def generate_phone_numbers(count: int = 10) -> List[str]:
        """Generate synthetic phone numbers"""
        phones = []
        for i in range(count):
            area = str(200 + i).zfill(3)
            prefix = str(555 + i % 100).zfill(3)
            line = str(1000 + i).zfill(4)
            phones.append(f"+1-{area}-{prefix}-{line}")
        return phones

    @staticmethod
    def generate_api_keys(count: int = 10) -> List[str]:
        """Generate synthetic API keys"""
        import secrets
        return [f"sk_test_{secrets.token_hex(32)}" for _ in range(count)]

    @staticmethod
    def generate_aws_keys(count: int = 10) -> List[Dict[str, str]]:
        """Generate synthetic AWS access keys"""
        import secrets
        keys = []
        for _ in range(count):
            keys.append({
                "access_key": f"AKIA{secrets.token_hex(16).upper()}",
                "secret_key": secrets.token_hex(40)
            })
        return keys

    @staticmethod
    def generate_passwords(count: int = 10) -> List[str]:
        """Generate synthetic passwords"""
        import secrets
        import string
        passwords = []
        for _ in range(count):
            alphabet = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(secrets.choice(alphabet) for _ in range(16))
            passwords.append(password)
        return passwords

    @staticmethod
    def generate_sample_texts(pii_type: str, count: int = 10) -> List[str]:
        """Generate sample texts containing PII"""
        generator = SyntheticPIIGenerator()
        texts = []

        if pii_type == "credit_card":
            cards = generator.generate_credit_cards(count)
            templates = [
                "Payment with card: {}",
                "CC: {}",
                "Credit card number {} approved",
                "Please charge card {}",
                "Card ending in {}",
            ]
            for i, card in enumerate(cards):
                template = templates[i % len(templates)]
                texts.append(template.format(card))

        elif pii_type == "ssn":
            ssns = generator.generate_ssns(count)
            templates = [
                "SSN: {}",
                "Social Security Number: {}",
                "Tax ID {}",
                "Employee SSN {}",
                "My SSN is {}",
            ]
            for i, ssn in enumerate(ssns):
                template = templates[i % len(templates)]
                texts.append(template.format(ssn))

        elif pii_type == "email":
            emails = generator.generate_emails(count)
            templates = [
                "Contact me at {}",
                "Email: {}",
                "Send to {}",
                "From: {}",
                "Reply to {}",
            ]
            for i, email in enumerate(emails):
                template = templates[i % len(templates)]
                texts.append(template.format(email))

        elif pii_type == "phone":
            phones = generator.generate_phone_numbers(count)
            templates = [
                "Call {}",
                "Phone: {}",
                "Contact number: {}",
                "Dial {}",
                "Mobile: {}",
            ]
            for i, phone in enumerate(phones):
                template = templates[i % len(templates)]
                texts.append(template.format(phone))

        elif pii_type == "api_key":
            keys = generator.generate_api_keys(count)
            templates = [
                "API_KEY={}",
                "Authorization: Bearer {}",
                "apiKey: '{}'",
                "key = '{}'",
                "API Key: {}",
            ]
            for i, key in enumerate(keys):
                template = templates[i % len(templates)]
                texts.append(template.format(key))

        return texts


class TestPIIDetectionAccuracy:
    """Test accuracy of PII detection"""

    @pytest.fixture
    def processor(self):
        return EventProcessor()

    @pytest.fixture
    def pii_generator(self):
        return SyntheticPIIGenerator()

    def test_detect_credit_cards_valid(self, processor, pii_generator):
        """Test detection of valid credit card numbers"""
        cards = pii_generator.generate_credit_cards(count=20, valid=True)

        detected = 0
        for card in cards:
            content = f"Payment information: {card}"
            result = processor._classify_content(content)

            # Check if credit card was detected
            if any(c["type"] == "credit_card" for c in result):
                detected += 1

        # Should detect at least 90% of valid cards
        accuracy = detected / len(cards)
        assert accuracy >= 0.9, f"Only detected {detected}/{len(cards)} cards"

    def test_reject_invalid_credit_cards(self, processor, pii_generator):
        """Test rejection of invalid credit card numbers (Luhn check)"""
        invalid_cards = pii_generator.generate_credit_cards(count=10, valid=False)

        false_positives = 0
        for card in invalid_cards:
            content = f"Card number: {card}"
            result = processor._classify_content(content)

            # Should NOT detect invalid cards
            if any(c["type"] == "credit_card" for c in result):
                false_positives += 1

        # Should have very few false positives
        assert false_positives <= 2, f"Too many false positives: {false_positives}/10"

    def test_detect_ssns(self, processor, pii_generator):
        """Test detection of Social Security Numbers"""
        ssns = pii_generator.generate_ssns(count=20)

        detected = 0
        for ssn in ssns:
            content = f"Employee SSN: {ssn}"
            result = processor._classify_content(content)

            if any(c["type"] == "ssn" for c in result):
                detected += 1

        accuracy = detected / len(ssns)
        assert accuracy >= 0.9, f"Only detected {detected}/{len(ssns)} SSNs"

    def test_detect_emails(self, processor, pii_generator):
        """Test detection of email addresses"""
        emails = pii_generator.generate_emails(count=20)

        detected = 0
        for email in emails:
            content = f"Contact: {email}"
            result = processor._classify_content(content)

            if any(c["type"] == "email" for c in result):
                detected += 1

        accuracy = detected / len(emails)
        assert accuracy >= 0.95, f"Only detected {detected}/{len(emails)} emails"

    def test_detect_phone_numbers(self, processor, pii_generator):
        """Test detection of phone numbers"""
        phones = pii_generator.generate_phone_numbers(count=20)

        detected = 0
        for phone in phones:
            content = f"Call: {phone}"
            result = processor._classify_content(content)

            if any(c["type"] == "phone" for c in result):
                detected += 1

        accuracy = detected / len(phones)
        assert accuracy >= 0.85, f"Only detected {detected}/{len(phones)} phones"

    def test_detect_api_keys(self, processor, pii_generator):
        """Test detection of API keys"""
        api_keys = pii_generator.generate_api_keys(count=20)

        detected = 0
        for key in api_keys:
            content = f"API_KEY={key}"
            result = processor._classify_content(content)

            if any(c["type"] == "api_key" for c in result):
                detected += 1

        accuracy = detected / len(api_keys)
        assert accuracy >= 0.9, f"Only detected {detected}/{len(api_keys)} API keys"

    def test_multiple_pii_types_same_content(self, processor, pii_generator):
        """Test detection of multiple PII types in same content"""
        card = pii_generator.generate_credit_cards(count=1)[0]
        ssn = pii_generator.generate_ssns(count=1)[0]
        email = pii_generator.generate_emails(count=1)[0]

        content = f"""
        Customer Information:
        Email: {email}
        SSN: {ssn}
        Payment Card: {card}
        """

        result = processor._classify_content(content)

        detected_types = [c["type"] for c in result]
        assert "email" in detected_types
        assert "ssn" in detected_types
        assert "credit_card" in detected_types

    def test_pii_in_different_formats(self, processor, pii_generator):
        """Test detection of PII in various formats"""
        # Credit card with spaces
        content1 = "Card: 4111 1111 1111 1111"
        result1 = processor._classify_content(content1)

        # Credit card with dashes
        content2 = "Card: 4111-1111-1111-1111"
        result2 = processor._classify_content(content2)

        # Should detect both
        assert any(c["type"] == "credit_card" for c in result1)
        assert any(c["type"] == "credit_card" for c in result2)


class TestDetectionPerformance:
    """Test detection performance and latency"""

    @pytest.fixture
    def processor(self):
        return EventProcessor()

    @pytest.fixture
    def pii_generator(self):
        return SyntheticPIIGenerator()

    def test_detection_latency_small_content(self, processor):
        """Test detection latency for small content"""
        import time

        content = "Email: test@example.com, SSN: 123-45-6789"

        start = time.time()
        for _ in range(100):
            processor._classify_content(content)
        duration = time.time() - start

        avg_latency = (duration / 100) * 1000  # ms
        assert avg_latency < 10, f"Too slow: {avg_latency:.2f}ms average"

    def test_detection_latency_large_content(self, processor, pii_generator):
        """Test detection latency for large content"""
        import time

        # Generate large content with embedded PII
        texts = pii_generator.generate_sample_texts("credit_card", count=100)
        content = " ".join(texts) * 10  # ~10KB of text

        start = time.time()
        result = processor._classify_content(content)
        duration = (time.time() - start) * 1000  # ms

        assert duration < 100, f"Too slow for large content: {duration:.2f}ms"
        assert len(result) > 0, "Should detect PII in large content"

    def test_batch_processing_performance(self, processor, pii_generator):
        """Test batch processing of multiple events"""
        import time

        # Generate 1000 test events
        events = []
        for i in range(1000):
            events.append({
                "event_id": f"evt-{i:04d}",
                "content": pii_generator.generate_sample_texts("email", count=1)[0]
            })

        start = time.time()
        for event in events:
            processor._classify_content(event["content"])
        duration = time.time() - start

        throughput = len(events) / duration
        assert throughput >= 100, f"Too slow: only {throughput:.0f} events/sec"


class TestFalsePositivesNegatives:
    """Test false positive and false negative rates"""

    @pytest.fixture
    def processor(self):
        return EventProcessor()

    def test_false_positives_credit_card(self, processor):
        """Test false positive rate for credit card detection"""
        # Non-credit card numbers that might look similar
        false_positive_texts = [
            "Order number: 1234567890123456",
            "Phone: 1234-5678-9012-3456",
            "ID: 9999-9999-9999-9999",
            "Tracking: 4111222233334444",  # Fails Luhn
            "Ref: 0000000000000000",
        ]

        false_positives = 0
        for text in false_positive_texts:
            result = processor._classify_content(text)
            if any(c["type"] == "credit_card" for c in result):
                false_positives += 1

        fp_rate = false_positives / len(false_positive_texts)
        assert fp_rate < 0.2, f"Too many false positives: {fp_rate:.1%}"

    def test_false_negatives_ssn(self, processor):
        """Test false negative rate for SSN detection"""
        # Valid SSNs in various contexts
        true_positive_texts = [
            "SSN:123-45-6789",
            "Social Security Number 123-45-6789",
            "Tax ID: 123-45-6789",
            "My SSN is 123-45-6789",
            "Employee #123-45-6789 (SSN)",
        ]

        detected = 0
        for text in true_positive_texts:
            result = processor._classify_content(text)
            if any(c["type"] == "ssn" for c in result):
                detected += 1

        fn_rate = (len(true_positive_texts) - detected) / len(true_positive_texts)
        assert fn_rate < 0.1, f"Too many false negatives: {fn_rate:.1%}"

    def test_confidence_scores(self, processor):
        """Test confidence score accuracy"""
        # High confidence cases
        high_conf_texts = [
            "Credit Card: 4111111111111111",
            "Email: test@example.com",
            "SSN: 123-45-6789",
        ]

        for text in high_conf_texts:
            result = processor._classify_content(text)
            if result:
                assert result[0]["confidence"] >= 0.8, \
                    f"Low confidence for obvious PII: {result[0]['confidence']}"

        # Low confidence cases (ambiguous)
        low_conf_texts = [
            "Number: 1234567890",
            "Code: ABC-12-3456",
        ]

        for text in low_conf_texts:
            result = processor._classify_content(text)
            if result:
                # If detected, should have lower confidence
                assert result[0]["confidence"] < 0.9, \
                    "Too high confidence for ambiguous text"


class TestContentRedaction:
    """Test PII redaction functionality"""

    @pytest.fixture
    def processor(self):
        return EventProcessor()

    @pytest.fixture
    def pii_generator(self):
        return SyntheticPIIGenerator()

    def test_redact_credit_card(self, processor, pii_generator):
        """Test credit card redaction"""
        card = pii_generator.generate_credit_cards(count=1)[0]
        content = f"Payment card: {card}"

        redacted = processor._redact_content(content)

        assert card not in redacted
        assert "[REDACTED]" in redacted or "****" in redacted

    def test_redact_multiple_pii(self, processor, pii_generator):
        """Test redaction of multiple PII types"""
        card = pii_generator.generate_credit_cards(count=1)[0]
        ssn = pii_generator.generate_ssns(count=1)[0]
        email = pii_generator.generate_emails(count=1)[0]

        content = f"Customer: {email}, SSN: {ssn}, Card: {card}"

        redacted = processor._redact_content(content)

        # All PII should be redacted
        assert card not in redacted
        assert ssn not in redacted
        assert email not in redacted

    def test_partial_redaction(self, processor):
        """Test partial redaction (showing last 4 digits)"""
        content = "Card: 4111111111111111"

        redacted = processor._redact_content(content, partial=True)

        # Should show last 4 digits
        assert "1111" in redacted
        assert "4111111111111111" not in redacted


class TestEventProcessingPipeline:
    """Test the complete event processing pipeline"""

    @pytest.fixture
    async def processor(self):
        processor = EventProcessor()
        await processor.initialize()
        return processor

    @pytest.fixture
    def sample_event(self, pii_generator):
        """Create sample event with PII"""
        return {
            "event_id": "evt-001",
            "@timestamp": datetime.utcnow().isoformat(),
            "agent": {
                "id": "agent-001",
                "name": "test-agent",
                "ip": "192.168.1.100"
            },
            "event": {
                "type": "clipboard",
                "severity": "medium"
            },
            "content": pii_generator.generate_sample_texts("credit_card", count=1)[0]
        }

    async def test_full_pipeline(self, processor, sample_event):
        """Test complete 6-stage processing pipeline"""
        result = await processor.process_event(sample_event)

        # Should complete all 6 stages
        assert "validated" in result
        assert "normalized" in result
        assert "enriched" in result
        assert "classification" in result
        assert "policy_evaluated" in result
        assert "actions_executed" in result

    async def test_pipeline_validation_stage(self, processor):
        """Test validation stage rejects invalid events"""
        invalid_event = {
            "event_id": "evt-002",
            # Missing required fields
        }

        with pytest.raises(Exception):
            await processor.process_event(invalid_event)

    async def test_pipeline_normalization_stage(self, processor, sample_event):
        """Test normalization stage standardizes data"""
        result = await processor.process_event(sample_event)

        # Should have ECS-compliant structure
        assert "@timestamp" in result
        assert "event" in result
        assert "agent" in result

    async def test_pipeline_classification_stage(self, processor, sample_event):
        """Test classification stage detects PII"""
        result = await processor.process_event(sample_event)

        assert "classification" in result
        assert len(result["classification"]) > 0
        assert result["classification"][0]["type"] == "credit_card"

    async def test_pipeline_performance(self, processor, sample_event):
        """Test end-to-end pipeline performance"""
        import time

        start = time.time()
        for _ in range(100):
            await processor.process_event(sample_event.copy())
        duration = time.time() - start

        avg_latency = (duration / 100) * 1000  # ms
        assert avg_latency < 100, f"Pipeline too slow: {avg_latency:.2f}ms average"


# Export synthetic data for use in other tests
@pytest.fixture(scope="session")
def synthetic_pii_dataset():
    """
    Generate comprehensive synthetic PII dataset
    Available to all tests via fixture
    """
    generator = SyntheticPIIGenerator()

    return {
        "credit_cards": {
            "valid": generator.generate_credit_cards(count=50, valid=True),
            "invalid": generator.generate_credit_cards(count=50, valid=False),
        },
        "ssns": generator.generate_ssns(count=50),
        "emails": generator.generate_emails(count=50),
        "phones": generator.generate_phone_numbers(count=50),
        "api_keys": generator.generate_api_keys(count=50),
        "aws_keys": generator.generate_aws_keys(count=50),
        "passwords": generator.generate_passwords(count=50),
        "sample_texts": {
            "credit_card": generator.generate_sample_texts("credit_card", count=50),
            "ssn": generator.generate_sample_texts("ssn", count=50),
            "email": generator.generate_sample_texts("email", count=50),
            "phone": generator.generate_sample_texts("phone", count=50),
            "api_key": generator.generate_sample_texts("api_key", count=50),
        }
    }
