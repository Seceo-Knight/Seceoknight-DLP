"""
Synthetic PII Data Generator for Testing
Generates realistic test data for DLP detection validation
"""

import random
import string
from datetime import datetime, timedelta
from typing import List, Dict, Any
from faker import Faker


class SyntheticPIIGenerator:
    """Generate synthetic PII data for testing detection accuracy"""

    def __init__(self, seed: int = 42):
        """Initialize generator with optional seed for reproducibility"""
        self.fake = Faker()
        Faker.seed(seed)
        random.seed(seed)

    def generate_credit_cards(self, count: int = 100) -> List[Dict[str, Any]]:
        """
        Generate valid credit card numbers (Luhn algorithm compliant)

        Returns list of dicts with:
        - number: Card number
        - is_valid: Always True (for positive tests)
        - type: Card type (Visa, Mastercard, etc.)
        """
        cards = []
        card_types = [
            ('Visa', '4'),
            ('Mastercard', '5'),
            ('Amex', '37'),
            ('Discover', '6011')
        ]

        for _ in range(count):
            card_type, prefix = random.choice(card_types)

            # Generate card number
            if card_type == 'Amex':
                length = 15
            else:
                length = 16

            # Start with prefix
            number = prefix

            # Generate remaining digits (except check digit)
            remaining = length - len(prefix) - 1
            for _ in range(remaining):
                number += str(random.randint(0, 9))

            # Calculate and append Luhn check digit
            check_digit = self._calculate_luhn_check_digit(number)
            number += str(check_digit)

            cards.append({
                'number': number,
                'formatted': self._format_credit_card(number),
                'is_valid': True,
                'type': card_type,
                'expiry': f"{random.randint(1,12):02d}/{random.randint(25,30)}"
            })

        return cards

    def generate_ssn(self, count: int = 100) -> List[Dict[str, Any]]:
        """
        Generate valid-looking US Social Security Numbers
        Format: XXX-XX-XXXX
        """
        ssns = []

        for _ in range(count):
            # SSN format: AAA-GG-SSSS
            # First 3 digits (Area): 001-899 (excluding 666)
            area = random.choice([n for n in range(1, 900) if n != 666])

            # Next 2 digits (Group): 01-99
            group = random.randint(1, 99)

            # Last 4 digits (Serial): 0001-9999
            serial = random.randint(1, 9999)

            ssn = f"{area:03d}-{group:02d}-{serial:04d}"
            ssn_plain = f"{area:03d}{group:02d}{serial:04d}"

            ssns.append({
                'number': ssn,
                'plain': ssn_plain,
                'is_valid': True,
                'format': 'XXX-XX-XXXX'
            })

        return ssns

    def generate_emails(self, count: int = 100) -> List[Dict[str, Any]]:
        """Generate realistic email addresses"""
        emails = []
        domains = [
            'gmail.com', 'yahoo.com', 'outlook.com', 'company.com',
            'corporate.net', 'business.org', 'enterprise.io'
        ]

        for _ in range(count):
            email = self.fake.email()
            # Mix in custom domains
            if random.random() < 0.3:
                username = email.split('@')[0]
                domain = random.choice(domains)
                email = f"{username}@{domain}"

            emails.append({
                'email': email,
                'is_valid': True,
                'username': email.split('@')[0],
                'domain': email.split('@')[1]
            })

        return emails

    def generate_phone_numbers(self, count: int = 100) -> List[Dict[str, Any]]:
        """Generate US phone numbers in various formats"""
        phones = []
        formats = [
            lambda a, b, c: f"({a}) {b}-{c}",      # (555) 123-4567
            lambda a, b, c: f"{a}-{b}-{c}",        # 555-123-4567
            lambda a, b, c: f"{a}.{b}.{c}",        # 555.123.4567
            lambda a, b, c: f"+1{a}{b}{c}",        # +15551234567
            lambda a, b, c: f"{a}{b}{c}",          # 5551234567
        ]

        for _ in range(count):
            area = random.randint(200, 999)
            exchange = random.randint(200, 999)
            number = random.randint(0, 9999)

            format_func = random.choice(formats)
            formatted = format_func(area, exchange, f"{number:04d}")

            phones.append({
                'number': formatted,
                'plain': f"{area}{exchange}{number:04d}",
                'is_valid': True,
                'area_code': area
            })

        return phones

    def generate_api_keys(self, count: int = 50) -> List[Dict[str, Any]]:
        """Generate realistic API keys and secrets"""
        api_keys = []

        patterns = [
            ('AWS', lambda: f"AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}"),
            ('GitHub', lambda: f"ghp_{''.join(random.choices(string.ascii_letters + string.digits, k=36))}"),
            ('Stripe', lambda: f"sk_live_{''.join(random.choices(string.ascii_letters + string.digits, k=24))}"),
            ('OpenAI', lambda: f"sk-{''.join(random.choices(string.ascii_letters + string.digits, k=48))}"),
            ('Generic', lambda: ''.join(random.choices(string.ascii_letters + string.digits, k=32)))
        ]

        for _ in range(count):
            key_type, generator = random.choice(patterns)
            key = generator()

            api_keys.append({
                'key': key,
                'type': key_type,
                'is_valid': True,
                'length': len(key)
            })

        return api_keys

    def generate_medical_records(self, count: int = 50) -> List[Dict[str, Any]]:
        """Generate HIPAA-relevant medical record identifiers"""
        records = []

        for _ in range(count):
            # Medical Record Number (MRN)
            mrn = f"MRN{random.randint(100000, 999999)}"

            # Patient ID
            patient_id = f"PT-{random.randint(10000, 99999)}"

            # Insurance ID
            insurance_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

            records.append({
                'mrn': mrn,
                'patient_id': patient_id,
                'insurance_id': insurance_id,
                'patient_name': self.fake.name(),
                'dob': self.fake.date_of_birth(minimum_age=18, maximum_age=90).isoformat(),
                'is_valid': True,
                'sensitivity': 'HIPAA'
            })

        return records

    def generate_financial_data(self, count: int = 50) -> List[Dict[str, Any]]:
        """Generate financial data (account numbers, routing numbers)"""
        financial = []

        for _ in range(count):
            # Bank account number (8-12 digits)
            account_length = random.randint(8, 12)
            account_number = ''.join(random.choices(string.digits, k=account_length))

            # Routing number (9 digits)
            routing = ''.join(random.choices(string.digits, k=9))

            # IBAN (International Bank Account Number)
            country = random.choice(['DE', 'FR', 'GB', 'IT'])
            iban = f"{country}{random.randint(10,99)}{''.join(random.choices(string.digits, k=18))}"

            financial.append({
                'account_number': account_number,
                'routing_number': routing,
                'iban': iban,
                'account_type': random.choice(['checking', 'savings', 'investment']),
                'is_valid': True,
                'sensitivity': 'PCI-DSS'
            })

        return financial

    def generate_negative_samples(self, count: int = 100) -> List[Dict[str, Any]]:
        """
        Generate data that should NOT be detected as PII
        (for testing false positives)
        """
        negatives = []

        patterns = [
            lambda: ''.join(random.choices(string.digits, k=16)),  # Random 16 digits (no Luhn)
            lambda: f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}",  # Wrong SSN format
            lambda: self.fake.text(max_nb_chars=50),  # Regular text
            lambda: f"user{random.randint(1000,9999)}@example.test",  # Test emails
            lambda: f"ID-{random.randint(100000,999999)}",  # Generic IDs
            lambda: str(random.randint(1000000000, 9999999999)),  # Random numbers
        ]

        for _ in range(count):
            pattern = random.choice(patterns)
            data = pattern()

            negatives.append({
                'data': data,
                'should_detect': False,
                'type': 'negative_sample'
            })

        return negatives

    def generate_mixed_dataset(self, size: int = 1000) -> Dict[str, List[Dict[str, Any]]]:
        """
        Generate a mixed dataset with all PII types

        Returns dict with keys:
        - credit_cards
        - ssn
        - emails
        - phones
        - api_keys
        - medical
        - financial
        - negatives
        """
        # Calculate counts per category (proportional distribution)
        counts = {
            'credit_cards': int(size * 0.15),
            'ssn': int(size * 0.15),
            'emails': int(size * 0.20),
            'phones': int(size * 0.15),
            'api_keys': int(size * 0.10),
            'medical': int(size * 0.10),
            'financial': int(size * 0.10),
            'negatives': int(size * 0.05)
        }

        dataset = {
            'credit_cards': self.generate_credit_cards(counts['credit_cards']),
            'ssn': self.generate_ssn(counts['ssn']),
            'emails': self.generate_emails(counts['emails']),
            'phones': self.generate_phone_numbers(counts['phones']),
            'api_keys': self.generate_api_keys(counts['api_keys']),
            'medical': self.generate_medical_records(counts['medical']),
            'financial': self.generate_financial_data(counts['financial']),
            'negatives': self.generate_negative_samples(counts['negatives'])
        }

        return dataset

    def generate_test_documents(self, count: int = 20) -> List[Dict[str, Any]]:
        """Generate complete documents with embedded PII for integration testing"""
        documents = []

        for i in range(count):
            # Generate PII data
            credit_card = self.generate_credit_cards(1)[0]
            ssn = self.generate_ssn(1)[0]
            email = self.generate_emails(1)[0]
            phone = self.generate_phone_numbers(1)[0]

            # Create document content with embedded PII
            content = f"""
            Customer Information Record #{i+1000}

            Name: {self.fake.name()}
            Email: {email['email']}
            Phone: {phone['number']}
            SSN: {ssn['number']}

            Payment Information:
            Credit Card: {credit_card['formatted']}
            Expiry: {credit_card['expiry']}

            Address:
            {self.fake.street_address()}
            {self.fake.city()}, {self.fake.state()} {self.fake.zipcode()}

            Additional Notes:
            {self.fake.text(max_nb_chars=200)}
            """

            documents.append({
                'id': f"DOC-{i+1:04d}",
                'content': content,
                'pii_count': 4,  # CC, SSN, Email, Phone
                'expected_detections': ['credit_card', 'ssn', 'email', 'phone'],
                'file_type': random.choice(['txt', 'doc', 'pdf', 'xlsx']),
                'created_at': (datetime.utcnow() - timedelta(days=random.randint(1, 365))).isoformat()
            })

        return documents

    # Helper methods

    def _calculate_luhn_check_digit(self, number: str) -> int:
        """Calculate Luhn algorithm check digit"""
        def digits_of(n):
            return [int(d) for d in str(n)]

        digits = digits_of(number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]

        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d * 2))

        return (10 - (checksum % 10)) % 10

    def _format_credit_card(self, number: str) -> str:
        """Format credit card number as XXXX-XXXX-XXXX-XXXX or XXXX-XXXXXX-XXXXX"""
        if len(number) == 15:  # Amex
            return f"{number[:4]}-{number[4:10]}-{number[10:]}"
        else:  # Visa, Mastercard, Discover
            return f"{number[:4]}-{number[4:8]}-{number[8:12]}-{number[12:]}"


# Convenience functions for quick testing

def generate_test_dataset(size: int = 1000, seed: int = 42) -> Dict[str, List[Dict[str, Any]]]:
    """Quick function to generate a full test dataset"""
    generator = SyntheticPIIGenerator(seed=seed)
    return generator.generate_mixed_dataset(size=size)


def generate_test_documents(count: int = 20, seed: int = 42) -> List[Dict[str, Any]]:
    """Quick function to generate test documents"""
    generator = SyntheticPIIGenerator(seed=seed)
    return generator.generate_test_documents(count=count)


if __name__ == "__main__":
    # Example usage
    generator = SyntheticPIIGenerator()

    print("Generating synthetic PII data...")
    dataset = generator.generate_mixed_dataset(size=100)

    print(f"\nDataset Summary:")
    for category, items in dataset.items():
        print(f"  {category}: {len(items)} items")

    print(f"\nSample Credit Card:")
    print(dataset['credit_cards'][0])

    print(f"\nSample SSN:")
    print(dataset['ssn'][0])

    print(f"\nSample Document:")
    docs = generator.generate_test_documents(count=1)
    print(docs[0]['content'][:200] + "...")
