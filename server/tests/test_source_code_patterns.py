"""
Test source code pattern detection
"""
import pytest
from app.services.event_processor import EventProcessor


class TestSourceCodePatterns:
    """Test source code detection patterns"""

    @pytest.fixture
    def processor(self):
        """Create EventProcessor instance"""
        return EventProcessor()

    @pytest.mark.asyncio
    async def test_source_code_function_detection(self, processor):
        """Test function definition detection"""
        event = {
            "event_id": "test-001",
            "content": "function myFunction() { return true; }",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "SOURCE_CODE" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_source_code_class_detection(self, processor):
        """Test class definition detection"""
        event = {
            "event_id": "test-002",
            "content": "class MyClass: def __init__(self): pass",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "SOURCE_CODE" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_source_code_import_detection(self, processor):
        """Test import statement detection"""
        event = {
            "event_id": "test-003",
            "content": "import os\nfrom datetime import datetime",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "SOURCE_CODE" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_source_code_variable_detection(self, processor):
        """Test variable declaration detection"""
        event = {
            "event_id": "test-004",
            "content": "const apiKey = 'secret';\nlet count = 0;",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "SOURCE_CODE" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_api_key_aws_detection(self, processor):
        """Test AWS API key detection in code"""
        event = {
            "event_id": "test-005",
            "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "API_KEY_IN_CODE" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_api_key_github_detection(self, processor):
        """Test GitHub token detection in code"""
        event = {
            "event_id": "test-006",
            "content": 'token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "API_KEY_IN_CODE" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_api_key_generic_detection(self, processor):
        """Test generic API key pattern in code"""
        event = {
            "event_id": "test-007",
            "content": 'api_key: "not_a_real_key_1234567890abcdefghijklmnopqrstuvwxyz"',
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "API_KEY_IN_CODE" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_database_jdbc_detection(self, processor):
        """Test JDBC connection string detection"""
        event = {
            "event_id": "test-008",
            "content": "jdbc:mysql://localhost:3306/mydb?user=root&password=secret",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "DATABASE_CONNECTION" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_database_mongodb_detection(self, processor):
        """Test MongoDB connection string detection"""
        event = {
            "event_id": "test-009",
            "content": "mongodb://user:password@localhost:27017/mydb",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "DATABASE_CONNECTION" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_database_mongodb_srv_detection(self, processor):
        """Test MongoDB SRV connection string detection"""
        event = {
            "event_id": "test-010",
            "content": "mongodb+srv://user:password@cluster.mongodb.net/mydb",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "DATABASE_CONNECTION" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_database_redis_detection(self, processor):
        """Test Redis connection string detection"""
        event = {
            "event_id": "test-011",
            "content": "redis://localhost:6379/0",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "DATABASE_CONNECTION" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_database_postgresql_detection(self, processor):
        """Test PostgreSQL JDBC connection string detection"""
        event = {
            "event_id": "test-012",
            "content": "jdbc:postgresql://localhost:5432/mydb",
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        assert any(c["label"] == "DATABASE_CONNECTION" for c in result["classification"])

    @pytest.mark.asyncio
    async def test_multiple_patterns_detection(self, processor):
        """Test detection of multiple patterns in same content"""
        event = {
            "event_id": "test-013",
            "content": """
            function connectDB() {
                const conn = "jdbc:mysql://localhost:3306/mydb";
                const apiKey = "AKIAIOSFODNN7EXAMPLE";
            }
            """,
            "event": {"type": "clipboard", "severity": "low"}
        }
        result = await processor.classify_event(event)
        assert "classification" in result
        labels = [c["label"] for c in result["classification"]]
        assert "SOURCE_CODE" in labels
        assert "API_KEY_IN_CODE" in labels
        assert "DATABASE_CONNECTION" in labels

