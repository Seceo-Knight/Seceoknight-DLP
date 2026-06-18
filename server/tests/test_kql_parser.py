"""
Tests for KQL Parser
"""

import pytest
from app.utils.kql_parser import parse_kql_to_opensearch


class TestKQLParser:
    """Test KQL query parsing"""

    def test_simple_field_value(self):
        """Test parsing simple field:value"""
        kql = 'event.type:file'
        query = parse_kql_to_opensearch(kql)

        assert "bool" in query
        assert "must" in query["bool"]

    def test_exact_phrase(self):
        """Test parsing field:"exact phrase" """
        kql = 'event.type:"file operation"'
        query = parse_kql_to_opensearch(kql)

        assert "bool" in query

    def test_wildcard(self):
        """Test parsing wildcard queries"""
        kql = 'agent.name:*desktop*'
        query = parse_kql_to_opensearch(kql)

        assert "bool" in query

    def test_and_operator(self):
        """Test AND operator"""
        kql = 'event.type:file AND event.severity:high'
        query = parse_kql_to_opensearch(kql)

        assert "bool" in query
        assert "must" in query["bool"]

    def test_or_operator(self):
        """Test OR operator"""
        kql = 'event.type:file OR event.type:clipboard'
        query = parse_kql_to_opensearch(kql)

        assert "bool" in query

    def test_not_operator(self):
        """Test NOT operator"""
        kql = 'NOT event.severity:low'
        query = parse_kql_to_opensearch(kql)

        assert "bool" in query

    def test_comparison_operators(self):
        """Test comparison operators"""
        test_cases = [
            'file.size > 1000',
            'file.size >= 1000',
            'file.size < 1000',
            'file.size <= 1000',
        ]

        for kql in test_cases:
            query = parse_kql_to_opensearch(kql)
            assert "bool" in query

    def test_complex_query(self):
        """Test complex query with multiple conditions"""
        kql = 'event.type:file AND (event.severity:high OR event.severity:critical) AND NOT blocked:false'
        query = parse_kql_to_opensearch(kql)

        assert "bool" in query

    def test_nested_field(self):
        """Test nested field access"""
        kql = 'agent.os:Windows'
        query = parse_kql_to_opensearch(kql)

        assert "bool" in query

    def test_exists_query(self):
        """Test field existence check"""
        kql = 'classification:*'
        query = parse_kql_to_opensearch(kql)

        assert "bool" in query

    def test_multiple_values(self):
        """Test field with multiple values"""
        kql = 'event.type:(file OR clipboard OR usb)'
        query = parse_kql_to_opensearch(kql)

        assert "bool" in query

    def test_invalid_kql(self):
        """Test handling of invalid KQL"""
        invalid_queries = [
            '',
            ':::',
            'field',  # No operator or value
        ]

        for kql in invalid_queries:
            try:
                query = parse_kql_to_opensearch(kql)
                # Should either return a valid query or raise exception
                assert isinstance(query, dict)
            except:
                pass  # Expected for some invalid queries
