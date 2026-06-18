"""
KQL (Kibana Query Language) Parser
Converts KQL queries to OpenSearch Query DSL

Supported KQL Syntax:
- Field queries: field:value, field:"quoted value"
- Boolean operators: AND, OR, NOT
- Wildcards: field:val*, field:*val, field:*val*
- Ranges: field > value, field >= value, field < value, field <= value
- Grouping: (field1:value1 OR field2:value2) AND field3:value3
- Nested fields: agent.id:value, classification.label:value

Examples:
- event.type:"file" AND event.severity:"critical"
- agent.id:"AGENT-0001" OR agent.id:"AGENT-0002"
- NOT blocked:true
- event.type:file* AND user.name:john
- @timestamp > "2025-01-01" AND @timestamp < "2025-01-31"
"""

import re
from typing import Dict, Any, List, Optional
from datetime import datetime


class KQLParseError(Exception):
    """Exception raised for KQL parsing errors"""
    pass


class KQLParser:
    """
    Simple KQL parser that converts KQL to OpenSearch Query DSL
    """

    # KQL operators
    OPERATORS = {
        'AND': 'must',
        'OR': 'should',
        'NOT': 'must_not'
    }

    # Comparison operators
    COMPARISONS = {
        '>=': 'gte',
        '<=': 'lte',
        '>': 'gt',
        '<': 'lt',
        '=': 'eq'
    }

    def __init__(self, kql: str):
        self.kql = kql.strip()
        self.tokens = []
        self.position = 0

    def parse(self) -> Dict[str, Any]:
        """
        Parse KQL and convert to OpenSearch Query DSL
        """
        if not self.kql:
            return {"match_all": {}}

        # Tokenize
        self.tokens = self._tokenize()
        self.position = 0

        try:
            # Parse expression
            query = self._parse_expression()

            # Wrap in bool query if needed
            if not isinstance(query, dict):
                return {"match_all": {}}

            # If it's already a complete query, return it
            if 'bool' in query or 'match_all' in query or 'term' in query or 'match' in query:
                return query

            return query

        except Exception as e:
            raise KQLParseError(f"Failed to parse KQL: {str(e)}")

    def _tokenize(self) -> List[str]:
        """
        Tokenize KQL string
        """
        # Pattern for tokenizing
        pattern = r'(\(|\)|AND|OR|NOT|>=|<=|>|<|:|"[^"]*"|[^\s()]+)'
        tokens = re.findall(pattern, self.kql)
        return [t for t in tokens if t.strip()]

    def _current_token(self) -> Optional[str]:
        """Get current token"""
        if self.position < len(self.tokens):
            return self.tokens[self.position]
        return None

    def _next_token(self) -> Optional[str]:
        """Move to next token and return it"""
        self.position += 1
        return self._current_token()

    def _parse_expression(self) -> Dict[str, Any]:
        """
        Parse a KQL expression
        """
        terms = []
        operator = 'must'  # Default: AND

        while self._current_token() is not None:
            token = self._current_token()

            # Handle grouping
            if token == '(':
                self._next_token()
                sub_expr = self._parse_expression()
                terms.append(sub_expr)
                # Skip closing paren
                if self._current_token() == ')':
                    self._next_token()

            # Handle closing paren (end of group)
            elif token == ')':
                break

            # Handle boolean operators
            elif token == 'AND':
                operator = 'must'
                self._next_token()

            elif token == 'OR':
                operator = 'should'
                self._next_token()

            elif token == 'NOT':
                self._next_token()
                not_term = self._parse_term()
                terms.append({
                    'bool': {
                        'must_not': [not_term]
                    }
                })

            # Handle field:value or comparisons
            else:
                term = self._parse_term()
                if term:
                    terms.append(term)

        # Build final query
        if not terms:
            return {"match_all": {}}

        if len(terms) == 1:
            return terms[0]

        return {
            'bool': {
                operator: terms
            }
        }

    def _parse_term(self) -> Optional[Dict[str, Any]]:
        """
        Parse a single term (field:value or field > value)
        """
        token = self._current_token()

        if token is None:
            return None

        # Check if next token is a colon (field:value)
        if self.position + 1 < len(self.tokens) and self.tokens[self.position + 1] == ':':
            field = token
            self._next_token()  # Skip to ':'
            self._next_token()  # Skip to value
            value = self._current_token()

            if value is None:
                return None

            # Remove quotes if present
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]

            self._next_token()  # Move past value

            # Check for wildcards
            if '*' in value:
                return self._build_wildcard_query(field, value)
            else:
                return self._build_term_query(field, value)

        # Check for comparison operators (field > value)
        elif self.position + 2 < len(self.tokens):
            field = token
            operator = self.tokens[self.position + 1]

            if operator in self.COMPARISONS:
                self._next_token()  # Skip to operator
                self._next_token()  # Skip to value
                value = self._current_token()

                if value is None:
                    return None

                # Remove quotes
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]

                self._next_token()  # Move past value

                return self._build_range_query(field, operator, value)

        # If no colon or comparison, just move to next token
        self._next_token()
        return None

    def _build_term_query(self, field: str, value: str) -> Dict[str, Any]:
        """
        Build a term query
        """
        # For boolean values
        if value.lower() in ['true', 'false']:
            return {
                'term': {
                    field: value.lower() == 'true'
                }
            }

        # For keyword fields, use .keyword suffix
        if '.' in field or field in ['event_id', 'agent_id']:
            return {
                'term': {
                    f"{field}.keyword" if not field.endswith('.keyword') else field: value
                }
            }

        # For text fields, use match
        return {
            'match': {
                field: value
            }
        }

    def _build_wildcard_query(self, field: str, value: str) -> Dict[str, Any]:
        """
        Build a wildcard query
        """
        # Convert KQL wildcard to OpenSearch wildcard (same syntax)
        return {
            'wildcard': {
                f"{field}.keyword" if not field.endswith('.keyword') else field: {
                    'value': value
                }
            }
        }

    def _build_range_query(self, field: str, operator: str, value: str) -> Dict[str, Any]:
        """
        Build a range query
        """
        op_name = self.COMPARISONS[operator]

        # Try to parse as date
        try:
            # Check if it's a date string
            if '-' in value or '/' in value:
                # Assume it's a date
                pass
        except:
            pass

        return {
            'range': {
                field: {
                    op_name: value
                }
            }
        }


def parse_kql_to_opensearch(kql: str) -> Dict[str, Any]:
    """
    Parse KQL string and convert to OpenSearch Query DSL

    Args:
        kql: KQL query string

    Returns:
        OpenSearch Query DSL dict

    Raises:
        KQLParseError: If KQL is invalid

    Examples:
        >>> parse_kql_to_opensearch('event.type:"file"')
        {'term': {'event.type.keyword': 'file'}}

        >>> parse_kql_to_opensearch('event.type:"file" AND event.severity:"high"')
        {'bool': {'must': [{'term': {'event.type.keyword': 'file'}}, {'term': {'event.severity.keyword': 'high'}}]}}
    """
    parser = KQLParser(kql)
    return parser.parse()


# Simple test cases
if __name__ == "__main__":
    # Test cases
    test_queries = [
        'event.type:"file"',
        'event.type:"file" AND event.severity:"high"',
        'agent.id:"AGENT-0001" OR agent.id:"AGENT-0002"',
        'NOT blocked:true',
        'event.type:file* AND user.name:john',
        '@timestamp > "2025-01-01"',
        '(event.type:"file" OR event.type:"usb") AND blocked:true'
    ]

    for kql in test_queries:
        print(f"\nKQL: {kql}")
        try:
            result = parse_kql_to_opensearch(kql)
            print(f"OpenSearch DSL: {result}")
        except KQLParseError as e:
            print(f"Error: {e}")
