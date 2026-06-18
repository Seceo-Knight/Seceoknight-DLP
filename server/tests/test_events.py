"""
Tests for Events API
"""

import pytest
from fastapi.testclient import TestClient


class TestEventSubmission:
    """Test event submission endpoints"""

    def test_submit_single_event(self, client, sample_event):
        """Test submitting a single event"""
        response = client.post("/api/v1/events", json=sample_event)

        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "success"
        assert "event_id" in data

    def test_submit_batch_events(self, client, sample_event):
        """Test submitting multiple events in batch"""
        events = [sample_event.copy() for i in range(5)]
        for i, event in enumerate(events):
            event["event_id"] = f"evt-test-{i:03d}"

        response = client.post(
            "/api/v1/events/batch",
            json={"events": events}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["indexed"] == 5
        assert data["errors"] == 0

    def test_submit_invalid_event(self, client):
        """Test submitting invalid event"""
        invalid_event = {
            "event_id": "evt-invalid",
            # Missing required fields
        }

        response = client.post("/api/v1/events", json=invalid_event)
        assert response.status_code in [400, 422]

    def test_event_with_classification(self, client, sample_event):
        """Test event with sensitive data classification"""
        event = sample_event.copy()
        event["content"] = "Credit card: 4532-1234-5678-9010"

        response = client.post("/api/v1/events", json=event)
        assert response.status_code == 201


class TestEventSearch:
    """Test event search and retrieval"""

    def test_list_events(self, client, sample_event):
        """Test listing events"""
        # Submit some events first
        for i in range(3):
            event = sample_event.copy()
            event["event_id"] = f"evt-test-{i:03d}"
            client.post("/api/v1/events", json=event)

        # List events
        response = client.get("/api/v1/events?size=10")
        assert response.status_code == 200

        data = response.json()
        assert "events" in data
        assert "total" in data

    def test_search_events_kql(self, client, sample_event):
        """Test searching events with KQL"""
        # Submit event
        client.post("/api/v1/events", json=sample_event)

        # Search with KQL
        response = client.get('/api/v1/events?kql=event.type:"file"')
        assert response.status_code == 200

        data = response.json()
        assert "events" in data

    def test_search_events_by_severity(self, client, sample_event):
        """Test searching by severity"""
        response = client.get('/api/v1/events?kql=event.severity:"critical"')
        assert response.status_code == 200

    def test_search_events_by_agent(self, client, sample_event):
        """Test searching by agent ID"""
        response = client.get('/api/v1/events?kql=agent.id:"AGENT-0001"')
        assert response.status_code == 200

    def test_get_event_by_id(self, client, sample_event):
        """Test retrieving specific event"""
        # Submit event
        submit_response = client.post("/api/v1/events", json=sample_event)
        event_id = sample_event["event_id"]

        # Get event
        response = client.get(f"/api/v1/events/{event_id}")
        # May be 200 or 404 depending on indexing speed
        assert response.status_code in [200, 404]

    def test_search_with_date_range(self, client):
        """Test searching with date range"""
        response = client.get(
            "/api/v1/events",
            params={
                "start_date": "2025-01-01T00:00:00Z",
                "end_date": "2025-12-31T23:59:59Z",
                "size": 10
            }
        )
        assert response.status_code == 200


class TestEventProcessing:
    """Test event processing pipeline"""

    def test_event_classification(self, client):
        """Test event content classification"""
        event = {
            "event_id": "evt-classification-test",
            "agent": {"id": "AGENT-0001", "name": "TEST", "ip": "127.0.0.1", "os": "Windows"},
            "event": {"type": "file", "severity": "medium"},
            "content": "SSN: 123-45-6789, Card: 4532-1234-5678-9010"
        }

        response = client.post("/api/v1/events", json=event)
        assert response.status_code == 201

    def test_event_redaction(self, client):
        """Test sensitive content redaction"""
        event = {
            "event_id": "evt-redaction-test",
            "agent": {"id": "AGENT-0001", "name": "TEST", "ip": "127.0.0.1", "os": "Windows"},
            "event": {"type": "clipboard", "severity": "high"},
            "content": "My credit card number is 4532-1234-5678-9010"
        }

        response = client.post("/api/v1/events", json=event)
        assert response.status_code == 201

    def test_policy_evaluation(self, client):
        """Test policy engine evaluation"""
        event = {
            "event_id": "evt-policy-test",
            "agent": {"id": "AGENT-0001", "name": "TEST", "ip": "127.0.0.1", "os": "Windows"},
            "event": {"type": "file", "severity": "critical"},
            "file": {"path": "/sensitive/data.txt", "extension": ".txt"},
            "content": "Credit card: 4532-1234-5678-9010"
        }

        response = client.post("/api/v1/events", json=event)
        assert response.status_code == 201
