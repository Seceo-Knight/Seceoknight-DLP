"""
Tests for Agent Registration API
"""

import pytest
from fastapi.testclient import TestClient


class TestAgentRegistration:
    """Test agent registration and authentication"""

    def test_agent_registration(self, client, sample_agent):
        """Test agent registration endpoint"""
        response = client.post("/api/v1/agents/register", json=sample_agent)

        assert response.status_code == 201
        data = response.json()
        assert "agent_id" in data
        assert "registration_key" in data
        assert data["agent_id"].startswith("AGENT-")
        assert len(data["registration_key"]) > 0

    def test_agent_authentication(self, client, sample_agent):
        """Test agent authentication with registration key"""
        # First register
        reg_response = client.post("/api/v1/agents/register", json=sample_agent)
        assert reg_response.status_code == 201

        agent_id = reg_response.json()["agent_id"]
        registration_key = reg_response.json()["registration_key"]

        # Then authenticate
        auth_response = client.post(
            "/api/v1/agents/auth",
            json={"agent_id": agent_id, "registration_key": registration_key}
        )

        assert auth_response.status_code == 200
        data = auth_response.json()
        assert "access_token" in data
        assert "expires_in" in data

    def test_agent_registration_duplicate_name(self, client, sample_agent):
        """Test registering agents with same name"""
        # Register first agent
        response1 = client.post("/api/v1/agents/register", json=sample_agent)
        assert response1.status_code == 201
        agent_id_1 = response1.json()["agent_id"]

        # Register second agent with same name
        response2 = client.post("/api/v1/agents/register", json=sample_agent)
        assert response2.status_code == 201
        agent_id_2 = response2.json()["agent_id"]

        # Should have different IDs
        assert agent_id_1 != agent_id_2

    def test_agent_authentication_invalid_key(self, client, sample_agent):
        """Test authentication with invalid registration key"""
        # Register agent
        reg_response = client.post("/api/v1/agents/register", json=sample_agent)
        agent_id = reg_response.json()["agent_id"]

        # Try to authenticate with wrong key
        auth_response = client.post(
            "/api/v1/agents/auth",
            json={"agent_id": agent_id, "registration_key": "invalid-key"}
        )

        assert auth_response.status_code == 401

    def test_list_agents(self, client, sample_agent):
        """Test listing all agents"""
        # Register multiple agents
        for i in range(3):
            agent_data = sample_agent.copy()
            agent_data["name"] = f"TEST-AGENT-{i:02d}"
            client.post("/api/v1/agents/register", json=agent_data)

        # List agents
        response = client.get("/api/v1/agents")
        assert response.status_code == 200

        agents = response.json()
        assert len(agents) >= 3

    def test_agent_heartbeat(self, client, sample_agent):
        """Test agent heartbeat"""
        # Register and authenticate agent
        reg_response = client.post("/api/v1/agents/register", json=sample_agent)
        agent_id = reg_response.json()["agent_id"]
        registration_key = reg_response.json()["registration_key"]

        auth_response = client.post(
            "/api/v1/agents/auth",
            json={"agent_id": agent_id, "registration_key": registration_key}
        )
        token = auth_response.json()["access_token"]

        # Send heartbeat
        heartbeat_response = client.post(
            f"/api/v1/agents/{agent_id}/heartbeat",
            json={"ip_address": "192.168.1.100", "status": "active"},
            headers={"Authorization": f"Bearer {token}"}
        )

        assert heartbeat_response.status_code == 200


class TestAgentManagement:
    """Test agent management operations"""

    def test_get_agent_details(self, client, sample_agent):
        """Test getting agent details"""
        # Register agent
        reg_response = client.post("/api/v1/agents/register", json=sample_agent)
        agent_id = reg_response.json()["agent_id"]

        # Get agent details
        response = client.get(f"/api/v1/agents/{agent_id}")
        assert response.status_code == 200

        data = response.json()
        assert data["agent_id"] == agent_id
        assert data["name"] == sample_agent["name"]

    def test_delete_agent(self, client, sample_agent, admin_token):
        """Test deleting an agent"""
        # Register agent
        reg_response = client.post("/api/v1/agents/register", json=sample_agent)
        agent_id = reg_response.json()["agent_id"]

        # Delete agent (requires admin)
        if admin_token:
            response = client.delete(
                f"/api/v1/agents/{agent_id}",
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            assert response.status_code in [200, 204]

    def test_agent_not_found(self, client):
        """Test getting non-existent agent"""
        response = client.get("/api/v1/agents/AGENT-9999")
        assert response.status_code == 404
