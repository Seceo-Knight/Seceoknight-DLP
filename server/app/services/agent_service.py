"""
Agent Service - Business logic for endpoint agent management
"""

from typing import Optional, List
from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent


class AgentService:
    """Service for agent-related operations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_agent_by_id(self, agent_id: str) -> Optional[Agent]:
        """
        Fetch agent by database ID

        Args:
            agent_id: UUID of the agent

        Returns:
            Agent object or None if not found
        """
        result = await self.db.execute(
            select(Agent).where(Agent.id == agent_id)
        )
        return result.scalar_one_or_none()

    async def get_agent_by_agent_id(self, agent_id: str) -> Optional[Agent]:
        """
        Fetch agent by agent_id field

        Args:
            agent_id: Agent identifier string

        Returns:
            Agent object or None if not found
        """
        result = await self.db.execute(
            select(Agent).where(Agent.agent_id == agent_id)
        )
        return result.scalar_one_or_none()

    async def get_all_agents(
        self,
        skip: int = 0,
        limit: int = 100,
        status: Optional[str] = None,
        os_type: Optional[str] = None,
    ) -> List[Agent]:
        """
        Fetch all agents with optional filtering

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            status: Filter by status (online, offline, error)
            os_type: Filter by OS type (windows, linux, macos)

        Returns:
            List of Agent objects
        """
        query = select(Agent)

        if status:
            query = query.where(Agent.status == status)
        if os_type:
            query = query.where(Agent.os_type == os_type)

        # Order by the numeric agent_code so listings match registration
        # order (001, 002, …). ORDER BY is rendered before LIMIT/OFFSET
        # by SQLAlchemy regardless of method-call order, but we keep the
        # call sequence explicit to mirror the spec.
        query = query.order_by(Agent.agent_code.asc()).offset(skip).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def register_agent(
        self,
        agent_id: str,
        agent_name: str,
        hostname: str,
        os_type: str,
        os_version: str,
        ip_address: str,
        agent_version: str = "1.0.0",
        capabilities: Optional[dict] = None,
    ) -> Agent:
        """
        Register a new agent or update if exists

        Args:
            agent_id: Unique agent identifier
            agent_name: Agent display name
            hostname: Machine hostname
            os_type: Operating system type
            os_version: OS version
            ip_address: Agent IP address
            agent_version: Agent software version
            capabilities: Agent capabilities (JSON)

        Returns:
            Registered Agent object
        """
        # Check if agent already exists
        existing_agent = await self.get_agent_by_agent_id(agent_id)

        if existing_agent:
            # Update existing agent
            existing_agent.agent_name = agent_name
            existing_agent.hostname = hostname
            existing_agent.os_type = os_type
            existing_agent.os_version = os_version
            existing_agent.ip_address = ip_address
            existing_agent.agent_version = agent_version
            existing_agent.capabilities = capabilities or {}
            existing_agent.status = "online"
            existing_agent.last_heartbeat = datetime.utcnow()
            existing_agent.updated_at = datetime.utcnow()

            await self.db.commit()
            await self.db.refresh(existing_agent)
            return existing_agent
        else:
            # Create new agent
            agent = Agent(
                agent_id=agent_id,
                agent_name=agent_name,
                hostname=hostname,
                os_type=os_type,
                os_version=os_version,
                ip_address=ip_address,
                agent_version=agent_version,
                capabilities=capabilities or {},
                status="online",
                last_heartbeat=datetime.utcnow(),
                total_events=0,
            )

            self.db.add(agent)
            await self.db.commit()
            await self.db.refresh(agent)
            return agent

    async def update_agent_heartbeat(self, agent_id: str) -> Optional[Agent]:
        """
        Update agent heartbeat timestamp

        Args:
            agent_id: Agent identifier string

        Returns:
            Updated Agent object or None if not found
        """
        agent = await self.get_agent_by_agent_id(agent_id)
        if not agent:
            return None

        agent.last_heartbeat = datetime.utcnow()
        agent.status = "online"

        await self.db.commit()
        await self.db.refresh(agent)
        return agent

    async def update_agent_status(
        self,
        agent_id: str,
        status: str,
        health_status: Optional[dict] = None,
    ) -> Optional[Agent]:
        """
        Update agent status

        Args:
            agent_id: Agent identifier string
            status: New status (online, offline, error, maintenance)
            health_status: Health status details (JSON)

        Returns:
            Updated Agent object or None if not found
        """
        agent = await self.get_agent_by_agent_id(agent_id)
        if not agent:
            return None

        agent.status = status
        if health_status:
            agent.health_status = health_status
        agent.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(agent)
        return agent

    async def increment_event_count(self, agent_id: str) -> Optional[Agent]:
        """
        Increment agent's event counter

        Args:
            agent_id: Agent identifier string

        Returns:
            Updated Agent object or None if not found
        """
        agent = await self.get_agent_by_agent_id(agent_id)
        if not agent:
            return None

        agent.total_events += 1
        agent.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(agent)
        return agent

    async def unregister_agent(self, agent_id: str) -> bool:
        """
        Unregister (delete) an agent

        Args:
            agent_id: Agent identifier string

        Returns:
            True if agent was deleted, False if not found
        """
        agent = await self.get_agent_by_agent_id(agent_id)
        if not agent:
            return False

        await self.db.delete(agent)
        await self.db.commit()
        return True

    async def get_online_agents(self, threshold_seconds: int = 5) -> List[Agent]:
        """
        Get agents that have sent heartbeat within threshold

        Args:
            threshold_seconds: Consider agent offline if no heartbeat in this many seconds

        Returns:
            List of online Agent objects
        """
        threshold_time = datetime.utcnow() - timedelta(seconds=threshold_seconds)

        query = select(Agent).where(
            Agent.last_heartbeat >= threshold_time
        )

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_offline_agents(self, threshold_seconds: int = 5) -> List[Agent]:
        """
        Get agents that haven't sent heartbeat within threshold

        Args:
            threshold_seconds: Consider agent offline if no heartbeat in this many seconds

        Returns:
            List of offline Agent objects
        """
        threshold_time = datetime.utcnow() - timedelta(seconds=threshold_seconds)

        query = select(Agent).where(
            Agent.last_heartbeat < threshold_time
        )

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def update_offline_agents(self, threshold_seconds: int = 5) -> int:
        """
        Mark agents as offline if they haven't sent heartbeat

        Args:
            threshold_seconds: Consider agent offline if no heartbeat in this many seconds

        Returns:
            Number of agents marked offline
        """
        offline_agents = await self.get_offline_agents(threshold_seconds)

        count = 0
        for agent in offline_agents:
            if agent.status != "offline":
                agent.status = "offline"
                count += 1

        if count > 0:
            await self.db.commit()

        return count

    async def get_agent_count(
        self,
        status: Optional[str] = None,
        os_type: Optional[str] = None,
    ) -> int:
        """
        Get total count of agents

        Args:
            status: Optional status filter
            os_type: Optional OS type filter

        Returns:
            Number of agents
        """
        from sqlalchemy import func

        query = select(func.count(Agent.id))

        if status:
            query = query.where(Agent.status == status)
        if os_type:
            query = query.where(Agent.os_type == os_type)

        result = await self.db.execute(query)
        return result.scalar_one()

    async def get_agent_statistics(self) -> dict:
        """
        Get agent statistics

        Returns:
            Dictionary with agent statistics
        """
        total = await self.get_agent_count()
        online = await self.get_agent_count(status="online")
        offline = await self.get_agent_count(status="offline")
        error = await self.get_agent_count(status="error")

        windows = await self.get_agent_count(os_type="windows")
        linux = await self.get_agent_count(os_type="linux")
        macos = await self.get_agent_count(os_type="macos")

        return {
            "total": total,
            "online": online,
            "offline": offline,
            "error": error,
            "by_os": {
                "windows": windows,
                "linux": linux,
                "macos": macos,
            },
        }
