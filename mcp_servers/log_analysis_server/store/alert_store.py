"""In-memory storage module for the MCP Server.

Provides a thread-safe store based on indexed collections
to retain early processed alerts and allow fast history queries.
"""

import asyncio
import json
import logging
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Any

from mcp_servers.log_analysis_server.models.analysis_output import ThreatAssessment

logger = logging.getLogger(__name__)


class InMemoryAlertStore:
    """Safely manages the RAM storage of generated alerts.
    
    Implements mutual exclusion locks (Mutex) to avoid race conditions
    when the host makes concurrent asynchronous queries over MCP tools.
    """

    def __init__(self, max_history_per_ip: int = 50) -> None:
        """Initializes internal dictionaries and locking mechanisms.
        
        Args:
            max_history_per_ip (int): Maximum number of verdicts retained per IP.
        """
        self._max_history: int = max_history_per_ip
        # Dictionary indexed by IP: [ThreatAssessment, ThreatAssessment, ...]
        self._store: Dict[str, List[ThreatAssessment]] = defaultdict(list)
        # Primitive lock to guarantee consistency in concurrent read/write
        self._lock: threading.Lock = threading.Lock()

    def add_assessment(self, ip: str, assessment: ThreatAssessment) -> None:
        """Records a new analytical verdict in the history for an IP.
        
        If the IP history exceeds the configured maximum limit, the oldest
        record is removed (behavior similar to a FIFO queue).

        Args:
            ip (str): Evaluated source IP address.
            assessment (ThreatAssessment): Object with the LLM verdict data.
        """
        with self._lock:
            # Insert the most recent verdict at the beginning of the list
            self._store[ip].insert(0, assessment)
            
            # Preventive trim to avoid memory leaks from infinite storage
            if len(self._store[ip]) > self._max_history:
                self._store[ip] = self._store[ip][:self._max_history]

    def get_history_by_ip(self, ip: str, limit: int = 10) -> List[ThreatAssessment]:
        """Retrieves the chronological list of historical verdicts for a specific IP.

        Args:
            ip (str): Query IP address.
            limit (int): Maximum number of historical records to return.

        Returns:
            List[ThreatAssessment]: List of threat assessment objects.
        """
        with self._lock:
            if ip not in self._store:
                return []
            # Returns a copy of the sliced list to prevent external corrupt mutations
            return list(self._store[ip][:limit])

    def clear_all(self) -> None:
        """Completely purges all records from the store memory."""
        with self._lock:
            self._store.clear()


class RedisAlertStore:
    """Redis-backed alert store for horizontal scalability.
    
    Supports multi-tenant isolation by including tenant_id in the Redis key.
    Suitable for deployments where multiple replicas of mcp_server share state.
    """

    def __init__(self, redis_client: Any, max_history_per_key: int = 50) -> None:
        """Initialize Redis alert store.
        
        Args:
            redis_client: Redis async client (redis.asyncio.Redis).
            max_history_per_key: Maximum alerts per tenant:IP combination.
        """
        self._redis = redis_client
        self._max_history = max_history_per_key
        self._logger = logger

    async def add_assessment(self, tenant_id: Optional[str], ip: str, assessment: ThreatAssessment) -> None:
        """Persist assessment to Redis with tenant isolation.
        
        Args:
            tenant_id: Tenant identifier (or None for default).
            ip: Source IP address.
            assessment: ThreatAssessment object to store.
        """
        if not self._redis:
            self._logger.warning("Redis client not connected, skipping alert persistence")
            return
        
        key = self._build_key(tenant_id, ip)
        try:
            # Serialize assessment as JSON and push to Redis list (newest first)
            payload = json.dumps(assessment.model_dump(), default=str)
            await self._redis.lpush(key, payload)
            # Trim to max history
            await self._redis.ltrim(key, 0, self._max_history - 1)
        except Exception as exc:
            self._logger.error(f"Failed to persist alert for {key}: {exc}")

    async def get_history_by_ip(self, tenant_id: Optional[str], ip: str, limit: int = 10) -> List[ThreatAssessment]:
        """Retrieve alert history from Redis with tenant isolation.
        
        Args:
            tenant_id: Tenant identifier (or None for default).
            ip: Source IP address.
            limit: Maximum number of records to return.
            
        Returns:
            List of ThreatAssessment objects.
        """
        if not self._redis:
            self._logger.warning("Redis client not connected, returning empty history")
            return []
        
        key = self._build_key(tenant_id, ip)
        try:
            raw_data = await self._redis.lrange(key, 0, limit - 1)
            if not raw_data:
                return []
            
            results = []
            for item in raw_data:
                try:
                    item_str = item.decode("utf-8") if isinstance(item, bytes) else item
                    data = json.loads(item_str)
                    assessment = ThreatAssessment.model_validate(data)
                    results.append(assessment)
                except Exception as e:
                    self._logger.warning(f"Failed to deserialize alert from {key}: {e}")
            return results
        except Exception as exc:
            self._logger.error(f"Failed to retrieve alerts from {key}: {exc}")
            return []

    async def clear_by_tenant_ip(self, tenant_id: Optional[str], ip: str) -> None:
        """Clear all alerts for a specific tenant:IP combination."""
        if not self._redis:
            return
        
        key = self._build_key(tenant_id, ip)
        try:
            await self._redis.delete(key)
        except Exception as exc:
            self._logger.error(f"Failed to clear alerts for {key}: {exc}")

    @staticmethod
    def _build_key(tenant_id: Optional[str], ip: str) -> str:
        """Build tenant-scoped alert key."""
        safe_tenant = tenant_id or "default"
        return f"alerts:{safe_tenant}:{ip}"


# Unique shared instance (Singleton) at MCP server level to maintain state consistency
# For now, defaults to in-memory for backwards compatibility; can be replaced by RedisAlertStore
# during initialization when Redis is available.
alert_store = InMemoryAlertStore()