"""In-memory storage module for the MCP Server.

Provides a thread-safe store based on indexed collections
to retain early processed alerts and allow fast history queries.
"""

import threading
from collections import defaultdict
from typing import Dict, List, Optional
from uuid import UUID

from mcp_servers.log_analysis_server.models.analysis_output import ThreatAssessment


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


# Unique shared instance (Singleton) at MCP server level to maintain state consistency
alert_store = InMemoryAlertStore()