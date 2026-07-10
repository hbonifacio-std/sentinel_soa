from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

from pydantic import BaseModel


class AnalyticsRepository(ABC):
    """
    Port for the analytics repository.
    """

    @abstractmethod
    async def get_paginated_reports(self, query: dict, page: int, limit: int) -> dict:
        """
        Retrieves a paginated list of analysis reports.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_report_by_id(self, report_id: str, client_id: str) -> Optional[dict]:
        """
        Retrieves a single analysis report by its ID.
        """
        raise NotImplementedError

    @abstractmethod
    async def update_report(self, report_id: str, client_id: str, updates: dict) -> bool:
        """
        Updates an analysis report.
        """
        raise NotImplementedError

    @abstractmethod
    async def add_action_to_report(self, report_id: str, client_id: str, action: dict) -> bool:
        """
        Adds a corrective action to an analysis report.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_distinct_source_ids(self, client_id: str) -> List[str]:
        """
        Gets a list of distinct source_ids from the reports.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_aggregated_stats(self, pipeline: list) -> List[dict]:
        """
        Executes an aggregation pipeline to get statistics.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_summary_stats(self) -> Dict[str, Any]:
        """
        Retrieves summary statistics for the dashboard.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_paginated_logs(self, query: dict, page: int, limit: int) -> dict:
        """
        Retrieves a paginated list of raw telemetry logs.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_debug_reports(self, client_id: str, limit: int) -> List[Dict[str, Any]]:
        """
        Retrieves a few sample documents from the analysis_reports collection for debugging.
        """
        raise NotImplementedError

    @abstractmethod
    async def create_report(self, report: BaseModel) -> str:
        """
        Creates a new analysis report.
        """
        raise NotImplementedError
