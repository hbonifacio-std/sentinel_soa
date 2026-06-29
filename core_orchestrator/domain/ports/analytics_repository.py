from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

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
    async def get_report_by_id(self, report_id: str) -> Optional[dict]:
        """
        Retrieves a single analysis report by its ID.
        """
        raise NotImplementedError

    @abstractmethod
    async def update_report(self, report_id: str, updates: dict) -> bool:
        """
        Updates an analysis report.
        """
        raise NotImplementedError

    @abstractmethod
    async def add_action_to_report(self, report_id: str, action: dict) -> bool:
        """
        Adds a corrective action to an analysis report.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_distinct_source_ids(self) -> List[str]:
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
    async def get_debug_reports(self, limit: int) -> List[Dict[str, Any]]:
        """
        Retrieves a few sample documents from the analysis_reports collection for debugging.
        """
        raise NotImplementedError
