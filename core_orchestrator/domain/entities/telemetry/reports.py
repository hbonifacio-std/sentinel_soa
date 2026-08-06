import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

@dataclass
class ThreatLevelStat:
    level: str
    count: int

@dataclass
class KillChainPhaseStat:
    phase: str
    count: int

@dataclass
class TopAttackerStat:
    attacker: str
    count: int

@dataclass
class MitreTacticStat:
    phase: str
    count: int

@dataclass
class ReportSummary:
    threat_levels: List[ThreatLevelStat]
    kill_chain_phases: List[KillChainPhaseStat]
    top_attackers: List[TopAttackerStat]
    mitre_tactics: List[MitreTacticStat]


@dataclass
class AnalysisActionEntry:
    comment: str
    created_at_utc: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

@dataclass
class SuggestedMitigation:
    action: str
    target: str
    reason:  str
    severity:  str
    automation_ready: bool=False


@dataclass
class AnalysisReport:
    """
    Represents an analysis report containing details of a security threat and the actions
    taken to address it.

    This class is designed to store and manage information related to analyzing threats,
    identifying potential risks, and tracking actions or decisions made during the analysis
    process. It provides mechanisms to mark the report as resolved and to append action
    comments for detailed tracking.

    Attributes:
        id: Unique identifier for the analysis report, generated automatically if not provided.
        source_id: Identifier for the source from which the threat was detected (optional).
        client_id: Identifier of the client associated with the detected threat (optional).
        source_ip: IP address associated with the threat source (optional).
        threat_level: Level of severity of the detected threat (e.g., "low", "medium", "high").
        threat_score: Numerical representation of the threat's severity or impact (optional).
        kill_chain_phase: Phase in the kill chain where the threat was identified (optional).
        reviewed: Status indicating if the report has been reviewed (default is False).
        resolved: Status indicating if the report has been resolved (default is False).
        actions: List of actions taken or comments added during the analysis process.
        created_at_utc: Timestamp indicating when the report was created, set to the current
            UTC time by default.
        resolved_at_utc: Timestamp indicating when the report was marked as resolved
            (optional).
    """
    id: Optional[str] = None
    threat_detected: bool = False
    source_id: Optional[str] = None
    window_id: Optional[str] = None
    client_id: Optional[str] = None
    source_ip: Optional[str] = None
    targeted_asset: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_tactic_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_sub_technique: Optional[str] = None
    mitre_sub_technique_id: Optional[str] = None
    threat_level: Optional[str] = None
    threat_score: Optional[float] = None
    error: Optional[str] = None
    indicators_found: List[str] = field(default_factory=list)
    reasoning_summary: Optional[str] = None
    recommendation: Optional[str] = None
    suggested_mitigations: List[SuggestedMitigation] = field(default_factory=list)
    kill_chain_phase: Optional[str] = None
    reviewed: bool = False
    resolved: bool = False
    actions: List[AnalysisActionEntry] = field(default_factory=list)
    created_at_utc: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    resolved_at_utc: Optional[datetime] = None

    def resolve_report(self) -> None:
        """
        Marks the report as resolved by updating the relevant status attributes.

        The method sets the `resolved` and `reviewed` attributes to `True ` and records
        the current UTC timestamp in the `resolved_at_utc` attribute.

        Raises:
            TypeError: If datetime or timezone modules are not properly imported.
        """
        self.resolved = True
        self.reviewed = True
        self.resolved_at_utc = datetime.now(timezone.utc)

    def add_action_comment(self, comment: str) -> None:
        """
        Adds a new action comment to the list of actions.

        This method creates a new AnalysisActionEntry using the provided comment
        and appends it to the action list.

        Parameters
        ----------
        comment : str
            The comment to associate with the action.

        Returns
        -------
        None
        """
        action = AnalysisActionEntry(comment=comment)
        self.actions.append(action)

@dataclass
class ForensicAnalysisRecord:
    analysis_id: str
    query: str
    markdown_report: str
    source_id: str
    client_id: str
    created_at_utc: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    total_matches: int = 0
    highlights: List[str] = field(default_factory=list)
    sample_results: List[Dict[str, Any]] = field(default_factory=list)
    llm_provider_used: Optional[str] = None
    llm_model_used: Optional[str] = None
    provider_source: Optional[str] = None

    def __post_init__(self) -> None:
        """
        Validates the value of the total_matches attribute during the initialization
        process of the class instance.

        Raises:
            ValueError: If total_matches is less than 0.
        """
        if self.total_matches < 0:
            raise ValueError("total_matches must be greater than or equal to 0")


    def add_highlight(self, highlight: str) -> None:
        """
        Adds a new highlight to the list of highlights if it's non-empty and not already present.

        Parameters:
        highlight (str): The highlight string to add.

        Returns:
        None
        """
        if highlight and highlight not in self.highlights:
            self.highlights.append(highlight)

    def attach_sample_result(self, result: Dict[str, Any]) -> None:
        """
        Adds a new sample result to the collection and increments the total match count.

        ARG
        ----------
        sample_results : list of dict
            A collection of sample result dictionaries.
        total_matches : int
            The total count of matches recorded.

        Parameters
        ----------
        result : Dict[str, Any]
            A dictionary containing the details of a sample result.

        Returns
        -------
        None
        """
        self.sample_results.append(result)
        self.total_matches += 1